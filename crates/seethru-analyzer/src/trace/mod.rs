mod catalog;
mod collect;
mod model;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use seethru_core::{
    Channel, Confidence, EdgeKind, EvidenceStep, Exposure, Location, Node, NodeId, NodeKind,
    RuleId, RuleScope, Severity, Strength as GuardStrength, Zone,
};

use crate::build_output::app_route_url;
use crate::classify::{FileRole, ProjectHints, file_name};
use crate::graph::{Graph, Verdict, file_id, file_location, file_step, step};
use crate::resolve::Resolver;
use crate::roles::Assigned;
use crate::rules::{self, EntryKind, Reached};
use crate::script::{Directive, is_service_role_env};

use catalog::{HTTP_METHODS, auth_like, is_project_specifier};
pub(crate) use collect::collect;
pub(crate) use model::FileFlow;
use model::{Candidate, ExportTarget, Imported, Matcher, Op, Strength, Target, Value};

const MAX_DEPTH: usize = 24;
const MAX_REEXPORTS: usize = 8;
const MAX_ROUNDS: usize = 20;
const MAX_HOPS: usize = 12;
const MAX_CALLERS: usize = 200;
const SERVICE_ROLE: &str = "principal:supabase:service_role";

pub(crate) struct Module {
    pub rel_path: String,
    pub role: FileRole,
    pub directive: Option<Directive>,
    pub flow: FileFlow,
}

type FnRef = (usize, usize);
type States = BTreeMap<(FnRef, Gate), Option<(FnRef, Gate, usize)>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Gate {
    Open,
    Unknown,
    Guarded,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GuardRef {
    file: usize,
    function: String,
    label: String,
    location: Location,
    strength: Strength,
}

#[derive(Debug, Clone, PartialEq)]
enum Resolved {
    Function(FnRef),
    ServiceClient(Location),
    OtherClient,
    Env(String),
    Secret,
    Package(String),
    Broken,
    Unknown,
}

struct Risk {
    function: FnRef,
    access: usize,
    client: Option<Location>,
}

struct Entry {
    id: String,
    label: String,
    kind: EntryKind,
    channel: Channel,
    file: usize,
    handlers: Vec<(FnRef, String)>,
    url: Option<String>,
    next_root: Option<String>,
}

struct Reach {
    gate: Gate,
    risk: usize,
    path: Vec<(FnRef, usize, FnRef)>,
    guard: Option<GuardRef>,
    truncated: bool,
    step_label: String,
    handler: FnRef,
}

struct Project<'p> {
    modules: &'p [Module],
    index: BTreeMap<&'p str, usize>,
    resolver: &'p Resolver<'p>,
    throwing: BTreeMap<FnRef, Strength>,
    checks: BTreeMap<FnRef, Strength>,
    guards_any: BTreeSet<FnRef>,
    callees: BTreeMap<FnRef, Vec<Option<FnRef>>>,
    gates: BTreeMap<FnRef, Vec<(Gate, Option<GuardRef>)>>,
}

impl<'p> Project<'p> {
    fn new(modules: &'p [Module], resolver: &'p Resolver<'p>) -> Self {
        let index = modules
            .iter()
            .enumerate()
            .map(|(position, module)| (module.rel_path.as_str(), position))
            .collect();
        let mut project = Self {
            modules,
            index,
            resolver,
            throwing: BTreeMap::new(),
            checks: BTreeMap::new(),
            guards_any: BTreeSet::new(),
            callees: BTreeMap::new(),
            gates: BTreeMap::new(),
        };
        project.link_calls();
        project.summarize();
        project.compute_gates();
        project
    }

    fn functions(&self) -> impl Iterator<Item = (FnRef, &'p model::FlowFunction)> + 'p {
        self.modules
            .iter()
            .enumerate()
            .filter(|(_, module)| !module.flow.opaque)
            .flat_map(|(file, module)| {
                module
                    .flow
                    .functions
                    .iter()
                    .enumerate()
                    .map(move |(index, function)| ((file, index), function))
            })
    }

    fn function(&self, at: FnRef) -> Option<&'p model::FlowFunction> {
        self.modules.get(at.0)?.flow.functions.get(at.1)
    }

    fn resolve(&self, file: usize, value: &Value, depth: usize) -> Resolved {
        if depth > MAX_DEPTH {
            return Resolved::Unknown;
        }
        let Some(module) = self.modules.get(file) else {
            return Resolved::Unknown;
        };
        let flow = &module.flow;
        match value {
            Value::Function(index) if *index < flow.functions.len() => {
                Resolved::Function((file, *index))
            }
            Value::Function(_) | Value::Unknown => Resolved::Unknown,
            Value::Binding(symbol) => {
                if let Some((specifier, imported)) = flow.imports.get(symbol) {
                    return self.resolve_import(file, specifier, imported, depth + 1, 0);
                }
                match flow.bindings.get(symbol) {
                    Some(bound) => self.resolve(file, bound, depth + 1),
                    None => Resolved::Unknown,
                }
            }
            Value::Member(symbol, name) => match flow.imports.get(symbol) {
                Some((specifier, Imported::Namespace)) => self.resolve_import(
                    file,
                    specifier,
                    &Imported::Named(name.clone()),
                    depth + 1,
                    0,
                ),
                _ => Resolved::Unknown,
            },
            Value::Call(callee) => match self.resolve(file, callee, depth + 1) {
                Resolved::Function(function) => self.returned(function, depth + 1),
                Resolved::Package(name) => Resolved::Package(name),
                Resolved::Broken => Resolved::Broken,
                _ => Resolved::Unknown,
            },
            Value::Client { key, location } => {
                if self.key_is_service(file, key, depth + 1) {
                    Resolved::ServiceClient(location.clone())
                } else {
                    Resolved::OtherClient
                }
            }
            Value::Env(name) => Resolved::Env(name.clone()),
            Value::SecretLiteral => Resolved::Secret,
            Value::Global(name) => Resolved::Package(name.clone()),
        }
    }

    fn key_is_service(&self, file: usize, key: &Value, depth: usize) -> bool {
        match self.resolve(file, key, depth) {
            Resolved::Env(name) => is_service_role_env(&name),
            Resolved::Secret => true,
            _ => false,
        }
    }

    fn is_service_key(&self, file: usize, key: &Value) -> bool {
        !self.modules[file].flow.opaque && self.key_is_service(file, key, 0)
    }

    fn resolve_import(
        &self,
        file: usize,
        specifier: &str,
        imported: &Imported,
        depth: usize,
        reexports: usize,
    ) -> Resolved {
        let Some(module) = self.modules.get(file) else {
            return Resolved::Unknown;
        };
        let Some(target) = self.resolver.resolve(&module.rel_path, specifier) else {
            if is_project_specifier(specifier) {
                return Resolved::Broken;
            }
            let name = match imported {
                Imported::Named(name) => name.clone(),
                Imported::Default | Imported::Namespace => specifier.to_owned(),
            };
            return Resolved::Package(name);
        };
        match self.index.get(target.as_str()) {
            Some(target) if !self.modules[*target].flow.opaque => {
                self.resolve_export(*target, imported, depth + 1, reexports)
            }
            _ => Resolved::Broken,
        }
    }

    fn resolve_export(
        &self,
        file: usize,
        imported: &Imported,
        depth: usize,
        reexports: usize,
    ) -> Resolved {
        if reexports > MAX_REEXPORTS || depth > MAX_DEPTH {
            return Resolved::Unknown;
        }
        let name = match imported {
            Imported::Default => "default",
            Imported::Named(name) => name.as_str(),
            Imported::Namespace => return Resolved::Unknown,
        };
        let flow = &self.modules[file].flow;
        match flow.exports.get(name) {
            Some(ExportTarget::Local(value)) => self.resolve(file, value, depth + 1),
            Some(ExportTarget::From {
                specifier,
                imported,
            }) => self.resolve_import(file, specifier, imported, depth + 1, reexports + 1),
            None => {
                for specifier in &flow.star_exports {
                    let found =
                        self.resolve_import(file, specifier, imported, depth + 1, reexports + 1);
                    if !matches!(found, Resolved::Unknown | Resolved::Broken) {
                        return found;
                    }
                }
                Resolved::Broken
            }
        }
    }

    fn returned(&self, function: FnRef, depth: usize) -> Resolved {
        let Some(body) = self.function(function) else {
            return Resolved::Unknown;
        };
        let mut service = None;
        for value in &body.returns {
            match self.resolve(function.0, value, depth + 1) {
                Resolved::ServiceClient(location) => {
                    service.get_or_insert(location);
                }
                Resolved::OtherClient => return Resolved::OtherClient,
                _ => {}
            }
        }
        service.map_or(Resolved::Unknown, Resolved::ServiceClient)
    }

    fn link_calls(&mut self) {
        let mut callees = BTreeMap::new();
        for (at, function) in self.functions() {
            let linked = function
                .calls
                .iter()
                .map(|call| match self.resolve(at.0, &call.callee, 0) {
                    Resolved::Function(target) => Some(target),
                    _ => None,
                })
                .collect();
            callees.insert(at, linked);
        }
        self.callees = callees;
    }

    fn summarize(&mut self) {
        let mut resolved: BTreeMap<FnRef, Vec<Option<FnRef>>> = BTreeMap::new();
        for (at, function) in self.functions() {
            let targets = function
                .candidates
                .iter()
                .map(|candidate| match candidate {
                    Candidate::CallGuard { callee, .. } => match self.resolve(at.0, callee, 0) {
                        Resolved::Function(target) => Some(target),
                        _ => None,
                    },
                    _ => None,
                })
                .collect();
            resolved.insert(at, targets);
        }
        for _ in 0..MAX_ROUNDS {
            let mut changed = false;
            for (at, function) in self.functions() {
                let mut throwing = self.throwing.get(&at).copied();
                let mut checks = self.checks.get(&at).copied();
                let mut guards = self.guards_any.contains(&at);
                let targets = resolved.get(&at);
                for (position, candidate) in function.candidates.iter().enumerate() {
                    match candidate {
                        Candidate::Guard {
                            strength,
                            exits_caller,
                            top,
                            ..
                        } => {
                            checks = checks.max(Some(*strength));
                            guards = true;
                            if *exits_caller && *top {
                                throwing = throwing.max(Some(*strength));
                            }
                        }
                        Candidate::Pending { strength } => checks = checks.max(Some(*strength)),
                        Candidate::CallGuard { tested, top, .. } => {
                            let Some(Some(target)) = targets.and_then(|t| t.get(position)) else {
                                continue;
                            };
                            let inner_throwing = self.throwing.get(target).copied();
                            let inner_checks = self.checks.get(target).copied();
                            checks = checks.max(inner_checks).max(inner_throwing);
                            if *top {
                                let passed = if *tested {
                                    inner_throwing.max(inner_checks)
                                } else {
                                    inner_throwing
                                };
                                throwing = throwing.max(passed);
                            }
                        }
                        Candidate::Unknown => {}
                    }
                }
                if let Some(called) = self.callees.get(&at) {
                    guards |= called
                        .iter()
                        .flatten()
                        .any(|target| self.guards_any.contains(target));
                }
                if throwing != self.throwing.get(&at).copied() {
                    if let Some(value) = throwing {
                        self.throwing.insert(at, value);
                    }
                    changed = true;
                }
                if checks != self.checks.get(&at).copied() {
                    if let Some(value) = checks {
                        self.checks.insert(at, value);
                    }
                    changed = true;
                }
                if guards && self.guards_any.insert(at) {
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn compute_gates(&mut self) {
        let mut gates = BTreeMap::new();
        for (at, function) in self.functions() {
            let list = function
                .candidates
                .iter()
                .map(|candidate| self.candidate_gate(at, candidate))
                .collect();
            gates.insert(at, list);
        }
        self.gates = gates;
    }

    fn guard_ref_of(&self, function: FnRef, strength: Strength) -> Option<GuardRef> {
        let body = self.function(function)?;
        Some(GuardRef {
            file: function.0,
            function: body.name.clone(),
            label: format!("{}()", body.name),
            location: body.location.clone(),
            strength,
        })
    }

    fn candidate_gate(&self, at: FnRef, candidate: &Candidate) -> (Gate, Option<GuardRef>) {
        match candidate {
            Candidate::Guard {
                strength,
                name,
                location,
                ..
            } => {
                let function = self
                    .function(at)
                    .map(|body| body.name.clone())
                    .unwrap_or_default();
                (
                    Gate::Guarded,
                    Some(GuardRef {
                        file: at.0,
                        function,
                        label: if name == "secret" {
                            "secret check".to_owned()
                        } else {
                            format!("{name}()")
                        },
                        location: location.clone(),
                        strength: *strength,
                    }),
                )
            }
            Candidate::Pending { .. } | Candidate::Unknown => (Gate::Unknown, None),
            Candidate::CallGuard {
                callee,
                name,
                tested,
                ..
            } => match self.resolve(at.0, callee, 0) {
                Resolved::Function(target) => {
                    let throwing = self.throwing.get(&target).copied();
                    let checks = self.checks.get(&target).copied();
                    if let Some(strength) = throwing {
                        (Gate::Guarded, self.guard_ref_of(target, strength))
                    } else if let (true, Some(strength)) = (*tested, checks) {
                        (Gate::Guarded, self.guard_ref_of(target, strength))
                    } else if checks.is_some() {
                        (Gate::Unknown, None)
                    } else {
                        (Gate::Open, None)
                    }
                }
                Resolved::Broken => (Gate::Unknown, None),
                Resolved::Package(_) | Resolved::Unknown if *tested || auth_like(name) => {
                    (Gate::Unknown, None)
                }
                _ => (Gate::Open, None),
            },
        }
    }

    fn site_gate(&self, at: FnRef, cover: &[u32]) -> (Gate, Option<GuardRef>) {
        let Some(gates) = self.gates.get(&at) else {
            return (Gate::Unknown, None);
        };
        let mut best = (Gate::Open, None);
        for id in cover {
            let Some((gate, guard)) = gates.get(*id as usize) else {
                continue;
            };
            if *gate > best.0 {
                best = (*gate, guard.clone());
            }
        }
        best
    }

    fn risks(&self) -> Vec<Risk> {
        let mut risks = Vec::new();
        for (at, function) in self.functions() {
            for (position, access) in function.accesses.iter().enumerate() {
                let resolved = self.resolve(at.0, &access.receiver, 0);
                let client = match resolved {
                    Resolved::ServiceClient(location) => Some(location),
                    Resolved::Unknown if access.op == Op::Admin => None,
                    _ => continue,
                };
                risks.push(Risk {
                    function: at,
                    access: position,
                    client,
                });
            }
        }
        risks
    }

    fn callers(&self) -> BTreeMap<FnRef, Vec<(FnRef, usize)>> {
        let mut callers: BTreeMap<FnRef, Vec<(FnRef, usize)>> = BTreeMap::new();
        for (caller, targets) in &self.callees {
            for (position, target) in targets.iter().enumerate() {
                if let Some(target) = target {
                    callers
                        .entry(*target)
                        .or_default()
                        .push((*caller, position));
                }
            }
        }
        callers
    }

    fn handlers(&self, file: usize, names: &[&str]) -> Vec<(FnRef, String)> {
        let flow = &self.modules[file].flow;
        names
            .iter()
            .filter_map(|name| {
                let ExportTarget::Local(value) = flow.exports.get(*name)? else {
                    return match self.resolve_export(
                        file,
                        &Imported::Named((*name).to_owned()),
                        0,
                        0,
                    ) {
                        Resolved::Function(target) => Some((target, (*name).to_owned())),
                        _ => None,
                    };
                };
                match self.resolve(file, value, 0) {
                    Resolved::Function(target) => Some((target, (*name).to_owned())),
                    _ => None,
                }
            })
            .collect()
    }

    fn middleware_gate(&self, file: usize) -> Gate {
        let flow = &self.modules[file].flow;
        let value = ["middleware", "proxy", "default"]
            .into_iter()
            .find_map(|name| flow.exports.get(name));
        let Some(target) = value else {
            return Gate::Open;
        };
        let resolved = match target {
            ExportTarget::Local(value) => self.resolve(file, value, 0),
            ExportTarget::From {
                specifier,
                imported,
            } => self.resolve_import(file, specifier, imported, 0, 0),
        };
        match resolved {
            Resolved::Function(function) if self.guards_any.contains(&function) => Gate::Unknown,
            Resolved::Function(_) => Gate::Open,
            Resolved::Package(name) if !auth_like(&name) => Gate::Open,
            _ => Gate::Unknown,
        }
    }
}

fn strip_extension(path: &str) -> &str {
    match path.rfind('.') {
        Some(dot) if !path[dot..].contains('/') => &path[..dot],
        _ => path,
    }
}

fn entries(project: &Project<'_>, hints: &ProjectHints) -> Vec<Entry> {
    let mut found = Vec::new();
    for (file, module) in project.modules.iter().enumerate() {
        if module.flow.opaque {
            continue;
        }
        let path = module.rel_path.as_str();
        if module.role == FileRole::EdgeFunction
            && let Some(name) = edge_function_name(path)
        {
            let handlers = module
                .flow
                .serve_handlers
                .iter()
                .filter_map(|value| match project.resolve(file, value, 0) {
                    Resolved::Function(target) => Some((target, format!("/functions/v1/{name}"))),
                    _ => None,
                })
                .collect();
            found.push(Entry {
                id: format!("entry:httpRoute:/functions/v1/{name}"),
                label: format!("/functions/v1/{name}"),
                kind: EntryKind::EdgeFunction,
                channel: Channel::HttpRoute,
                file,
                handlers,
                url: None,
                next_root: None,
            });
            continue;
        }
        let Some(root) = hints.next_root_for(path) else {
            continue;
        };
        let inner = if root.is_empty() {
            path
        } else {
            path.strip_prefix(root)
                .and_then(|rest| rest.strip_prefix('/'))
                .unwrap_or(path)
        };
        let inner = inner.strip_prefix("src/").unwrap_or(inner);
        let stem = strip_extension(file_name(inner));
        if let Some(rest) = inner.strip_prefix("app/")
            && stem == "route"
        {
            let url = app_route_url(&format!("/{}", strip_extension(rest)));
            let handlers = project
                .handlers(file, HTTP_METHODS)
                .into_iter()
                .map(|(target, method)| (target, format!("{method} {url}")))
                .collect();
            found.push(route_entry(file, &url, handlers, root));
        } else if let Some(rest) = inner.strip_prefix("pages/api/") {
            let mut url = format!("/api/{}", strip_extension(rest));
            if let Some(parent) = url.strip_suffix("/index") {
                url = parent.to_owned();
            }
            let handlers = project
                .handlers(file, &["default"])
                .into_iter()
                .map(|(target, _)| (target, url.clone()))
                .collect();
            found.push(route_entry(file, &url, handlers, root));
        } else if module.directive == Some(Directive::UseServer) {
            for name in module.flow.exports.keys() {
                let handlers = project.handlers(file, &[name.as_str()]);
                if handlers.is_empty() {
                    continue;
                }
                let label = format!("{name}()");
                found.push(Entry {
                    id: format!("entry:serverAction:{path}#{name}"),
                    label: label.clone(),
                    kind: EntryKind::ServerAction,
                    channel: Channel::ServerAction,
                    file,
                    handlers: handlers
                        .into_iter()
                        .map(|(target, _)| (target, label.clone()))
                        .collect(),
                    url: None,
                    next_root: Some(root.to_owned()),
                });
            }
        }
    }
    found
}

fn route_entry(file: usize, url: &str, handlers: Vec<(FnRef, String)>, root: &str) -> Entry {
    Entry {
        id: format!("entry:httpRoute:{url}"),
        label: url.to_owned(),
        kind: EntryKind::Route,
        channel: Channel::HttpRoute,
        file,
        handlers,
        url: Some(url.to_owned()),
        next_root: Some(root.to_owned()),
    }
}

fn edge_function_name(path: &str) -> Option<&str> {
    let at = path.rfind("supabase/functions/")?;
    let rest = &path[at + "supabase/functions/".len()..];
    let (name, file) = rest.split_once('/')?;
    let stem = strip_extension(file);
    (stem == "index" && !name.starts_with('_') && !name.is_empty()).then_some(name)
}

fn middleware_files(project: &Project<'_>) -> BTreeMap<String, usize> {
    let mut found = BTreeMap::new();
    for (file, module) in project.modules.iter().enumerate() {
        let path = module.rel_path.as_str();
        let (dir, name) = match path.rfind('/') {
            Some(slash) => (&path[..slash], &path[slash + 1..]),
            None => ("", path),
        };
        let stem = strip_extension(name);
        if stem != "middleware" && stem != "proxy" {
            continue;
        }
        let root = dir
            .strip_suffix("/src")
            .or(if dir == "src" { Some("") } else { None });
        found.insert(root.unwrap_or(dir).to_owned(), file);
    }
    found
}

fn matcher_applies(matcher: Option<&Matcher>, url: Option<&str>) -> bool {
    let (Some(Matcher::Patterns(patterns)), Some(url)) = (matcher, url) else {
        return true;
    };
    patterns.iter().any(|pattern| pattern_applies(pattern, url))
}

fn pattern_applies(pattern: &str, url: &str) -> bool {
    const REGEX: &[char] = &[
        '*', '+', '?', '(', ')', '[', ']', '{', '}', '^', '$', '\\', '|',
    ];
    if let Some(inner) = pattern
        .strip_prefix("/((?!")
        .and_then(|rest| rest.strip_suffix(").*)"))
    {
        let path = url.trim_start_matches('/');
        return !inner
            .split('|')
            .filter(|alternative| !alternative.contains(REGEX))
            .any(|alternative| !alternative.is_empty() && path.starts_with(alternative));
    }
    let base = pattern
        .split_once("/:")
        .map_or(pattern, |(prefix, _)| prefix);
    if base.contains(REGEX) {
        return true;
    }
    if pattern.contains("/:") {
        url == base || url.starts_with(&format!("{base}/"))
    } else {
        url == pattern
    }
}

fn reached_of(target: &Target, op: Op) -> Reached<'_> {
    match (target, op) {
        (Target::Table(table), Op::Write) => Reached::WriteTable(table),
        (Target::Table(table), _) => Reached::ReadTable(table),
        (Target::Bucket(bucket), Op::Write) => Reached::WriteBucket(bucket),
        (Target::Bucket(bucket), _) => Reached::ReadBucket(bucket),
        (Target::Function(function), _) => Reached::Rpc(function),
        (Target::Admin(method), _) => Reached::Admin(method),
    }
}

fn target_node(target: &Target) -> (String, Option<NodeId>) {
    match target {
        Target::Table(table) => (
            table.clone(),
            Some(NodeId::new(format!("table:public.{table}"))),
        ),
        Target::Bucket(bucket) => (
            bucket.clone(),
            Some(NodeId::new(format!("store:storageBucket:{bucket}"))),
        ),
        Target::Function(function) => (
            format!("{function}()"),
            Some(NodeId::new(format!("entry:rpc:public.{function}"))),
        ),
        Target::Admin(method) => (format!("auth.admin.{method}()"), None),
    }
}

fn search(
    project: &Project<'_>,
    callers: &BTreeMap<FnRef, Vec<(FnRef, usize)>>,
    risk: &Risk,
) -> (States, bool) {
    let mut states = BTreeMap::new();
    let mut truncated = false;
    let Some(access) = project
        .function(risk.function)
        .and_then(|body| body.accesses.get(risk.access))
    else {
        return (states, truncated);
    };
    let start = (
        risk.function,
        project.site_gate(risk.function, &access.cover).0,
    );
    states.insert(start, None);
    let mut queue = VecDeque::from([(start, 0usize)]);
    while let Some(((function, gate), depth)) = queue.pop_front() {
        let Some(list) = callers.get(&function) else {
            continue;
        };
        if depth >= MAX_HOPS || list.len() > MAX_CALLERS {
            truncated = true;
            if depth >= MAX_HOPS {
                continue;
            }
        }
        for (caller, position) in list.iter().take(MAX_CALLERS) {
            let Some(call) = project
                .function(*caller)
                .and_then(|body| body.calls.get(*position))
            else {
                continue;
            };
            let next = (*caller, project.site_gate(*caller, &call.cover).0.max(gate));
            if let std::collections::btree_map::Entry::Vacant(slot) = states.entry(next) {
                slot.insert(Some((function, gate, *position)));
                queue.push_back((next, depth + 1));
            }
        }
    }
    (states, truncated)
}

fn walk_path(states: &States, from: (FnRef, Gate)) -> Vec<(FnRef, usize, FnRef)> {
    let mut path = Vec::new();
    let mut current = from;
    for _ in 0..=MAX_HOPS {
        let Some(Some((callee, gate, position))) = states.get(&current) else {
            break;
        };
        path.push((current.0, *position, *callee));
        current = (*callee, *gate);
    }
    path
}

fn first_guard(
    project: &Project<'_>,
    path: &[(FnRef, usize, FnRef)],
    risk: &Risk,
) -> Option<GuardRef> {
    for (caller, position, _) in path {
        let call = project.function(*caller)?.calls.get(*position)?;
        if let (Gate::Guarded, guard) = project.site_gate(*caller, &call.cover) {
            return guard;
        }
    }
    let access = project.function(risk.function)?.accesses.get(risk.access)?;
    project.site_gate(risk.function, &access.cover).1
}

pub(crate) fn emit(
    modules: &[Module],
    resolver: &Resolver<'_>,
    hints: &ProjectHints,
    graph: &mut Graph,
    assigned_of: &dyn Fn(&str, FileRole) -> Assigned,
) {
    let project = Project::new(modules, resolver);
    let add_file = |graph: &mut Graph, file: usize| {
        let module = &modules[file];
        let assigned = assigned_of(&module.rel_path, module.role);
        graph.add_file(&module.rel_path, assigned.role, assigned.basis)
    };
    let principal = |graph: &mut Graph| {
        graph.add_node(Node {
            id: NodeId::new(SERVICE_ROLE),
            label: "service_role".to_owned(),
            kind: NodeKind::Principal {},
            zone: Zone::Database,
            location: None,
        })
    };
    for (file, module) in modules.iter().enumerate() {
        for (key, _) in &module.flow.clients {
            if project.is_service_key(file, key) {
                let file_node = add_file(graph, file);
                let principal_node = principal(graph);
                graph.add_edge(file_node, principal_node, EdgeKind::ActsAs);
                break;
            }
        }
    }

    let risks = project.risks();
    let callers = project.callers();
    let searches: Vec<_> = risks
        .iter()
        .map(|risk| search(&project, &callers, risk))
        .collect();
    let middleware = middleware_files(&project);

    for entry in entries(&project, hints) {
        let middleware_gate = entry
            .next_root
            .as_ref()
            .and_then(|root| middleware.get(root))
            .filter(|file| {
                entry.kind == EntryKind::ServerAction
                    || matcher_applies(
                        project.modules[**file].flow.matcher.as_ref(),
                        entry.url.as_deref(),
                    )
            })
            .map_or(Gate::Open, |file| project.middleware_gate(*file));
        let mut reaches = Vec::new();
        for (handler, step_label) in &entry.handlers {
            for (position, (states, truncated)) in searches.iter().enumerate() {
                for gate in [Gate::Open, Gate::Unknown, Gate::Guarded] {
                    if !states.contains_key(&(*handler, gate)) {
                        continue;
                    }
                    let path = walk_path(states, (*handler, gate));
                    let guard = if gate == Gate::Guarded {
                        first_guard(&project, &path, &risks[position])
                    } else {
                        None
                    };
                    reaches.push(Reach {
                        gate: gate.max(middleware_gate),
                        risk: position,
                        path,
                        guard,
                        truncated: *truncated,
                        step_label: step_label.clone(),
                        handler: *handler,
                    });
                }
            }
        }
        let exposure = if reaches.is_empty() {
            Exposure::Unknown
        } else if reaches.iter().any(|reach| reach.gate == Gate::Open) {
            Exposure::Public
        } else if reaches
            .iter()
            .all(|reach| reach.gate == Gate::Guarded && !reach.truncated)
        {
            Exposure::Authenticated
        } else {
            Exposure::Unknown
        };
        let file_node = add_file(graph, entry.file);
        let location = entry
            .handlers
            .first()
            .and_then(|(handler, _)| project.function(*handler))
            .map_or_else(
                || file_location(&modules[entry.file].rel_path),
                |body| body.location.clone(),
            );
        let entry_id = graph.add_node(Node {
            id: NodeId::new(entry.id.clone()),
            label: entry.label.clone(),
            kind: NodeKind::EntryPoint {
                channel: entry.channel,
                exposure,
            },
            zone: Zone::Server,
            location: Some(location.clone()),
        });
        graph.add_edge(entry_id.clone(), file_node, EdgeKind::Invokes);
        if exposure == Exposure::Authenticated {
            let guards: BTreeSet<GuardRef> = reaches
                .iter()
                .filter_map(|reach| reach.guard.clone())
                .collect();
            for guard in guards {
                let path = &modules[guard.file].rel_path;
                let guard_id = graph.add_node(Node {
                    id: NodeId::new(format!("guard:{path}#{}", guard.function)),
                    label: guard.label.clone(),
                    kind: NodeKind::AccessRule {
                        scope: RuleScope::Conditional,
                        strength: Some(match guard.strength {
                            Strength::Verified => GuardStrength::Verified,
                            Strength::Weak => GuardStrength::Weak,
                        }),
                        detail: None,
                    },
                    zone: Zone::Server,
                    location: Some(guard.location.clone()),
                });
                graph.add_edge(entry_id.clone(), guard_id, EdgeKind::GuardedBy);
            }
        }
        if exposure != Exposure::Public {
            continue;
        }
        let open: Vec<&Reach> = reaches
            .iter()
            .filter(|reach| reach.gate == Gate::Open)
            .collect();
        let access_of = |reach: &Reach| {
            let risk = &risks[reach.risk];
            project
                .function(risk.function)
                .and_then(|body| body.accesses.get(risk.access))
        };
        let Some(chosen) = open.iter().copied().max_by(|a, b| {
            let key = |reach: &Reach| {
                access_of(reach).map(|access| {
                    (
                        access.op,
                        std::cmp::Reverse((
                            modules[risks[reach.risk].function.0].rel_path.clone(),
                            access.location.clone(),
                        )),
                    )
                })
            };
            key(a).cmp(&key(b))
        }) else {
            continue;
        };
        let Some(access) = access_of(chosen) else {
            continue;
        };
        let distinct: BTreeSet<usize> = open.iter().map(|reach| reach.risk).collect();
        let changes = open
            .iter()
            .filter_map(|reach| access_of(reach))
            .any(|access| access.op.changes_data());
        let mut evidence: Vec<EvidenceStep> = Vec::new();
        let handler_location = project
            .function(chosen.handler)
            .map_or_else(|| location.clone(), |body| body.location.clone());
        evidence.push(step(
            &chosen.step_label,
            None,
            Some(entry_id.clone()),
            Some(handler_location.clone()),
        ));
        let handler_file = chosen.handler.0;
        add_file(graph, handler_file);
        evidence.push(file_step(
            &modules[handler_file].rel_path,
            Some(EdgeKind::Invokes),
            handler_location,
        ));
        for (caller, position, callee) in &chosen.path {
            let (Some(call), Some(target)) = (
                project
                    .function(*caller)
                    .and_then(|body| body.calls.get(*position)),
                project.function(*callee),
            ) else {
                continue;
            };
            add_file(graph, callee.0);
            evidence.push(step(
                &format!("{}()", target.name),
                Some(EdgeKind::Calls),
                Some(file_id(&modules[callee.0].rel_path)),
                Some(call.location.clone()),
            ));
        }
        let risk = &risks[chosen.risk];
        let principal_node = principal(graph);
        evidence.push(step(
            "service_role",
            Some(EdgeKind::ActsAs),
            Some(principal_node),
            risk.client.clone(),
        ));
        let (target_label, target_id) = target_node(&access.target);
        evidence.push(step(
            &target_label,
            Some(if access.op == Op::Read || access.op == Op::Rpc {
                EdgeKind::Reads
            } else {
                EdgeKind::Writes
            }),
            target_id,
            Some(access.location.clone()),
        ));
        graph.add_finding(
            Verdict {
                rule: RuleId::SupabaseServiceRoleUnguarded,
                severity: if changes {
                    Severity::High
                } else {
                    Severity::Medium
                },
                confidence: Confidence::Likely,
                from_build: false,
            },
            rules::service_role_unguarded(
                entry.kind,
                &chosen.step_label,
                reached_of(&access.target, access.op),
                distinct.len().saturating_sub(1),
            ),
            entry_id,
            Some(location),
            evidence,
        );
    }
}

#[cfg(test)]
mod tests;
