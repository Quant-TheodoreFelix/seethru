pub(crate) mod compile_db;
mod lexer;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use seethru_core::{
    Basis, Channel, Confidence, ConfigDetail, EdgeKind, Exposure, Location, Node, NodeId, NodeKind,
    RuleId, Severity, Zone,
};

use crate::Lines;
use crate::classify::{FileRole, file_name};
use crate::graph::{Graph, Verdict, file_step, step};
use crate::rules;
use lexer::{Kind, Tokens};

const MAX_FUNCTIONS: usize = 2_000;
const MAX_CALLS: usize = 20_000;
const MAX_ROUTES: usize = 500;
const MAX_HOPS: usize = 8;
const MAX_VISITED: usize = 2_000;
const MAX_OPTION_LINES: usize = 20_000;
const MAX_TEXT_CHARS: usize = 200;

const CONTROL: &[&str] = &[
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "catch",
    "do",
    "else",
    "case",
    "alignof",
    "decltype",
    "typeof",
    "defined",
    "static_assert",
    "_Static_assert",
    "__attribute__",
    "new",
    "delete",
    "throw",
];
const QUALIFIERS: &[&str] = &["const", "noexcept", "override", "final", "volatile"];
const CALLER_WORDS: &[&str] = &[
    "auth",
    "login",
    "passw",
    "credential",
    "token",
    "verify",
    "signature",
    "session",
    "permission",
    "hmac",
    "api_key",
    "apikey",
    "api-key",
];
const OTA_WRITES: &[&str] = &[
    "esp_ota_write",
    "esp_ota_write_with_offset",
    "esp_https_ota",
    "esp_https_ota_begin",
];
const OTA_STORE: &str = "store:flash:ota";

pub(crate) fn caller_word(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    CALLER_WORDS.iter().any(|word| lower.contains(word))
}

#[derive(Debug)]
pub(crate) struct Call {
    pub name: String,
    pub location: Location,
}

#[derive(Debug)]
pub(crate) struct Function {
    pub name: String,
    pub location: Location,
    pub calls: Vec<Call>,
    pub checks_caller: bool,
}

#[derive(Debug)]
pub(crate) struct Route {
    pub uri: String,
    pub method: Option<String>,
    pub handler: String,
    pub location: Location,
}

#[derive(Debug, Default)]
pub(crate) struct Facts {
    pub functions: Vec<Function>,
    pub routes: Vec<Route>,
    pub wrappers: Vec<String>,
    pub partial: bool,
}

#[derive(Default)]
struct Fields {
    uri: Option<String>,
    method: Option<String>,
    handler: Option<String>,
    offset: usize,
}

enum Block {
    Function(usize),
    Other(Fields),
}

pub(crate) fn collect(rel_path: &str, text: &str) -> Facts {
    let tokens = lexer::lex(text);
    let lines = Lines::new(text);
    let mut facts = Facts {
        partial: tokens.truncated,
        ..Facts::default()
    };
    let wants_routes = text.contains("httpd_uri_t");
    let mut blocks: Vec<Block> = Vec::new();
    let mut opens: Vec<usize> = Vec::new();
    let mut last_pair: Option<(usize, usize)> = None;
    let mut calls = 0usize;
    for index in 0..tokens.list.len() {
        let Some(token) = tokens.list.get(index).copied() else {
            break;
        };
        let current = blocks.iter().rev().find_map(|block| match block {
            Block::Function(function) => Some(*function),
            Block::Other(_) => None,
        });
        match token.kind {
            Kind::Punct(b'(') => opens.push(index),
            Kind::Punct(b')') => {
                if let Some(open) = opens.pop() {
                    last_pair = Some((open, index));
                }
            }
            Kind::Punct(b'{') => {
                let started = current
                    .is_none()
                    .then(|| function_name(&tokens, index, last_pair))
                    .flatten();
                match started {
                    Some(name_index) if facts.functions.len() < MAX_FUNCTIONS => {
                        let start = tokens.list.get(name_index).map_or(0, |name| name.start);
                        facts.functions.push(Function {
                            name: tokens.text(name_index).to_owned(),
                            location: lines.location(rel_path, start),
                            calls: Vec::new(),
                            checks_caller: false,
                        });
                        blocks.push(Block::Function(facts.functions.len() - 1));
                    }
                    Some(_) => {
                        facts.partial = true;
                        blocks.push(Block::Other(Fields::default()));
                    }
                    None => blocks.push(Block::Other(Fields {
                        offset: token.start,
                        ..Fields::default()
                    })),
                }
            }
            Kind::Punct(b'}') => {
                if let Some(Block::Other(Fields {
                    uri: Some(uri),
                    method,
                    handler: Some(handler),
                    offset,
                })) = blocks.pop()
                    && wants_routes
                {
                    if facts.routes.len() < MAX_ROUTES {
                        facts.routes.push(Route {
                            uri,
                            method,
                            handler,
                            location: lines.location(rel_path, offset),
                        });
                    } else {
                        facts.partial = true;
                    }
                }
            }
            Kind::Punct(b'.') if wants_routes => {
                let field = tokens.text(index + 1);
                if tokens.kind(index + 1) == Some(Kind::Ident)
                    && tokens.is_punct(index + 2, b'=')
                    && !tokens.is_punct(index + 3, b'=')
                    && matches!(field, "uri" | "method" | "handler")
                {
                    let designated = index.checked_sub(1).is_some_and(|before| {
                        tokens.is_punct(before, b'{') || tokens.is_punct(before, b',')
                    });
                    let word = (tokens.kind(index + 3) == Some(Kind::Ident))
                        .then(|| tokens.text(index + 3).to_owned());
                    if !designated {
                        if field == "handler" {
                            match word {
                                Some(word) => facts.wrappers.push(word),
                                None => facts.partial = true,
                            }
                        }
                    } else if let Some(Block::Other(fields)) = blocks.last_mut() {
                        match field {
                            "uri" => {
                                fields.uri = tokens
                                    .literal(index + 3)
                                    .filter(|uri| uri.starts_with('/') && is_plain(uri))
                                    .map(str::to_owned);
                            }
                            "method" => {
                                fields.method = word
                                    .as_deref()
                                    .and_then(|word| word.strip_prefix("HTTP_"))
                                    .filter(|method| *method != "ANY")
                                    .map(str::to_owned);
                            }
                            _ => fields.handler = word,
                        }
                    }
                }
            }
            Kind::Ident => {
                if let Some(function) = current.and_then(|i| facts.functions.get_mut(i))
                    && tokens.is_punct(index + 1, b'(')
                {
                    let name = tokens.text(index);
                    if !CONTROL.contains(&name) {
                        function.checks_caller |= caller_word(name);
                        if calls < MAX_CALLS {
                            calls += 1;
                            function.calls.push(Call {
                                name: name.to_owned(),
                                location: lines.location(rel_path, token.start),
                            });
                        } else {
                            facts.partial = true;
                        }
                    }
                }
            }
            Kind::Text => {
                if let Some(function) = current.and_then(|i| facts.functions.get_mut(i))
                    && let Some(literal) = tokens.literal(index)
                    && literal.len() <= MAX_TEXT_CHARS
                {
                    function.checks_caller |= caller_word(literal);
                }
            }
            _ => {}
        }
    }
    facts
}

fn is_plain(text: &str) -> bool {
    text.len() <= MAX_TEXT_CHARS
        && text
            .chars()
            .all(|c| c.is_ascii_graphic() && !matches!(c, '`' | '\\' | '"'))
}

fn function_name(
    tokens: &Tokens<'_>,
    brace: usize,
    last_pair: Option<(usize, usize)>,
) -> Option<usize> {
    let mut before = brace.checked_sub(1)?;
    while tokens.kind(before) == Some(Kind::Ident) && QUALIFIERS.contains(&tokens.text(before)) {
        before = before.checked_sub(1)?;
    }
    let (open, close) = last_pair?;
    if close != before {
        return None;
    }
    let name = open.checked_sub(1)?;
    (tokens.kind(name) == Some(Kind::Ident) && !CONTROL.contains(&tokens.text(name)))
        .then_some(name)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OptionLine {
    pub key: String,
    pub value: String,
    pub offset: usize,
}

pub(crate) fn options(text: &str) -> Vec<OptionLine> {
    let mut found = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n').take(MAX_OPTION_LINES) {
        let start = offset + (line.len() - line.trim_start().len());
        offset += line.len();
        let line = line.trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !key.starts_with("CONFIG_")
            || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        found.push(OptionLine {
            key: key.to_owned(),
            value: value.trim().trim_matches('"').to_owned(),
            offset: start,
        });
    }
    found
}

pub(crate) fn is_test_config(rel_path: &str) -> bool {
    let name = file_name(rel_path);
    name.contains(".ci")
        || rel_path.split('/').any(|part| {
            matches!(
                part,
                "test" | "tests" | "test_apps" | "examples" | "example" | "samples"
            )
        })
}

pub(crate) fn emit_options(rel_path: &str, text: &str, graph: &mut Graph) {
    if is_test_config(rel_path) {
        return;
    }
    let lines = Lines::new(text);
    for line in options(text) {
        if line.value != "y" {
            continue;
        }
        let Some(option) = rules::RISKY_OPTIONS
            .iter()
            .find(|option| option.key == line.key)
        else {
            continue;
        };
        let location = lines.location(rel_path, line.offset);
        let file_id = graph.add_file(rel_path, FileRole::BuildConfig, Basis::Path);
        let config_id = graph.add_node(Node {
            id: NodeId::new(format!("config:{rel_path}:{}", line.key)),
            label: line.key.clone(),
            kind: NodeKind::Config {
                detail: Some(ConfigDetail::BuildOption {
                    value: line.value.clone(),
                }),
            },
            zone: Zone::Device,
            location: Some(location.clone()),
        });
        graph.add_edge(file_id, config_id.clone(), EdgeKind::Defines);
        graph.add_finding(
            Verdict {
                rule: option.rule,
                severity: option.severity,
                confidence: Confidence::Certain,
                from_build: false,
            },
            rules::risky_option(option, rel_path),
            config_id.clone(),
            Some(location.clone()),
            vec![
                file_step(rel_path, None, crate::graph::file_location(rel_path)),
                step(
                    &line.key,
                    Some(EdgeKind::Defines),
                    Some(config_id),
                    Some(location),
                ),
            ],
        );
    }
}

pub(crate) struct Source {
    pub rel_path: String,
    pub role: FileRole,
    pub root: String,
    pub facts: Facts,
}

struct Program<'a> {
    sources: &'a [Source],
    by_name: BTreeMap<&'a str, Vec<(usize, usize)>>,
}

impl<'a> Program<'a> {
    fn new(sources: &'a [Source]) -> Self {
        let mut by_name: BTreeMap<&str, Vec<(usize, usize)>> = BTreeMap::new();
        for (file, source) in sources.iter().enumerate() {
            for (index, function) in source.facts.functions.iter().enumerate() {
                by_name
                    .entry(function.name.as_str())
                    .or_default()
                    .push((file, index));
            }
        }
        Self { sources, by_name }
    }

    fn function(&self, at: (usize, usize)) -> Option<&'a Function> {
        self.sources.get(at.0)?.facts.functions.get(at.1)
    }

    fn resolve(&self, from: usize, name: &str) -> Option<(usize, usize)> {
        let all = self.by_name.get(name)?;
        let mut here = all.iter().filter(|at| at.0 == from);
        if let Some(first) = here.next() {
            return here.next().is_none().then_some(*first);
        }
        let root = &self.sources.get(from)?.root;
        let mut near = all
            .iter()
            .filter(|at| self.sources.get(at.0).is_some_and(|s| s.root == *root));
        let first = near.next()?;
        near.next().is_none().then_some(*first)
    }

    fn path_to_update(&self, start: (usize, usize)) -> Option<(Vec<(usize, usize)>, &'a Call)> {
        let mut queue = VecDeque::from([(start, 0usize)]);
        let mut parent: BTreeMap<(usize, usize), (usize, usize)> = BTreeMap::new();
        let mut seen = BTreeSet::from([start]);
        while let Some((at, depth)) = queue.pop_front() {
            let function = self.function(at)?;
            if let Some(call) = function
                .calls
                .iter()
                .find(|call| OTA_WRITES.contains(&call.name.as_str()))
            {
                let mut path = vec![at];
                let mut cursor = at;
                while let Some(before) = parent.get(&cursor) {
                    path.push(*before);
                    cursor = *before;
                }
                path.reverse();
                return Some((path, call));
            }
            if depth >= MAX_HOPS {
                continue;
            }
            for call in &function.calls {
                if let Some(next) = self.resolve(at.0, &call.name)
                    && seen.len() < MAX_VISITED
                    && seen.insert(next)
                {
                    parent.insert(next, at);
                    queue.push_back((next, depth + 1));
                }
            }
        }
        None
    }
}

pub(crate) fn emit(sources: &[Source], graph: &mut Graph) -> bool {
    let program = Program::new(sources);
    let many_roots = sources
        .iter()
        .filter(|source| !source.facts.routes.is_empty())
        .map(|source| source.root.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        > 1;
    let mut partial = false;
    let mut reported = BTreeSet::new();
    for (file, source) in sources.iter().enumerate() {
        partial |= source.facts.partial;
        let wrapped = source.facts.wrappers.iter().any(|name| {
            caller_word(name)
                || program
                    .resolve(file, name)
                    .and_then(|at| program.function(at))
                    .is_none_or(|function| function.checks_caller)
        });
        for route in &source.facts.routes {
            let entry_key = if many_roots {
                let root = if source.root.is_empty() {
                    "."
                } else {
                    &source.root
                };
                format!("entry:httpRoute:{root}:{}", route.uri)
            } else {
                format!("entry:httpRoute:{}", route.uri)
            };
            let entry_id = NodeId::new(entry_key);
            let handler = program.resolve(file, &route.handler);
            let found = handler.and_then(|at| program.path_to_update(at));
            let open = found.as_ref().is_some_and(|(path, _)| {
                !wrapped
                    && !caller_word(&route.handler)
                    && path.iter().all(|at| {
                        program
                            .function(*at)
                            .is_some_and(|function| !function.checks_caller)
                    })
            });
            let file_id = graph.add_file(&source.rel_path, source.role, Basis::Path);
            graph.add_node(Node {
                id: entry_id.clone(),
                label: route.uri.clone(),
                kind: NodeKind::EntryPoint {
                    channel: Channel::HttpRoute,
                    exposure: Exposure::Unknown,
                },
                zone: Zone::Device,
                location: Some(route.location.clone()),
            });
            graph.add_edge(entry_id.clone(), file_id, EdgeKind::Invokes);
            let Some((path, call)) = found.filter(|_| open) else {
                continue;
            };
            if !reported.insert(entry_id.clone()) {
                continue;
            }
            graph.set_exposure(&entry_id, Exposure::Public);
            let store_id = graph.add_node(Node {
                id: NodeId::new(OTA_STORE),
                label: "firmware update slot".to_owned(),
                kind: NodeKind::DataStore { detail: None },
                zone: Zone::Device,
                location: None,
            });
            let label = match &route.method {
                Some(method) => format!("{method} {}", route.uri),
                None => route.uri.clone(),
            };
            let mut evidence = vec![step(
                &label,
                None,
                Some(entry_id.clone()),
                Some(route.location.clone()),
            )];
            let mut via = EdgeKind::Invokes;
            let mut last_file = None;
            for at in &path {
                let (Some(function), Some(owner)) = (program.function(*at), sources.get(at.0))
                else {
                    continue;
                };
                let owner_id = graph.add_file(&owner.rel_path, owner.role, Basis::Path);
                evidence.push(step(
                    &format!("{}()", function.name),
                    Some(via),
                    Some(owner_id.clone()),
                    Some(function.location.clone()),
                ));
                via = EdgeKind::Calls;
                last_file = Some(owner_id);
            }
            if let Some(writer) = last_file {
                graph.add_edge(writer, store_id.clone(), EdgeKind::Writes);
            }
            evidence.push(step(
                &format!("{}()", call.name),
                Some(EdgeKind::Writes),
                Some(store_id),
                Some(call.location.clone()),
            ));
            graph.add_finding(
                Verdict {
                    rule: RuleId::FirmwareOtaUnguarded,
                    severity: Severity::High,
                    confidence: Confidence::Likely,
                    from_build: false,
                },
                rules::ota_unguarded(&label, 0),
                entry_id,
                Some(route.location.clone()),
                evidence,
            );
        }
    }
    partial
}

#[cfg(test)]
mod tests;
