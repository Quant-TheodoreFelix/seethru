mod classify;
mod config;
mod env;
mod glob;
mod graph;
mod resolve;
mod roles;
mod rules;
mod script;
mod secrets;
mod supabase;
mod walk;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use seethru_core::{
    Confidence, CredentialDetail, Ecosystem, EdgeKind, EvidenceStep, Input, LimitationCode,
    Location, Node, NodeId, NodeKind, RuleId, ScanReport, Severity, TargetInfo, Zone,
};

use classify::{Class, Content, FileRole, ProjectHints};
use config::Config;
use graph::{Graph, Verdict, file_location, file_step, step};
use resolve::{ConfigText, Resolver};
use roles::{Assigned, Module};
use supabase::Migrations;

pub use config::CONFIG_FILE;

const MAX_RESOLVER_CONFIG_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub enum ScanError {
    NotADirectory,
    Io(std::io::Error),
    Config(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotADirectory => f.write_str("scan target is not a directory"),
            Self::Io(error) => write!(f, "cannot read scan target: {error}"),
            Self::Config(message) => write!(f, "cannot use {CONFIG_FILE}: {message}"),
        }
    }
}

impl std::error::Error for ScanError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOptions {
    pub read_config: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { read_config: true }
    }
}

pub fn scan(root: &Path) -> Result<ScanReport, ScanError> {
    scan_with(root, ScanOptions::default())
}

pub fn scan_with(root: &Path, options: ScanOptions) -> Result<ScanReport, ScanError> {
    let root = std::fs::canonicalize(root).map_err(ScanError::Io)?;
    if !root.is_dir() {
        return Err(ScanError::NotADirectory);
    }
    let config = if options.read_config {
        Config::load(&root)?
    } else {
        None
    };
    let walked = walk::walk(&root, classify::is_wanted, |rel_path| {
        config
            .as_ref()
            .is_some_and(|config| config.is_excluded(rel_path))
    })?;
    let hints =
        ProjectHints::from_paths(walked.entries.iter().map(|entry| entry.rel_path.as_str()));

    let mut migrations = Migrations::default();
    let mut scripts = Vec::new();
    let mut modules = Vec::new();
    let mut secret_records = Vec::new();
    let mut configs = Vec::new();
    let mut scanned = 0u32;
    let mut skipped = walked.skipped;
    let mut uses_supabase = false;

    for entry in &walked.entries {
        let Some(class) = hints.classify(&entry.rel_path) else {
            continue;
        };
        let Some(text) = walk::read_text(&entry.abs_path) else {
            skipped = skipped.saturating_add(1);
            continue;
        };
        scanned = scanned.saturating_add(1);
        if class.content == Content::Sql {
            migrations.apply_file(&entry.rel_path, &text);
            uses_supabase |=
                entry.rel_path.starts_with("supabase/") || entry.rel_path.contains("/supabase/");
        }
        if is_resolver_config(&entry.rel_path, class) && text.len() <= MAX_RESOLVER_CONFIG_BYTES {
            configs.push(ConfigText {
                rel_path: entry.rel_path.clone(),
                text: text.clone(),
            });
        }
        if class.content == Content::Script
            && class.role != FileRole::BuildOutput
            && let Some(mut facts) = script::analyze(&entry.rel_path, &text)
        {
            uses_supabase |= facts.uses_supabase;
            let lines = Lines::new(&text);
            modules.push(Module {
                rel_path: entry.rel_path.clone(),
                role: class.role,
                directive: facts.directive,
                server_only: facts.server_only,
                imports: std::mem::take(&mut facts.imports)
                    .into_iter()
                    .map(|import| roles::Import {
                        specifier: import.specifier,
                        location: lines.location(&entry.rel_path, import.offset),
                    })
                    .collect(),
            });
            scripts.push(ScriptRecord::new(&entry.rel_path, &lines, facts));
        }
        if let Some(record) = SecretRecord::new(&entry.rel_path, class, &text) {
            secret_records.push(record);
        }
    }

    let module_paths: BTreeSet<String> = modules.iter().map(|m| m.rel_path.clone()).collect();
    let resolver = Resolver::new(&module_paths, hints.roots(), &configs);
    let roles = roles::assign(&modules, &resolver);
    let assigned_of = |rel_path: &str, fallback: FileRole| {
        roles
            .get(rel_path)
            .cloned()
            .unwrap_or_else(|| Assigned::by_path(fallback))
    };

    let mut first_use: BTreeMap<String, Location> = BTreeMap::new();
    if uses_supabase {
        for record in &scripts {
            for (table, _, location) in &record.queries {
                if !migrations.is_view("public", table) {
                    first_use
                        .entry(table.clone())
                        .or_insert_with(|| location.clone());
                }
            }
        }
    }

    let mut graph = Graph::default();
    migrations.emit(&mut graph);
    for record in scripts {
        let assigned = assigned_of(&record.rel_path, FileRole::UnknownCode);
        record.emit(&mut graph, &assigned);
    }
    for (table, location) in first_use {
        let table_id = NodeId::new(format!("table:public.{table}"));
        if graph.table_rls(&table_id) == Some(seethru_core::RlsStatus::Unknown) {
            let evidence = vec![
                file_step(&location.path, None, file_location(&location.path)),
                step(
                    &table,
                    Some(EdgeKind::Reads),
                    Some(table_id.clone()),
                    Some(location.clone()),
                ),
            ];
            graph.add_finding(
                Verdict {
                    rule: RuleId::SupabaseTableSchemaMissing,
                    severity: Severity::Info,
                    confidence: Confidence::Review,
                },
                rules::table_schema_missing(&table),
                table_id,
                Some(location),
                evidence,
            );
        }
    }
    for record in secret_records {
        let assigned = assigned_of(&record.rel_path, record.class.role);
        record.emit(&mut graph, &assigned);
    }

    let mut ecosystems = hints.ecosystems();
    if uses_supabase {
        ecosystems.push(Ecosystem::Supabase);
    }
    ecosystems.sort();
    let mut limitations = Vec::new();
    if !modules.is_empty() {
        limitations.push(rules::limitation(LimitationCode::BuildOutputNotRead));
    }
    if uses_supabase {
        limitations.push(rules::limitation(LimitationCode::DashboardPoliciesUnseen));
    }

    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("project")
        .to_owned();
    let mut report = graph.finish(TargetInfo {
        name,
        files_scanned: scanned,
        files_skipped: skipped,
        files_excluded: walked.excluded,
        truncated: walked.truncated,
        config_file: config.as_ref().map(|_| CONFIG_FILE.to_owned()),
        ecosystems,
        inputs: vec![Input::Source {}],
        limitations,
    });
    if let Some(config) = &config {
        for finding in &mut report.findings {
            finding.accepted = config.acceptance(finding);
        }
        report.summary = seethru_core::Summary::from_findings(&report.findings);
    }
    Ok(report)
}

pub(crate) struct Lines<'a> {
    text: &'a str,
    starts: Vec<usize>,
}

impl<'a> Lines<'a> {
    pub(crate) fn new(text: &'a str) -> Self {
        let starts = std::iter::once(0)
            .chain(text.match_indices('\n').map(|(index, _)| index + 1))
            .collect();
        Self { text, starts }
    }

    pub(crate) fn position(&self, offset: usize) -> (u32, u32) {
        let offset = offset.min(self.text.len());
        let line = self.starts.partition_point(|start| *start <= offset);
        let line_start = line
            .checked_sub(1)
            .and_then(|index| self.starts.get(index))
            .copied()
            .unwrap_or(0);
        let column = self
            .text
            .get(line_start..offset)
            .map_or(0, |span| span.chars().count())
            .saturating_add(1);
        (
            u32::try_from(line.max(1)).unwrap_or(u32::MAX),
            u32::try_from(column).unwrap_or(u32::MAX),
        )
    }

    pub(crate) fn location(&self, rel_path: &str, offset: usize) -> Location {
        let (line, column) = self.position(offset);
        Location {
            path: rel_path.to_owned(),
            line,
            column,
        }
    }
}

fn file_steps(rel_path: &str, assigned: &Assigned) -> Vec<EvidenceStep> {
    let mut steps = Vec::with_capacity(assigned.via.len() + 1);
    let mut via = None;
    let mut from: Option<&Location> = None;
    for hop in &assigned.via {
        let at = from
            .cloned()
            .unwrap_or_else(|| file_location(&hop.rel_path));
        steps.push(file_step(&hop.rel_path, via, at));
        via = Some(EdgeKind::Imports);
        from = Some(&hop.location);
    }
    let at = from.cloned().unwrap_or_else(|| file_location(rel_path));
    steps.push(file_step(rel_path, via, at));
    steps
}

fn is_resolver_config(rel_path: &str, class: Class) -> bool {
    let name = classify::file_name(rel_path);
    class.role == FileRole::Other
        && name.ends_with(".json")
        && (name == "package.json" || name.starts_with("tsconfig") || name.starts_with("jsconfig"))
}

struct SecretHit {
    kind: seethru_core::SecretKind,
    masked: seethru_core::MaskedSecret,
    location: Location,
    public_var: Option<String>,
}

struct SecretRecord {
    rel_path: String,
    class: Class,
    real_env_file: bool,
    hits: Vec<SecretHit>,
}

impl SecretRecord {
    fn new(rel_path: &str, class: Class, text: &str) -> Option<Self> {
        let found = secrets::find(text);
        if found.is_empty() {
            return None;
        }
        let real_env_file =
            class.content == Content::Env && !env::is_template_file(classify::file_name(rel_path));
        let lines = Lines::new(text);
        let mut hits = Vec::new();
        for hit in found {
            let public_var = if real_env_file {
                match env::var_at(text, hit.offset) {
                    Some(var) if env::is_public(var) => Some(var.to_owned()),
                    _ => continue,
                }
            } else {
                None
            };
            hits.push(SecretHit {
                kind: hit.kind,
                masked: hit.masked,
                location: lines.location(rel_path, hit.offset),
                public_var,
            });
        }
        Some(Self {
            rel_path: rel_path.to_owned(),
            class,
            real_env_file,
            hits,
        })
    }

    fn emit(self, graph: &mut Graph, assigned: &Assigned) {
        let rel_path = self.rel_path.as_str();
        let role = assigned.role;
        let delivered_as_is = role == FileRole::BuildOutput || self.class.served_as_is;
        let mut ordinals: BTreeMap<seethru_core::SecretKind, u32> = BTreeMap::new();
        for hit in self.hits {
            let ordinal = ordinals.entry(hit.kind).or_insert(0);
            *ordinal = ordinal.saturating_add(1);
            let secret_id = format!("secret:{rel_path}:{}:{ordinal}", hit.kind.as_str());
            let (verdict, explanation) = match (&hit.public_var, self.real_env_file) {
                (Some(var), true) => (
                    Verdict {
                        rule: RuleId::SecretInPublicEnvVar,
                        severity: Severity::Critical,
                        confidence: Confidence::Certain,
                    },
                    rules::secret_in_public_env(hit.kind, var),
                ),
                _ if role.runs_in_browser() => (
                    Verdict {
                        rule: RuleId::SecretInBrowserCode,
                        severity: Severity::Critical,
                        confidence: if delivered_as_is {
                            Confidence::Certain
                        } else {
                            Confidence::Likely
                        },
                    },
                    rules::secret_in_browser(hit.kind, rel_path),
                ),
                _ => (
                    Verdict {
                        rule: RuleId::SecretInSourceCode,
                        severity: Severity::High,
                        confidence: Confidence::Certain,
                    },
                    rules::secret_in_source(hit.kind, rel_path),
                ),
            };
            let file_id = graph.add_file(rel_path, role, assigned.basis);
            let mut evidence = file_steps(rel_path, assigned);
            let zone = match &hit.public_var {
                Some(var) if env::is_public(var) => Zone::Client,
                Some(_) => Zone::Server,
                None => role.runtime().zone(),
            };
            let secret_id = graph.add_node(Node {
                id: NodeId::new(secret_id),
                label: hit.masked.as_str().to_owned(),
                kind: NodeKind::Credential {
                    detail: CredentialDetail::Secret {
                        secret_kind: hit.kind,
                        masked: hit.masked.clone(),
                    },
                },
                zone,
                location: Some(hit.location.clone()),
            });
            match hit.public_var {
                Some(var) => {
                    let env_id = graph.add_env_var(&var);
                    evidence.push(step(
                        &var,
                        Some(EdgeKind::Defines),
                        Some(env_id.clone()),
                        Some(hit.location.clone()),
                    ));
                    graph.add_edge(file_id, env_id.clone(), EdgeKind::Defines);
                    graph.add_edge(env_id, secret_id.clone(), EdgeKind::Contains);
                }
                None => graph.add_edge(file_id, secret_id.clone(), EdgeKind::Contains),
            }
            evidence.push(step(
                hit.masked.as_str(),
                Some(EdgeKind::Contains),
                Some(secret_id.clone()),
                Some(hit.location.clone()),
            ));
            graph.add_finding(
                verdict,
                explanation,
                secret_id,
                Some(hit.location),
                evidence,
            );
        }
    }
}

struct ScriptRecord {
    rel_path: String,
    env_reads: Vec<(String, Location)>,
    queries: Vec<(String, script::Access, Location)>,
}

impl ScriptRecord {
    fn new(rel_path: &str, lines: &Lines<'_>, facts: script::Facts) -> Self {
        let at = |offset: usize| lines.location(rel_path, offset);
        Self {
            rel_path: rel_path.to_owned(),
            env_reads: facts
                .env_reads
                .into_iter()
                .map(|read| {
                    let location = at(read.offset);
                    (read.name, location)
                })
                .collect(),
            queries: facts
                .queries
                .into_iter()
                .map(|query| {
                    let location = at(query.offset);
                    (query.table, query.access, location)
                })
                .collect(),
        }
    }

    fn emit(self, graph: &mut Graph, assigned: &Assigned) {
        if self.env_reads.is_empty() && self.queries.is_empty() {
            return;
        }
        let role = assigned.role;
        let file_id = graph.add_file(&self.rel_path, role, assigned.basis);
        for (table, access, _) in &self.queries {
            let table_id = graph.add_table("public", table);
            let kind = match access {
                script::Access::Read => EdgeKind::Reads,
                script::Access::Write => EdgeKind::Writes,
            };
            graph.add_edge(file_id.clone(), table_id, kind);
        }
        for (name, location) in self.env_reads {
            let env_id = graph.add_env_var(&name);
            graph.add_edge(file_id.clone(), env_id.clone(), EdgeKind::UsesConfig);
            let exposed_prefix = env::public_prefix(&name);
            if let (true, true, Some(prefix)) = (
                role.runs_in_browser(),
                script::is_service_role_env(&name),
                exposed_prefix,
            ) {
                let mut evidence = file_steps(&self.rel_path, assigned);
                evidence.push(step(
                    &name,
                    Some(EdgeKind::UsesConfig),
                    Some(env_id.clone()),
                    Some(location.clone()),
                ));
                graph.add_finding(
                    Verdict {
                        rule: RuleId::SupabaseServiceRoleInBrowser,
                        severity: Severity::Critical,
                        confidence: Confidence::Likely,
                    },
                    rules::service_role_in_browser(&name, prefix),
                    env_id,
                    Some(location),
                    evidence,
                );
            }
        }
    }
}
