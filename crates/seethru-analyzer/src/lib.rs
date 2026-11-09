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

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use seethru_core::{
    EdgeKind, FileRole, Location, Node, NodeId, NodeKind, RuleId, ScanReport, Severity, TargetInfo,
};

use classify::{Class, Content, ProjectHints};
use config::Config;
use graph::Graph;
use resolve::{ConfigText, Resolver};
use roles::Module;
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
            modules.push(Module {
                rel_path: entry.rel_path.clone(),
                role: class.role,
                directive: facts.directive,
                server_only: facts.server_only,
                imports: std::mem::take(&mut facts.imports),
            });
            scripts.push(ScriptRecord::new(&entry.rel_path, &text, facts));
        }
        if let Some(record) = SecretRecord::new(&entry.rel_path, class, &text) {
            secret_records.push(record);
        }
    }

    let module_paths: BTreeSet<String> = modules.iter().map(|m| m.rel_path.clone()).collect();
    let resolver = Resolver::new(&module_paths, hints.roots(), &configs);
    let roles = roles::assign(&modules, &resolver);
    let role_of =
        |rel_path: &str, fallback: FileRole| roles.get(rel_path).copied().unwrap_or(fallback);

    let mut graph = Graph::default();
    migrations.emit(&mut graph);
    for record in scripts {
        let role = role_of(&record.rel_path, FileRole::UnknownCode);
        record.emit(&mut graph, role);
    }
    for record in secret_records {
        let role = role_of(&record.rel_path, record.class.role);
        record.emit(&mut graph, role);
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
    });
    if let Some(config) = &config {
        for finding in &mut report.findings {
            finding.accepted = config.acceptance(finding);
        }
        report.summary = seethru_core::Summary::from_findings(&report.findings);
    }
    Ok(report)
}

pub(crate) fn position(text: &str, offset: usize) -> (u32, u32) {
    let before = &text[..offset.min(text.len())];
    let line = before.matches('\n').count().saturating_add(1);
    let line_start = before.rfind('\n').map_or(0, |n| n + 1);
    let column = before[line_start..].chars().count().saturating_add(1);
    (
        u32::try_from(line).unwrap_or(u32::MAX),
        u32::try_from(column).unwrap_or(u32::MAX),
    )
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
            let (line, column) = position(text, hit.offset);
            hits.push(SecretHit {
                kind: hit.kind,
                masked: hit.masked,
                location: Location {
                    path: rel_path.to_owned(),
                    line,
                    column,
                },
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

    fn emit(self, graph: &mut Graph, role: FileRole) {
        let rel_path = self.rel_path.as_str();
        for hit in self.hits {
            let (rule, severity, explanation) = match (&hit.public_var, self.real_env_file) {
                (Some(var), true) => (
                    RuleId::SecretInPublicEnvVar,
                    Severity::Critical,
                    rules::secret_in_public_env(hit.kind, var),
                ),
                _ if role.runs_in_browser() => (
                    RuleId::SecretInBrowserCode,
                    Severity::Critical,
                    rules::secret_in_browser(hit.kind, rel_path),
                ),
                _ => (
                    RuleId::SecretInSourceCode,
                    Severity::High,
                    rules::secret_in_source(hit.kind, rel_path),
                ),
            };
            let Location { line, column, .. } = hit.location;
            let file_id = graph.add_file(rel_path, role);
            let secret_id = graph.add_node(Node {
                id: NodeId::new(format!("secret:{rel_path}:{line}:{column}")),
                label: hit.masked.as_str().to_owned(),
                kind: NodeKind::Secret {
                    secret_kind: hit.kind,
                    masked: hit.masked,
                },
                location: Some(hit.location.clone()),
            });
            match hit.public_var {
                Some(var) => {
                    let env_id = graph.add_env_var(&var);
                    graph.add_edge(file_id, env_id.clone(), EdgeKind::Defines);
                    graph.add_edge(env_id, secret_id.clone(), EdgeKind::Contains);
                }
                None => graph.add_edge(file_id, secret_id.clone(), EdgeKind::Contains),
            }
            graph.add_finding(rule, severity, explanation, secret_id, Some(hit.location));
        }
    }
}

struct ScriptRecord {
    rel_path: String,
    env_reads: Vec<(String, Location)>,
    queries: Vec<(String, script::Access, Location)>,
}

impl ScriptRecord {
    fn new(rel_path: &str, text: &str, facts: script::Facts) -> Self {
        let at = |offset: usize| {
            let (line, column) = position(text, offset);
            Location {
                path: rel_path.to_owned(),
                line,
                column,
            }
        };
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

    fn emit(self, graph: &mut Graph, role: FileRole) {
        if self.env_reads.is_empty() && self.queries.is_empty() {
            return;
        }
        let file_id = graph.add_file(&self.rel_path, role);
        for (table, access, _) in &self.queries {
            let table_id = graph.add_table("public", table);
            let kind = match access {
                script::Access::Read => EdgeKind::Queries,
                script::Access::Write => EdgeKind::Writes,
            };
            graph.add_edge(file_id.clone(), table_id, kind);
        }
        for (name, location) in self.env_reads {
            let env_id = graph.add_env_var(&name);
            graph.add_edge(file_id.clone(), env_id.clone(), EdgeKind::Reads);
            let exposed_prefix = env::public_prefix(&name);
            if let (true, true, Some(prefix)) = (
                role.runs_in_browser(),
                script::is_service_role_env(&name),
                exposed_prefix,
            ) {
                graph.add_finding(
                    RuleId::SupabaseServiceRoleInBrowser,
                    Severity::Critical,
                    rules::service_role_in_browser(&name, prefix),
                    env_id,
                    Some(location),
                );
            }
        }
    }
}
