mod classify;
mod env;
mod graph;
mod rules;
mod secrets;
mod supabase;
mod walk;

use std::fmt;
use std::path::Path;

use seethru_core::{
    EdgeKind, Location, Node, NodeId, NodeKind, RuleId, ScanReport, Severity, TargetInfo,
};

use classify::{Class, Content, ProjectHints};
use graph::Graph;
use supabase::Migrations;

#[derive(Debug)]
pub enum ScanError {
    NotADirectory,
    Io(std::io::Error),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotADirectory => f.write_str("scan target is not a directory"),
            Self::Io(error) => write!(f, "cannot read scan target: {error}"),
        }
    }
}

impl std::error::Error for ScanError {}

pub fn scan(root: &Path) -> Result<ScanReport, ScanError> {
    let root = std::fs::canonicalize(root).map_err(ScanError::Io)?;
    if !root.is_dir() {
        return Err(ScanError::NotADirectory);
    }
    let walked = walk::walk(&root, classify::is_wanted)?;
    let hints =
        ProjectHints::from_paths(walked.entries.iter().map(|entry| entry.rel_path.as_str()));

    let mut graph = Graph::default();
    let mut migrations = Migrations::default();
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
        record_secrets(&mut graph, &entry.rel_path, class, &text);
    }
    migrations.emit(&mut graph);

    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("project")
        .to_owned();
    Ok(graph.finish(TargetInfo {
        name,
        files_scanned: scanned,
        files_skipped: skipped,
        truncated: walked.truncated,
    }))
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

fn record_secrets(graph: &mut Graph, rel_path: &str, class: Class, text: &str) {
    let hits = secrets::find(text);
    if hits.is_empty() {
        return;
    }
    let real_env_file =
        class.content == Content::Env && !env::is_template_file(classify::file_name(rel_path));
    for hit in hits {
        let (line, column) = position(text, hit.offset);
        let location = Location {
            path: rel_path.to_owned(),
            line,
            column,
        };
        let (rule, severity, explanation, holder) = if real_env_file {
            let Some(var) = env::var_at(text, hit.offset) else {
                continue;
            };
            if !env::is_public(var) {
                continue;
            }
            (
                RuleId::SecretInPublicEnvVar,
                Severity::Critical,
                rules::secret_in_public_env(hit.kind, var),
                Some(var),
            )
        } else if class.role.runs_in_browser() {
            (
                RuleId::SecretInBrowserCode,
                Severity::Critical,
                rules::secret_in_browser(hit.kind, rel_path),
                None,
            )
        } else {
            (
                RuleId::SecretInSourceCode,
                Severity::High,
                rules::secret_in_source(hit.kind, rel_path),
                None,
            )
        };

        let file_id = graph.add_file(rel_path, class.role);
        let secret_id = graph.add_node(Node {
            id: NodeId::new(format!("secret:{rel_path}:{line}:{column}")),
            label: hit.masked.as_str().to_owned(),
            kind: NodeKind::Secret {
                secret_kind: hit.kind,
                masked: hit.masked,
            },
            location: Some(location.clone()),
        });
        match holder {
            Some(var) => {
                let env_id = graph.add_env_var(var);
                graph.add_edge(file_id, env_id.clone(), EdgeKind::Defines);
                graph.add_edge(env_id, secret_id.clone(), EdgeKind::Contains);
            }
            None => graph.add_edge(file_id, secret_id.clone(), EdgeKind::Contains),
        }
        graph.add_finding(rule, severity, explanation, secret_id, Some(location));
    }
}
