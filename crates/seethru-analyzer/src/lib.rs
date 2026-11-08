mod classify;
mod graph;
mod rules;
mod supabase;
mod walk;

use std::fmt;
use std::path::Path;

use seethru_core::{ScanReport, TargetInfo};

use classify::{Content, ProjectHints};
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
