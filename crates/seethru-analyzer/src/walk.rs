use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::ScanError;

pub(crate) const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_FILES: usize = 50_000;
pub(crate) const MAX_DEPTH: usize = 40;

const SKIPPED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".pnpm-store",
    ".yarn",
    ".seethru",
];

const BINARY_PROBE_BYTES: usize = 8192;

pub(crate) struct Entry {
    pub rel_path: String,
    pub abs_path: PathBuf,
}

pub(crate) struct Walk {
    pub entries: Vec<Entry>,
    pub skipped: u32,
    pub truncated: bool,
}

pub(crate) fn walk(root: &Path, wanted: impl Fn(&str) -> bool) -> Result<Walk, ScanError> {
    let mut out = Walk {
        entries: Vec::new(),
        skipped: 0,
        truncated: false,
    };
    let mut stack: Vec<(PathBuf, String, usize)> = vec![(root.to_path_buf(), String::new(), 0)];

    while let Some((dir, rel_dir, depth)) = stack.pop() {
        let mut children = Vec::new();
        let read_dir = match fs::read_dir(&dir) {
            Ok(read_dir) => read_dir,
            Err(error) if depth == 0 => return Err(ScanError::Io(error)),
            Err(_) => {
                out.skipped = out.skipped.saturating_add(1);
                continue;
            }
        };
        for item in read_dir {
            let Ok(item) = item else {
                out.skipped = out.skipped.saturating_add(1);
                continue;
            };
            let Ok(name) = item.file_name().into_string() else {
                out.skipped = out.skipped.saturating_add(1);
                continue;
            };
            children.push((name, item.path()));
        }
        children.sort_by(|a, b| b.0.cmp(&a.0));

        for (name, path) in children {
            let Ok(meta) = fs::symlink_metadata(&path) else {
                out.skipped = out.skipped.saturating_add(1);
                continue;
            };
            let rel_path = if rel_dir.is_empty() {
                name.clone()
            } else {
                format!("{rel_dir}/{name}")
            };
            let file_type = meta.file_type();
            if file_type.is_symlink() {
                out.skipped = out.skipped.saturating_add(1);
            } else if file_type.is_dir() {
                if SKIPPED_DIRS.contains(&name.as_str()) {
                    continue;
                }
                if depth + 1 >= MAX_DEPTH {
                    out.truncated = true;
                    continue;
                }
                stack.push((path, rel_path, depth + 1));
            } else if file_type.is_file() && wanted(&rel_path) {
                if meta.len() > MAX_FILE_BYTES {
                    out.skipped = out.skipped.saturating_add(1);
                    continue;
                }
                if out.entries.len() >= MAX_FILES {
                    out.truncated = true;
                    return Ok(finish(out));
                }
                out.entries.push(Entry {
                    rel_path,
                    abs_path: path,
                });
            }
        }
    }
    Ok(finish(out))
}

fn finish(mut walk: Walk) -> Walk {
    walk.entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    walk
}

pub(crate) fn read_text(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return None;
    }
    let probe = &bytes[..bytes.len().min(BINARY_PROBE_BYTES)];
    if probe.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}
