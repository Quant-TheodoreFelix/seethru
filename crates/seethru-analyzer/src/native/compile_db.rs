use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

use crate::ScanError;

const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const MAX_PATH_BYTES: usize = 4096;

#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    directory: Option<String>,
    #[serde(default)]
    file: Option<String>,
}

pub(crate) struct CompileDb {
    pub rel: String,
    pub files: BTreeSet<String>,
}

pub(crate) fn read(root: &Path, given: &Path) -> Result<CompileDb, ScanError> {
    let fail = |reason: &str| ScanError::CompileCommands(format!("{} {reason}", given.display()));
    let meta = fs::symlink_metadata(given).map_err(|_| fail("cannot be read"))?;
    if meta.file_type().is_symlink() {
        return Err(fail("is a symbolic link"));
    }
    if !meta.file_type().is_file() {
        return Err(fail("is not a regular file"));
    }
    if meta.len() > MAX_BYTES {
        return Err(fail("is larger than 32 MB"));
    }
    let abs = fs::canonicalize(given).map_err(|_| fail("cannot be read"))?;
    let rel = inside(root, &abs).ok_or_else(|| fail("is outside the scanned project"))?;
    let mut bytes = Vec::new();
    File::open(&abs)
        .map_err(|_| fail("cannot be read"))?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail("cannot be read"))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(fail("is larger than 32 MB"));
    }
    let entries: Vec<Entry> =
        serde_json::from_slice(&bytes).map_err(|_| fail("is not a compile database"))?;
    if entries.len() > MAX_ENTRIES {
        return Err(fail("has too many entries"));
    }
    let mut files = BTreeSet::new();
    for entry in entries {
        let Some(file) = entry.file.filter(|file| file.len() <= MAX_PATH_BYTES) else {
            continue;
        };
        let path = Path::new(&file);
        let joined = if path.is_absolute() {
            path.to_path_buf()
        } else {
            match entry.directory.filter(|dir| dir.len() <= MAX_PATH_BYTES) {
                Some(directory) => Path::new(&directory).join(path),
                None => continue,
            }
        };
        if let Some(rel) = lexical(&joined)
            .as_deref()
            .and_then(|path| inside(root, path))
        {
            files.insert(rel);
        }
    }
    Ok(CompileDb { rel, files })
}

fn lexical(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    Some(out)
}

fn inside(root: &Path, path: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in path.strip_prefix(root).ok()?.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?),
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}
