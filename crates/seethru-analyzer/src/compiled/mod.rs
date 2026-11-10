mod asm;
mod flow;
mod ir;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Component, Path, PathBuf};

use seethru_core::{
    Basis, Confidence, EdgeKind, Finding, Input, Location, NodeId, Origin, RuleId, Severity,
};

use crate::ScanError;
use crate::classify::FileRole;
use crate::graph::{Graph, file_id, file_step};
use crate::rules;
use crate::walk::{SKIPPED_DIRS, read_bytes};

const MAX_FILES: usize = 64;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DEPTH: usize = 6;
const MAX_FINDINGS: usize = 500;
const MAX_STEPS: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Division {
    pub path: String,
    pub line: u32,
    pub callers: Vec<(String, u32)>,
    pub by_variable: bool,
    pub confirmed: bool,
}

pub(crate) struct Compiled {
    pub inputs: Vec<Input>,
    pub divisions: Vec<Division>,
    pub machine_code: bool,
    pub unoptimized: bool,
    pub partial: bool,
    pub wipes: usize,
}

struct Unit {
    module: ir::Module,
    listing: Option<asm::Listing>,
}

pub(crate) fn read(
    root: &Path,
    given: &[PathBuf],
    excluded: &dyn Fn(&str) -> bool,
) -> Result<Compiled, ScanError> {
    let mut units = Vec::new();
    let mut inputs = Vec::new();
    let mut partial = false;
    let mut budget = MAX_TOTAL_BYTES;
    for path in given {
        let fail = |reason: &str| ScanError::CompiledOutput(format!("{} {reason}", path.display()));
        let meta = fs::symlink_metadata(path).map_err(|_| fail("cannot be read"))?;
        if meta.file_type().is_symlink() {
            return Err(fail("is a symbolic link"));
        }
        let mut files = Vec::new();
        if meta.is_dir() {
            partial |= collect(path, 0, &mut files);
        } else if meta.is_file() && has_extension(path, "ll") {
            files.push(path.clone());
        } else {
            return Err(fail("is not a folder or a .ll file"));
        }
        files.sort();
        if files.is_empty() {
            return Err(fail("has no .ll files"));
        }
        let before = units.len();
        let mut functions = 0usize;
        let mut with_machine_code = 0usize;
        for file in files {
            if units.len() >= MAX_FILES {
                partial = true;
                break;
            }
            let Some(bytes) = read_bytes(&file, MAX_FILE_BYTES.min(budget)) else {
                partial = true;
                continue;
            };
            budget = budget.saturating_sub(bytes.len() as u64);
            let module = ir::parse(&String::from_utf8_lossy(&bytes));
            partial |= module.truncated;
            functions += module.functions.len();
            let listing = read_bytes(&file.with_extension("s"), MAX_FILE_BYTES.min(budget))
                .map(|bytes| {
                    budget = budget.saturating_sub(bytes.len() as u64);
                    asm::parse(&String::from_utf8_lossy(&bytes))
                })
                .filter(|listing| listing.has_lines || module.functions.is_empty());
            with_machine_code += usize::from(listing.is_some());
            units.push(Unit { module, listing });
        }
        let count = units.len() - before;
        inputs.push(Input::CompiledOutput {
            path: shown(root, path),
            files: u32::try_from(count).unwrap_or(u32::MAX),
            functions: u32::try_from(functions).unwrap_or(u32::MAX),
            machine_code: count > 0 && with_machine_code == count,
        });
    }

    let modules: Vec<ir::Module> = units
        .iter_mut()
        .map(|unit| std::mem::take(&mut unit.module))
        .collect();
    let flow = flow::analyze(&modules);
    partial |= flow.truncated;

    let total: usize = modules.iter().map(|module| module.functions.len()).sum();
    let slow: usize = modules
        .iter()
        .flat_map(|module| &module.functions)
        .filter(|function| function.unoptimized)
        .count();
    let mut places: HashMap<String, Option<String>> = HashMap::new();
    let mut place = |raw: &str| -> Option<String> {
        places
            .entry(raw.to_owned())
            .or_insert_with(|| project_path(root, raw).filter(|rel| !excluded(rel)))
            .clone()
    };
    let mut merged: BTreeMap<(String, u32), Division> = BTreeMap::new();
    for site in &flow.sites {
        let module = &modules[site.module];
        let frames = module.frames(site.debug);
        let Some(inner) = frames.first() else {
            continue;
        };
        let confirmed = units[site.module].listing.as_ref().map(|listing| {
            listing
                .divisions
                .contains(&(inner.path.clone(), inner.line))
        });
        if confirmed == Some(false) && !site.by_variable {
            continue;
        }
        let mut inside: Vec<(String, u32)> = frames
            .iter()
            .filter(|frame| frame.line > 0)
            .filter_map(|frame| Some((place(&frame.path)?, frame.line)))
            .collect();
        inside.dedup();
        if inside.is_empty() {
            partial = true;
            continue;
        }
        let (path, line) = inside.remove(0);
        inside.truncate(MAX_STEPS - 1);
        inside.reverse();
        let entry = merged
            .entry((path.clone(), line))
            .or_insert_with(|| Division {
                path,
                line,
                callers: inside,
                by_variable: false,
                confirmed: false,
            });
        entry.by_variable |= site.by_variable;
        entry.confirmed |= confirmed == Some(true);
    }
    let mut divisions: Vec<Division> = merged.into_values().collect();
    if divisions.len() > MAX_FINDINGS {
        divisions.truncate(MAX_FINDINGS);
        partial = true;
    }
    Ok(Compiled {
        machine_code: !units.is_empty() && units.iter().all(|unit| unit.listing.is_some()),
        unoptimized: total > 0 && slow * 2 > total,
        inputs,
        divisions,
        partial,
        wipes: flow.wipes,
    })
}

pub(crate) fn emit(
    compiled: &Compiled,
    graph: &mut Graph,
    package_of: &dyn Fn(&str) -> Option<NodeId>,
) {
    let mut orders: BTreeMap<&str, u32> = BTreeMap::new();
    for division in &compiled.divisions {
        let node = graph.add_file(&division.path, FileRole::NativeCode, Basis::Path);
        if let Some(package) = package_of(&division.path) {
            graph.add_edge(package, node.clone(), EdgeKind::Contains);
        }
        let location = Location {
            path: division.path.clone(),
            line: division.line,
            column: 1,
        };
        let mut evidence = Vec::new();
        for (path, line) in &division.callers {
            let caller = graph.add_file(path, FileRole::NativeCode, Basis::Path);
            if let Some(package) = package_of(path) {
                graph.add_edge(package, caller, EdgeKind::Contains);
            }
            let via = (!evidence.is_empty()).then_some(EdgeKind::Calls);
            evidence.push(file_step(
                path,
                via,
                Location {
                    path: path.clone(),
                    line: *line,
                    column: 1,
                },
            ));
        }
        let via = (!evidence.is_empty()).then_some(EdgeKind::Calls);
        evidence.push(file_step(&division.path, via, location.clone()));
        let text =
            rules::secret_dependent_division(&division.path, division.line, division.confirmed);
        let rule = RuleId::SecretDependentDivision;
        let order = orders.entry(division.path.as_str()).or_insert(0u32);
        *order += 1;
        graph.add_external(Finding {
            id: format!("{}:{}:{order}", rule.as_str(), file_id(&division.path)),
            rule,
            severity: Severity::Medium,
            confidence: if division.confirmed {
                Confidence::Likely
            } else {
                Confidence::Review
            },
            title: text.title,
            explanation: text.explanation,
            node,
            location: Some(location),
            evidence,
            origin: Origin::seethru_with_compiled_output(),
            cwe: rule.cwe().to_vec(),
            proof: None,
            fix_prompt: None,
            accepted: None,
        });
    }
}

fn collect(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return true;
    };
    let mut partial = false;
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            if depth + 1 >= MAX_DEPTH {
                partial = true;
            } else {
                partial |= collect(&path, depth + 1, out);
            }
        } else if meta.is_file() && has_extension(&path, "ll") {
            if out.len() >= MAX_FILES * 4 {
                return true;
            }
            out.push(path);
        }
    }
    partial
}

fn has_extension(path: &Path, wanted: &str) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some(wanted)
}

fn shown(root: &Path, given: &Path) -> String {
    let inside = fs::canonicalize(given)
        .ok()
        .and_then(|abs| relative(root, &abs));
    inside.unwrap_or_else(|| {
        given
            .file_name()
            .and_then(|name| name.to_str())
            .map_or_else(|| "compiled output".to_owned(), rules::display_name)
    })
}

fn relative(root: &Path, path: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in path.strip_prefix(root).ok()?.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?),
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn project_path(root: &Path, raw: &str) -> Option<String> {
    if raw.len() > 4096 || raw.chars().any(char::is_control) {
        return None;
    }
    let mut lexical = PathBuf::new();
    for component in Path::new(raw).components() {
        match component {
            Component::ParentDir => {
                if !lexical.pop() {
                    return None;
                }
            }
            Component::CurDir => {}
            other => lexical.push(other),
        }
    }
    let joined = if lexical.is_absolute() {
        lexical
    } else {
        root.join(lexical)
    };
    let rel = relative(root, &joined)?;
    if rel.split('/').any(|part| SKIPPED_DIRS.contains(&part)) {
        return None;
    }
    let real = fs::canonicalize(&joined).ok()?;
    (real.is_file() && relative(root, &real).is_some()).then_some(rel)
}
