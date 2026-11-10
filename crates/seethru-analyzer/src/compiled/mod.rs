mod asm;
mod flow;
mod ir;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Component, Path, PathBuf};

use seethru_core::{
    AssemblyLine, Basis, Confidence, DivisionLine, EdgeKind, EvidenceStep, Finding, Input,
    Location, MachineCode, NodeId, Origin, RuleId, Severity,
};

use crate::ScanError;
use crate::classify::FileRole;
use crate::graph::{Graph, file_id, file_step};
use crate::rules;
use crate::walk::{SKIPPED_DIRS, read_bytes};

const MAX_FILES: usize = 1024;
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 2048 * 1024 * 1024;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Stop {
    pub path: String,
    pub line: u32,
    pub callers: Vec<(String, u32)>,
}

pub(crate) struct Compiled {
    pub inputs: Vec<Input>,
    pub divisions: Vec<Division>,
    pub by_hand: Vec<Division>,
    pub stops: Vec<Stop>,
    pub entries: usize,
    pub machine_code: bool,
    pub unoptimized: bool,
    pub partial: bool,
    pub wipes: usize,
    pub machine: Option<MachineCode>,
    pub unknown_cpu: bool,
    pub file_assembly: bool,
}

type Place = (String, u32);
type Scope = (usize, Option<usize>, String, u32);

struct Unit {
    module: ir::Module,
    listing: Option<asm::Listing>,
    matched: bool,
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
                    asm::parse(&String::from_utf8_lossy(&bytes), module.naming, module.cpu)
                })
                .filter(|listing| listing.has_lines || module.functions.is_empty());
            with_machine_code += usize::from(listing.is_some());
            let matched = listing.as_ref().is_some_and(|listing| {
                module
                    .functions
                    .iter()
                    .any(|function| listing.functions.contains(function.symbol.as_str()))
            });
            units.push(Unit {
                module,
                listing,
                matched,
            });
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
    let mut inside_of = |frames: &[ir::Frame]| -> Vec<Place> {
        let mut inside: Vec<Place> = frames
            .iter()
            .filter(|frame| frame.line > 0)
            .filter_map(|frame| Some((place(&frame.path)?, frame.line)))
            .collect();
        inside.dedup();
        inside
    };
    let mut divided: HashMap<Scope, BTreeSet<Place>> = HashMap::new();
    let mut merged: BTreeMap<Place, Division> = BTreeMap::new();
    for site in &flow.sites {
        let module = &modules[site.module];
        let frames = module.frames(site.debug);
        let Some(inner) = frames.first() else {
            continue;
        };
        let unit = &units[site.module];
        let scope = unit.matched.then_some(site.function);
        let mut inside = inside_of(&frames);
        if unit.listing.is_some() {
            divided
                .entry((site.module, scope, inner.path.clone(), inner.line))
                .or_default()
                .extend(inside.first().cloned());
        }
        if !site.secret {
            continue;
        }
        let function = scope
            .and_then(|at| module.functions.get(at))
            .map(|function| function.symbol.as_str());
        let confirmed = unit
            .listing
            .as_ref()
            .map(|listing| listing.divides(function, &inner.path, inner.line))
            .filter(|found| *found || module.cpu != asm::Cpu::Other);
        if confirmed == Some(false) && !site.by_variable {
            continue;
        }
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
    let mut written: HashMap<Scope, BTreeSet<(Vec<Place>, bool)>> = HashMap::new();
    for site in &flow.assembly {
        let unit = &units[site.module];
        if unit.listing.is_none() {
            continue;
        }
        let frames = modules[site.module].frames(site.debug);
        let Some(inner) = frames.first() else {
            continue;
        };
        let scope = unit.matched.then_some(site.function);
        written
            .entry((site.module, scope, inner.path.clone(), inner.line))
            .or_default()
            .insert((inside_of(&frames), site.secret));
    }
    let mut halted: BTreeMap<Place, Stop> = BTreeMap::new();
    for site in &flow.stops {
        let frames = modules[site.module].frames(site.debug);
        let mut inside = inside_of(&frames);
        if inside.is_empty() {
            continue;
        }
        let (path, line) = inside.remove(0);
        inside.truncate(MAX_STEPS - 1);
        inside.reverse();
        halted.entry((path.clone(), line)).or_insert(Stop {
            path,
            line,
            callers: inside,
        });
    }

    let mut machine = MachineCode::default();
    let mut division_lines: BTreeMap<Place, bool> = BTreeMap::new();
    let mut assembly_lines: BTreeMap<Place, AssemblyLine> = BTreeMap::new();
    let mut handmade: BTreeMap<Place, Division> = BTreeMap::new();
    let mut unknown_cpu = false;
    let mut file_assembly = false;
    let mut listed = false;
    for (at, unit) in units.iter().enumerate() {
        let Some(listing) = &unit.listing else {
            continue;
        };
        let module = &modules[at];
        listed = true;
        partial |= listing.truncated;
        file_assembly |= module.file_assembly;
        unknown_cpu |= module.cpu == asm::Cpu::Other;
        let symbols: HashMap<&str, usize> = module
            .functions
            .iter()
            .enumerate()
            .filter(|_| unit.matched)
            .map(|(index, function)| (function.symbol.as_str(), index))
            .collect();
        let scope = |spot: &asm::Spot| -> Option<Scope> {
            let (path, line) = spot.place.as_ref()?;
            let function = match unit.matched {
                true => Some(*symbols.get(spot.function.as_deref()?)?),
                false => None,
            };
            Some((at, function, path.to_string(), *line))
        };
        for (spot, count) in &listing.divisions {
            machine.divisions = machine.divisions.saturating_add(*count);
            let lines = scope(spot)
                .and_then(|scope| divided.get(&scope))
                .filter(|lines| !lines.is_empty());
            match lines {
                Some(lines) => {
                    for line in lines {
                        division_lines.entry(line.clone()).or_insert(false);
                    }
                }
                None => {
                    machine.divisions_without_line =
                        machine.divisions_without_line.saturating_add(*count);
                }
            }
        }
        for (spot, block) in &listing.by_hand {
            machine.assembly_blocks = machine.assembly_blocks.saturating_add(block.blocks);
            machine.divisions = machine.divisions.saturating_add(block.divisions);
            let sites: Vec<(&Place, &[Place], bool)> = scope(spot)
                .and_then(|scope| written.get(&scope))
                .into_iter()
                .flatten()
                .filter_map(|(inside, secret)| {
                    let (first, callers) = inside.split_first()?;
                    Some((first, callers, *secret))
                })
                .collect();
            if sites.is_empty() {
                machine.assembly_blocks_without_line = machine
                    .assembly_blocks_without_line
                    .saturating_add(block.blocks);
                machine.divisions_without_line = machine
                    .divisions_without_line
                    .saturating_add(block.divisions);
                continue;
            }
            for (first, callers, secret) in sites {
                let (path, line) = first.clone();
                let entry = assembly_lines
                    .entry(first.clone())
                    .or_insert_with(|| AssemblyLine {
                        path: path.clone(),
                        line,
                        divides: false,
                        branches: false,
                        secret: false,
                    });
                entry.divides |= block.divisions > 0;
                entry.branches |= block.branches;
                entry.secret |= secret;
                if block.divisions == 0 {
                    continue;
                }
                division_lines.insert(first.clone(), true);
                if secret {
                    let mut callers = callers.to_vec();
                    callers.truncate(MAX_STEPS - 1);
                    callers.reverse();
                    handmade.entry(first.clone()).or_insert(Division {
                        path,
                        line,
                        callers,
                        by_variable: true,
                        confirmed: false,
                    });
                }
            }
        }
    }

    let mut cut = |len: usize| {
        partial |= len > MAX_FINDINGS;
        len.min(MAX_FINDINGS)
    };
    let mut stops: Vec<Stop> = halted.into_values().collect();
    stops.truncate(cut(stops.len()));
    let mut divisions: Vec<Division> = merged.into_values().collect();
    divisions.truncate(cut(divisions.len()));
    let mut by_hand: Vec<Division> = handmade.into_values().collect();
    by_hand.truncate(cut(by_hand.len()));
    let reported: BTreeSet<(&str, u32)> = divisions
        .iter()
        .chain(&by_hand)
        .map(|division| (division.path.as_str(), division.line))
        .collect();
    machine.division_lines = division_lines
        .into_iter()
        .map(|((path, line), assembly)| DivisionLine {
            secret: reported.contains(&(path.as_str(), line)),
            path,
            line,
            assembly,
        })
        .collect();
    machine
        .division_lines
        .truncate(cut(machine.division_lines.len()));
    machine.assembly_lines = assembly_lines.into_values().collect();
    machine
        .assembly_lines
        .truncate(cut(machine.assembly_lines.len()));
    Ok(Compiled {
        machine_code: !units.is_empty() && units.iter().all(|unit| unit.listing.is_some()),
        unoptimized: total > 0 && slow * 2 > total,
        inputs,
        divisions,
        by_hand,
        stops,
        entries: flow.entries,
        partial,
        wipes: flow.wipes,
        machine: listed.then_some(machine),
        unknown_cpu,
        file_assembly,
    })
}

fn trail(
    graph: &mut Graph,
    package_of: &dyn Fn(&str) -> Option<NodeId>,
    path: &str,
    line: u32,
    callers: &[Place],
) -> (NodeId, Location, Vec<EvidenceStep>) {
    let node = graph.add_file(path, FileRole::NativeCode, Basis::Path);
    if let Some(package) = package_of(path) {
        graph.add_edge(package, node.clone(), EdgeKind::Contains);
    }
    let location = Location {
        path: path.to_owned(),
        line,
        column: 1,
    };
    let mut evidence = Vec::new();
    for (path, line) in callers {
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
    evidence.push(file_step(path, via, location.clone()));
    (node, location, evidence)
}

pub(crate) fn emit(
    compiled: &Compiled,
    graph: &mut Graph,
    package_of: &dyn Fn(&str) -> Option<NodeId>,
) {
    let mut orders: BTreeMap<&str, u32> = BTreeMap::new();
    for stop in &compiled.stops {
        let (node, location, evidence) =
            trail(graph, package_of, &stop.path, stop.line, &stop.callers);
        let text = rules::stop_on_outside_input(&stop.path, stop.line);
        let rule = RuleId::StopOnOutsideInput;
        let order = orders.entry(stop.path.as_str()).or_insert(0u32);
        *order += 1;
        graph.add_external(Finding {
            id: format!("{}:{}:{order}", rule.as_str(), file_id(&stop.path)),
            rule,
            severity: Severity::Low,
            confidence: Confidence::Review,
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
    for (divisions, by_hand) in [(&compiled.divisions, false), (&compiled.by_hand, true)] {
        let mut orders: BTreeMap<&str, u32> = BTreeMap::new();
        for division in divisions {
            let (node, location, evidence) = trail(
                graph,
                package_of,
                &division.path,
                division.line,
                &division.callers,
            );
            let (text, kind) = if by_hand {
                (
                    rules::secret_division_in_assembly(&division.path, division.line),
                    ":asm",
                )
            } else {
                (
                    rules::secret_dependent_division(
                        &division.path,
                        division.line,
                        division.confirmed,
                    ),
                    "",
                )
            };
            let rule = RuleId::SecretDependentDivision;
            let order = orders.entry(division.path.as_str()).or_insert(0u32);
            *order += 1;
            graph.add_external(Finding {
                id: format!(
                    "{}:{}{kind}:{order}",
                    rule.as_str(),
                    file_id(&division.path)
                ),
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
            if out.len() >= MAX_FILES {
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
