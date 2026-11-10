mod wipes;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Component, Path, PathBuf};

use seethru_core::{
    Basis, BinaryFormat, Confidence, EdgeKind, Finding, Input, LimitationCode, Location, NodeId,
    Origin, RuleId, Severity, ToolUse,
};

use crate::classify::FileRole;
use crate::graph::{Graph, file_id, file_step};
use crate::rules;
use crate::walk::SKIPPED_DIRS;

pub(crate) use wipes::{Wipe, find as find_wipes};

const MAX_PATHS: usize = 100_000;
const MAX_LINES: usize = 2_000_000;
const MAX_PATH_BYTES: usize = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BinaryCode {
    rows: BTreeSet<(String, u32)>,
    calls: BTreeSet<(String, u32)>,
    instructions: u64,
    marked: u64,
    units: u64,
}

impl BinaryCode {
    pub fn problem(&self) -> Option<LimitationCode> {
        if self.instructions == 0 || (self.marked > 0 && self.units == 0) {
            Some(LimitationCode::BinaryToolFailed)
        } else if self.marked == 0 || (self.rows.is_empty() && self.calls.is_empty()) {
            Some(LimitationCode::BinaryWithoutLineInfo)
        } else {
            None
        }
    }

    fn lines(&self) -> u32 {
        let all: BTreeSet<&(String, u32)> = self.rows.iter().chain(&self.calls).collect();
        u32::try_from(all.len()).unwrap_or(u32::MAX)
    }

    fn has(&self, path: &str, lines: (u32, u32)) -> bool {
        let range = (path.to_owned(), lines.0)..=(path.to_owned(), lines.1);
        self.rows.range(range.clone()).next().is_some() || self.calls.range(range).next().is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryInput {
    pub path: PathBuf,
    pub format: BinaryFormat,
    pub tools: Vec<ToolUse>,
    pub code: BinaryCode,
}

#[derive(Default)]
struct Inlined {
    open: bool,
    file: Option<String>,
    line: Option<u32>,
    has_code: bool,
}

pub struct CodeReader {
    root: PathBuf,
    seen: HashMap<String, Option<String>>,
    current: Option<(String, u32)>,
    marker: bool,
    inlined: Inlined,
    code: BinaryCode,
}

impl CodeReader {
    pub fn new(root: &Path) -> std::io::Result<Self> {
        Ok(Self {
            root: fs::canonicalize(root)?,
            seen: HashMap::new(),
            current: None,
            marker: false,
            inlined: Inlined::default(),
            code: BinaryCode::default(),
        })
    }

    pub fn disassembly(&mut self, line: &str) {
        let text = line.trim();
        if text.is_empty() {
            return;
        }
        if is_instruction(text) {
            self.code.instructions = self.code.instructions.saturating_add(1);
            if self.marker {
                self.code.marked = self.code.marked.saturating_add(1);
            }
            if let Some(at) = &self.current
                && self.code.rows.len() < MAX_LINES
            {
                self.code.rows.insert(at.clone());
            }
        } else if text.ends_with(">:") {
            self.marker = false;
            self.current = None;
        } else if let Some((path, number)) = marker(text) {
            self.marker = true;
            self.current = self.resolve(path).map(|path| (path, number));
        }
    }

    pub fn debug_info(&mut self, line: &str) {
        let text = line.trim();
        if text.is_empty() {
            self.flush();
            return;
        }
        if let Some(at) = text.find("DW_TAG_") {
            self.flush();
            let tag = &text[at..];
            if tag == "DW_TAG_compile_unit" {
                self.code.units = self.code.units.saturating_add(1);
            }
            self.inlined.open = tag == "DW_TAG_inlined_subroutine";
            return;
        }
        if !self.inlined.open {
            return;
        }
        if let Some(rest) = text.strip_prefix("DW_AT_call_file") {
            self.inlined.file = between(rest, "(\"", "\")").map(str::to_owned);
        } else if let Some(rest) = text.strip_prefix("DW_AT_call_line") {
            self.inlined.line = between(rest, "(", ")").and_then(|value| value.parse().ok());
        } else if let Some(rest) = text.strip_prefix("DW_AT_low_pc") {
            let address = between(rest, "(0x", ")")
                .and_then(|value| u64::from_str_radix(value, 16).ok())
                .unwrap_or(0);
            self.inlined.has_code |= address != 0 && address != u64::MAX;
        } else if text.starts_with("DW_AT_ranges") {
            self.inlined.has_code = true;
        }
    }

    pub fn finish(mut self) -> BinaryCode {
        self.flush();
        self.code
    }

    fn flush(&mut self) {
        let inlined = std::mem::take(&mut self.inlined);
        if !inlined.open || !inlined.has_code {
            return;
        }
        if let (Some(file), Some(line)) = (inlined.file, inlined.line)
            && line > 0
            && let Some(path) = self.resolve(&file)
            && self.code.calls.len() < MAX_LINES
        {
            self.code.calls.insert((path, line));
        }
    }

    fn resolve(&mut self, raw: &str) -> Option<String> {
        if let Some(known) = self.seen.get(raw) {
            return known.clone();
        }
        let found = project_path(&self.root, raw);
        if self.seen.len() < MAX_PATHS {
            self.seen.insert(raw.to_owned(), found.clone());
        }
        found
    }
}

fn between<'a>(text: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = text.find(open)? + open.len();
    let end = text.rfind(close)?;
    text.get(start..end)
}

fn is_instruction(text: &str) -> bool {
    text.split_once(':').is_some_and(|(address, rest)| {
        !address.is_empty()
            && address.bytes().all(|byte| byte.is_ascii_hexdigit())
            && rest.starts_with([' ', '\t'])
            && !rest.trim().is_empty()
    })
}

fn marker(text: &str) -> Option<(&str, u32)> {
    let text = text.strip_prefix("; ").unwrap_or(text);
    let text = text.find(" (discriminator").map_or(text, |at| &text[..at]);
    let (path, number) = text.rsplit_once(':')?;
    let number: u32 = number.parse().ok()?;
    (number > 0 && !path.is_empty() && !path.ends_with(')')).then_some((path, number))
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
    if raw.len() > MAX_PATH_BYTES || raw.chars().any(char::is_control) {
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
    if !lexical.is_absolute() {
        return None;
    }
    let real = fs::canonicalize(&lexical).ok()?;
    let rel = relative(root, &real)?;
    let skipped = rel.split('/').any(|part| SKIPPED_DIRS.contains(&part));
    (real.is_file() && !skipped).then_some(rel)
}

fn shown(root: &Path, given: &Path) -> String {
    fs::canonicalize(given)
        .ok()
        .and_then(|real| relative(root, &real))
        .or_else(|| {
            given
                .file_name()
                .and_then(|name| name.to_str())
                .map(rules::display_name)
        })
        .unwrap_or_else(|| "program".to_owned())
}

pub(crate) struct Source {
    pub(crate) path: String,
    pub(crate) wipes: Vec<Wipe>,
}

pub(crate) struct Checked {
    pub(crate) inputs: Vec<Input>,
    pub(crate) limitations: Vec<LimitationCode>,
}

struct Missing {
    line: u32,
    order: u32,
    sure: bool,
    programs: Vec<String>,
}

pub(crate) fn emit(
    root: &Path,
    binaries: &[BinaryInput],
    problems: &[LimitationCode],
    sources: &[Source],
    graph: &mut Graph,
    package_of: &dyn Fn(&str) -> Option<NodeId>,
) -> Checked {
    let mut inputs = Vec::new();
    let mut limitations: Vec<LimitationCode> = problems.to_vec();
    let mut missing: BTreeMap<(&str, u32), Missing> = BTreeMap::new();
    let mut tools: BTreeSet<String> = BTreeSet::new();
    for binary in binaries {
        if let Some(problem) = binary.code.problem() {
            limitations.push(problem);
            continue;
        }
        let label = shown(root, &binary.path);
        inputs.push(Input::Binary {
            path: label.clone(),
            format: binary.format,
            tools: binary.tools.clone(),
            lines: binary.code.lines(),
        });
        limitations.push(LimitationCode::BinaryChecksPartial);
        let mut located = 0usize;
        let mut kept_missing = 0usize;
        let mut gone = Vec::new();
        for source in sources {
            let mut order = 0u32;
            for wipe in &source.wipes {
                if !wipe.kept {
                    order += 1;
                }
                if !binary.code.has(&source.path, wipe.function) {
                    continue;
                }
                if binary.code.has(&source.path, wipe.region) {
                    located += 1;
                } else if wipe.kept {
                    kept_missing += 1;
                } else {
                    gone.push((source.path.as_str(), wipe.line, order));
                }
            }
        }
        if gone.is_empty() {
            continue;
        }
        if located == 0 {
            limitations.push(LimitationCode::BinaryWipesNotConfirmed);
            continue;
        }
        tools.extend(binary.tools.iter().map(|tool| tool.name.clone()));
        for (path, line, order) in gone {
            let entry = missing.entry((path, line)).or_insert(Missing {
                line,
                order,
                sure: true,
                programs: Vec::new(),
            });
            entry.sure &= kept_missing == 0;
            entry.programs.push(label.clone());
        }
    }
    for ((path, _), found) in missing {
        let node = graph.add_file(path, FileRole::NativeCode, Basis::Path);
        if let Some(package) = package_of(path) {
            graph.add_edge(package, node.clone(), EdgeKind::Contains);
        }
        let location = Location {
            path: path.to_owned(),
            line: found.line,
            column: 1,
        };
        let text = rules::memory_wipe_removed(path, found.line, &found.programs, found.sure);
        let rule = RuleId::MemoryWipeRemoved;
        graph.add_external(Finding {
            id: format!("{}:{}:{}", rule.as_str(), file_id(path), found.order),
            rule,
            severity: Severity::Low,
            confidence: if found.sure {
                Confidence::Likely
            } else {
                Confidence::Review
            },
            title: text.title,
            explanation: text.explanation,
            node,
            location: Some(location.clone()),
            evidence: vec![file_step(path, None, location)],
            origin: Origin::seethru_with_binary(tools.iter().cloned().collect()),
            cwe: rule.cwe().to_vec(),
            proof: None,
            fix_prompt: None,
            accepted: None,
        });
    }
    let mut unique = Vec::new();
    for code in limitations {
        if !unique.contains(&code) {
            unique.push(code);
        }
    }
    Checked {
        inputs,
        limitations: unique,
    }
}
