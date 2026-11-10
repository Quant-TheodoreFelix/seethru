use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

const MAX_LINE_BYTES: usize = 16 * 1024;
const MAX_SPOTS: usize = 65_536;

const DIVIDE: &[&str] = &[
    "sdiv", "udiv", "div", "divu", "rem", "remu", "divw", "divuw", "remw", "remuw", "idiv", "divb",
    "divl", "divq", "idivb", "idivw", "idivl", "idivq", "sdivr", "udivr",
];

const RISCV_VECTOR_DIVIDE: &[&str] = &["vdiv", "vdivu", "vrem", "vremu"];

const DIVIDE_CALLS: &[&str] = &[
    "__udivsi3",
    "__divsi3",
    "__umodsi3",
    "__modsi3",
    "__udivdi3",
    "__divdi3",
    "__umoddi3",
    "__moddi3",
    "__udivti3",
    "__divti3",
    "__umodti3",
    "__modti3",
    "__udivmodsi4",
    "__divmodsi4",
    "__udivmoddi4",
    "__divmoddi4",
    "__aeabi_idiv",
    "__aeabi_uidiv",
    "__aeabi_idivmod",
    "__aeabi_uidivmod",
    "__aeabi_ldivmod",
    "__aeabi_uldivmod",
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Naming {
    #[default]
    Plain,
    Underscored,
}

impl Naming {
    pub(crate) fn of(layout: &str) -> Self {
        let mode = layout
            .trim()
            .trim_matches('"')
            .split('-')
            .find_map(|part| part.strip_prefix("m:"));
        match mode {
            Some("o" | "x") => Self::Underscored,
            _ => Self::Plain,
        }
    }

    fn function(self, label: &str) -> Option<&str> {
        if label.is_empty() || label.starts_with('$') || label.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        match self {
            Self::Plain => (!label.starts_with(".L")).then_some(label),
            Self::Underscored => {
                let numbered = label.strip_prefix("ltmp").is_some_and(|rest| {
                    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
                });
                if label.starts_with('L') || numbered {
                    None
                } else {
                    Some(label.strip_prefix('_').unwrap_or(label))
                }
            }
        }
    }
}

const ARM_CONDITIONS: &[&str] = &[
    "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
];

const RISCV_BRANCHES: &[&str] = &[
    "beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez", "blez", "bgez", "bltz", "bgtz",
    "bgt", "ble", "bgtu", "bleu", "c.beqz", "c.bnez",
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Cpu {
    X86,
    Arm64,
    Arm,
    RiscV,
    #[default]
    Other,
}

impl Cpu {
    pub(crate) fn of(triple: &str) -> Self {
        let arch = triple
            .trim()
            .trim_matches('"')
            .split('-')
            .next()
            .unwrap_or_default();
        let x86_32 = arch.len() == 4 && arch.starts_with('i') && arch.ends_with("86");
        if arch.starts_with("x86_64") || x86_32 {
            Self::X86
        } else if arch.starts_with("aarch64") || arch.starts_with("arm64") {
            Self::Arm64
        } else if arch.starts_with("arm") || arch.starts_with("thumb") {
            Self::Arm
        } else if arch.starts_with("riscv") {
            Self::RiscV
        } else {
            Self::Other
        }
    }

    fn divides(self, word: &str) -> bool {
        let plain = match self {
            Self::Arm => {
                let word = word
                    .strip_suffix(".n")
                    .or_else(|| word.strip_suffix(".w"))
                    .unwrap_or(word);
                ARM_CONDITIONS
                    .iter()
                    .find_map(|condition| word.strip_suffix(condition))
                    .filter(|base| matches!(*base, "udiv" | "sdiv"))
                    .unwrap_or(word)
            }
            Self::RiscV => {
                let vector = word.split_once('.').map_or(word, |(base, _)| base);
                if RISCV_VECTOR_DIVIDE.contains(&vector) {
                    return true;
                }
                word
            }
            _ => word,
        };
        DIVIDE.contains(&plain)
    }

    fn branches(self, word: &str) -> bool {
        match self {
            Self::X86 => {
                (word.starts_with('j') && !word.starts_with("jmp")) || word.starts_with("loop")
            }
            Self::Arm64 => {
                word.starts_with("b.")
                    || word.starts_with("bc.")
                    || matches!(word, "cbz" | "cbnz" | "tbz" | "tbnz")
            }
            Self::Arm => {
                let word = word
                    .strip_suffix(".n")
                    .or_else(|| word.strip_suffix(".w"))
                    .unwrap_or(word);
                matches!(word, "cbz" | "cbnz")
                    || ["blx", "bx", "bl", "b"].iter().any(|prefix| {
                        word.strip_prefix(prefix)
                            .is_some_and(|condition| ARM_CONDITIONS.contains(&condition))
                    })
            }
            Self::RiscV => RISCV_BRANCHES.contains(&word),
            Self::Other => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Spot {
    pub function: Option<Rc<str>>,
    pub place: Option<(Rc<str>, u32)>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Block {
    pub blocks: u32,
    pub divisions: u32,
    pub branches: bool,
}

#[derive(Default)]
pub(crate) struct Listing {
    pub functions: BTreeSet<Rc<str>>,
    pub divisions: BTreeMap<Spot, u32>,
    pub by_hand: BTreeMap<Spot, Block>,
    pub has_lines: bool,
    pub truncated: bool,
    lines: BTreeSet<(Rc<str>, u32)>,
}

impl Listing {
    pub(crate) fn divides(&self, function: Option<&str>, path: &str, line: u32) -> bool {
        let place = (Rc::from(path), line);
        match function {
            None => self.lines.contains(&place),
            Some(function) => self.divisions.contains_key(&Spot {
                function: Some(Rc::from(function)),
                place: Some(place),
            }),
        }
    }

    fn close(&mut self, open: Option<(Spot, Block)>) {
        let Some((spot, block)) = open else { return };
        if self.by_hand.len() >= MAX_SPOTS && !self.by_hand.contains_key(&spot) {
            self.truncated = true;
            return;
        }
        let entry = self.by_hand.entry(spot).or_default();
        entry.blocks = entry.blocks.saturating_add(1);
        entry.divisions = entry.divisions.saturating_add(block.divisions);
        entry.branches |= block.branches;
    }
}

fn marker(line: &str) -> Option<bool> {
    let rest = line.trim_start_matches(['#', '/', ';', '@']);
    if rest.len() == line.len() {
        return None;
    }
    match rest.trim() {
        "APP" | "InlineAsm Start" => Some(true),
        "NO_APP" | "InlineAsm End" => Some(false),
        _ => None,
    }
}

fn label(line: &str, word: &str) -> Option<String> {
    match quoted(line) {
        Some((name, rest)) => rest.starts_with(':').then_some(name),
        None => word.strip_suffix(':').map(str::to_owned),
    }
}

pub(crate) fn parse(text: &str, naming: Naming, cpu: Cpu) -> Listing {
    let mut out = Listing::default();
    let mut files: HashMap<u32, Rc<str>> = HashMap::new();
    let mut at: Option<(u32, u32)> = None;
    let mut function: Option<Rc<str>> = None;
    let mut by_hand: Option<(Spot, Block)> = None;
    for line in text.lines() {
        if line.len() > MAX_LINE_BYTES {
            continue;
        }
        let line = line.trim();
        let spot = |function: &Option<Rc<str>>, at: Option<(u32, u32)>| Spot {
            function: function.clone(),
            place: at.and_then(|(file, line)| Some((files.get(&file)?.clone(), line))),
        };
        match marker(line) {
            Some(true) => {
                match by_hand {
                    None => by_hand = Some((spot(&function, at), Block::default())),
                    Some(_) => out.truncated = true,
                }
                continue;
            }
            Some(false) => {
                out.truncated |= by_hand.is_none();
                out.close(by_hand.take());
                continue;
            }
            None => {}
        }
        if line.is_empty() || line.starts_with(['#', ';', '@']) || line.starts_with("//") {
            continue;
        }
        let (mut word, mut rest) = split(line);
        if let Some(name) = label(line, word) {
            if by_hand.is_none()
                && let Some(name) = naming.function(&name)
            {
                let name: Rc<str> = Rc::from(name);
                out.functions.insert(name.clone());
                function = Some(name);
                at = None;
            }
            if rest.is_empty() || line.starts_with('"') {
                continue;
            }
            (word, rest) = split(rest);
        }
        match word {
            ".file" => {
                let (number, names) = split(rest);
                if let Ok(number) = number.parse::<u32>() {
                    let mut parts = strings(names).into_iter();
                    let path = match (parts.next(), parts.next()) {
                        (Some(directory), Some(name)) if !name.starts_with('/') => {
                            if directory.is_empty() {
                                name
                            } else {
                                format!("{}/{name}", directory.trim_end_matches('/'))
                            }
                        }
                        (_, Some(name)) | (Some(name), None) => name,
                        (None, None) => continue,
                    };
                    files.insert(number, Rc::from(path));
                }
            }
            ".loc" => {
                let mut numbers = rest.split_ascii_whitespace();
                let file = numbers.next().and_then(|n| n.parse::<u32>().ok());
                let line = numbers.next().and_then(|n| n.parse::<u32>().ok());
                at = file.zip(line.filter(|line| *line > 0));
                out.has_lines |= at.is_some();
            }
            _ if word.starts_with('.') => {}
            _ => {
                let word = word.to_ascii_lowercase();
                let divides = cpu.divides(&word)
                    || rest
                        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .map(|name| match naming {
                            Naming::Plain => name,
                            Naming::Underscored => name.strip_prefix('_').unwrap_or(name),
                        })
                        .any(|name| DIVIDE_CALLS.contains(&name));
                if let Some((_, block)) = by_hand.as_mut() {
                    block.divisions = block.divisions.saturating_add(u32::from(divides));
                    block.branches |= cpu.branches(&word);
                } else if divides {
                    let spot = spot(&function, at);
                    if out.divisions.len() >= MAX_SPOTS && !out.divisions.contains_key(&spot) {
                        out.truncated = true;
                    } else {
                        out.lines.extend(spot.place.clone());
                        let count = out.divisions.entry(spot).or_insert(0);
                        *count = count.saturating_add(1);
                    }
                }
            }
        }
    }
    out.truncated |= by_hand.is_some();
    out.close(by_hand.take());
    out
}

fn split(text: &str) -> (&str, &str) {
    let (word, rest) = text
        .split_once(|c: char| c.is_ascii_whitespace())
        .unwrap_or((text, ""));
    (word, rest.trim_start())
}

fn quoted(text: &str) -> Option<(String, &str)> {
    let mut value = String::new();
    let mut chars = text.strip_prefix('"')?.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return Some((value, text.get(at + 2..).unwrap_or_default())),
            '\\' => value.extend(chars.next().map(|(_, c)| c)),
            other => value.push(other),
        }
    }
    None
}

fn strings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text.trim_start();
    while let Some((value, after)) = quoted(rest) {
        out.push(value);
        rest = after.trim_start();
    }
    out
}
