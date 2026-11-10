use std::collections::{BTreeSet, HashMap};

const MAX_LINE_BYTES: usize = 16 * 1024;

const DIVIDE: &[&str] = &[
    "sdiv", "udiv", "div", "divu", "rem", "remu", "divw", "divuw", "remw", "remuw", "idiv", "divb",
    "divl", "divq", "idivb", "idivw", "idivl", "idivq",
];

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Spot {
    pub function: Option<String>,
    pub path: String,
    pub line: u32,
}

#[derive(Default)]
pub(crate) struct Listing {
    pub functions: BTreeSet<String>,
    pub divisions: BTreeSet<Spot>,
    pub has_lines: bool,
}

impl Listing {
    pub(crate) fn divides(&self, function: Option<&str>, path: &str, line: u32) -> bool {
        self.divisions.iter().any(|spot| {
            spot.path == path
                && spot.line == line
                && function.is_none_or(|function| spot.function.as_deref() == Some(function))
        })
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

pub(crate) fn parse(text: &str, naming: Naming) -> Listing {
    let mut out = Listing::default();
    let mut files: HashMap<u32, String> = HashMap::new();
    let mut at: Option<(u32, u32)> = None;
    let mut function: Option<String> = None;
    let mut by_hand = false;
    for line in text.lines() {
        if line.len() > MAX_LINE_BYTES {
            continue;
        }
        let line = line.trim();
        if let Some(starts) = marker(line) {
            by_hand = starts;
            continue;
        }
        if line.is_empty() || line.starts_with(['#', ';', '@']) || line.starts_with("//") {
            continue;
        }
        let (word, rest) = line
            .split_once(|c: char| c.is_ascii_whitespace())
            .unwrap_or((line, ""));
        let rest = rest.trim_start();
        if let Some(name) = label(line, word) {
            if !by_hand && let Some(name) = naming.function(&name) {
                out.functions.insert(name.to_owned());
                function = Some(name.to_owned());
                at = None;
            }
            continue;
        }
        match word {
            ".file" => {
                let (number, names) = rest
                    .split_once(|c: char| c.is_ascii_whitespace())
                    .unwrap_or((rest, ""));
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
                    files.insert(number, path);
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
                let divides = DIVIDE.contains(&word)
                    || rest
                        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .any(|name| DIVIDE_CALLS.contains(&name));
                if divides
                    && let Some((file, line)) = at
                    && let Some(path) = files.get(&file)
                {
                    out.divisions.insert(Spot {
                        function: function.clone(),
                        path: path.clone(),
                        line,
                    });
                }
            }
        }
    }
    out
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
