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

#[derive(Default)]
pub(crate) struct Listing {
    pub divisions: BTreeSet<(String, u32)>,
    pub has_lines: bool,
}

pub(crate) fn parse(text: &str) -> Listing {
    let mut out = Listing::default();
    let mut files: HashMap<u32, String> = HashMap::new();
    let mut at: Option<(u32, u32)> = None;
    for line in text.lines() {
        if line.len() > MAX_LINE_BYTES {
            continue;
        }
        let line = line.trim();
        let (word, rest) = line
            .split_once(|c: char| c.is_ascii_whitespace())
            .unwrap_or((line, ""));
        let rest = rest.trim_start();
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
                at = file.zip(line);
                out.has_lines |= at.is_some();
            }
            _ if word.ends_with(':') || word.starts_with('.') || word.is_empty() => {}
            _ => {
                let divides = DIVIDE.contains(&word)
                    || rest
                        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .any(|name| DIVIDE_CALLS.contains(&name));
                if divides
                    && let Some((file, line)) = at
                    && let Some(path) = files.get(&file)
                {
                    out.divisions.insert((path.clone(), line));
                }
            }
        }
    }
    out
}

fn strings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '"' {
            if !c.is_ascii_whitespace() {
                break;
            }
            continue;
        }
        let mut value = String::new();
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => value.extend(chars.next()),
                other => value.push(other),
            }
        }
        out.push(value);
    }
    out
}
