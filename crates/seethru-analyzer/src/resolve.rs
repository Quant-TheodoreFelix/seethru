use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

const SCRIPT_EXTENSIONS: [&str; 8] = ["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"];
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_EXTENDS_DEPTH: usize = 5;
const MAX_PATH_RULES: usize = 256;
const MAX_TARGETS: usize = 16;
const ALIAS_SHORTHANDS: [&str; 2] = ["@/", "~/"];

pub(crate) struct ConfigText {
    pub rel_path: String,
    pub text: String,
}

#[derive(Default)]
struct Aliases {
    base_url: Option<String>,
    paths: Vec<(String, Vec<String>)>,
}

struct Package {
    name: String,
    dir: String,
    main: Option<String>,
}

pub(crate) struct Resolver<'a> {
    files: &'a BTreeSet<String>,
    roots: Vec<String>,
    aliases: BTreeMap<String, Aliases>,
    packages: Vec<Package>,
}

impl<'a> Resolver<'a> {
    pub(crate) fn new(
        files: &'a BTreeSet<String>,
        roots: Vec<String>,
        configs: &[ConfigText],
    ) -> Self {
        let parsed: BTreeMap<&str, Value> = configs
            .iter()
            .filter(|config| config.text.len() <= MAX_CONFIG_BYTES)
            .filter_map(|config| Some((config.rel_path.as_str(), parse_jsonc(&config.text)?)))
            .collect();

        let mut aliases: BTreeMap<String, Aliases> = BTreeMap::new();
        let mut packages = Vec::new();
        for (rel_path, value) in &parsed {
            let (dir, name) = split_dir(rel_path);
            if name == "package.json" {
                if let Some(package_name) = value.get("name").and_then(Value::as_str) {
                    let main = ["module", "main", "source"]
                        .iter()
                        .find_map(|field| value.get(*field).and_then(Value::as_str))
                        .and_then(|main| join(dir, main));
                    packages.push(Package {
                        name: package_name.to_owned(),
                        dir: dir.to_owned(),
                        main,
                    });
                }
            } else if is_ts_config(name) {
                let found = compiler_aliases(&parsed, rel_path, 0);
                let entry = aliases.entry(dir.to_owned()).or_default();
                if entry.base_url.is_none() {
                    entry.base_url = found.base_url;
                }
                for rule in found.paths {
                    if entry.paths.len() < MAX_PATH_RULES && !entry.paths.contains(&rule) {
                        entry.paths.push(rule);
                    }
                }
            }
        }
        aliases.retain(|_, found| found.base_url.is_some() || !found.paths.is_empty());
        packages.sort_by(|a, b| b.name.len().cmp(&a.name.len()).then(a.name.cmp(&b.name)));
        Self {
            files,
            roots,
            aliases,
            packages,
        }
    }

    pub(crate) fn resolve(&self, from: &str, specifier: &str) -> Option<String> {
        let (dir, _) = split_dir(from);
        if specifier.starts_with("./")
            || specifier.starts_with("../")
            || specifier == "."
            || specifier == ".."
        {
            return self.probe(&join(dir, specifier)?);
        }
        if specifier.starts_with('/') || specifier.contains(':') {
            return None;
        }
        if let Some(found) = self.through_aliases(from, specifier) {
            return Some(found);
        }
        if let Some(found) = self.through_shorthand(from, specifier) {
            return Some(found);
        }
        self.through_packages(specifier)
    }

    pub(crate) fn points_into_project(&self, from: &str, specifier: &str) -> bool {
        if specifier.starts_with('.') || specifier.starts_with('/') {
            return true;
        }
        if ALIAS_SHORTHANDS
            .iter()
            .any(|prefix| specifier.starts_with(prefix))
        {
            return true;
        }
        if self.packages.iter().any(|package| {
            specifier == package.name || specifier.starts_with(&format!("{}/", package.name))
        }) {
            return true;
        }
        ancestors(from)
            .find_map(|dir| self.aliases.get(dir))
            .is_some_and(|aliases| {
                aliases
                    .paths
                    .iter()
                    .any(|(pattern, _)| pattern_match(pattern, specifier).is_some())
            })
    }

    fn through_aliases(&self, from: &str, specifier: &str) -> Option<String> {
        let aliases = ancestors(from).find_map(|dir| self.aliases.get(dir))?;
        let mut rules: Vec<(&String, &Vec<String>, usize)> = aliases
            .paths
            .iter()
            .filter_map(|(pattern, targets)| {
                pattern_match(pattern, specifier).map(|_| (pattern, targets, pattern.len()))
            })
            .collect();
        rules.sort_by_key(|rule| std::cmp::Reverse(rule.2));
        for (pattern, targets, _) in rules {
            let Some(star) = pattern_match(pattern, specifier) else {
                continue;
            };
            for target in targets.iter().take(MAX_TARGETS) {
                if let Some(found) = self.probe(&target.replacen('*', star, 1)) {
                    return Some(found);
                }
            }
        }
        let base = aliases.base_url.as_deref()?;
        self.probe(&join(base, specifier)?)
    }

    fn through_shorthand(&self, from: &str, specifier: &str) -> Option<String> {
        let rest = ALIAS_SHORTHANDS
            .iter()
            .find_map(|prefix| specifier.strip_prefix(prefix))?;
        let root = self
            .roots
            .iter()
            .filter(|root| root.is_empty() || from.starts_with(&format!("{root}/")))
            .max_by_key(|root| root.len())?;
        [format!("src/{rest}"), rest.to_owned()]
            .iter()
            .find_map(|inner| self.probe(&join(root, inner)?))
    }

    fn through_packages(&self, specifier: &str) -> Option<String> {
        let package = self.packages.iter().find(|package| {
            specifier == package.name || specifier.starts_with(&format!("{}/", package.name))
        })?;
        let sub = specifier[package.name.len()..].trim_start_matches('/');
        if sub.is_empty() {
            let mut candidates: Vec<String> = package.main.iter().cloned().collect();
            candidates.extend(join(&package.dir, "src/index"));
            candidates.extend(join(&package.dir, "index"));
            return candidates
                .iter()
                .find_map(|candidate| self.probe(candidate));
        }
        [
            join(&package.dir, sub),
            join(&package.dir, &format!("src/{sub}")),
        ]
        .into_iter()
        .flatten()
        .find_map(|candidate| self.probe(&candidate))
    }

    fn probe(&self, candidate: &str) -> Option<String> {
        let candidate = normalize(candidate)?;
        if self.files.contains(&candidate) {
            return Some(candidate);
        }
        let swaps: &[(&str, &[&str])] = &[
            (".js", &["ts", "tsx"]),
            (".jsx", &["tsx"]),
            (".mjs", &["mts"]),
            (".cjs", &["cts"]),
        ];
        for (from, to) in swaps {
            if let Some(stem) = candidate.strip_suffix(from) {
                for ext in *to {
                    let swapped = format!("{stem}.{ext}");
                    if self.files.contains(&swapped) {
                        return Some(swapped);
                    }
                }
            }
        }
        SCRIPT_EXTENSIONS
            .iter()
            .map(|ext| format!("{candidate}.{ext}"))
            .chain(
                SCRIPT_EXTENSIONS
                    .iter()
                    .map(|ext| format!("{candidate}/index.{ext}")),
            )
            .find(|path| self.files.contains(path))
    }
}

fn compiler_aliases(parsed: &BTreeMap<&str, Value>, rel_path: &str, depth: usize) -> Aliases {
    let Some(value) = parsed.get(rel_path) else {
        return Aliases::default();
    };
    let (dir, _) = split_dir(rel_path);
    let mut found = Aliases::default();
    if depth < MAX_EXTENDS_DEPTH {
        let parents: Vec<&str> = match value.get("extends") {
            Some(Value::String(parent)) => vec![parent.as_str()],
            Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        for parent in parents {
            if !(parent.starts_with("./") || parent.starts_with("../")) {
                continue;
            }
            let Some(mut parent_path) = join(dir, parent) else {
                continue;
            };
            if !parent_path.ends_with(".json") {
                parent_path.push_str(".json");
            }
            let inherited = compiler_aliases(parsed, &parent_path, depth + 1);
            if inherited.base_url.is_some() {
                found.base_url = inherited.base_url;
            }
            if !inherited.paths.is_empty() {
                found.paths = inherited.paths;
            }
        }
    }
    let options = value.get("compilerOptions");
    let own_base = options
        .and_then(|options| options.get("baseUrl"))
        .and_then(Value::as_str)
        .and_then(|base| join(dir, base));
    if own_base.is_some() {
        found.base_url = own_base;
    }
    if let Some(Value::Object(paths)) = options.and_then(|options| options.get("paths")) {
        let anchor = found.base_url.clone().unwrap_or_else(|| dir.to_owned());
        found.paths = paths
            .iter()
            .take(MAX_PATH_RULES)
            .filter(|(pattern, _)| pattern.matches('*').count() <= 1)
            .map(|(pattern, targets)| {
                let targets = match targets {
                    Value::Array(list) => list
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|target| target.matches('*').count() <= 1)
                        .take(MAX_TARGETS)
                        .filter_map(|target| join(&anchor, target))
                        .collect(),
                    _ => Vec::new(),
                };
                (pattern.clone(), targets)
            })
            .collect();
    }
    found
}

fn pattern_match<'s>(pattern: &str, specifier: &'s str) -> Option<&'s str> {
    match pattern.split_once('*') {
        Some((prefix, suffix)) => specifier
            .strip_prefix(prefix)?
            .strip_suffix(suffix)
            .filter(|_| specifier.len() >= prefix.len() + suffix.len()),
        None => (pattern == specifier).then_some(""),
    }
}

fn is_ts_config(name: &str) -> bool {
    (name.starts_with("tsconfig") || name.starts_with("jsconfig")) && name.ends_with(".json")
}

fn ancestors(rel_path: &str) -> impl Iterator<Item = &str> {
    let mut current = Some(split_dir(rel_path).0);
    std::iter::from_fn(move || {
        let dir = current?;
        current = if dir.is_empty() {
            None
        } else {
            Some(split_dir(dir).0)
        };
        Some(dir)
    })
}

fn split_dir(rel_path: &str) -> (&str, &str) {
    rel_path.rsplit_once('/').unwrap_or(("", rel_path))
}

fn join(dir: &str, path: &str) -> Option<String> {
    if path.starts_with('/') || path.contains('\\') || path.contains('\0') {
        return None;
    }
    if dir.is_empty() {
        normalize(path)
    } else {
        normalize(&format!("{dir}/{path}"))
    }
}

fn normalize(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    Some(parts.join("/"))
}

pub(crate) fn parse_jsonc(text: &str) -> Option<Value> {
    if text.len() > MAX_CONFIG_BYTES {
        return None;
    }
    serde_json::from_str(&drop_trailing_commas(&strip_comments(text))).ok()
}

fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            match c {
                '\\' => out.extend(chars.next()),
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match (c, chars.peek()) {
            ('/', Some('/')) => {
                if chars.by_ref().any(|skipped| skipped == '\n') {
                    out.push('\n');
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut previous = ' ';
                for skipped in chars.by_ref() {
                    if previous == '*' && skipped == '/' {
                        break;
                    }
                    previous = skipped;
                }
                out.push(' ');
            }
            _ => {
                in_string = c == '"';
                out.push(c);
            }
        }
    }
    out
}

fn drop_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut index = 0;
    while let Some(&c) = chars.get(index) {
        index += 1;
        if in_string {
            out.push(c);
            match c {
                '\\' => {
                    out.extend(chars.get(index));
                    index += 1;
                }
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        if c == ',' {
            let next = chars[index..].iter().find(|c| !c.is_whitespace());
            if matches!(next, Some('}' | ']')) {
                continue;
            }
        }
        in_string = c == '"';
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests;
