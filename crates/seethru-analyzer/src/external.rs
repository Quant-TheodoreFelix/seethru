use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};

use seethru_core::{Basis, Confidence, Finding, Input, InputKind, Origin, RuleId, Severity};
use serde::Deserialize;
use serde::de::{DeserializeOwned, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::ScanError;
use crate::classify::FileRole;
use crate::graph::{Graph, file_id, file_step};
use crate::walk::SKIPPED_DIRS;

pub(crate) const MAX_FILES: usize = 8;
const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_RUNS: usize = 8;
const MAX_LIST: usize = 20_000;
const MAX_KEPT: usize = 5_000;
const MAX_NEW_FILES: usize = 500;
const MAX_RULE_CHARS: usize = 200;
const MAX_ENGINE_CHARS: usize = 32;
const MAX_URI_BYTES: usize = 4096;
const MAX_BASE_DEPTH: usize = 4;
const MAX_CWE: usize = 8;
const MAX_NAME_CHARS: usize = 120;

struct Lenient<T>(Option<T>);

impl<T> Default for Lenient<T> {
    fn default() -> Self {
        Self(None)
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Lenient<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Ok(Self(serde_json::from_value(value).ok()))
    }
}

struct List<T> {
    items: Vec<T>,
    lost: u32,
}

impl<T> Default for List<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            lost: 0,
        }
    }
}

struct ListVisitor<T>(PhantomData<T>);

impl<'de, T: DeserializeOwned> Visitor<'de> for ListVisitor<T> {
    type Value = List<T>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any value")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut list = List::default();
        loop {
            if list.items.len() >= MAX_LIST {
                if seq.next_element::<IgnoredAny>()?.is_none() {
                    break;
                }
                list.lost = list.lost.saturating_add(1);
                continue;
            }
            match seq.next_element::<Lenient<T>>()? {
                None => break,
                Some(Lenient(Some(item))) => list.items.push(item),
                Some(Lenient(None)) => list.lost = list.lost.saturating_add(1),
            }
        }
        Ok(list)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(List::default())
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(List::default())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(List::default())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(List::default())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(List::default())
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(List::default())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(List::default())
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for List<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ListVisitor(PhantomData))
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Log {
    version: Lenient<String>,
    runs: List<Run>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Run {
    tool: Lenient<Tool>,
    results: List<Reported>,
    original_uri_base_ids: Lenient<BTreeMap<String, Lenient<ArtifactLocation>>>,
    artifacts: List<Artifact>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Tool {
    driver: Lenient<Driver>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Driver {
    name: Lenient<String>,
    rules: List<Rule>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Rule {
    id: Lenient<String>,
    default_configuration: Lenient<Configuration>,
    properties: Lenient<Properties>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Configuration {
    level: Lenient<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Properties {
    tags: List<String>,
    #[serde(rename = "security-severity")]
    security_severity: Value,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Reported {
    rule_id: Lenient<String>,
    rule: Lenient<RuleRef>,
    rule_index: Lenient<i64>,
    level: Lenient<String>,
    kind: Lenient<String>,
    suppressions: List<IgnoredAny>,
    locations: List<Place>,
    properties: Lenient<Properties>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RuleRef {
    id: Lenient<String>,
    index: Lenient<i64>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Place {
    physical_location: Lenient<Physical>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Physical {
    artifact_location: Lenient<ArtifactLocation>,
    region: Lenient<Region>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct ArtifactLocation {
    uri: Lenient<String>,
    uri_base_id: Lenient<String>,
    index: Lenient<i64>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Region {
    start_line: Lenient<u32>,
    start_column: Lenient<u32>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Artifact {
    location: Lenient<ArtifactLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Item {
    pub engine: String,
    pub rule: String,
    pub path: String,
    pub line: u32,
    pub column: u32,
    pub severity: Severity,
    pub cwe: Vec<u32>,
}

#[derive(Default)]
pub(crate) struct Imported {
    pub items: Vec<Item>,
    pub inputs: Vec<Input>,
    pub dropped: bool,
}

pub(crate) fn read_all(
    root: &Path,
    given: &Path,
    files: &[PathBuf],
    excluded: &dyn Fn(&str) -> bool,
) -> Result<Imported, ScanError> {
    let mut imported = Imported::default();
    if files.len() > MAX_FILES {
        return Err(ScanError::Sarif(format!(
            "at most {MAX_FILES} files can be given"
        )));
    }
    let mut seen = BTreeSet::new();
    for file in files {
        let fail = |reason: &str| ScanError::Sarif(format!("{} {reason}", file.display()));
        let text = read_file(file).map_err(fail)?;
        let log: Log = serde_json::from_str(&text).map_err(|_| fail("is not valid JSON"))?;
        if log.version.0.as_deref() != Some("2.1.0") {
            return Err(fail("is not a SARIF 2.1.0 file"));
        }
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| {
                name.chars()
                    .filter(|c| !c.is_control() && *c != '`')
                    .take(MAX_NAME_CHARS)
                    .collect::<String>()
            })
            .unwrap_or_default();
        let mut counts: BTreeMap<String, (u32, u32)> = BTreeMap::new();
        let mut lost = log.runs.lost;
        for run in log.runs.items.into_iter().take(MAX_RUNS) {
            let engine = engine_of(&run);
            let slot = counts.entry(engine.clone()).or_default();
            slot.1 = slot.1.saturating_add(run.results.lost);
            let rules = run
                .tool
                .0
                .and_then(|tool| tool.driver.0)
                .map(|driver| driver.rules.items)
                .unwrap_or_default();
            let bases = run.original_uri_base_ids.0.unwrap_or_default();
            let roots = claimed_roots(&[root, given], &bases);
            for reported in run.results.items {
                if reported
                    .kind
                    .0
                    .as_deref()
                    .is_some_and(|kind| kind != "fail")
                    || !reported.suppressions.items.is_empty()
                    || reported.suppressions.lost > 0
                {
                    continue;
                }
                let item = item_of(
                    &reported,
                    &engine,
                    &rules,
                    &run.artifacts.items,
                    &bases,
                    &roots,
                )
                .and_then(|mut item| {
                    item.path = inside(root, &item.path, excluded)?;
                    Some(item)
                });
                match item {
                    Some(item) if imported.items.len() < MAX_KEPT => {
                        let key = (
                            item.engine.clone(),
                            item.rule.clone(),
                            item.path.clone(),
                            item.line,
                            item.column,
                        );
                        if seen.insert(key) {
                            slot.0 = slot.0.saturating_add(1);
                            imported.items.push(item);
                        }
                    }
                    _ => slot.1 = slot.1.saturating_add(1),
                }
            }
        }
        if counts.is_empty() {
            counts.insert("unknown".to_owned(), (0, 0));
        }
        for (engine, (results, dropped)) in counts {
            let dropped = dropped.saturating_add(std::mem::take(&mut lost));
            imported.dropped |= dropped > 0;
            imported.inputs.push(Input::Sarif {
                path: name.clone(),
                engine,
                results,
                dropped,
            });
        }
    }
    imported.items.sort();
    Ok(imported)
}

fn read_file(path: &Path) -> Result<String, &'static str> {
    let meta = fs::symlink_metadata(path).map_err(|_| "cannot be read")?;
    if meta.file_type().is_symlink() {
        return Err("is a symbolic link");
    }
    if !meta.file_type().is_file() {
        return Err("is not a regular file");
    }
    if meta.len() > MAX_BYTES {
        return Err("is larger than 32 MB");
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "cannot be read")?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot be read")?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("is larger than 32 MB");
    }
    String::from_utf8(bytes).map_err(|_| "is not UTF-8 text")
}

fn engine_of(run: &Run) -> String {
    let name = run
        .tool
        .0
        .as_ref()
        .and_then(|tool| tool.driver.0.as_ref())
        .and_then(|driver| driver.name.0.as_deref())
        .unwrap_or_default();
    engine_slug(name)
}

pub(crate) fn engine_slug(name: &str) -> String {
    let mut slug = String::new();
    for c in name.chars().take(MAX_ENGINE_CHARS * 2) {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    let slug: String = slug
        .trim_end_matches('-')
        .chars()
        .take(MAX_ENGINE_CHARS)
        .collect();
    let slug = slug.trim_end_matches('-');
    for known in ["semgrep", "codeql", "joern", "cppcheck"] {
        if slug.starts_with(known) {
            return known.to_owned();
        }
    }
    match slug {
        "" => "unknown".to_owned(),
        "seethru" => "external-seethru".to_owned(),
        "gnu-c" | "gnu-c17" | "gnu-c-17" | "gcc" | "gnu-c23" => "gcc".to_owned(),
        _ if slug.starts_with("gnu-c") => "gcc".to_owned(),
        _ if slug.starts_with("clang") => "clang".to_owned(),
        _ => slug.to_owned(),
    }
}

fn rule_name(raw: &str) -> Option<String> {
    let name: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let fits = !name.is_empty() && raw.chars().count() <= MAX_RULE_CHARS;
    (fits && crate::secrets::find(raw).is_empty()).then_some(name)
}

fn item_of(
    reported: &Reported,
    engine: &str,
    rules: &[Rule],
    artifacts: &[Artifact],
    bases: &BTreeMap<String, Lenient<ArtifactLocation>>,
    roots: &[String],
) -> Option<Item> {
    let reference = reported.rule.0.as_ref();
    let index = reported
        .rule_index
        .0
        .or_else(|| reference.and_then(|rule| rule.index.0))
        .and_then(|index| usize::try_from(index).ok());
    let id = reported
        .rule_id
        .0
        .as_deref()
        .or_else(|| reference.and_then(|rule| rule.id.0.as_deref()));
    let rule = index
        .and_then(|index| rules.get(index))
        .filter(|rule| id.is_none() || rule.id.0.as_deref() == id)
        .or_else(|| {
            rules
                .iter()
                .find(|rule| id.is_some() && rule.id.0.as_deref() == id)
        });
    let id = id.or_else(|| rule.and_then(|rule| rule.id.0.as_deref()))?;
    let name = rule_name(id)?;

    let place = reported
        .locations
        .items
        .first()?
        .physical_location
        .0
        .as_ref()?;
    let direct = place.artifact_location.0.as_ref()?;
    let location = match direct.uri.0 {
        Some(_) => direct,
        None => {
            let index = usize::try_from(direct.index.0?).ok()?;
            artifacts.get(index)?.location.0.as_ref()?
        }
    };
    let path = resolve(
        location.uri.0.as_deref()?,
        location.uri_base_id.0.as_deref(),
        bases,
        roots,
    )?;
    let region = place.region.0.as_ref();
    let line = region
        .and_then(|region| region.start_line.0)
        .unwrap_or(1)
        .max(1);
    let column = region
        .and_then(|region| region.start_column.0)
        .unwrap_or(1)
        .max(1);

    let own = reported.properties.0.as_ref();
    let shared = rule.and_then(|rule| rule.properties.0.as_ref());
    let score = own
        .and_then(|properties| score_of(&properties.security_severity))
        .or_else(|| shared.and_then(|properties| score_of(&properties.security_severity)));
    let level = reported.level.0.as_deref().or_else(|| {
        rule.and_then(|rule| rule.default_configuration.0.as_ref())
            .and_then(|configuration| configuration.level.0.as_deref())
    });
    let mut cwe = Vec::new();
    for properties in [own, shared].into_iter().flatten() {
        for tag in &properties.tags.items {
            if let Some(number) = cwe_of(tag)
                && !cwe.contains(&number)
                && cwe.len() < MAX_CWE
            {
                cwe.push(number);
            }
        }
    }
    cwe.sort_unstable();
    Some(Item {
        engine: engine.to_owned(),
        rule: name,
        path,
        line,
        column,
        severity: severity_of(score, level),
        cwe,
    })
}

fn score_of(value: &Value) -> Option<f64> {
    let score = match value {
        Value::Number(number) => number.as_f64()?,
        Value::String(text) if text.len() <= 8 => text.trim().parse().ok()?,
        _ => return None,
    };
    (score.is_finite() && (0.0..=10.0).contains(&score)).then_some(score)
}

fn severity_of(score: Option<f64>, level: Option<&str>) -> Severity {
    match score {
        Some(score) if score >= 7.0 => Severity::High,
        Some(score) if score >= 4.0 => Severity::Medium,
        Some(score) if score > 0.0 => Severity::Low,
        Some(_) => Severity::Info,
        None => match level {
            Some("error") => Severity::Medium,
            Some("warning") | None => Severity::Low,
            Some(_) => Severity::Info,
        },
    }
}

fn cwe_of(tag: &str) -> Option<u32> {
    if tag.len() > 200 {
        return None;
    }
    let lower = tag.to_ascii_lowercase();
    let start = lower.rfind("cwe-")? + 4;
    let digits: String = lower[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .take(6)
        .collect();
    let number: u32 = digits.parse().ok()?;
    (1..=99_999).contains(&number).then_some(number)
}

fn is_clean(text: &str) -> bool {
    text.len() <= MAX_URI_BYTES
        && !text.chars().any(|c| {
            c.is_control()
                || c == '\\'
                || matches!(
                    c,
                    '\u{200B}'..='\u{200F}'
                        | '\u{2028}'..='\u{202E}'
                        | '\u{2060}'..='\u{2069}'
                        | '\u{FEFF}'
                        | '\u{E0000}'..='\u{E007F}'
                )
        })
}

fn has_scheme(text: &str) -> bool {
    let Some((scheme, _)) = text.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

fn decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let pair = text.get(index + 1..index + 3)?;
            out.push(u8::from_str_radix(pair, 16).ok()?);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8(out).ok().filter(|text| is_clean(text))
}

fn local_path(uri: &str) -> Option<String> {
    if !is_clean(uri) {
        return None;
    }
    let end = uri.find(['#', '?']).unwrap_or(uri.len());
    let uri = &uri[..end];
    let rest = if let Some(rest) = uri.strip_prefix("file://") {
        let slash = rest.find('/')?;
        let host = &rest[..slash];
        if !(host.is_empty() || host == "localhost") {
            return None;
        }
        &rest[slash..]
    } else if let Some(rest) = uri.strip_prefix("file:") {
        rest
    } else if has_scheme(uri) || uri.starts_with("//") {
        return None;
    } else {
        uri
    };
    decode(rest)
}

fn claimed_roots(
    known: &[&Path],
    bases: &BTreeMap<String, Lenient<ArtifactLocation>>,
) -> Vec<String> {
    let mut roots: Vec<String> = bases
        .values()
        .filter_map(|base| base.0.as_ref()?.uri.0.as_deref())
        .filter_map(local_path)
        .chain(
            known
                .iter()
                .filter_map(|path| path.to_str().map(str::to_owned)),
        )
        .filter(|path| path.starts_with('/'))
        .map(|path| format!("{}/", path.trim_end_matches('/')))
        .filter(|path| path.len() > 1)
        .collect();
    roots.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    roots.dedup();
    roots
}

fn resolve(
    uri: &str,
    base_id: Option<&str>,
    bases: &BTreeMap<String, Lenient<ArtifactLocation>>,
    roots: &[String],
) -> Option<String> {
    let mut path = local_path(uri)?;
    if path.starts_with('/') {
        let inner = roots
            .iter()
            .find_map(|root| path.strip_prefix(root.as_str()))?;
        path = inner.to_owned();
    } else {
        let mut next = base_id;
        let mut seen = BTreeSet::new();
        while let Some(id) = next {
            if seen.len() >= MAX_BASE_DEPTH || !seen.insert(id) {
                return None;
            }
            let Some(base) = bases.get(id).and_then(|base| base.0.as_ref()) else {
                break;
            };
            let Some(prefix) = base.uri.0.as_deref().and_then(local_path) else {
                break;
            };
            if prefix.starts_with('/') {
                break;
            }
            path = format!("{}/{path}", prefix.trim_end_matches('/'));
            next = base.uri_base_id.0.as_deref();
        }
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            part => parts.push(part),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn inside(root: &Path, rel_path: &str, excluded: &dyn Fn(&str) -> bool) -> Option<String> {
    let abs = fs::canonicalize(root.join(rel_path)).ok()?;
    if !fs::symlink_metadata(&abs).ok()?.file_type().is_file() {
        return None;
    }
    let mut parts = Vec::new();
    for component in abs.strip_prefix(root).ok()?.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str()?;
                if SKIPPED_DIRS.contains(&part) || !is_clean(part) || part.contains('`') {
                    return None;
                }
                parts.push(part);
            }
            _ => return None,
        }
    }
    let rel = parts.join("/");
    (!parts.is_empty() && !excluded(&rel)).then_some(rel)
}

pub(crate) fn emit(
    imported: &Imported,
    graph: &mut Graph,
    known: &dyn Fn(&str) -> Option<(FileRole, Basis)>,
) -> bool {
    let mut dropped = false;
    let mut added = BTreeSet::new();
    let mut ordinals: BTreeMap<(&str, &str, &str), u32> = BTreeMap::new();
    for item in &imported.items {
        let node = file_id(&item.path);
        if !graph.has_node(&node) && !added.contains(&item.path) {
            if added.len() >= MAX_NEW_FILES {
                dropped = true;
                continue;
            }
            added.insert(item.path.clone());
        }
        let ordinal = ordinals
            .entry((&item.engine, &item.rule, &item.path))
            .or_insert(0);
        *ordinal += 1;
        let (role, basis) = known(&item.path).unwrap_or((FileRole::UnknownCode, Basis::Engine));
        graph.add_file(&item.path, role, basis);
        let location = seethru_core::Location {
            path: item.path.clone(),
            line: item.line,
            column: item.column,
        };
        let text =
            crate::rules::external(&item.engine, &item.rule, &item.cwe, &item.path, item.line);
        graph.add_external(Finding {
            id: format!(
                "external:{}:{}:{}:{}",
                item.engine, item.rule, node, ordinal
            ),
            rule: RuleId::External,
            severity: item.severity,
            confidence: Confidence::Review,
            title: text.title,
            explanation: text.explanation,
            node: node.clone(),
            location: Some(location.clone()),
            evidence: vec![file_step(&item.path, None, location)],
            origin: Origin {
                engine: item.engine.clone(),
                inputs: vec![InputKind::Sarif],
                rule: Some(item.rule.clone()),
            },
            cwe: item.cwe.clone(),
            proof: None,
            fix_prompt: None,
            accepted: None,
        });
    }
    dropped
}
