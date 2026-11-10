use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use seethru_core::{
    Artifact, Basis, Confidence, EdgeKind, Location, Node, NodeId, NodeKind, RuleId, Runtime,
    Severity, Unit,
};
use toml::{Table, Value};

use crate::glob::Glob;
use crate::graph::{Graph, Verdict, step};
use crate::rules;

const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_PACKAGES: usize = 500;
const MANIFEST: &str = "Cargo.toml";
const DEPENDENCY_TABLES: [&str; 2] = ["dependencies", "build-dependencies"];

pub(crate) struct Manifest {
    pub rel_path: String,
    pub text: String,
}

#[derive(Debug, PartialEq, Eq)]
enum Source {
    Path(String),
    Git { pinned: bool },
    Registry { any_version: bool },
    Unknown,
}

struct Dependency {
    name: String,
    source: Source,
    line: u32,
}

struct Package {
    name: String,
    dir: String,
    manifest: String,
    dependencies: Vec<Dependency>,
}

enum Member {
    Exact(String),
    Pattern(Glob),
}

impl Member {
    fn matches(&self, dir: &str) -> bool {
        match self {
            Self::Exact(exact) => exact == dir,
            Self::Pattern(glob) => glob.matches(dir),
        }
    }
}

#[derive(Default)]
pub(crate) struct Workspace {
    packages: Vec<Package>,
    locked: BTreeSet<String>,
}

pub(crate) fn is_manifest(rel_path: &str) -> bool {
    rel_path == MANIFEST || rel_path.ends_with("/Cargo.toml")
}

fn dir_of(rel_path: &str) -> &str {
    rel_path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

fn join(dir: &str, path: &str) -> Option<String> {
    let mut parts: Vec<&str> = dir.split('/').filter(|part| !part.is_empty()).collect();
    for part in path.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

fn under(path: &str, dir: &str) -> bool {
    dir.is_empty()
        || path
            .strip_prefix(dir)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

impl Workspace {
    pub(crate) fn read(root: &Path, manifests: &[Manifest]) -> Self {
        let mut parsed: BTreeMap<&str, Table> = BTreeMap::new();
        for manifest in manifests {
            if manifest.text.len() <= MAX_MANIFEST_BYTES
                && let Ok(table) = manifest.text.parse::<Table>()
            {
                parsed.insert(dir_of(&manifest.rel_path), table);
            }
        }
        let text_of: BTreeMap<&str, &str> = manifests
            .iter()
            .map(|manifest| (dir_of(&manifest.rel_path), manifest.text.as_str()))
            .collect();
        let tops: Vec<&str> = parsed
            .keys()
            .copied()
            .filter(|dir| !parsed.keys().any(|other| other != dir && under(dir, other)))
            .collect();

        let mut out = Self::default();
        let mut taken: BTreeSet<String> = BTreeSet::new();
        for top in tops {
            let Some(table) = parsed.get(top) else {
                continue;
            };
            let workspace = table.get("workspace").and_then(Value::as_table);
            let shared = workspace
                .and_then(|workspace| workspace.get("dependencies"))
                .and_then(Value::as_table);
            let patterns = |key: &str| -> Vec<Member> {
                workspace
                    .and_then(|workspace| workspace.get(key))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .filter_map(|pattern| join(top, pattern))
                    .filter_map(|pattern| {
                        if pattern.contains(['*', '?', '[']) {
                            Glob::new(&pattern).ok().map(Member::Pattern)
                        } else {
                            Some(Member::Exact(pattern))
                        }
                    })
                    .collect()
            };
            let members = patterns("members");
            let excluded = patterns("exclude");
            let mut queue: Vec<String> = vec![top.to_owned()];
            queue.extend(
                parsed
                    .keys()
                    .filter(|dir| members.iter().any(|member| member.matches(dir)))
                    .filter(|dir| !excluded.iter().any(|member| member.matches(dir)))
                    .map(|dir| (*dir).to_owned()),
            );
            if root.join(top).join("Cargo.lock").is_file() {
                out.locked.insert(top.to_owned());
            }
            while let Some(dir) = queue.pop() {
                if out.packages.len() >= MAX_PACKAGES || !taken.insert(dir.clone()) {
                    continue;
                }
                let Some(table) = parsed.get(dir.as_str()) else {
                    continue;
                };
                let Some(name) = table
                    .get("package")
                    .and_then(Value::as_table)
                    .and_then(|package| package.get("name"))
                    .and_then(Value::as_str)
                else {
                    continue;
                };
                let text = text_of.get(dir.as_str()).copied().unwrap_or_default();
                let mut dependencies = Vec::new();
                let mut tables: Vec<&Table> = DEPENDENCY_TABLES
                    .iter()
                    .filter_map(|key| table.get(*key).and_then(Value::as_table))
                    .collect();
                if let Some(targets) = table.get("target").and_then(Value::as_table) {
                    for target in targets.values().filter_map(Value::as_table) {
                        tables.extend(
                            DEPENDENCY_TABLES
                                .iter()
                                .filter_map(|key| target.get(*key).and_then(Value::as_table)),
                        );
                    }
                }
                for (key, value) in tables.into_iter().flatten() {
                    let inherited = value
                        .as_table()
                        .and_then(|spec| spec.get("workspace"))
                        .and_then(Value::as_bool)
                        == Some(true);
                    let (value, base) = if inherited {
                        match shared.and_then(|shared| shared.get(key)) {
                            Some(value) => (value, top),
                            None => continue,
                        }
                    } else {
                        (value, dir.as_str())
                    };
                    let source = source_of(value, base);
                    if let Source::Path(path) = &source {
                        queue.push(path.clone());
                    }
                    dependencies.push(Dependency {
                        name: key.clone(),
                        source,
                        line: line_of(text, key),
                    });
                }
                out.packages.push(Package {
                    name: name.to_owned(),
                    manifest: if dir.is_empty() {
                        MANIFEST.to_owned()
                    } else {
                        format!("{dir}/{MANIFEST}")
                    },
                    dir,
                    dependencies,
                });
            }
        }
        out.packages.sort_by(|a, b| a.dir.cmp(&b.dir));
        out
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    pub(crate) fn package_of(&self, rel_path: &str) -> Option<NodeId> {
        self.packages
            .iter()
            .filter(|package| under(rel_path, &package.dir))
            .max_by_key(|package| package.dir.len())
            .map(|package| package_id(&package.name))
    }

    pub(crate) fn emit(&self, graph: &mut Graph) {
        for package in &self.packages {
            graph.add_node(Node {
                id: package_id(&package.name),
                label: rules::display_name(&package.name),
                kind: NodeKind::Component {
                    runtime: Runtime::Native,
                    artifact: Artifact::Source,
                    unit: Unit::Package,
                    basis: Basis::Path,
                },
                zone: Runtime::Native.zone(),
                location: Some(Location {
                    path: package.manifest.clone(),
                    line: 1,
                    column: 1,
                }),
            });
        }
        for package in &self.packages {
            let locked = self.locked.iter().any(|top| under(&package.dir, top));
            for dependency in &package.dependencies {
                let git = match &dependency.source {
                    Source::Path(dir) => {
                        if let Some(target) = self.packages.iter().find(|other| other.dir == *dir) {
                            graph.add_edge(
                                package_id(&package.name),
                                package_id(&target.name),
                                EdgeKind::Imports,
                            );
                        }
                        continue;
                    }
                    Source::Git { pinned: false } => true,
                    Source::Registry { any_version: true } => false,
                    _ => continue,
                };
                if locked {
                    continue;
                }
                let location = Location {
                    path: package.manifest.clone(),
                    line: dependency.line,
                    column: 1,
                };
                let node = graph.add_node(Node {
                    id: NodeId::new(format!(
                        "dependency:cargo:{}:{}",
                        package.name, dependency.name
                    )),
                    label: rules::display_name(&dependency.name),
                    kind: NodeKind::Service {},
                    zone: seethru_core::Zone::ThirdParty,
                    location: Some(location.clone()),
                });
                graph.add_edge(package_id(&package.name), node.clone(), EdgeKind::Imports);
                graph.add_finding(
                    Verdict {
                        rule: RuleId::CargoDependencyNotPinned,
                        severity: Severity::Low,
                        confidence: Confidence::Certain,
                        from_build: false,
                    },
                    rules::cargo_dependency_not_pinned(&dependency.name, &package.manifest, git),
                    node.clone(),
                    Some(location.clone()),
                    vec![step(
                        &rules::display_name(&dependency.name),
                        None,
                        Some(node),
                        Some(location),
                    )],
                );
            }
        }
    }
}

fn package_id(name: &str) -> NodeId {
    NodeId::new(format!("package:cargo:{name}"))
}

fn source_of(value: &Value, base: &str) -> Source {
    match value {
        Value::String(version) => Source::Registry {
            any_version: version.trim() == "*",
        },
        Value::Table(spec) => {
            if let Some(path) = spec.get("path").and_then(Value::as_str) {
                return join(base, path).map_or(Source::Unknown, Source::Path);
            }
            if spec.contains_key("git") {
                return Source::Git {
                    pinned: spec.get("rev").and_then(Value::as_str).is_some(),
                };
            }
            match spec.get("version").and_then(Value::as_str) {
                Some(version) => Source::Registry {
                    any_version: version.trim() == "*",
                },
                None => Source::Unknown,
            }
        }
        _ => Source::Unknown,
    }
}

fn line_of(text: &str, key: &str) -> u32 {
    let found = text.lines().position(|line| {
        let line = line.trim_start();
        let rest = line
            .strip_prefix(key)
            .or_else(|| {
                line.strip_prefix('"')
                    .and_then(|line| line.strip_prefix(key))
                    .and_then(|line| line.strip_prefix('"'))
            })
            .or_else(|| {
                line.strip_prefix("[dependencies.")
                    .and_then(|line| line.strip_prefix(key))
            });
        rest.is_some_and(|rest| {
            let rest = rest.trim_start();
            rest.starts_with('=') || rest.starts_with('.') || rest.starts_with(']')
        })
    });
    found.map_or(1, |index| u32::try_from(index + 1).unwrap_or(1))
}
