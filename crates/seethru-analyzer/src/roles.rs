use std::collections::{BTreeMap, VecDeque};

use seethru_core::{Basis, Location};

use crate::classify::FileRole;
use crate::resolve::Resolver;
use crate::script::Directive;

const MAX_HOPS: usize = 12;

pub(crate) struct Module {
    pub rel_path: String,
    pub role: FileRole,
    pub directive: Option<Directive>,
    pub server_only: bool,
    pub imports: Vec<Import>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Import {
    pub specifier: String,
    pub location: Location,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Assigned {
    pub role: FileRole,
    pub basis: Basis,
    pub via: Vec<Hop>,
    pub built_into: Option<String>,
}

impl Assigned {
    pub(crate) fn by_path(role: FileRole) -> Self {
        Self {
            role,
            basis: Basis::Path,
            via: Vec::new(),
            built_into: None,
        }
    }

    pub(crate) fn by_build(role: FileRole, built_into: Option<String>) -> Self {
        Self {
            role,
            basis: Basis::BuildOutput,
            via: Vec::new(),
            built_into,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hop {
    pub rel_path: String,
    pub location: Location,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reached {
    Start,
    Via { parent: usize, import: usize },
}

impl Module {
    fn is_fixed(&self) -> bool {
        is_fixed(self.role)
    }

    fn stays_on_server(&self) -> bool {
        self.directive == Some(Directive::UseServer) || self.server_only
    }

    fn starts_in_browser(&self) -> bool {
        !self.is_fixed()
            && !self.stays_on_server()
            && (self.directive == Some(Directive::UseClient) || self.role == FileRole::BrowserCode)
    }

    fn starts_on_server(&self) -> bool {
        !self.is_fixed() && (self.stays_on_server() || self.role == FileRole::ServerCode)
    }

    fn start_basis(&self, browser: bool) -> Basis {
        let by_directive = if browser {
            self.directive == Some(Directive::UseClient)
        } else {
            self.stays_on_server()
        };
        if by_directive {
            Basis::Directive
        } else {
            Basis::Path
        }
    }
}

pub(crate) fn is_fixed(role: FileRole) -> bool {
    matches!(
        role,
        FileRole::EdgeFunction
            | FileRole::BuildOutput
            | FileRole::ServerBuildOutput
            | FileRole::BuildCache
            | FileRole::Migration
            | FileRole::EnvFile
    )
}

pub(crate) fn assign(modules: &[Module], resolver: &Resolver<'_>) -> BTreeMap<String, Assigned> {
    let index: BTreeMap<&str, usize> = modules
        .iter()
        .enumerate()
        .map(|(position, module)| (module.rel_path.as_str(), position))
        .collect();
    let edges: Vec<Vec<(usize, usize)>> = modules
        .iter()
        .map(|module| {
            module
                .imports
                .iter()
                .enumerate()
                .filter_map(|(import, item)| {
                    let target = resolver.resolve(&module.rel_path, &item.specifier)?;
                    Some((*index.get(target.as_str())?, import))
                })
                .collect()
        })
        .collect();

    let browser = reach(modules, &edges, Module::starts_in_browser, |module| {
        module.is_fixed() || module.stays_on_server()
    });
    let server = reach(modules, &edges, Module::starts_on_server, Module::is_fixed);

    modules
        .iter()
        .enumerate()
        .map(|(position, module)| {
            let assigned = if module.is_fixed() {
                Assigned::by_path(module.role)
            } else if browser[position].is_some() {
                assigned(modules, &browser, position, FileRole::BrowserCode, true)
            } else if server[position].is_some() {
                assigned(modules, &server, position, FileRole::ServerCode, false)
            } else {
                Assigned::by_path(module.role)
            };
            (module.rel_path.clone(), assigned)
        })
        .collect()
}

fn assigned(
    modules: &[Module],
    reached: &[Option<Reached>],
    position: usize,
    role: FileRole,
    browser: bool,
) -> Assigned {
    let mut hops = Vec::new();
    let mut current = position;
    for _ in 0..modules.len() {
        match reached[current] {
            Some(Reached::Via { parent, import }) => {
                if let Some(item) = modules[parent].imports.get(import) {
                    hops.push(Hop {
                        rel_path: modules[parent].rel_path.clone(),
                        location: item.location.clone(),
                    });
                }
                current = parent;
            }
            _ => break,
        }
    }
    hops.reverse();
    if hops.is_empty() {
        return Assigned {
            role,
            basis: modules[position].start_basis(browser),
            via: hops,
            built_into: None,
        };
    }
    let skip = hops.len().saturating_sub(MAX_HOPS);
    Assigned {
        role,
        basis: Basis::Imports,
        via: hops.split_off(skip),
        built_into: None,
    }
}

fn reach(
    modules: &[Module],
    edges: &[Vec<(usize, usize)>],
    starts: impl Fn(&Module) -> bool,
    blocks: impl Fn(&Module) -> bool,
) -> Vec<Option<Reached>> {
    let mut seen: Vec<Option<Reached>> = modules
        .iter()
        .map(|module| starts(module).then_some(Reached::Start))
        .collect();
    let mut queue: VecDeque<usize> = seen
        .iter()
        .enumerate()
        .filter_map(|(position, start)| start.map(|_| position))
        .collect();
    while let Some(current) = queue.pop_front() {
        for &(next, import) in &edges[current] {
            if seen[next].is_none() && !blocks(&modules[next]) {
                seen[next] = Some(Reached::Via {
                    parent: current,
                    import,
                });
                queue.push_back(next);
            }
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use seethru_core::{Basis, Location};

    use super::{Import, Module, assign};
    use crate::classify::FileRole;
    use crate::resolve::Resolver;
    use crate::script::Directive;

    fn module(
        rel_path: &str,
        role: FileRole,
        directive: Option<Directive>,
        imports: &[&str],
    ) -> Module {
        Module {
            rel_path: rel_path.to_owned(),
            role,
            directive,
            server_only: false,
            imports: imports
                .iter()
                .enumerate()
                .map(|(line, import)| Import {
                    specifier: (*import).to_owned(),
                    location: Location {
                        path: rel_path.to_owned(),
                        line: u32::try_from(line).unwrap_or(0).saturating_add(1),
                        column: 1,
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn client_components_pull_their_imports_into_the_browser() {
        let mut modules = vec![
            module(
                "app/page.tsx",
                FileRole::ServerCode,
                None,
                &["./TodoList", "../lib/header", "../lib/data"],
            ),
            module(
                "app/TodoList.tsx",
                FileRole::ServerCode,
                Some(Directive::UseClient),
                &["../lib/admin", "./actions", "../lib/secret"],
            ),
            module(
                "app/actions.ts",
                FileRole::ServerCode,
                Some(Directive::UseServer),
                &["../lib/data"],
            ),
            module("lib/admin.ts", FileRole::UnknownCode, None, &["./shared"]),
            module("lib/shared.ts", FileRole::UnknownCode, None, &[]),
            module("lib/header.tsx", FileRole::UnknownCode, None, &["./shared"]),
            module("lib/data.ts", FileRole::UnknownCode, None, &[]),
            module("lib/secret.ts", FileRole::UnknownCode, None, &[]),
            module(
                "scripts/seed.ts",
                FileRole::UnknownCode,
                None,
                &["../lib/data"],
            ),
        ];
        modules[7].server_only = true;
        let files: BTreeSet<String> = modules.iter().map(|m| m.rel_path.clone()).collect();
        let resolver = Resolver::new(&files, Vec::new(), &[]);
        let roles = assign(&modules, &resolver);
        let role = |path: &str| roles.get(path).map(|assigned| assigned.role);
        let basis = |path: &str| roles.get(path).map(|assigned| assigned.basis);

        assert_eq!(role("app/page.tsx"), Some(FileRole::ServerCode));
        assert_eq!(role("app/TodoList.tsx"), Some(FileRole::BrowserCode));
        assert_eq!(role("app/actions.ts"), Some(FileRole::ServerCode));
        assert_eq!(role("lib/admin.ts"), Some(FileRole::BrowserCode));
        assert_eq!(role("lib/shared.ts"), Some(FileRole::BrowserCode));
        assert_eq!(role("lib/header.tsx"), Some(FileRole::ServerCode));
        assert_eq!(role("lib/data.ts"), Some(FileRole::ServerCode));
        assert_eq!(role("lib/secret.ts"), Some(FileRole::ServerCode));
        assert_eq!(role("scripts/seed.ts"), Some(FileRole::UnknownCode));

        assert_eq!(basis("app/page.tsx"), Some(Basis::Path));
        assert_eq!(basis("app/TodoList.tsx"), Some(Basis::Directive));
        assert_eq!(basis("app/actions.ts"), Some(Basis::Directive));
        assert_eq!(basis("lib/shared.ts"), Some(Basis::Imports));
        assert_eq!(basis("lib/secret.ts"), Some(Basis::Directive));
        assert_eq!(basis("scripts/seed.ts"), Some(Basis::Path));

        let shared = roles.get("lib/shared.ts").map(|assigned| {
            assigned
                .via
                .iter()
                .map(|hop| (hop.rel_path.as_str(), hop.location.line))
                .collect::<Vec<_>>()
        });
        assert_eq!(
            shared,
            Some(vec![("app/TodoList.tsx", 1), ("lib/admin.ts", 1)])
        );
    }

    #[test]
    fn browser_code_reaches_shared_folders_but_never_edge_functions() {
        let modules = vec![
            module(
                "src/main.tsx",
                FileRole::BrowserCode,
                None,
                &["../shared/config", "../supabase/functions/pay/index"],
            ),
            module("shared/config.ts", FileRole::UnknownCode, None, &[]),
            module(
                "supabase/functions/pay/index.ts",
                FileRole::EdgeFunction,
                None,
                &[],
            ),
        ];
        let files: BTreeSet<String> = modules.iter().map(|m| m.rel_path.clone()).collect();
        let resolver = Resolver::new(&files, Vec::new(), &[]);
        let roles = assign(&modules, &resolver);
        let role = |path: &str| roles.get(path).map(|assigned| assigned.role);
        assert_eq!(role("shared/config.ts"), Some(FileRole::BrowserCode));
        assert_eq!(
            role("supabase/functions/pay/index.ts"),
            Some(FileRole::EdgeFunction)
        );
        assert_eq!(
            roles.get("src/main.tsx").map(|assigned| assigned.basis),
            Some(Basis::Path)
        );
    }
}
