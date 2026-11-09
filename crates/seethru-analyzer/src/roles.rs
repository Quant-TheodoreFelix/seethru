use std::collections::{BTreeMap, VecDeque};

use seethru_core::FileRole;

use crate::resolve::Resolver;
use crate::script::Directive;

pub(crate) struct Module {
    pub rel_path: String,
    pub role: FileRole,
    pub directive: Option<Directive>,
    pub server_only: bool,
    pub imports: Vec<String>,
}

impl Module {
    fn is_fixed(&self) -> bool {
        matches!(
            self.role,
            FileRole::EdgeFunction
                | FileRole::BuildOutput
                | FileRole::Migration
                | FileRole::EnvFile
        )
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
}

pub(crate) fn assign(modules: &[Module], resolver: &Resolver<'_>) -> BTreeMap<String, FileRole> {
    let index: BTreeMap<&str, usize> = modules
        .iter()
        .enumerate()
        .map(|(position, module)| (module.rel_path.as_str(), position))
        .collect();
    let edges: Vec<Vec<usize>> = modules
        .iter()
        .map(|module| {
            module
                .imports
                .iter()
                .filter_map(|specifier| resolver.resolve(&module.rel_path, specifier))
                .filter_map(|target| index.get(target.as_str()).copied())
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
            let role = if module.is_fixed() {
                module.role
            } else if browser[position] {
                FileRole::BrowserCode
            } else if server[position] {
                FileRole::ServerCode
            } else {
                module.role
            };
            (module.rel_path.clone(), role)
        })
        .collect()
}

fn reach(
    modules: &[Module],
    edges: &[Vec<usize>],
    starts: impl Fn(&Module) -> bool,
    blocks: impl Fn(&Module) -> bool,
) -> Vec<bool> {
    let mut seen: Vec<bool> = modules.iter().map(&starts).collect();
    let mut queue: VecDeque<usize> = seen
        .iter()
        .enumerate()
        .filter_map(|(position, start)| start.then_some(position))
        .collect();
    while let Some(current) = queue.pop_front() {
        for &next in &edges[current] {
            if !seen[next] && !blocks(&modules[next]) {
                seen[next] = true;
                queue.push_back(next);
            }
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use seethru_core::FileRole;

    use super::{Module, assign};
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
            imports: imports.iter().map(|import| (*import).to_owned()).collect(),
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
        let role = |path: &str| roles.get(path).copied();

        assert_eq!(role("app/page.tsx"), Some(FileRole::ServerCode));
        assert_eq!(role("app/TodoList.tsx"), Some(FileRole::BrowserCode));
        assert_eq!(role("app/actions.ts"), Some(FileRole::ServerCode));
        assert_eq!(role("lib/admin.ts"), Some(FileRole::BrowserCode));
        assert_eq!(role("lib/shared.ts"), Some(FileRole::BrowserCode));
        assert_eq!(role("lib/header.tsx"), Some(FileRole::ServerCode));
        assert_eq!(role("lib/data.ts"), Some(FileRole::ServerCode));
        assert_eq!(role("lib/secret.ts"), Some(FileRole::ServerCode));
        assert_eq!(role("scripts/seed.ts"), Some(FileRole::UnknownCode));
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
        assert_eq!(roles.get("shared/config.ts"), Some(&FileRole::BrowserCode));
        assert_eq!(
            roles.get("supabase/functions/pay/index.ts"),
            Some(&FileRole::EdgeFunction)
        );
    }
}
