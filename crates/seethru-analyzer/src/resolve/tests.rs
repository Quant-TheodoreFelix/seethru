use std::collections::BTreeSet;

use super::{ConfigText, Resolver, parse_jsonc};

fn files(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|path| (*path).to_owned()).collect()
}

fn config(rel_path: &str, text: &str) -> ConfigText {
    ConfigText {
        rel_path: rel_path.to_owned(),
        text: text.to_owned(),
    }
}

#[test]
fn reads_tsconfig_with_comments_and_trailing_commas() {
    let text = r#"{
        // compiler settings
        "compilerOptions": {
            /* aliases */
            "paths": { "@/*": ["./src/*"], }, // keep this
            "url": "https://example.invalid/a//b",
        },
    }"#;
    let value = parse_jsonc(text).unwrap_or_default();
    assert_eq!(value["compilerOptions"]["paths"]["@/*"][0], "./src/*");
    assert_eq!(
        value["compilerOptions"]["url"],
        "https://example.invalid/a//b"
    );
    assert!(parse_jsonc("{ not json").is_none());
}

#[test]
fn resolves_relative_imports_with_extensions_and_index_files() {
    let set = files(&[
        "src/app/page.tsx",
        "src/lib/db.ts",
        "src/components/index.tsx",
        "src/util.ts",
    ]);
    let resolver = Resolver::new(&set, Vec::new(), &[]);
    let resolve = |specifier: &str| resolver.resolve("src/app/page.tsx", specifier);
    assert_eq!(resolve("../lib/db").as_deref(), Some("src/lib/db.ts"));
    assert_eq!(resolve("../lib/db.js").as_deref(), Some("src/lib/db.ts"));
    assert_eq!(
        resolve("../components").as_deref(),
        Some("src/components/index.tsx")
    );
    assert_eq!(resolve("../../../etc/passwd"), None);
    assert_eq!(resolve("react"), None);
    assert_eq!(resolve("/src/util"), None);
}

#[test]
fn follows_tsconfig_paths_base_url_and_relative_extends() {
    let set = files(&[
        "apps/web/src/app/page.tsx",
        "apps/web/src/lib/admin.ts",
        "apps/web/components/Button.tsx",
    ]);
    let configs = [
        config(
            "apps/web/tsconfig.base.json",
            r#"{ "compilerOptions": { "paths": { "@/*": ["./src/*"] } } }"#,
        ),
        config(
            "apps/web/tsconfig.json",
            r#"{ "extends": "./tsconfig.base", "compilerOptions": { "baseUrl": "." } }"#,
        ),
    ];
    let resolver = Resolver::new(&set, Vec::new(), &configs);
    let from = "apps/web/src/app/page.tsx";
    assert_eq!(
        resolver.resolve(from, "@/lib/admin").as_deref(),
        Some("apps/web/src/lib/admin.ts")
    );
    assert_eq!(
        resolver.resolve(from, "components/Button").as_deref(),
        Some("apps/web/components/Button.tsx")
    );
}

#[test]
fn falls_back_to_the_usual_alias_when_no_config_names_it() {
    let set = files(&["src/main.tsx", "src/integrations/supabase/client.ts"]);
    let resolver = Resolver::new(&set, vec![String::new()], &[]);
    assert_eq!(
        resolver
            .resolve("src/main.tsx", "@/integrations/supabase/client")
            .as_deref(),
        Some("src/integrations/supabase/client.ts")
    );
}

#[test]
fn resolves_workspace_packages_by_name() {
    let set = files(&[
        "apps/web/app/page.tsx",
        "packages/db/src/index.ts",
        "packages/db/src/admin.ts",
    ]);
    let configs = [config(
        "packages/db/package.json",
        r#"{ "name": "@acme/db", "main": "./src/index.ts" }"#,
    )];
    let resolver = Resolver::new(&set, Vec::new(), &configs);
    let from = "apps/web/app/page.tsx";
    assert_eq!(
        resolver.resolve(from, "@acme/db").as_deref(),
        Some("packages/db/src/index.ts")
    );
    assert_eq!(
        resolver.resolve(from, "@acme/db/admin").as_deref(),
        Some("packages/db/src/admin.ts")
    );
    assert_eq!(resolver.resolve(from, "@acme/dbx"), None);
}
