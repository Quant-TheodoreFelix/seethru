use std::path::PathBuf;

use seethru_core::{Artifact, Basis, EdgeKind, NodeKind, RuleId, Runtime, Severity, Zone};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

#[test]
fn supabase_vite_fixture_reports_expected_findings() {
    let result = seethru_analyzer::scan(&fixture("supabase-vite"));
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };

    assert_eq!(report.target.name, "supabase-vite");
    let got: Vec<(RuleId, Severity, &str)> = report
        .findings
        .iter()
        .map(|finding| (finding.rule, finding.severity, finding.node.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            (
                RuleId::SupabaseRlsDisabled,
                Severity::Critical,
                "table:public.todos"
            ),
            (
                RuleId::SupabaseServiceRoleInBrowser,
                Severity::Critical,
                "env:VITE_SUPABASE_SERVICE_ROLE_KEY"
            ),
            (
                RuleId::SupabasePolicyUnrestricted,
                Severity::High,
                "policy:public.posts/Signed in users can edit posts"
            ),
            (
                RuleId::SupabaseFunctionBypassesRls,
                Severity::High,
                "entry:rpc:public.delete_any_post"
            ),
            (
                RuleId::SupabaseViewBypassesRls,
                Severity::High,
                "table:public.post_feed"
            ),
            (
                RuleId::SupabaseStoragePolicyUnrestricted,
                Severity::High,
                "policy:storage.objects/Anyone can upload invoices"
            ),
            (
                RuleId::SupabasePolicyUnrestricted,
                Severity::Medium,
                "policy:public.profiles/Profiles are public"
            ),
            (
                RuleId::SupabasePolicyUnrestricted,
                Severity::Medium,
                "policy:public.posts/Anyone can read posts"
            ),
            (
                RuleId::SupabaseStoragePolicyUnrestricted,
                Severity::Medium,
                "policy:storage.objects/Avatar images are public"
            ),
            (
                RuleId::SupabaseServiceRoleUnguarded,
                Severity::Medium,
                "entry:httpRoute:/functions/v1/admin-report"
            ),
            (
                RuleId::SupabaseFunctionBypassesRls,
                Severity::Low,
                "entry:rpc:public.is_note_owner"
            ),
        ]
    );
    assert_eq!(report.summary.critical, 2);

    let edge = |from: &str, to: &str, kind: EdgeKind| {
        report
            .edges
            .iter()
            .any(|edge| edge.from.as_str() == from && edge.to.as_str() == to && edge.kind == kind)
    };
    assert!(edge(
        "entry:rpc:public.list_profiles",
        "principal:supabase:postgres",
        EdgeKind::ActsAs
    ));
    assert!(edge(
        "store:storageBucket:invoices",
        "policy:storage.objects/Users manage their own invoices",
        EdgeKind::GuardedBy
    ));
    assert!(edge(
        "file:src/pages/Todos.tsx",
        "table:public.todos",
        EdgeKind::Reads
    ));
    assert!(edge(
        "file:src/pages/Todos.tsx",
        "table:public.todos",
        EdgeKind::Writes
    ));
    assert!(edge(
        "file:src/lib/admin.ts",
        "env:VITE_SUPABASE_SERVICE_ROLE_KEY",
        EdgeKind::UsesConfig
    ));
    assert!(edge(
        "file:src/lib/admin.ts",
        "table:public.posts",
        EdgeKind::Writes
    ));
    assert!(edge(
        "file:supabase/functions/admin-report/index.ts",
        "env:SUPABASE_SERVICE_ROLE_KEY",
        EdgeKind::UsesConfig
    ));
    assert_eq!(report.schema_version, 6);
    assert_eq!(
        report.target.ecosystems,
        vec![
            seethru_core::Ecosystem::Vite,
            seethru_core::Ecosystem::Supabase
        ]
    );
    assert_eq!(report.target.inputs, vec![seethru_core::Input::Source {}]);
    assert_eq!(report.target.limitations.len(), 2);
    assert!(
        report
            .findings
            .iter()
            .all(|finding| !finding.evidence.is_empty())
    );
    assert!(report.findings.iter().all(|finding| {
        finding
            .evidence
            .iter()
            .any(|step| step.node.as_ref() == Some(&finding.node))
    }));
}

#[test]
fn report_paths_are_relative_to_the_scanned_project() {
    let root = fixture("supabase-vite");
    let result = seethru_analyzer::scan(&root);
    let Ok(report) = result else { return };
    let json = serde_json::to_string(&report).unwrap_or_default();
    let absolute = std::fs::canonicalize(&root).unwrap_or(root);
    assert!(!json.contains(&*absolute.to_string_lossy()));
    assert!(!json.contains("/Users/"));
}

#[test]
fn supabase_next_fixture_tells_server_code_from_browser_code() {
    let result = seethru_analyzer::scan(&fixture("supabase-next"));
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };

    let component = |path: &str| {
        report.nodes.iter().find_map(|node| match &node.kind {
            NodeKind::Component {
                runtime,
                artifact,
                basis,
                ..
            } if node.id.as_str() == format!("file:{path}") => {
                Some((*runtime, *artifact, *basis, node.zone))
            }
            _ => None,
        })
    };
    let source =
        |runtime: Runtime, basis: Basis| Some((runtime, Artifact::Source, basis, runtime.zone()));
    assert_eq!(
        component("src/components/TodoList.tsx"),
        source(Runtime::Browser, Basis::Directive)
    );
    assert_eq!(
        component("src/lib/admin.ts"),
        source(Runtime::Browser, Basis::Imports)
    );
    assert_eq!(
        component("src/lib/supabase-browser.ts"),
        source(Runtime::Browser, Basis::Imports)
    );
    assert_eq!(
        component("src/app/actions.ts"),
        source(Runtime::Server, Basis::Directive)
    );
    assert_eq!(
        component("src/app/api/todos/route.ts"),
        source(Runtime::Server, Basis::Path)
    );
    assert_eq!(
        component("src/lib/admin-server.ts"),
        source(Runtime::Server, Basis::Directive)
    );
    assert_eq!(
        component("src/lib/stats.ts"),
        source(Runtime::Server, Basis::Imports)
    );
    assert_eq!(
        component("scripts/seed.ts"),
        source(Runtime::Unknown, Basis::Path)
    );
    assert_eq!(
        component("supabase/migrations/20250301000000_todos.sql")
            .map(|(runtime, artifact, _, zone)| (runtime, artifact, zone)),
        Some((Runtime::Database, Artifact::Migration, Zone::Database))
    );

    let got: Vec<(RuleId, &str)> = report
        .findings
        .iter()
        .map(|finding| (finding.rule, finding.node.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            (
                RuleId::SupabaseServiceRoleInBrowser,
                "env:NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"
            ),
            (
                RuleId::SupabaseServiceRoleUnguarded,
                "entry:serverAction:src/app/actions.ts#addTodo"
            ),
            (
                RuleId::SupabaseServiceRoleUnguarded,
                "entry:httpRoute:/api/todos"
            ),
        ]
    );
    let exposure = |id: &str| {
        report.nodes.iter().find_map(|node| match &node.kind {
            NodeKind::EntryPoint { exposure, .. } if node.id.as_str() == id => Some(*exposure),
            _ => None,
        })
    };
    assert_eq!(
        exposure("entry:httpRoute:/api/stats"),
        Some(seethru_core::Exposure::Authenticated)
    );
    let edge = |from: &str, to: &str, kind: EdgeKind| {
        report
            .edges
            .iter()
            .any(|edge| edge.from.as_str() == from && edge.to.as_str() == to && edge.kind == kind)
    };
    assert!(edge(
        "entry:httpRoute:/api/stats",
        "guard:src/lib/auth.ts#requireUser",
        EdgeKind::GuardedBy
    ));
    assert!(edge(
        "file:src/lib/admin-server.ts",
        "principal:supabase:service_role",
        EdgeKind::ActsAs
    ));
    let route = report
        .findings
        .iter()
        .find(|finding| finding.node.as_str() == "entry:httpRoute:/api/todos");
    let route_steps: Vec<(&str, Option<EdgeKind>)> = route
        .map(|finding| {
            finding
                .evidence
                .iter()
                .map(|step| (step.label.as_str(), step.via))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        route_steps,
        vec![
            ("DELETE /api/todos", None),
            ("route.ts", Some(EdgeKind::Invokes)),
            ("service_role", Some(EdgeKind::ActsAs)),
            ("todos", Some(EdgeKind::Writes)),
        ]
    );
    type Step<'a> = (
        &'a str,
        Option<EdgeKind>,
        Option<&'a str>,
        Option<(&'a str, u32)>,
    );
    let evidence: Vec<Step<'_>> = report
        .findings
        .iter()
        .filter(|finding| finding.rule == RuleId::SupabaseServiceRoleInBrowser)
        .flat_map(|finding| &finding.evidence)
        .map(|step| {
            (
                step.label.as_str(),
                step.via,
                step.node.as_ref().map(|node| node.as_str()),
                step.location
                    .as_ref()
                    .map(|location| (location.path.as_str(), location.line)),
            )
        })
        .collect();
    assert_eq!(
        evidence,
        vec![
            (
                "TodoList.tsx",
                None,
                Some("file:src/components/TodoList.tsx"),
                Some(("src/components/TodoList.tsx", 1))
            ),
            (
                "admin.ts",
                Some(EdgeKind::Imports),
                Some("file:src/lib/admin.ts"),
                Some(("src/components/TodoList.tsx", 5))
            ),
            (
                "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY",
                Some(EdgeKind::UsesConfig),
                Some("env:NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"),
                Some(("src/lib/admin.ts", 5))
            ),
        ]
    );
}

#[test]
fn scanning_a_file_is_rejected() {
    let result = seethru_analyzer::scan(&fixture("supabase-vite/vite.config.ts"));
    assert!(matches!(
        result,
        Err(seethru_analyzer::ScanError::NotADirectory)
    ));
}
