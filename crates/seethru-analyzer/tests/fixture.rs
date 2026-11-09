use std::path::PathBuf;

use seethru_core::{EdgeKind, FileRole, NodeKind, RuleId, Severity};

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
                RuleId::SupabasePolicyUnrestricted,
                Severity::Medium,
                "policy:public.profiles/Profiles are public"
            ),
            (
                RuleId::SupabasePolicyUnrestricted,
                Severity::Medium,
                "policy:public.posts/Anyone can read posts"
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
        "file:src/pages/Todos.tsx",
        "table:public.todos",
        EdgeKind::Queries
    ));
    assert!(edge(
        "file:src/pages/Todos.tsx",
        "table:public.todos",
        EdgeKind::Writes
    ));
    assert!(edge(
        "file:src/lib/admin.ts",
        "env:VITE_SUPABASE_SERVICE_ROLE_KEY",
        EdgeKind::Reads
    ));
    assert!(edge(
        "file:src/lib/admin.ts",
        "table:public.posts",
        EdgeKind::Writes
    ));
    assert!(edge(
        "file:supabase/functions/admin-report/index.ts",
        "env:SUPABASE_SERVICE_ROLE_KEY",
        EdgeKind::Reads
    ));
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

    let role = |path: &str| {
        report.nodes.iter().find_map(|node| match &node.kind {
            NodeKind::File { role } if node.id.as_str() == format!("file:{path}") => Some(*role),
            _ => None,
        })
    };
    assert_eq!(
        role("src/components/TodoList.tsx"),
        Some(FileRole::BrowserCode)
    );
    assert_eq!(role("src/lib/admin.ts"), Some(FileRole::BrowserCode));
    assert_eq!(
        role("src/lib/supabase-browser.ts"),
        Some(FileRole::BrowserCode)
    );
    assert_eq!(role("src/app/actions.ts"), Some(FileRole::ServerCode));
    assert_eq!(
        role("src/app/api/todos/route.ts"),
        Some(FileRole::ServerCode)
    );
    assert_eq!(role("src/lib/admin-server.ts"), Some(FileRole::ServerCode));
    assert_eq!(role("src/lib/stats.ts"), Some(FileRole::ServerCode));
    assert_eq!(role("scripts/seed.ts"), Some(FileRole::UnknownCode));

    let got: Vec<(RuleId, &str)> = report
        .findings
        .iter()
        .map(|finding| (finding.rule, finding.node.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![(
            RuleId::SupabaseServiceRoleInBrowser,
            "env:NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"
        )]
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
