use std::path::PathBuf;

use seethru_core::{RuleId, Severity};

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
    assert_eq!(report.summary.critical, 1);
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
fn scanning_a_file_is_rejected() {
    let result = seethru_analyzer::scan(&fixture("supabase-vite/vite.config.ts"));
    assert!(matches!(
        result,
        Err(seethru_analyzer::ScanError::NotADirectory)
    ));
}
