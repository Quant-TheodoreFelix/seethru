use std::path::PathBuf;

use seethru_core::{
    Finding, Location, MaskedSecret, Node, NodeId, NodeKind, RuleId, SCHEMA_VERSION, ScanReport,
    SecretKind, Severity, Summary, TargetInfo, ToolInfo,
};

use super::{attach_fix_prompts, fix_prompt};

fn fixture_report() -> Option<ScanReport> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/supabase-vite");
    seethru_analyzer::scan(&root).ok()
}

fn prompt_for(report: &ScanReport, rule: RuleId) -> String {
    report
        .findings
        .iter()
        .find(|finding| finding.rule == rule)
        .and_then(|finding| finding.fix_prompt.clone())
        .unwrap_or_default()
}

#[test]
fn every_finding_gets_a_prompt_with_its_location() {
    let Some(mut report) = fixture_report() else {
        unreachable!("fixture scan failed")
    };
    attach_fix_prompts(&mut report);
    assert!(!report.findings.is_empty());
    for finding in &report.findings {
        let prompt = finding.fix_prompt.as_deref().unwrap_or_default();
        let path = finding
            .location
            .as_ref()
            .map(|l| l.path.as_str())
            .unwrap_or_default();
        assert!(prompt.contains(path), "{prompt}");
        assert!(prompt.ends_with("알려 줘."), "{prompt}");
    }
}

#[test]
fn rls_prompt_names_the_table_and_the_code_that_uses_it() {
    let Some(mut report) = fixture_report() else {
        unreachable!("fixture scan failed")
    };
    attach_fix_prompts(&mut report);
    let prompt = prompt_for(&report, RuleId::SupabaseRlsDisabled);
    assert!(
        prompt.contains("alter table public.todos enable row level security;"),
        "{prompt}"
    );
    assert!(prompt.contains("`src/pages/Todos.tsx`"), "{prompt}");
}

#[test]
fn policy_and_service_role_prompts_point_at_the_right_places() {
    let Some(mut report) = fixture_report() else {
        unreachable!("fixture scan failed")
    };
    attach_fix_prompts(&mut report);
    let service = prompt_for(&report, RuleId::SupabaseServiceRoleInBrowser);
    assert!(
        service.contains("`VITE_SUPABASE_SERVICE_ROLE_KEY`"),
        "{service}"
    );
    assert!(service.contains("`src/lib/admin.ts`"), "{service}");
    let policy = prompt_for(&report, RuleId::SupabasePolicyUnrestricted);
    assert!(
        policy.contains("`posts` 테이블의 `Signed in users can edit posts` 정책"),
        "{policy}"
    );
}

fn secret_report(label: &str) -> (ScanReport, String) {
    let raw = ["sk", "_live_", "Q7mZr2Kx9VbT4nWc8LpY3hGd6FsJ5aEu"].concat();
    let masked = MaskedSecret::mask(&raw, 8);
    let node = Node {
        id: NodeId::new("secret:a"),
        label: label.to_owned(),
        kind: NodeKind::Secret {
            secret_kind: SecretKind::StripeSecretKey,
            masked: masked.clone(),
        },
        location: None,
    };
    let finding = Finding {
        id: "secret-in-source-code:secret:a".to_owned(),
        rule: RuleId::SecretInSourceCode,
        severity: Severity::High,
        title: "t".to_owned(),
        explanation: "e".to_owned(),
        node: node.id.clone(),
        location: Some(Location {
            path: "src/pay`ment\n.ts".to_owned(),
            line: 3,
            column: 7,
        }),
        fix_prompt: None,
    };
    let report = ScanReport {
        schema_version: SCHEMA_VERSION,
        tool: ToolInfo {
            name: "seethru".to_owned(),
            version: "0".to_owned(),
        },
        target: TargetInfo {
            name: "t".to_owned(),
            files_scanned: 1,
            files_skipped: 0,
            truncated: false,
        },
        summary: Summary::default(),
        nodes: vec![node],
        edges: Vec::new(),
        findings: vec![finding],
    };
    (report, masked.as_str().to_owned())
}

#[test]
fn secret_prompts_never_carry_the_value_and_strip_hostile_names() {
    let (report, masked) = secret_report("label");
    let prompt = report
        .findings
        .first()
        .map(|finding| fix_prompt(&report, finding))
        .unwrap_or_default();
    assert!(prompt.contains("`src/payment.ts:3`"), "{prompt}");
    assert!(!prompt.contains(&masked));
    assert!(!prompt.contains("sk_live_"));
    assert!(prompt.contains("Stripe 비밀 키"));
}
