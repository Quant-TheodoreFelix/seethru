use std::path::PathBuf;

use seethru_core::{
    Confidence, CredentialDetail, DataStoreDetail, Finding, Lang, LocalizedText, Location,
    MaskedSecret, Node, NodeId, NodeKind, Origin, RuleId, SCHEMA_VERSION, ScanReport, SecretKind,
    Severity, Summary, TargetInfo, ToolInfo, Zone,
};

use super::{CLOSING_EN, CLOSING_KO, attach_fix_prompts, fix_prompt};

fn fixture_report() -> Option<ScanReport> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/supabase-vite");
    seethru_analyzer::scan(&root).ok()
}

fn prompt_for(report: &ScanReport, rule: RuleId) -> LocalizedText {
    report
        .findings
        .iter()
        .find(|finding| finding.rule == rule)
        .and_then(|finding| finding.fix_prompt.clone())
        .unwrap_or_default()
}

fn has_hangul(text: &str) -> bool {
    text.chars().any(|c| ('\u{AC00}'..='\u{D7A3}').contains(&c))
}

#[test]
fn every_finding_gets_a_prompt_in_both_languages_with_its_location() {
    let Some(mut report) = fixture_report() else {
        unreachable!("fixture scan failed")
    };
    attach_fix_prompts(&mut report);
    assert!(!report.findings.is_empty());
    for finding in &report.findings {
        let prompt = finding.fix_prompt.clone().unwrap_or_default();
        let path = finding
            .location
            .as_ref()
            .map(|l| l.path.as_str())
            .unwrap_or_default();
        assert!(prompt.en.contains(path), "{prompt:?}");
        assert!(prompt.ko.contains(path), "{prompt:?}");
        assert!(prompt.en.ends_with(CLOSING_EN), "{prompt:?}");
        assert!(prompt.ko.ends_with(CLOSING_KO), "{prompt:?}");
        assert!(!has_hangul(&prompt.en), "{prompt:?}");
        assert!(!prompt.ko.contains('\u{2014}'), "{prompt:?}");
    }
}

#[test]
fn rls_prompt_names_the_table_and_the_code_that_uses_it() {
    let Some(mut report) = fixture_report() else {
        unreachable!("fixture scan failed")
    };
    attach_fix_prompts(&mut report);
    let prompt = prompt_for(&report, RuleId::SupabaseRlsDisabled);
    for text in [&prompt.en, &prompt.ko] {
        assert!(
            text.contains("alter table public.todos enable row level security;"),
            "{text}"
        );
        assert!(text.contains("`src/pages/Todos.tsx`"), "{text}");
    }
}

#[test]
fn policy_and_service_role_prompts_point_at_the_right_places() {
    let Some(mut report) = fixture_report() else {
        unreachable!("fixture scan failed")
    };
    attach_fix_prompts(&mut report);
    let service = prompt_for(&report, RuleId::SupabaseServiceRoleInBrowser);
    for text in [&service.en, &service.ko] {
        assert!(text.contains("`VITE_SUPABASE_SERVICE_ROLE_KEY`"), "{text}");
        assert!(text.contains("`src/lib/admin.ts`"), "{text}");
    }
    let policy = prompt_for(&report, RuleId::SupabasePolicyUnrestricted);
    assert!(
        policy.en.contains("The `Signed in users can edit posts` policy on the Supabase `posts` table (`update` for authenticated)"),
        "{policy:?}"
    );
    assert!(
        policy.ko.contains("Supabase `posts` 테이블의 `Signed in users can edit posts` 정책(`update`, 대상 authenticated)"),
        "{policy:?}"
    );
}

fn secret_report(label: &str) -> (ScanReport, String) {
    let raw = ["sk", "_live_", "Q7mZr2Kx9VbT4nWc8LpY3hGd6FsJ5aEu"].concat();
    let masked = MaskedSecret::mask(&raw, 8);
    let node = Node {
        id: NodeId::new("secret:a"),
        label: label.to_owned(),
        kind: NodeKind::Credential {
            detail: CredentialDetail::Secret {
                secret_kind: SecretKind::StripeSecretKey,
                masked: masked.clone(),
            },
        },
        zone: Zone::Server,
        location: None,
    };
    let finding = Finding {
        id: "secret-in-source-code:secret:a".to_owned(),
        rule: RuleId::SecretInSourceCode,
        severity: Severity::High,
        confidence: Confidence::Certain,
        title: LocalizedText {
            en: "t".to_owned(),
            ko: "t".to_owned(),
        },
        explanation: LocalizedText {
            en: "e".to_owned(),
            ko: "e".to_owned(),
        },
        node: node.id.clone(),
        location: Some(Location {
            path: "src/pay`ment\n.ts".to_owned(),
            line: 3,
            column: 7,
        }),
        evidence: Vec::new(),
        origin: Origin::seethru(),
        cwe: Vec::new(),
        proof: None,
        fix_prompt: None,
        accepted: None,
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
            files_excluded: 0,
            truncated: false,
            config_file: None,
            ecosystems: Vec::new(),
            inputs: Vec::new(),
            limitations: Vec::new(),
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
    for (lang, name) in [
        (Lang::En, "a Stripe secret key"),
        (Lang::Ko, "Stripe 비밀 키"),
    ] {
        let prompt = report
            .findings
            .first()
            .map(|finding| fix_prompt(&report, finding, lang))
            .unwrap_or_default();
        assert!(prompt.contains("`src/payment.ts:3`"), "{prompt}");
        assert!(!prompt.contains(&masked));
        assert!(!prompt.contains("sk_live_"));
        assert!(prompt.contains(name), "{prompt}");
    }
}

#[test]
fn schema_missing_prompt_turns_rls_on_and_asks_to_compare_policies() {
    let table = Node {
        id: NodeId::new("table:public.orders"),
        label: "orders".to_owned(),
        kind: NodeKind::DataStore {
            detail: Some(DataStoreDetail::PostgresTable {
                schema: "public".to_owned(),
                rls: seethru_core::RlsStatus::Unknown,
            }),
        },
        zone: Zone::Database,
        location: None,
    };
    let finding = Finding {
        id: "supabase-table-schema-missing:table:public.orders".to_owned(),
        rule: RuleId::SupabaseTableSchemaMissing,
        severity: Severity::Info,
        confidence: Confidence::Review,
        title: LocalizedText::default(),
        explanation: LocalizedText::default(),
        node: table.id.clone(),
        location: Some(Location {
            path: "src/pages/Orders.tsx".to_owned(),
            line: 3,
            column: 9,
        }),
        evidence: Vec::new(),
        origin: Origin::seethru(),
        cwe: Vec::new(),
        proof: None,
        fix_prompt: None,
        accepted: None,
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
            files_excluded: 0,
            truncated: false,
            config_file: None,
            ecosystems: Vec::new(),
            inputs: Vec::new(),
            limitations: Vec::new(),
        },
        summary: Summary::default(),
        nodes: vec![table],
        edges: Vec::new(),
        findings: vec![finding],
    };
    for (lang, closing) in [(Lang::En, CLOSING_EN), (Lang::Ko, CLOSING_KO)] {
        let prompt = report
            .findings
            .first()
            .map(|finding| fix_prompt(&report, finding, lang))
            .unwrap_or_default();
        assert!(
            prompt.contains("alter table public.orders enable row level security;"),
            "{prompt}"
        );
        assert!(prompt.contains("`src/pages/Orders.tsx:3`"), "{prompt}");
        assert!(
            prompt.contains("supabase db dump --schema public"),
            "{prompt}"
        );
        assert!(prompt.ends_with(closing), "{prompt}");
    }
}

#[test]
fn database_prompts_name_the_function_view_and_bucket() {
    let Some(mut report) = fixture_report() else {
        unreachable!("fixture scan failed")
    };
    attach_fix_prompts(&mut report);
    let function = prompt_for(&report, RuleId::SupabaseFunctionBypassesRls);
    for text in [&function.en, &function.ko] {
        assert!(
            text.contains(
                "revoke execute on function public.delete_any_post from public, anon, authenticated;"
            ),
            "{text}"
        );
    }
    let view = prompt_for(&report, RuleId::SupabaseViewBypassesRls);
    for text in [&view.en, &view.ko] {
        assert!(
            text.contains("alter view public.post_feed set (security_invoker = true);"),
            "{text}"
        );
    }
    let storage: Vec<LocalizedText> = report
        .findings
        .iter()
        .filter(|finding| finding.rule == RuleId::SupabaseStoragePolicyUnrestricted)
        .filter_map(|finding| finding.fix_prompt.clone())
        .collect();
    assert_eq!(storage.len(), 2);
    for prompt in &storage {
        for text in [&prompt.en, &prompt.ko] {
            assert!(
                text.contains("`avatars`") || text.contains("`invoices`"),
                "{text}"
            );
            assert!(text.contains("storage.objects"), "{text}");
        }
    }
}

#[test]
fn unguarded_service_role_prompt_names_the_entry_and_the_client() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/supabase-next");
    let Ok(mut report) = seethru_analyzer::scan(&root) else {
        unreachable!("fixture scan failed")
    };
    attach_fix_prompts(&mut report);
    let prompts: Vec<(String, LocalizedText)> = report
        .findings
        .iter()
        .filter(|finding| finding.rule == RuleId::SupabaseServiceRoleUnguarded)
        .filter_map(|finding| Some((finding.node.to_string(), finding.fix_prompt.clone()?)))
        .collect();
    assert_eq!(prompts.len(), 2);
    for (node, prompt) in &prompts {
        for text in [&prompt.en, &prompt.ko] {
            assert!(text.contains("supabase.auth.getUser()"), "{text}");
            if node.ends_with("/api/todos") {
                assert!(text.contains("`DELETE /api/todos`"), "{text}");
                assert!(text.contains("`src/lib/admin-server.ts:4`"), "{text}");
            } else {
                assert!(text.contains("`addTodo()`"), "{text}");
                assert!(text.contains("POST"), "{text}");
            }
        }
    }
}

#[test]
fn outside_scanner_prompt_keeps_scanner_text_out() {
    let finding = Finding {
        id: "external:semgrep:evil.rule:file:src/a.c:1".to_owned(),
        rule: RuleId::External,
        severity: Severity::High,
        confidence: Confidence::Review,
        title: LocalizedText::default(),
        explanation: LocalizedText::default(),
        node: NodeId::new("file:src/a.c"),
        location: Some(Location {
            path: "src/a.c".to_owned(),
            line: 12,
            column: 3,
        }),
        evidence: Vec::new(),
        origin: Origin {
            engine: "semgrep".to_owned(),
            inputs: vec![seethru_core::InputKind::Sarif],
            rule: Some("evil.rule".to_owned()),
            tools: Vec::new(),
        },
        cwe: vec![78],
        proof: None,
        fix_prompt: None,
        accepted: None,
    };
    let report = ScanReport {
        schema_version: SCHEMA_VERSION,
        tool: ToolInfo {
            name: "seethru".to_owned(),
            version: "0.0.0".to_owned(),
        },
        target: TargetInfo {
            name: "app".to_owned(),
            files_scanned: 1,
            files_skipped: 0,
            files_excluded: 0,
            truncated: false,
            config_file: None,
            ecosystems: Vec::new(),
            inputs: Vec::new(),
            limitations: Vec::new(),
        },
        summary: Summary::default(),
        nodes: Vec::new(),
        edges: Vec::new(),
        findings: vec![finding.clone()],
    };
    for lang in Lang::ALL {
        let prompt = fix_prompt(&report, &finding, lang);
        assert!(prompt.contains("`src/a.c:12`"), "{prompt}");
        assert!(prompt.contains("CWE-78"), "{prompt}");
        assert!(!prompt.contains("evil.rule"), "{prompt}");
        assert!(!prompt.contains("semgrep"), "{prompt}");
    }
    assert!(has_hangul(&fix_prompt(&report, &finding, Lang::Ko)));
}

#[test]
fn rust_prompts_name_the_line_and_ask_for_a_rebuild() {
    let finding = |rule: RuleId, node: &str, path: &str| Finding {
        id: format!("{}:{node}", rule.as_str()),
        rule,
        severity: Severity::Medium,
        confidence: Confidence::Likely,
        title: LocalizedText::default(),
        explanation: LocalizedText::default(),
        node: NodeId::new(node),
        location: Some(Location {
            path: path.to_owned(),
            line: 18,
            column: 1,
        }),
        evidence: Vec::new(),
        origin: Origin::seethru_with_compiled_output(),
        cwe: rule.cwe().to_vec(),
        proof: None,
        fix_prompt: None,
        accepted: None,
    };
    let division = finding(
        RuleId::SecretDependentDivision,
        "file:vault/src/lib.rs",
        "vault/src/lib.rs",
    );
    let loose = finding(
        RuleId::CargoDependencyNotPinned,
        "dependency:cargo:app:remote",
        "Cargo.toml",
    );
    let report = ScanReport {
        schema_version: SCHEMA_VERSION,
        tool: ToolInfo {
            name: "seethru".to_owned(),
            version: "0.0.0".to_owned(),
        },
        target: TargetInfo {
            name: "app".to_owned(),
            files_scanned: 1,
            files_skipped: 0,
            files_excluded: 0,
            truncated: false,
            config_file: None,
            ecosystems: Vec::new(),
            inputs: Vec::new(),
            limitations: Vec::new(),
        },
        summary: Summary::default(),
        nodes: vec![Node {
            id: NodeId::new("dependency:cargo:app:remote"),
            label: "remote".to_owned(),
            kind: NodeKind::Service {},
            zone: Zone::ThirdParty,
            location: None,
        }],
        edges: Vec::new(),
        findings: vec![division.clone(), loose.clone()],
    };
    for lang in Lang::ALL {
        let prompt = fix_prompt(&report, &division, lang);
        assert!(prompt.contains("`vault/src/lib.rs:18`"), "{prompt}");
        assert!(prompt.contains("rem_euclid"), "{prompt}");
        let prompt = fix_prompt(&report, &loose, lang);
        assert!(prompt.contains("`remote`"), "{prompt}");
        assert!(prompt.contains("`Cargo.lock`"), "{prompt}");
    }
    assert!(fix_prompt(&report, &division, Lang::En).contains("build again"));
    assert!(has_hangul(&fix_prompt(&report, &division, Lang::Ko)));
    assert!(has_hangul(&fix_prompt(&report, &loose, Lang::Ko)));
}
