use seethru_core::{
    CredentialDetail, Lang, MaskedSecret, Node, NodeId, NodeKind, SCHEMA_VERSION, ScanReport,
    SecretKind, Summary, TargetInfo, ToolInfo, Zone,
};

fn raw_secret() -> String {
    ["sk", "_live_", "SEETHRU", "TESTONLY", "0123456789abcdef"].concat()
}

fn report() -> ScanReport {
    ScanReport {
        schema_version: SCHEMA_VERSION,
        tool: ToolInfo {
            name: "seethru".to_owned(),
            version: "0.0.0".to_owned(),
        },
        target: TargetInfo {
            name: "</title><script>alert(1)</script>".to_owned(),
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
            id: NodeId::new("secret:a"),
            label: "</script><script>alert(1)</script>".to_owned(),
            kind: NodeKind::Credential {
                detail: CredentialDetail::Secret {
                    secret_kind: SecretKind::StripeSecretKey,
                    masked: MaskedSecret::mask(&raw_secret(), 8),
                },
            },
            zone: Zone::Client,
            location: None,
        }],
        edges: Vec::new(),
        findings: Vec::new(),
    }
}

#[test]
fn rendered_report_is_self_contained_and_never_contains_raw_secrets() {
    let rendered = seethru_report::render_html(&report(), Lang::En);
    if !seethru_report::html_available() {
        assert!(matches!(
            rendered,
            Err(seethru_report::ReportError::WebUiMissing)
        ));
        return;
    }
    assert!(rendered.is_ok(), "{rendered:?}");
    let Ok(html) = rendered else { return };

    assert!(!html.contains(&raw_secret()));
    assert!(html.contains("sk_live_****cdef"));
    assert!(html.contains("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'sha256-"));
    assert!(!html.contains("<script src="));
    assert!(!html.contains("<link "));
    assert_eq!(html.matches("</script>").count(), 2);
    assert_eq!(html.matches("</title>").count(), 1);
    assert!(
        html.contains(
            "<title>seethru - &lt;/title&gt;&lt;script&gt;alert(1)&lt;/script&gt;</title>"
        )
    );
}

#[test]
fn rendered_report_starts_in_the_chosen_language() {
    if !seethru_report::html_available() {
        return;
    }
    for lang in Lang::ALL {
        let html = seethru_report::render_html(&report(), lang).unwrap_or_default();
        let opening = format!("<html lang=\"{}\">", lang.code());
        assert!(html.contains(&opening), "{opening}");
    }
}
