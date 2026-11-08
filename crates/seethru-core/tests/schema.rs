#[test]
fn committed_schema_matches_the_model() {
    let committed: serde_json::Value =
        serde_json::from_str(include_str!("../../../schema/scan-report.schema.json"))
            .unwrap_or_default();
    assert_eq!(
        committed,
        seethru_core::report_schema(),
        "schema/scan-report.schema.json is stale, regenerate it with `cargo run -p seethru-cli -- schema > schema/scan-report.schema.json`"
    );
}
