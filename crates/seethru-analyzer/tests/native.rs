mod common;

use std::path::PathBuf;

use common::TempProject;
use seethru_analyzer::{ScanError, ScanOptions};
use seethru_core::{
    Confidence, Ecosystem, Exposure, Input, LimitationCode, NodeKind, RuleId, ScanReport, Severity,
    Zone,
};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/esp-idf-firmware")
}

fn rules(report: &ScanReport) -> Vec<(RuleId, &str, Severity, Confidence)> {
    report
        .findings
        .iter()
        .map(|f| (f.rule, f.node.as_str(), f.severity, f.confidence))
        .collect()
}

fn private_key() -> String {
    let body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7".repeat(3);
    [
        "-----BEGIN ",
        "PRIVATE KEY",
        "-----\\n\"\n    \"",
        &body,
        "\\n\"\n    \"-----END ",
        "PRIVATE KEY",
        "-----",
    ]
    .concat()
}

#[test]
fn firmware_fixture_reports_settings_and_the_open_update_route() {
    let result = seethru_analyzer::scan(&fixture());
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert_eq!(report.target.ecosystems, [Ecosystem::EspIdf]);
    assert_eq!(
        rules(&report),
        [
            (
                RuleId::FirmwareInsecureOptionOn,
                "config:sdkconfig.defaults:CONFIG_SECURE_BOOT_ALLOW_JTAG",
                Severity::High,
                Confidence::Certain
            ),
            (
                RuleId::FirmwareOtaOverHttp,
                "config:sdkconfig.defaults:CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP",
                Severity::High,
                Confidence::Certain
            ),
            (
                RuleId::FirmwareOtaUnguarded,
                "entry:httpRoute:/api/update",
                Severity::High,
                Confidence::Likely
            ),
        ]
    );
    let exposure = |id: &str| {
        report.nodes.iter().find_map(|node| match &node.kind {
            NodeKind::EntryPoint { exposure, .. } if node.id.as_str() == id => {
                Some((*exposure, node.zone))
            }
            _ => None,
        })
    };
    assert_eq!(
        exposure("entry:httpRoute:/api/update"),
        Some((Exposure::Public, Zone::Device))
    );
    assert_eq!(
        exposure("entry:httpRoute:/api/admin/update"),
        Some((Exposure::Unknown, Zone::Device))
    );
    assert_eq!(
        exposure("entry:httpRoute:/api/status"),
        Some((Exposure::Unknown, Zone::Device))
    );
    let update = &report.findings[2];
    let steps: Vec<(&str, Option<u32>)> = update
        .evidence
        .iter()
        .map(|step| (step.label.as_str(), step.location.as_ref().map(|l| l.line)))
        .collect();
    assert_eq!(
        steps,
        [
            ("POST /api/update", Some(46)),
            ("post_update()", Some(11)),
            ("updater_write_image()", Some(5)),
            ("esp_ota_write()", Some(21)),
        ]
    );
    let codes: Vec<LimitationCode> = report.target.limitations.iter().map(|l| l.code).collect();
    assert_eq!(
        codes,
        [
            LimitationCode::FirmwareProtectionNotChecked,
            LimitationCode::NativeCodePartlyRead
        ]
    );
}

#[test]
fn secrets_in_native_code_get_their_own_rule_and_markers_are_not_keys() {
    let project = TempProject::new("native-secret");
    project.write("CMakeLists.txt", "project(tool)\n");
    project.write(
        "src/key.c",
        &format!("static const char *KEY =\n    \"{}\\n\";\n", private_key()),
    );
    project.write(
        "src/parse.c",
        &format!(
            "int kind(const char *line) {{\n  if (!strcmp(line, \"{}RSA PRIVATE KEY{}\\n\")) return 1;\n  return compute_other_things(line) + another_long_function_name(line) + yet_another_function(line);\n}}\n",
            "-----BEGIN ", "-----"
        ),
    );
    project.write(
        "build/config.json",
        &format!("{{\"key\": \"{}\"}}\n", private_key()),
    );
    project.write(
        "build/compile_commands.json",
        r#"[{"directory": "/elsewhere", "file": "/elsewhere/x.c"}, {"directory": "ROOT/build", "file": "../src/other.c", "command": "rm -rf /"}]"#,
    );
    let result = seethru_analyzer::scan(&project.root);
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert_eq!(
        rules(&report),
        [(
            RuleId::SecretInNativeCode,
            "secret:src/key.c:privateKey:1",
            Severity::High,
            Confidence::Certain
        )]
    );
    assert!(report.target.ecosystems.is_empty());
    let text = serde_json::to_string(&report).unwrap_or_default();
    assert!(!text.contains("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7MIIE"));

    let root = project.root.canonicalize();
    assert!(root.is_ok());
    let Ok(root) = root else { return };
    let database = format!(
        r#"[{{"directory": "{0}/build", "file": "../src/other.c", "command": "rm -rf /"}},
            {{"directory": "/elsewhere", "file": "/elsewhere/x.c"}},
            {{"directory": "{0}", "file": "../../outside.c"}}]"#,
        root.to_string_lossy().replace('\\', "/")
    );
    project.write("build/compile_commands.json", &database);
    project.write("src/other.c", "int other(void) { return 0; }\n");
    let options = |path: PathBuf| ScanOptions {
        compile_commands: Some(path),
        ..ScanOptions::default()
    };
    let with_database = seethru_analyzer::scan_with(
        &project.root,
        options(project.root.join("build/compile_commands.json")),
    );
    assert!(with_database.is_ok(), "{with_database:?}");
    let Ok(with_database) = with_database else {
        return;
    };
    assert_eq!(
        rules(&with_database),
        [(
            RuleId::SecretInNativeCode,
            "secret:src/key.c:privateKey:1",
            Severity::High,
            Confidence::Review
        )]
    );
    assert!(
        with_database
            .target
            .inputs
            .contains(&Input::CompileDatabase {
                path: "build/compile_commands.json".to_owned(),
                files: 1,
            })
    );

    project.write("build/broken.json", "{");
    for path in [
        project.root.join("build/broken.json"),
        project.root.join("missing.json"),
        std::env::temp_dir(),
    ] {
        let result = seethru_analyzer::scan_with(&project.root, options(path));
        assert!(
            matches!(result, Err(ScanError::CompileCommands(_))),
            "{result:?}"
        );
    }
}

#[test]
fn test_settings_and_checked_handlers_stay_silent() {
    let project = TempProject::new("native-quiet");
    project.write("sdkconfig.ci", "CONFIG_SECURE_BOOT_INSECURE=y\n");
    project.write(
        "sdkconfig.defaults",
        "# CONFIG_SECURE_BOOT_INSECURE is not set\nCONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY=n\n",
    );
    project.write("app/prj.conf", "CONFIG_BT_USE_DEBUG_KEYS=y\n");
    project.write(
        "main/server.c",
        r#"
static esp_err_t upload(httpd_req_t *req) { return esp_ota_write(h, b, n); }
static esp_err_t guarded(httpd_req_t *req) {
    if (!session_is_valid(req)) { return ESP_FAIL; }
    return upload(req);
}
static esp_err_t wrap(httpd_req_t *req) { return check_login(req); }
void start(void) {
    httpd_uri_t a = { .uri = "/a", .method = HTTP_POST, .handler = guarded };
    httpd_uri_t b = { .uri = "/b", .method = HTTP_POST, .handler = upload };
    httpd_uri_t c = { .uri = "/c", .method = HTTP_POST, .handler = missing_handler };
    b.handler = wrap;
}
"#,
    );
    let result = seethru_analyzer::scan(&project.root);
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert_eq!(
        rules(&report),
        [(
            RuleId::FirmwareInsecureOptionOn,
            "config:app/prj.conf:CONFIG_BT_USE_DEBUG_KEYS",
            Severity::High,
            Confidence::Certain
        )]
    );
    assert_eq!(
        report.target.ecosystems,
        [Ecosystem::EspIdf, Ecosystem::Zephyr]
    );
    assert!(report.nodes.iter().all(|node| !matches!(
        node.kind,
        NodeKind::EntryPoint {
            exposure: Exposure::Public,
            ..
        }
    )));
}
