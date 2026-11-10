use std::fs;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use seethru_core::{RuleId, ScanReport, Severity};

struct TempProject {
    root: PathBuf,
}

impl TempProject {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("seethru-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let created = fs::create_dir_all(&root);
        assert!(created.is_ok(), "{created:?}");
        Self { root }
    }

    fn write(&self, rel_path: &str, content: &str) {
        let path = self.root.join(rel_path);
        if let Some(parent) = path.parent() {
            let created = fs::create_dir_all(parent);
            assert!(created.is_ok(), "{created:?}");
        }
        let written = fs::write(path, content);
        assert!(written.is_ok(), "{written:?}");
    }

    fn scan(&self) -> ScanReport {
        let result = seethru_analyzer::scan(&self.root);
        assert!(result.is_ok(), "{result:?}");
        result.unwrap_or_else(|_| empty_report())
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn empty_report() -> ScanReport {
    ScanReport {
        schema_version: 0,
        tool: seethru_core::ToolInfo {
            name: String::new(),
            version: String::new(),
        },
        target: seethru_core::TargetInfo {
            name: String::new(),
            files_scanned: 0,
            files_skipped: 0,
            files_excluded: 0,
            truncated: false,
            config_file: None,
            ecosystems: Vec::new(),
            inputs: Vec::new(),
            limitations: Vec::new(),
            machine_code: None,
        },
        summary: seethru_core::Summary::default(),
        nodes: Vec::new(),
        edges: Vec::new(),
        findings: Vec::new(),
    }
}

fn body(len: usize) -> String {
    "Q7mZr2Kx9VbT4nWc8LpY3hGd6FsJ5aEuR1tN0kHqXvBzMjC"
        .chars()
        .cycle()
        .skip(3)
        .take(len)
        .collect()
}

fn service_role_jwt() -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD
        .encode(br#"{"iss":"supabase","ref":"seethrutestonly","role":"service_role"}"#);
    format!("{header}.{payload}.{}", body(43))
}

fn findings(report: &ScanReport) -> Vec<(RuleId, Severity, String)> {
    report
        .findings
        .iter()
        .map(|finding| {
            let place = finding
                .location
                .as_ref()
                .map(|l| l.path.clone())
                .unwrap_or_default();
            (finding.rule, finding.severity, place)
        })
        .collect()
}

#[test]
fn secrets_are_reported_by_where_they_live_and_never_leak_into_the_report() {
    let project = TempProject::new("secrets");
    let jwt = service_role_jwt();
    let stripe = ["sk", "_live_", &body(32)].concat();
    let openai = ["sk-", "proj-", &body(64)].concat();
    let db_password = body(24);
    let db_url =
        format!("postgresql://postgres:{db_password}@db.seethrutestonly.supabase.co:5432/postgres");

    project.write("vite.config.ts", "export default {};\n");
    project.write(
        "src/lib/admin.ts",
        &format!("export const key = \"{jwt}\";\n"),
    );
    project.write(".env.local", &format!("VITE_SUPABASE_URL=https://seethrutestonly.supabase.co\nVITE_SUPABASE_SERVICE_ROLE_KEY={jwt}\n"));
    project.write(".env", &format!("SUPABASE_SERVICE_ROLE_KEY={jwt}\n"));
    project.write(".env.example", &format!("STRIPE_SECRET_KEY={stripe}\n"));
    project.write(
        "supabase/functions/report/index.ts",
        &format!("const db = \"{db_url}\";\n"),
    );
    project.write("dist/assets/index-abc.js", &format!("var a=\"{openai}\";"));
    project.write(
        ".next/static/chunks/app/page-1a2b.js",
        &format!("var b=\"{openai}\";"),
    );
    project.write(
        ".next/server/app/api/pay/route.js",
        &format!("var c=\"{stripe}\";"),
    );
    let second_stripe = ["sk", "_live_", &body(33)].concat();
    project.write(
        "server/pay.ts",
        &format!("const a = \"{stripe}\";\nconst b = \"{second_stripe}\";\n"),
    );
    project.write("node_modules/pkg/index.js", &format!("var a=\"{openai}\";"));

    let report = project.scan();
    let mut got = findings(&report);
    got.sort();
    let mut want = vec![
        (
            RuleId::SecretInBrowserCode,
            Severity::Critical,
            ".next/static/chunks/app/page-1a2b.js".to_owned(),
        ),
        (
            RuleId::SecretInSourceCode,
            Severity::High,
            ".next/server/app/api/pay/route.js".to_owned(),
        ),
        (
            RuleId::SecretInBrowserCode,
            Severity::Critical,
            "dist/assets/index-abc.js".to_owned(),
        ),
        (
            RuleId::SecretInBrowserCode,
            Severity::Critical,
            "src/lib/admin.ts".to_owned(),
        ),
        (
            RuleId::SecretInPublicEnvVar,
            Severity::Critical,
            ".env.local".to_owned(),
        ),
        (
            RuleId::SecretInSourceCode,
            Severity::High,
            ".env.example".to_owned(),
        ),
        (
            RuleId::SecretInSourceCode,
            Severity::High,
            "server/pay.ts".to_owned(),
        ),
        (
            RuleId::SecretInSourceCode,
            Severity::High,
            "server/pay.ts".to_owned(),
        ),
        (
            RuleId::SecretInSourceCode,
            Severity::High,
            "supabase/functions/report/index.ts".to_owned(),
        ),
    ];
    want.sort();
    assert_eq!(got, want);

    assert!(report.edges.iter().any(|edge| edge.from.as_str()
        == "env:VITE_SUPABASE_SERVICE_ROLE_KEY"
        && edge.to.as_str() == "secret:.env.local:supabaseServiceRoleKey:1"));
    let ids: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.id.contains(":secret:server/pay.ts:"))
        .map(|finding| finding.id.as_str())
        .collect();
    assert_eq!(
        ids,
        vec![
            "secret-in-source-code:secret:server/pay.ts:stripeSecretKey:1",
            "secret-in-source-code:secret:server/pay.ts:stripeSecretKey:2",
        ]
    );

    let json = serde_json::to_string(&report).unwrap_or_default();
    for raw in [
        jwt.as_str(),
        stripe.as_str(),
        second_stripe.as_str(),
        openai.as_str(),
        db_password.as_str(),
    ] {
        assert!(!json.contains(raw), "raw secret leaked into report");
    }
    assert!(!json.contains(&*project.root.to_string_lossy()));
}

#[cfg(unix)]
#[test]
fn symlinks_are_never_followed() {
    let outside = TempProject::new("outside");
    outside.write(
        "secret.ts",
        &format!("const k = \"{}\";\n", ["sk", "_live_", &body(32)].concat()),
    );
    let project = TempProject::new("symlinks");
    project.write("src/app.ts", "export {};\n");
    let linked = std::os::unix::fs::symlink(
        outside.root.join("secret.ts"),
        project.root.join("src/linked.ts"),
    );
    assert!(linked.is_ok(), "{linked:?}");
    let dir_link = std::os::unix::fs::symlink(&outside.root, project.root.join("vendor"));
    assert!(dir_link.is_ok(), "{dir_link:?}");

    let report = project.scan();
    assert!(report.findings.is_empty());
    assert_eq!(report.target.files_skipped, 2);
}
