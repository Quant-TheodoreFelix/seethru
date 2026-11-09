mod common;

use std::fs::File;
use std::time::{Duration, SystemTime};

use common::TempProject;
use seethru_analyzer::{ScanError, ScanOptions};
use seethru_core::{
    Basis, BuildTool, Confidence, EdgeKind, Input, InputKind, LimitationCode, NodeKind, RuleId,
    Runtime, ScanReport, Severity,
};

const VITE_ENTRY_MAPPINGS: &str = "8pBAAA,IAAMA,EAAA,wBAEN,eAAsBC,GAAQ,CAC5B,OAAO,MAAM,iBAAkB,CAAE,OAAQ,SAAU,QAAS,CAAE,OAAQD,CAAI,CAAE,CAAC,CAC/E,CCJA,SAAgBE,GAAQ,CACtB,MAAO,OACT,C,o+CCCA,SAAS,eAAe,KAAK,CAAC,CAAE,YAAcA,EAAM,EACpD,SAAS,iBAAiB,QAAS,SAAY,EAE7C,MAAAC,MADmB,OAAO,+BACrB,OAAO,EACZ,MAAMF,EAAM,CACd,CAAC";

const VITE_MANIFEST: &str = r#"{
  "index.html": {
    "file": "assets/index-DWa_saO0.js",
    "name": "index",
    "src": "index.html",
    "isEntry": true,
    "dynamicImports": ["src/pages/Settings.ts"]
  },
  "src/pages/Settings.ts": {
    "file": "assets/Settings-BXJJZpdy.js",
    "name": "Settings",
    "src": "src/pages/Settings.ts",
    "isDynamicEntry": true
  }
}"#;

fn body(len: usize) -> String {
    "Q7mZr2Kx9VbT4nWc8LpY3hGd6FsJ5aEuR1tN0kHqXvBzMjC"
        .chars()
        .cycle()
        .skip(5)
        .take(len)
        .collect()
}

fn stripe_key() -> String {
    ["sk", "_live_", &body(32)].concat()
}

fn vlq(values: &[i64]) -> String {
    const DIGITS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for &value in values {
        let mut rest = if value < 0 {
            ((-value) << 1) | 1
        } else {
            value << 1
        };
        loop {
            let mut digit = rest & 31;
            rest >>= 5;
            if rest > 0 {
                digit |= 32;
            }
            out.push(char::from(DIGITS[usize::try_from(digit).unwrap_or(0)]));
            if rest == 0 {
                break;
            }
        }
    }
    out
}

fn write_vite_sources(project: &TempProject) {
    project.write(
        "vite.config.ts",
        "export default { build: { manifest: true, sourcemap: true } };\n",
    );
    project.write(
        "src/main.ts",
        "import { purge } from \"./lib/admin\";\nimport { label } from \"./lib/shared\";\n\ndocument.body.textContent = label();\ndocument.addEventListener(\"click\", async () => {\n  const page = await import(\"./pages/Settings\");\n  page.render();\n  await purge();\n});\n",
    );
    project.write(
        "src/lib/admin.ts",
        "const key = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY;\n\nexport async function purge() {\n  return fetch(\"/rest/v1/todos\", { method: \"DELETE\", headers: { apikey: key } });\n}\n",
    );
    project.write(
        "src/lib/shared.ts",
        "export function label() {\n  return \"todos\";\n}\n",
    );
    project.write(
        "src/lib/unused.ts",
        &format!("export const never = \"{}\";\n", stripe_key()),
    );
    project.write(
        "src/pages/Settings.ts",
        "export function render() {\n  const token = \"settings-page-marker\";\n  console.log(token);\n}\n",
    );
}

fn write_vite_build(project: &TempProject) {
    project.write("dist/.vite/manifest.json", VITE_MANIFEST);
    project.write(
        "dist/assets/index-DWa_saO0.js",
        "var e=`placeholder`;\n//# sourceMappingURL=index-DWa_saO0.js.map\n",
    );
    project.write(
        "dist/assets/index-DWa_saO0.js.map",
        &format!(
            r#"{{"version":3,"names":[],"sources":["../../src/lib/admin.ts","../../src/lib/shared.ts","../../src/main.ts"],"file":"index-DWa_saO0.js","mappings":"{VITE_ENTRY_MAPPINGS}"}}"#
        ),
    );
    let mappings = [vlq(&[0, 0, 0, 0]), vlq(&[7, 0, 2, 8])].join(",");
    project.write(
        "dist/assets/Settings-BXJJZpdy.js",
        &format!(
            "var k=\"{}\";console.log(k);\n//# sourceMappingURL=Settings-BXJJZpdy.js.map\n",
            stripe_key()
        ),
    );
    project.write(
        "dist/assets/Settings-BXJJZpdy.js.map",
        &format!(
            r#"{{"version":3,"file":"Settings-BXJJZpdy.js","names":[],"sources":["../../src/pages/Settings.ts"],"mappings":"{mappings}"}}"#
        ),
    );
}

fn scan(project: &TempProject, build_output: &str) -> Result<ScanReport, ScanError> {
    seethru_analyzer::scan_with(
        &project.root,
        ScanOptions {
            build_output: Some(project.root.join(build_output)),
            ..ScanOptions::default()
        },
    )
}

fn component(report: &ScanReport, path: &str) -> Option<(Runtime, Basis)> {
    report.nodes.iter().find_map(|node| match &node.kind {
        NodeKind::Component { runtime, basis, .. }
            if node.id.as_str() == format!("file:{path}") =>
        {
            Some((*runtime, *basis))
        }
        _ => None,
    })
}

fn limitations(report: &ScanReport) -> Vec<LimitationCode> {
    report
        .target
        .limitations
        .iter()
        .map(|limitation| limitation.code)
        .collect()
}

#[test]
fn vite_build_output_confirms_browser_files_and_drops_files_left_out_of_the_bundle() {
    let project = TempProject::new("vite-build");
    write_vite_sources(&project);
    let before = seethru_analyzer::scan(&project.root);
    assert!(before.is_ok(), "{before:?}");
    let Ok(before) = before else { return };
    let unused = |report: &ScanReport| {
        report
            .findings
            .iter()
            .find(|finding| finding.node.as_str() == "secret:src/lib/unused.ts:stripeSecretKey:1")
            .map(|finding| (finding.rule, finding.severity, finding.confidence))
    };
    assert_eq!(
        unused(&before),
        Some((
            RuleId::SecretInBrowserCode,
            Severity::Critical,
            Confidence::Likely
        ))
    );
    assert_eq!(
        limitations(&before),
        vec![LimitationCode::BuildOutputNotRead]
    );

    write_vite_build(&project);
    let result = scan(&project, "dist");
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };

    assert!(report.target.inputs.contains(&Input::BuildOutput {
        path: "dist".to_owned(),
        tool: BuildTool::Vite,
    }));
    assert!(
        limitations(&report).is_empty(),
        "{:?}",
        report.target.limitations
    );
    assert_eq!(
        component(&report, "src/lib/admin.ts"),
        Some((Runtime::Browser, Basis::BuildOutput))
    );
    assert_eq!(
        component(&report, "src/lib/unused.ts"),
        Some((Runtime::Unknown, Basis::BuildOutput))
    );
    assert_eq!(
        unused(&report),
        Some((
            RuleId::SecretInSourceCode,
            Severity::High,
            Confidence::Certain
        ))
    );

    let service_role = report
        .findings
        .iter()
        .find(|finding| finding.rule == RuleId::SupabaseServiceRoleInBrowser);
    assert_eq!(
        service_role.map(|finding| finding.confidence),
        Some(Confidence::Certain)
    );
    assert_eq!(
        service_role.map(|finding| finding.origin.inputs.clone()),
        Some(vec![InputKind::Source, InputKind::BuildOutput])
    );
    let steps: Vec<(&str, Option<EdgeKind>)> = service_role
        .map(|finding| {
            finding
                .evidence
                .iter()
                .map(|step| (step.label.as_str(), step.via))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        steps,
        vec![
            ("index-DWa_saO0.js", None),
            ("admin.ts", Some(EdgeKind::BuiltFrom)),
            ("VITE_SUPABASE_SERVICE_ROLE_KEY", Some(EdgeKind::UsesConfig)),
        ]
    );

    let chunk_secret = report.findings.iter().find(|finding| {
        finding.node.as_str() == "secret:dist/assets/Settings-BXJJZpdy.js:stripeSecretKey:1"
    });
    assert_eq!(
        chunk_secret.map(|finding| (finding.rule, finding.confidence)),
        Some((RuleId::SecretInBrowserCode, Confidence::Certain))
    );
    let source_step = chunk_secret
        .and_then(|finding| finding.evidence.get(1))
        .and_then(|step| step.location.as_ref())
        .map(|location| (location.path.as_str(), location.line, location.column));
    assert_eq!(source_step, Some(("src/pages/Settings.ts", 3, 9)));
    assert!(
        report
            .edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::BuiltFrom
                && edge.from.as_str() == "file:dist/assets/Settings-BXJJZpdy.js"
                && edge.to.as_str() == "file:src/pages/Settings.ts")
    );

    let json = serde_json::to_string(&report).unwrap_or_default();
    assert!(!json.contains(&*project.root.to_string_lossy()));
    assert!(!json.contains(&stripe_key()));
}

#[test]
fn stale_build_output_is_not_used() {
    let project = TempProject::new("vite-stale");
    write_vite_sources(&project);
    write_vite_build(&project);
    let later = SystemTime::now() + Duration::from_secs(60);
    let touched = File::options()
        .write(true)
        .open(project.root.join("src/lib/shared.ts"))
        .and_then(|file| file.set_modified(later));
    assert!(touched.is_ok(), "{touched:?}");

    let result = scan(&project, "dist");
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert_eq!(limitations(&report), vec![LimitationCode::BuildOutputStale]);
    assert_eq!(
        component(&report, "src/lib/admin.ts"),
        Some((Runtime::Browser, Basis::Path))
    );
    assert!(
        report
            .edges
            .iter()
            .all(|edge| edge.kind != EdgeKind::BuiltFrom)
    );
}

fn write_next_sources(project: &TempProject) {
    project.write("next.config.mjs", "export default {};\n");
    project.write(
        "src/app/page.jsx",
        "import { TodoList } from \"../components/TodoList\";\n\nexport default function Page() {\n  return <TodoList />;\n}\n",
    );
    project.write(
        "src/components/TodoList.jsx",
        "\"use client\";\n\nimport { purge } from \"../lib/admin\";\n\nexport function TodoList() {\n  return <button onClick={() => purge()}>x</button>;\n}\n",
    );
    project.write(
        "src/lib/admin.js",
        "const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n\nexport async function purge() {\n  return fetch(\"/rest/v1/todos\", { headers: { apikey: key } });\n}\n",
    );
    project.write(
        "src/lib/orphan.js",
        "const url = process.env.SUPABASE_SERVICE_ROLE_KEY;\nexport const value = url;\n",
    );
}

fn write_next_build(project: &TempProject) {
    project.write(".next/BUILD_ID", "S96k6rQ0hs5UqnNsfHyGn");
    project.write(
        ".next/required-server-files.json",
        r#"{"version":1,"config":{"distDir":".next"},"appDir":"/ci/app","relativeAppDir":"","files":[],"ignore":[]}"#,
    );
    project.write(
        ".next/server/app/page_client-reference-manifest.js",
        "globalThis.__RSC_MANIFEST = globalThis.__RSC_MANIFEST || {};\nglobalThis.__RSC_MANIFEST[\"/page\"] = {\"moduleLoading\":{\"prefix\":\"\"},\"clientModules\":{\"[project]/node_modules/next/dist/esm/client/components/layout-router.js\":{},\"[project]/src/components/TodoList.jsx\":{}}};\n",
    );
    project.write(
        ".next/server/chunks/ssr/_0drz0u8-t85q-._.js",
        "module.exports=1;\n//# sourceMappingURL=_0drz0u8-t85q-._.js.map\n",
    );
    project.write(
        ".next/server/chunks/ssr/_0drz0u8-t85q-._.js.map",
        r#"{"version":3,"sources":[],"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["../../../../src/lib/admin.js","../../../../src/lib/orphan.js","../../../../src/components/TodoList.jsx"],"mappings":"AAAA"}}]}"#,
    );
}

#[test]
fn next_build_output_confirms_client_boundaries_and_server_files() {
    let project = TempProject::new("next-build");
    write_next_sources(&project);
    write_next_build(&project);
    let result = scan(&project, ".next");
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };

    assert!(report.target.inputs.contains(&Input::BuildOutput {
        path: ".next".to_owned(),
        tool: BuildTool::Next,
    }));
    assert_eq!(
        limitations(&report),
        vec![LimitationCode::BuildOutputWithoutSourceMaps]
    );
    assert_eq!(
        component(&report, "src/lib/admin.js"),
        Some((Runtime::Browser, Basis::Imports))
    );
    assert_eq!(
        component(&report, "src/lib/orphan.js"),
        Some((Runtime::Server, Basis::BuildOutput))
    );
    let service_role = report
        .findings
        .iter()
        .find(|finding| finding.rule == RuleId::SupabaseServiceRoleInBrowser);
    assert_eq!(
        service_role.map(|finding| finding.confidence),
        Some(Confidence::Likely)
    );

    project.write(
        ".next/static/chunks/0im9a9sy3oza0.js",
        "(globalThis.TURBOPACK=globalThis.TURBOPACK||[]).push([]);\n//# sourceMappingURL=3s0mx51nrvfsy.js.map\n",
    );
    project.write(
        ".next/static/chunks/3s0mx51nrvfsy.js.map",
        r#"{"version":3,"sources":["turbopack:///[project]/src/lib/admin.js","turbopack:///[project]/src/app/data:5afd0f <text/javascript>","turbopack:///[project]/src/components/TodoList.jsx"],"names":[],"mappings":"AAAA"}"#,
    );
    let result = scan(&project, ".next");
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert!(
        limitations(&report).is_empty(),
        "{:?}",
        report.target.limitations
    );
    assert_eq!(
        component(&report, "src/lib/admin.js"),
        Some((Runtime::Browser, Basis::BuildOutput))
    );
    let service_role = report
        .findings
        .iter()
        .find(|finding| finding.rule == RuleId::SupabaseServiceRoleInBrowser);
    assert_eq!(
        service_role.map(|finding| finding.confidence),
        Some(Confidence::Certain)
    );
}

#[test]
fn build_output_must_be_a_recognized_folder_inside_the_project() {
    let project = TempProject::new("build-errors");
    write_vite_sources(&project);
    project.write("other/readme.txt", "x\n");
    let outside = TempProject::new("build-outside");
    outside.write("dist/.vite/manifest.json", "{}");

    let rejected =
        |result: Result<ScanReport, ScanError>| matches!(result, Err(ScanError::BuildOutput(_)));
    assert!(rejected(scan(&project, "missing")));
    assert!(rejected(scan(&project, "src/main.ts")));
    assert!(rejected(scan(&project, ".")));
    assert!(rejected(seethru_analyzer::scan_with(
        &project.root,
        ScanOptions {
            build_output: Some(outside.root.join("dist")),
            ..ScanOptions::default()
        },
    )));

    let plain = TempProject::new("build-unknown");
    plain.write("src/app.ts", "export {};\n");
    plain.write("out/app.js", "var a=1;\n");
    assert!(rejected(scan(&plain, "out")));

    #[cfg(unix)]
    {
        let linked =
            std::os::unix::fs::symlink(outside.root.join("dist"), project.root.join("dist"));
        assert!(linked.is_ok(), "{linked:?}");
        assert!(rejected(scan(&project, "dist")));
    }
}
