mod common;

use std::path::PathBuf;

use common::TempProject;
use seethru_analyzer::{ScanError, ScanOptions};
use seethru_core::{
    Confidence, Ecosystem, EdgeKind, Input, InputKind, LimitationCode, NodeKind, RuleId,
    ScanReport, Severity, Unit,
};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rust-vault")
}

fn with_output(paths: &[PathBuf]) -> ScanOptions {
    ScanOptions {
        llvm_ir: paths.to_vec(),
        ..ScanOptions::default()
    }
}

fn codes(report: &ScanReport) -> Vec<LimitationCode> {
    report.target.limitations.iter().map(|l| l.code).collect()
}

fn divisions(report: &ScanReport) -> Vec<(String, u32, Confidence)> {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule == RuleId::SecretDependentDivision)
        .filter_map(|finding| {
            let location = finding.location.as_ref()?;
            Some((location.path.clone(), location.line, finding.confidence))
        })
        .collect()
}

const UNIT: &str = r#"target triple = "aarch64-unknown-none"

define i32 @keep(ptr %key, i32 %m) !dbg !4 {
start:
  %v = load i32, ptr %key, align 4, !dbg !7
  %r = urem i32 %v, %m, !dbg !7
  store volatile i32 0, ptr %key, align 4, !dbg !8
  ret i32 %r, !dbg !7
}

define i32 @hygiene(ptr %state, i32 %m) !dbg !5 {
start:
  %v = load i32, ptr %state, align 4, !dbg !9
  %r = urem i32 %v, %m, !dbg !9
  store volatile i32 0, ptr %state, align 4, !dbg !11
  ret i32 %r, !dbg !9
}

define i32 @fixed(ptr %key) !dbg !12 {
start:
  %v = load i32, ptr %key, align 4, !dbg !13
  %r = urem i32 %v, 3329, !dbg !13
  store volatile i32 0, ptr %key, align 4, !dbg !14
  ret i32 %r, !dbg !13
}

define i32 @open(ptr %public, i32 %m) !dbg !15 {
start:
  %v = load i32, ptr %public, align 4, !dbg !16
  %r = urem i32 %v, %m, !dbg !16
  ret i32 %r, !dbg !16
}

define i32 @helper(ptr %data, i32 %m) !dbg !17 {
start:
  %v = load i32, ptr %data, align 4, !dbg !18
  %r = urem i32 %v, %m, !dbg !18
  ret i32 %r, !dbg !18
}

define i32 @caller(ptr %key, i32 %m) !dbg !19 {
start:
  %r = call i32 @helper(ptr noundef %key, i32 %m), !dbg !20
  call void @wipe(ptr %key), !dbg !21
  ret i32 %r, !dbg !20
}

define void @wipe(ptr %target) !dbg !22 {
start:
  store volatile i32 0, ptr %target, align 4, !dbg !23
  ret void, !dbg !23
}

!1 = !DIFile(filename: "src/lib.rs", directory: "")
!4 = distinct !DISubprogram(name: "keep", file: !1, line: 1)
!5 = distinct !DISubprogram(name: "hygiene", file: !1, line: 5)
!6 = distinct !DISubprogram(name: "drop", file: !1, line: 9)
!7 = !DILocation(line: 2, column: 5, scope: !4)
!8 = !DILocation(line: 3, column: 5, scope: !4)
!9 = !DILocation(line: 6, column: 5, scope: !5)
!10 = !DILocation(line: 7, column: 5, scope: !5)
!11 = !DILocation(line: 10, column: 9, scope: !6, inlinedAt: !10)
!12 = distinct !DISubprogram(name: "fixed", file: !1, line: 12)
!13 = !DILocation(line: 13, column: 5, scope: !12)
!14 = !DILocation(line: 14, column: 5, scope: !12)
!15 = distinct !DISubprogram(name: "open", file: !1, line: 16)
!16 = !DILocation(line: 17, column: 5, scope: !15)
!17 = distinct !DISubprogram(name: "helper", file: !1, line: 19)
!18 = !DILocation(line: 20, column: 5, scope: !17)
!19 = distinct !DISubprogram(name: "caller", file: !1, line: 22)
!20 = !DILocation(line: 23, column: 5, scope: !19)
!21 = !DILocation(line: 24, column: 5, scope: !19)
!22 = distinct !DISubprogram(name: "wipe", file: !1, line: 26)
!23 = !DILocation(line: 27, column: 5, scope: !22)
"#;

const LISTING: &str = "\t.file\t1 \"src/lib.rs\"\nkeep:\n\t.loc\t1 2 5\n\tudiv\tw0, w0, w1\n\tret\nfixed:\n\t.loc\t1 13 5\n\tumull\tx0, w0, w1\n\tret\nhelper:\n\t.loc\t1 20 5\n\tudiv\tw0, w0, w1\n\tret\n";

fn project(name: &str) -> TempProject {
    let project = TempProject::new(name);
    project.write(
        "Cargo.toml",
        "[package]\nname = \"unit\"\nversion = \"0.1.0\"\n",
    );
    project.write("src/lib.rs", &"// line\n".repeat(30));
    project.write("out/unit.ll", UNIT);
    project
}

#[test]
fn fixture_reports_the_division_of_a_wiped_value_and_not_the_public_one() {
    let root = fixture();
    let result = seethru_analyzer::scan_with(&root, with_output(&[root.join("compiled")]));
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert_eq!(report.target.ecosystems, [Ecosystem::Cargo]);
    assert_eq!(
        divisions(&report),
        [("vault/src/lib.rs".to_owned(), 18, Confidence::Likely)]
    );
    let finding = &report.findings[0];
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.cwe, [208]);
    assert_eq!(
        finding.origin.inputs,
        [InputKind::Source, InputKind::CompiledOutput]
    );
    assert_eq!(
        finding.id,
        "secret-dependent-division:file:vault/src/lib.rs:1"
    );
    assert!(report.target.inputs.contains(&Input::CompiledOutput {
        path: "compiled".to_owned(),
        files: 1,
        functions: 4,
        machine_code: true,
    }));
    assert_eq!(codes(&report), [LimitationCode::CompiledChecksPartial]);
    let package = report.nodes.iter().find(|node| {
        matches!(
            node.kind,
            NodeKind::Component {
                unit: Unit::Package,
                ..
            }
        )
    });
    assert_eq!(package.map(|node| node.label.as_str()), Some("vault"));
    assert!(report.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Contains
            && edge.from.as_str() == "package:cargo:vault"
            && edge.to.as_str() == "file:vault/src/lib.rs"
    }));
}

#[test]
fn a_rust_project_without_compiled_output_says_what_was_not_checked() {
    let result = seethru_analyzer::scan(&fixture());
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(codes(&report), [LimitationCode::CompiledOutputNotRead]);
}

#[test]
fn only_explicit_wipes_make_a_value_secret() {
    let project = project("compiled-explicit");
    let result =
        seethru_analyzer::scan_with(&project.root, with_output(&[project.root.join("out")]));
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert_eq!(
        divisions(&report),
        [
            ("src/lib.rs".to_owned(), 2, Confidence::Review),
            ("src/lib.rs".to_owned(), 13, Confidence::Review),
            ("src/lib.rs".to_owned(), 20, Confidence::Review),
        ]
    );
    assert_eq!(
        codes(&report),
        [
            LimitationCode::CompiledChecksPartial,
            LimitationCode::CompiledOutputWithoutMachineCode
        ]
    );
    let through_call = report
        .findings
        .iter()
        .find(|finding| finding.location.as_ref().is_some_and(|l| l.line == 20));
    let lines: Vec<u32> = through_call
        .into_iter()
        .flat_map(|finding| &finding.evidence)
        .filter_map(|step| step.location.as_ref().map(|l| l.line))
        .collect();
    assert_eq!(lines, [20]);
}

#[test]
fn machine_code_confirms_a_division_or_shows_the_compiler_removed_it() {
    let project = project("compiled-listing");
    project.write("out/unit.s", LISTING);
    let result =
        seethru_analyzer::scan_with(&project.root, with_output(&[project.root.join("out")]));
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert_eq!(
        divisions(&report),
        [
            ("src/lib.rs".to_owned(), 2, Confidence::Likely),
            ("src/lib.rs".to_owned(), 20, Confidence::Likely),
        ]
    );
    assert_eq!(codes(&report), [LimitationCode::CompiledChecksPartial]);
}

#[test]
fn output_that_points_outside_the_project_is_left_out() {
    let project = project("compiled-outside");
    project.write(
        "out/unit.ll",
        &UNIT.replace(
            "filename: \"src/lib.rs\"",
            "filename: \"../elsewhere/lib.rs\"",
        ),
    );
    let result =
        seethru_analyzer::scan_with(&project.root, with_output(&[project.root.join("out")]));
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert!(codes(&report).contains(&LimitationCode::CompiledOutputPartlyRead));
}

#[test]
fn output_without_an_explicit_wipe_says_nothing_was_treated_as_secret() {
    let project = project("compiled-no-wipe");
    project.write(
        "out/unit.ll",
        &UNIT.replace("store volatile i32 0", "store i32 0"),
    );
    let result =
        seethru_analyzer::scan_with(&project.root, with_output(&[project.root.join("out")]));
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert!(codes(&report).contains(&LimitationCode::CompiledOutputWithoutWipes));
}

#[test]
fn finding_ids_count_within_the_file_and_do_not_carry_line_numbers() {
    let project = project("compiled-ids");
    let result =
        seethru_analyzer::scan_with(&project.root, with_output(&[project.root.join("out")]));
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "secret-dependent-division:file:src/lib.rs:1",
            "secret-dependent-division:file:src/lib.rs:2",
            "secret-dependent-division:file:src/lib.rs:3",
        ]
    );
}

#[test]
fn compiled_output_must_be_a_folder_or_file_with_ir() {
    let project = project("compiled-bad");
    project.write("empty/readme.txt", "nothing");
    for path in ["empty", "missing", "src/lib.rs"] {
        let result =
            seethru_analyzer::scan_with(&project.root, with_output(&[project.root.join(path)]));
        assert!(
            matches!(result, Err(ScanError::CompiledOutput(_))),
            "{path}: {result:?}"
        );
    }
}

#[test]
fn cargo_workspace_becomes_packages_and_dependency_edges() {
    let project = TempProject::new("cargo-workspace");
    project.write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"app\", \"libs/*\"]\nexclude = [\"libs/old\"]\n\n[workspace.dependencies]\ncore-lib = { path = \"libs/core-lib\" }\n",
    );
    project.write(
        "app/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncore-lib = { workspace = true }\nremote = { git = \"https://example.invalid/remote.git\", branch = \"main\" }\npinned = { git = \"https://example.invalid/pinned.git\", rev = \"0123abc\" }\nloose = \"*\"\nexact = \"1.2.3\"\n",
    );
    project.write(
        "libs/core-lib/Cargo.toml",
        "[package]\nname = \"core-lib\"\nversion = \"0.1.0\"\n",
    );
    project.write(
        "libs/old/Cargo.toml",
        "[package]\nname = \"old\"\nversion = \"0.1.0\"\n",
    );
    project.write("target/debug/build/notes.txt", "build output");
    let result = seethru_analyzer::scan(&project.root);
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert_eq!(report.target.ecosystems, [Ecosystem::Cargo]);
    let mut packages: Vec<&str> = report
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                node.kind,
                NodeKind::Component {
                    unit: Unit::Package,
                    ..
                }
            )
        })
        .map(|node| node.label.as_str())
        .collect();
    packages.sort_unstable();
    assert_eq!(packages, ["app", "core-lib"]);
    assert!(report.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Imports
            && edge.from.as_str() == "package:cargo:app"
            && edge.to.as_str() == "package:cargo:core-lib"
    }));
    let loose: Vec<(&str, u32)> = report
        .findings
        .iter()
        .filter(|finding| finding.rule == RuleId::CargoDependencyNotPinned)
        .map(|finding| {
            (
                finding.node.as_str(),
                finding.location.as_ref().map_or(0, |l| l.line),
            )
        })
        .collect();
    assert_eq!(
        loose,
        [
            ("dependency:cargo:app:remote", 7),
            ("dependency:cargo:app:loose", 9)
        ]
    );
    assert_eq!(report.target.files_scanned, 4);

    project.write("Cargo.lock", "version = 4\n");
    let locked = seethru_analyzer::scan(&project.root);
    assert!(locked.is_ok(), "{locked:?}");
    let Ok(locked) = locked else { return };
    assert!(locked.findings.is_empty(), "{:?}", locked.findings);
}

#[test]
fn a_project_seethru_does_not_recognize_says_so() {
    let project = TempProject::new("unknown-kind");
    project.write("notes.txt", "hello");
    project.write("tool.py", "print('hi')\n");
    let result = seethru_analyzer::scan(&project.root);
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert_eq!(codes(&report), [LimitationCode::ProjectKindNotRecognized]);
}
