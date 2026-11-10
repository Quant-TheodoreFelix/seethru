mod common;

use std::path::PathBuf;

use common::TempProject;
use seethru_analyzer::{ScanError, ScanOptions};
use seethru_core::{
    AssemblyLine, Confidence, DivisionLine, Ecosystem, EdgeKind, Input, InputKind, LimitationCode,
    MachineCode, NodeKind, RuleId, ScanReport, Severity, Unit,
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

fn division_line(path: &str, line: u32, secret: bool, assembly: bool) -> DivisionLine {
    DivisionLine {
        path: path.to_owned(),
        line,
        secret,
        assembly,
    }
}

fn assembly_line(line: u32, divides: bool, branches: bool, secret: bool) -> AssemblyLine {
    AssemblyLine {
        path: "src/lib.rs".to_owned(),
        line,
        divides,
        branches,
        secret,
    }
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
    assert_eq!(
        codes(&report),
        [
            LimitationCode::CompiledChecksPartial,
            LimitationCode::OutsideEntriesNotFound
        ]
    );
    assert_eq!(
        report.target.machine_code,
        Some(MachineCode {
            divisions: 2,
            division_lines: vec![
                division_line("vault/src/lib.rs", 18, true, false),
                division_line("vault/src/lib.rs", 40, false, false),
            ],
            ..MachineCode::default()
        })
    );
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
    assert_eq!(report.target.machine_code, None);
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

const SHARED_LINE: &str = r#"SEALED {
start:
  %v = load i32, ptr %key, align 4, !dbg !8
  %r = urem i32 %v, 3329, !dbg !8
  store volatile i32 0, ptr %key, align 4, !dbg !9
  ret i32 %r, !dbg !9
}

OPEN {
start:
  %v = load i32, ptr %public, align 4, !dbg !11
  %r = urem i32 %v, %m, !dbg !11
  ret i32 %r, !dbg !11
}

!1 = !DIFile(filename: "src/lib.rs", directory: "")
!4 = distinct !DISubprogram(name: "sealed", file: !1, line: 4)
!5 = distinct !DISubprogram(name: "open", file: !1, line: 8)
!6 = distinct !DISubprogram(name: "shared", file: !1, line: 1)
!7 = !DILocation(line: 5, column: 5, scope: !4)
!8 = !DILocation(line: 2, column: 5, scope: !6, inlinedAt: !7)
!9 = !DILocation(line: 6, column: 5, scope: !4)
!10 = !DILocation(line: 9, column: 5, scope: !5)
!11 = !DILocation(line: 2, column: 5, scope: !6, inlinedAt: !10)
"#;

fn shared_line(layout: &str, sealed: &str, open: &str) -> String {
    let unit = SHARED_LINE
        .replace("SEALED", &format!("define i32 @{sealed}(ptr %key) !dbg !4"))
        .replace(
            "OPEN",
            &format!("define i32 @{open}(ptr %public, i32 %m) !dbg !5"),
        );
    let triple = if layout.contains("m:o") {
        "arm64-apple-macosx11.0.0"
    } else {
        "aarch64-unknown-none"
    };
    format!("target datalayout = \"{layout}\"\ntarget triple = \"{triple}\"\n\n{unit}")
}

fn shared_report(name: &str, unit: &str, listing: &str) -> Option<ScanReport> {
    let project = project(name);
    project.write("out/unit.ll", unit);
    project.write("out/unit.s", listing);
    let result =
        seethru_analyzer::scan_with(&project.root, with_output(&[project.root.join("out")]));
    assert!(result.is_ok(), "{result:?}");
    result.ok()
}

fn scan_shared_line(name: &str, unit: &str, listing: &str) -> Vec<(String, u32, Confidence)> {
    shared_report(name, unit, listing)
        .map(|report| divisions(&report))
        .unwrap_or_default()
}

#[test]
fn a_division_instruction_in_another_function_does_not_confirm_this_one() {
    let unit = shared_line("e-m:e-i64:64", "sealed", "open");
    let listing = "\t.file\t1 \"src/lib.rs\"\n\t.type\tsealed,@function\nsealed:\n.Lfunc_begin0:\n\t.loc\t1 2 5\n\tumull\tx0, w0, w1\n\tret\n\t.type\topen,@function\nopen:\n.Lfunc_begin1:\n\t.loc\t1 2 5\n.LBB1_1:\n\tudiv\tw0, w0, w1\n\tret\n";
    assert_eq!(scan_shared_line("compiled-shared-line", &unit, listing), []);

    let kept = listing.replace("umull\tx0, w0, w1", "udiv\tw0, w0, w1");
    assert_eq!(
        scan_shared_line("compiled-shared-line-kept", &unit, &kept),
        [("src/lib.rs".to_owned(), 2, Confidence::Likely)]
    );

    let by_variable = unit.replace("urem i32 %v, 3329", "urem i32 %v, %v");
    assert_eq!(
        scan_shared_line("compiled-shared-line-variable", &by_variable, listing),
        [("src/lib.rs".to_owned(), 2, Confidence::Review)]
    );
}

#[test]
fn functions_are_matched_across_naming_styles_of_the_machine_code() {
    let mach_o = shared_line("e-m:o-i64:64-i128:128-n32:64-S128-Fn32", "sealed", "open");
    let listing = "\t.file\t1 \"src/lib.rs\"\n\t.globl\t_sealed\n_sealed:\nLfunc_begin0:\n\t.loc\t1 2 5\n\tumull\tx0, w0, w1\n\tret\n\t.globl\t_open\n_open:\nLfunc_begin1:\n\t.loc\t1 2 5\nLBB1_1:\n\tudiv\tw0, w0, w1\nltmp3:\n\tret\n";
    assert_eq!(
        scan_shared_line("compiled-names-mach-o", &mach_o, listing),
        []
    );

    let mangled = shared_line(
        "e-m:e-i64:64",
        "\"_ZN4unit21Seal$LT$T$GT$6sealed17h0E\"",
        "\"_ZN4unit4open17h1E\"",
    );
    let listing = "\t.file\t1 \"src/lib.rs\"\n_ZN4unit21Seal$LT$T$GT$6sealed17h0E:\n\t.loc\t1 2 5\n\tumull\tx0, w0, w1\n\tret\n\"_ZN4unit4open17h1E\":\n\t.loc\t1 2 5\n\tudiv\tw0, w0, w1\n\tret\n";
    assert_eq!(
        scan_shared_line("compiled-names-mangled", &mangled, listing),
        []
    );

    let quoted = "\t.file\t1 \"src/lib.rs\"\n\"_ZN4unit21Seal$LT$T$GT$6sealed17h0E\":\n\t.loc\t1 2 5\n\tudiv\tw0, w0, w1\n\tret\n_ZN4unit4open17h1E:\n\t.loc\t1 2 5\n\tumull\tx0, w0, w1\n\tret\n";
    assert_eq!(
        scan_shared_line("compiled-names-quoted", &mangled, quoted),
        [("src/lib.rs".to_owned(), 2, Confidence::Likely)]
    );
}

#[test]
fn machine_code_with_unknown_function_names_is_still_matched_by_line() {
    let unit = shared_line("e-m:e-i64:64", "sealed", "open");
    let listing = "\t.file\t1 \"src/lib.rs\"\nfirst$entry:\n\t.loc\t1 2 5\n\tumull\tx0, w0, w1\n\tret\nsecond$entry:\n\t.loc\t1 2 5\n\tudiv\tw0, w0, w1\n\tret\n";
    let Some(report) = shared_report("compiled-names-unknown", &unit, listing) else {
        return;
    };
    assert_eq!(
        divisions(&report),
        [("src/lib.rs".to_owned(), 2, Confidence::Likely)]
    );
    assert_eq!(
        report.target.machine_code,
        Some(MachineCode {
            divisions: 1,
            division_lines: vec![division_line("src/lib.rs", 2, true, false)],
            ..MachineCode::default()
        })
    );
}

#[test]
fn an_unknown_processor_never_makes_a_finding_disappear() {
    let unit = shared_line("e-m:e-i64:64", "sealed", "open")
        .replace("aarch64-unknown-none", "powerpc64le-unknown-linux-gnu");
    let listing = "\t.file\t1 \"src/lib.rs\"\nsealed:\n\t.loc\t1 2 5\n\tdivdu\t3, 3, 4\n\tblr\nopen:\n\t.loc\t1 2 5\n\tdivdu\t3, 3, 4\n\tblr\n";
    let Some(report) = shared_report("compiled-unknown-processor", &unit, listing) else {
        return;
    };
    assert_eq!(
        divisions(&report),
        [("src/lib.rs".to_owned(), 2, Confidence::Review)]
    );
    assert!(codes(&report).contains(&LimitationCode::MachineCodeProcessorNotKnown));
    assert_eq!(report.target.machine_code, Some(MachineCode::default()));

    let known = shared_line("e-m:e-i64:64", "sealed", "open");
    let Some(report) = shared_report("compiled-known-processor", &known, listing) else {
        return;
    };
    assert_eq!(divisions(&report), []);
    assert!(!codes(&report).contains(&LimitationCode::MachineCodeProcessorNotKnown));
}

#[test]
fn files_without_machine_code_are_named_next_to_the_list() {
    let project = project("compiled-mixed");
    project.write("out/unit.s", LISTING);
    project.write(
        "out/other.ll",
        &shared_line("e-m:e-i64:64", "sealed_twice", "open_twice"),
    );
    let result =
        seethru_analyzer::scan_with(&project.root, with_output(&[project.root.join("out")]));
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert!(codes(&report).contains(&LimitationCode::CompiledOutputWithoutMachineCode));
    let machine = report.target.machine_code.unwrap_or_default();
    assert_eq!(machine.divisions, 2);
    assert_eq!(
        machine.division_lines,
        [
            division_line("src/lib.rs", 2, true, false),
            division_line("src/lib.rs", 20, true, false),
        ]
    );
}

#[test]
fn a_long_machine_code_list_is_cut_and_said_to_be_partial() {
    let mut body = String::new();
    let mut places = String::new();
    let mut listing = String::from("\t.file\t1 \"src/lib.rs\"\nmany:\n");
    for line in 1..=501u32 {
        let id = line + 10;
        body += &format!("  %r{line} = urem i32 %a, %b, !dbg !{id}\n");
        places += &format!("!{id} = !DILocation(line: {line}, column: 5, scope: !4)\n");
        listing += &format!("\t.loc\t1 {line} 5\n\tudiv\tw0, w0, w1\n");
    }
    let unit = format!(
        "target triple = \"aarch64-unknown-none\"\n\ndefine i32 @many(i32 %a, i32 %b) !dbg !4 {{\nstart:\n{body}  ret i32 %r1\n}}\n\n!1 = !DIFile(filename: \"src/lib.rs\", directory: \"\")\n!4 = distinct !DISubprogram(name: \"many\", file: !1, line: 1)\n{places}"
    );
    let Some(report) = shared_report("compiled-long-list", &unit, &listing) else {
        return;
    };
    assert!(codes(&report).contains(&LimitationCode::CompiledOutputPartlyRead));
    let machine = report.target.machine_code.unwrap_or_default();
    assert_eq!(machine.divisions, 501);
    assert_eq!(machine.divisions_without_line, 0);
    assert_eq!(machine.division_lines.len(), 500);
}

#[test]
fn every_division_in_the_machine_code_is_listed_at_the_line_that_reaches_it() {
    let unit = shared_line("e-m:e-i64:64", "sealed", "open")
        .replace(
            "!6 = distinct !DISubprogram(name: \"shared\", file: !1, line: 1)",
            "!6 = distinct !DISubprogram(name: \"shared\", file: !12, line: 1)\n!12 = !DIFile(filename: \"num.rs\", directory: \"/toolchain/core\")",
        )
        .replace("urem i32 %v, 3329", "urem i32 %v, %v");
    let listing = "\t.file\t1 \"src/lib.rs\"\n\t.file\t2 \"/toolchain/core\" \"num.rs\"\nsealed:\n\t.loc\t2 2 5\n\tudiv\tw0, w0, w1\n\tret\nopen:\n\t.loc\t2 2 5\n\tudiv\tw0, w0, w1\n\tudiv\tw2, w2, w1\n\tret\nOUTLINED_FUNCTION_0:\n\tudiv\tw0, w0, w1\n\tret\nalone:\n\t.loc\t2 2 5\n\tudiv\tw0, w0, w1\n\tret\n";
    let project = project("compiled-machine-list");
    project.write("out/unit.ll", &unit);
    project.write("out/unit.s", listing);
    let result =
        seethru_analyzer::scan_with(&project.root, with_output(&[project.root.join("out")]));
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert_eq!(
        divisions(&report),
        [("src/lib.rs".to_owned(), 5, Confidence::Likely)]
    );
    assert_eq!(
        report.target.machine_code,
        Some(MachineCode {
            divisions: 5,
            divisions_without_line: 2,
            division_lines: vec![
                division_line("src/lib.rs", 5, true, false),
                division_line("src/lib.rs", 9, false, false),
            ],
            ..MachineCode::default()
        })
    );
    let text = format!("{:?}", report.target.machine_code);
    assert!(!text.contains("toolchain"), "{text}");
}

const BY_HAND: &str = r#"target triple = "TRIPLE"

define i32 @reduce(ptr %key, i32 %m) !dbg !4 {
start:
  %v = load i32, ptr %key, align 4, !dbg !7
  %q = tail call i32 asm sideeffect inteldialect "xor edx, edx\0Adiv ${1:k}", "={ax},r,0,~{dx},~{dirflag},~{fpsr},~{flags}"(i32 %m, i32 %v) #1, !dbg !8, !srcloc !3
  store volatile i32 0, ptr %key, align 4, !dbg !9
  ret i32 %q, !dbg !9
}

define i32 @spin(i32 %n) !dbg !5 {
start:
  %r = tail call i32 asm sideeffect inteldialect "2:\0Adec ${0:k}\0Ajnz 2b", "=&r,0,~{dirflag},~{fpsr},~{flags}"(i32 %n) #1, !dbg !10, !srcloc !3
  ret i32 %r, !dbg !10
}

define i32 @keep(ptr %key, i32 %m) !dbg !6 {
start:
  %v = load i32, ptr %key, align 4, !dbg !11
  %r = urem i32 %v, %m, !dbg !11
  store volatile i32 0, ptr %key, align 4, !dbg !12
  ret i32 %r, !dbg !11
}

!1 = !DIFile(filename: "src/lib.rs", directory: "")
!3 = !{i64 100}
!4 = distinct !DISubprogram(name: "reduce", file: !1, line: 2)
!5 = distinct !DISubprogram(name: "spin", file: !1, line: 10)
!6 = distinct !DISubprogram(name: "keep", file: !1, line: 18)
!7 = !DILocation(line: 3, column: 5, scope: !4)
!8 = !DILocation(line: 4, column: 9, scope: !4)
!9 = !DILocation(line: 5, column: 5, scope: !4)
!10 = !DILocation(line: 12, column: 9, scope: !5)
!11 = !DILocation(line: 20, column: 5, scope: !6)
!12 = !DILocation(line: 21, column: 5, scope: !6)
"#;

const BY_HAND_LISTING: &str = "\t.file\t1 \"src/lib.rs\"\nreduce:\n\t.loc\t1 3 5\n\tmovl\t(%rdi), %eax\n\t.loc\t1 4 9\n\t#APP\n\n\txorl\t%edx, %edx\n\tdivl\t%esi\n\n\t#NO_APP\n\tretq\nspin:\n\t.loc\t1 12 9\n\t#APP\n\n.Ltmp1:\n\tdecl\t%eax\n\tjne\t.Ltmp1\n\n\t#NO_APP\n\tretq\nkeep:\n\t.loc\t1 20 5\n\tdivl\t%esi\n\tretq\nstray:\n\t#APP\n\tnop\n\t#NO_APP\n\tretq\n";

fn by_hand(name: &str, unit: &str) -> Option<ScanReport> {
    let project = project(name);
    project.write("out/unit.ll", unit);
    project.write("out/unit.s", BY_HAND_LISTING);
    let result =
        seethru_analyzer::scan_with(&project.root, with_output(&[project.root.join("out")]));
    assert!(result.is_ok(), "{result:?}");
    result.ok()
}

#[test]
fn hand_written_assembly_is_read_from_the_machine_code() {
    let unit = BY_HAND.replace("TRIPLE", "x86_64-unknown-none-elf");
    let Some(report) = by_hand("compiled-by-hand", &unit) else {
        return;
    };
    let found: Vec<(&str, u32, Confidence)> = report
        .findings
        .iter()
        .filter_map(|f| Some((f.id.as_str(), f.location.as_ref()?.line, f.confidence)))
        .collect();
    assert_eq!(
        found,
        [
            (
                "secret-dependent-division:file:src/lib.rs:asm:1",
                4,
                Confidence::Review
            ),
            (
                "secret-dependent-division:file:src/lib.rs:1",
                20,
                Confidence::Likely
            ),
        ]
    );
    let in_block = report.findings.iter().find(|f| f.id.ends_with(":asm:1"));
    let title = in_block.map(|f| f.title.en.as_str()).unwrap_or_default();
    assert!(title.contains("Hand-written assembly"), "{title}");
    assert_eq!(
        report.target.machine_code,
        Some(MachineCode {
            divisions: 2,
            divisions_without_line: 0,
            division_lines: vec![
                division_line("src/lib.rs", 4, true, true),
                division_line("src/lib.rs", 20, true, false),
            ],
            assembly_blocks: 3,
            assembly_blocks_without_line: 1,
            assembly_lines: vec![
                assembly_line(4, true, false, true),
                assembly_line(12, false, true, false),
            ],
        })
    );
    assert_eq!(codes(&report), [LimitationCode::CompiledChecksPartial]);
}

#[test]
fn assembly_seethru_cannot_read_is_named_as_not_checked() {
    let outside = format!(
        "module asm \".globl raw\"\nmodule asm \"raw:\"\n{}",
        BY_HAND.replace("TRIPLE", "x86_64-unknown-none-elf")
    );
    let Some(report) = by_hand("compiled-by-hand-outside", &outside) else {
        return;
    };
    assert!(codes(&report).contains(&LimitationCode::AssemblyOutsideFunctionsNotRead));
    assert!(!codes(&report).contains(&LimitationCode::MachineCodeProcessorNotKnown));

    let unknown = BY_HAND.replace("TRIPLE", "mips64-unknown-linux-gnuabi64");
    let Some(report) = by_hand("compiled-by-hand-unknown", &unknown) else {
        return;
    };
    assert!(codes(&report).contains(&LimitationCode::MachineCodeProcessorNotKnown));
    assert!(!codes(&report).contains(&LimitationCode::AssemblyOutsideFunctionsNotRead));
    let lines = report
        .target
        .machine_code
        .map(|machine| machine.assembly_lines)
        .unwrap_or_default();
    assert_eq!(
        lines,
        [
            assembly_line(4, true, false, true),
            assembly_line(12, false, false, false),
        ]
    );
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

const KERNEL: &str = r#"
@TABLE = internal global [4 x i64] zeroinitializer

define dso_local void @handle_call(ptr noundef %ctx) !dbg !4 {
start:
  %number = load i64, ptr %ctx, align 8, !dbg !10
  switch i64 %number, label %other [
    i64 1, label %first
    i64 2, label %second
  ], !dbg !10

first:                                            ; preds = %start
  %slot.ptr = getelementptr inbounds i8, ptr %ctx, i64 8, !dbg !11
  %slot = load i64, ptr %slot.ptr, align 8, !dbg !11
  %inside = icmp ult i64 %slot, 4, !dbg !12
  br i1 %inside, label %read, label %panic, !dbg !12

read:                                             ; preds = %first
  %entry = getelementptr inbounds [4 x i64], ptr @TABLE, i64 0, i64 %slot, !dbg !12
  %held = load i64, ptr %entry, align 8, !dbg !12
  %sum = add i64 %held, 1, !dbg !13
  %wrapped = icmp eq i64 %sum, 0, !dbg !13
  br i1 %wrapped, label %panic.kept, label %other, !dbg !13

second:                                           ; preds = %start
  %value = getelementptr inbounds i8, ptr %ctx, i64 16, !dbg !14
  call fastcc void @_ZN4unit6helper17h0123456789abcdefE(ptr %value), !dbg !14
  store volatile i32 1, ptr inttoptr (i64 4096 to ptr), align 4, !dbg !14
  br label %other, !dbg !14

other:                                            ; preds = %second, %read, %start
  ret void, !dbg !15

panic:                                            ; preds = %first
  call void @_ZN4core9panicking18panic_bounds_check17h0123456789abcdefE(i64 %slot, i64 4), !dbg !12
  unreachable, !dbg !12

panic.kept:                                       ; preds = %read
  call void @_ZN4core9panicking11panic_const24panic_const_add_overflow17h0123456789abcdefE(), !dbg !13
  unreachable, !dbg !13
}

define internal fastcc void @_ZN4unit6helper17h0123456789abcdefE(ptr %value) !dbg !5 {
start:
  %length = load i64, ptr %value, align 8, !dbg !16
  %fits = icmp ult i64 %length, 64, !dbg !17
  br i1 %fits, label %done, label %panic, !dbg !17

done:                                             ; preds = %start
  ret void, !dbg !18

panic:                                            ; preds = %start
  call void @_ZN4core5slice5index24slice_end_index_len_fail17h0123456789abcdefE(i64 %length, i64 64), !dbg !17
  unreachable, !dbg !17
}

define void @_ZN4unit6public17h0123456789abcdefE(i64 %index) !dbg !6 {
start:
  %inside = icmp ult i64 %index, 4, !dbg !19
  br i1 %inside, label %done, label %panic, !dbg !19

done:                                             ; preds = %start
  ret void, !dbg !19

panic:                                            ; preds = %start
  call void @_ZN4core9panicking18panic_bounds_check17h0123456789abcdefE(i64 %index, i64 4), !dbg !19
  unreachable, !dbg !19
}

!1 = !DIFile(filename: "src/lib.rs", directory: "")
!4 = distinct !DISubprogram(name: "handle_call", file: !1, line: 1)
!5 = distinct !DISubprogram(name: "helper", file: !1, line: 20)
!6 = distinct !DISubprogram(name: "public", file: !1, line: 26)
!10 = !DILocation(line: 2, column: 5, scope: !4)
!11 = !DILocation(line: 4, column: 5, scope: !4)
!12 = !DILocation(line: 5, column: 5, scope: !4)
!13 = !DILocation(line: 6, column: 5, scope: !4)
!14 = !DILocation(line: 9, column: 5, scope: !4)
!15 = !DILocation(line: 11, column: 5, scope: !4)
!16 = !DILocation(line: 21, column: 5, scope: !5)
!17 = !DILocation(line: 22, column: 5, scope: !5)
!18 = !DILocation(line: 23, column: 5, scope: !5)
!19 = !DILocation(line: 27, column: 5, scope: !6)
"#;

fn stops(report: &ScanReport) -> Vec<(String, u32)> {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule == RuleId::StopOnOutsideInput)
        .filter_map(|finding| {
            let location = finding.location.as_ref()?;
            Some((location.path.clone(), location.line))
        })
        .collect()
}

#[test]
fn reports_checks_that_panic_on_a_value_from_an_exported_entry() {
    let project = project("compiled-stops");
    project.write("out/unit.ll", KERNEL);
    let result =
        seethru_analyzer::scan_with(&project.root, with_output(&[project.root.join("out")]));
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };

    assert_eq!(
        stops(&report),
        [("src/lib.rs".to_owned(), 5), ("src/lib.rs".to_owned(), 22)]
    );
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule == RuleId::StopOnOutsideInput);
    assert!(finding.is_some());
    let Some(finding) = finding else { return };
    assert_eq!(finding.id, "stop-on-outside-input:file:src/lib.rs:1");
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(finding.confidence, Confidence::Review);
    assert_eq!(finding.cwe, [248]);

    let codes = codes(&report);
    assert!(!codes.contains(&LimitationCode::OutsideEntriesNotFound));
    assert!(codes.contains(&LimitationCode::CompiledOutputWithoutWipes));
}

#[test]
fn says_so_when_no_exported_entry_takes_outside_values() {
    let project = project("compiled-no-entry");
    project.write(
        "out/unit.ll",
        &KERNEL.replace(
            "define dso_local void @handle_call",
            "define internal void @handle_call",
        ),
    );
    let result =
        seethru_analyzer::scan_with(&project.root, with_output(&[project.root.join("out")]));
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert!(stops(&report).is_empty());
    assert!(codes(&report).contains(&LimitationCode::OutsideEntriesNotFound));
}
