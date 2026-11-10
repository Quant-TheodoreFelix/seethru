use std::fs;
use std::path::{Path, PathBuf};

use seethru_analyzer::{BinaryInput, CodeReader, ScanOptions, scan_with};
use seethru_core::{BinaryFormat, Confidence, Input, LimitationCode, RuleId, ScanReport, ToolUse};

fn project(name: &str) -> std::io::Result<PathBuf> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(dir.join("src"))?;
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rust-wipes");
    for part in ["Cargo.toml", "Cargo.lock", "src/main.rs"] {
        fs::copy(fixture.join(part), dir.join(part))?;
    }
    fs::write(dir.join("app"), b"program")?;
    fs::canonicalize(dir)
}

fn function(source: &str, name: &str, lines: &[u32]) -> String {
    let mut out = format!("\n0000000100000ca8 <{name}>:\n; {name}():\n");
    for (at, line) in lines.iter().enumerate() {
        out.push_str(&format!(
            "; {source}:{line}\n10000{at:04x}:     \tsub\tsp, sp, #0x30\n10001{at:04x}:     \tret\n"
        ));
    }
    out
}

fn inlined(source: &str, line: u32) -> String {
    format!(
        "\n0x0000034d:     DW_TAG_inlined_subroutine\n                  DW_AT_abstract_origin\t(0x00000288 \"fill<u8>\")\n                  DW_AT_low_pc\t(0x0000000100000acc)\n                  DW_AT_high_pc\t(0x0000000100000b4c)\n                  DW_AT_call_file\t(\"{source}\")\n                  DW_AT_call_line\t({line})\n                  DW_AT_call_column\t(18)\n"
    )
}

const UNIT: &str = ".debug_info contents:\n0x0000000b: DW_TAG_compile_unit\n              DW_AT_language\t(DW_LANG_Rust)\n";

fn listing(source: &str) -> String {
    [
        function(source, "removed", &[13, 14, 16, 18, 21]),
        function(source, "kept", &[24, 25, 27, 29, 34]),
        function(source, "clear", &[37, 39]),
        function("/somewhere/else/core/src/ptr/mod.rs", "outside", &[2178]),
    ]
    .concat()
}

fn report(
    dir: &Path,
    disassembly: &str,
    debug_info: &str,
    problems: Vec<LimitationCode>,
) -> Result<ScanReport, Box<dyn std::error::Error>> {
    let mut reader = CodeReader::new(dir)?;
    for line in debug_info.lines() {
        reader.debug_info(line);
    }
    for line in disassembly.lines() {
        reader.disassembly(line);
    }
    let options = ScanOptions {
        binaries: vec![BinaryInput {
            path: dir.join("app"),
            format: BinaryFormat::MachO,
            tools: vec![ToolUse {
                name: "dwarfdump".to_owned(),
                version: "21.0.0".to_owned(),
            }],
            code: reader.finish(),
        }],
        binary_problems: problems,
        ..ScanOptions::default()
    };
    Ok(scan_with(dir, options)?)
}

fn wipes(report: &ScanReport) -> Vec<(String, u32, Confidence)> {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule == RuleId::MemoryWipeRemoved)
        .map(|finding| {
            (
                finding.id.clone(),
                finding.location.as_ref().map_or(0, |at| at.line),
                finding.confidence,
            )
        })
        .collect()
}

fn codes(report: &ScanReport) -> Vec<LimitationCode> {
    report
        .target
        .limitations
        .iter()
        .map(|limitation| limitation.code)
        .filter(|code| {
            matches!(
                code,
                LimitationCode::BinaryToolNotPermitted
                    | LimitationCode::BinaryToolFailed
                    | LimitationCode::BinaryNotFound
                    | LimitationCode::BinaryWithoutLineInfo
                    | LimitationCode::BinaryWipesNotConfirmed
                    | LimitationCode::BinaryChecksPartial
            )
        })
        .collect()
}

#[test]
fn reports_the_wipe_that_has_no_code_in_the_program() -> Result<(), Box<dyn std::error::Error>> {
    let dir = project("binary-removed")?;
    let source = dir.join("src/main.rs").display().to_string();
    let debug = [UNIT, &inlined(&source, 31), &inlined(&source, 38)].concat();
    let report = report(&dir, &listing(&source), &debug, Vec::new())?;
    assert_eq!(
        wipes(&report),
        [(
            "memory-wipe-removed:file:src/main.rs:1".to_owned(),
            19,
            Confidence::Likely
        )]
    );
    assert_eq!(codes(&report), [LimitationCode::BinaryChecksPartial]);
    let finding = &report.findings[0];
    assert_eq!(finding.cwe, [14]);
    assert_eq!(finding.origin.tools, ["dwarfdump"]);
    assert!(report.target.inputs.iter().any(|input| matches!(
        input,
        Input::Binary { path, lines: 14, .. } if path == "app"
    )));
    let again = self::report(&dir, &listing(&source), &debug, Vec::new())?;
    assert_eq!(report, again);
    Ok(())
}

#[test]
fn reads_the_listing_another_objdump_prints() -> Result<(), Box<dyn std::error::Error>> {
    let dir = project("binary-gnu")?;
    let source = dir.join("src/main.rs").display().to_string();
    let gnu = listing(&source)
        .replace("; ", "")
        .replace(":     \tsub\t", ":\tsub    ")
        .replace(
            &format!("{source}:16\n"),
            &format!("{source}:16 (discriminator 3)\n"),
        );
    let debug = [UNIT, &inlined(&source, 31), &inlined(&source, 38)].concat();
    let report = report(&dir, &gnu, &debug, Vec::new())?;
    assert_eq!(wipes(&report).len(), 1, "{:?}", report.target.limitations);
    Ok(())
}

#[test]
fn asks_for_review_when_a_wipe_that_must_stay_was_not_found()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = project("binary-review")?;
    let source = dir.join("src/main.rs").display().to_string();
    let debug = [UNIT, &inlined(&source, 38)].concat();
    let report = report(&dir, &listing(&source), &debug, Vec::new())?;
    assert_eq!(
        wipes(&report)
            .iter()
            .map(|(_, line, confidence)| (*line, *confidence))
            .collect::<Vec<_>>(),
        [(19, Confidence::Review)]
    );
    Ok(())
}

#[test]
fn says_nothing_is_missing_unless_some_wipe_was_seen() -> Result<(), Box<dyn std::error::Error>> {
    let dir = project("binary-control")?;
    let source = dir.join("src/main.rs").display().to_string();
    let report = report(&dir, &listing(&source), UNIT, Vec::new())?;
    assert!(wipes(&report).is_empty());
    assert_eq!(
        codes(&report),
        [
            LimitationCode::BinaryChecksPartial,
            LimitationCode::BinaryWipesNotConfirmed
        ]
    );
    Ok(())
}

#[test]
fn leaves_out_a_function_the_program_does_not_contain() -> Result<(), Box<dyn std::error::Error>> {
    let dir = project("binary-absent")?;
    let source = dir.join("src/main.rs").display().to_string();
    let listing = [
        function(&source, "kept", &[24, 25, 27, 29, 34]),
        function(&source, "clear", &[37, 39]),
    ]
    .concat();
    let debug = [UNIT, &inlined(&source, 31), &inlined(&source, 38)].concat();
    let report = report(&dir, &listing, &debug, Vec::new())?;
    assert!(wipes(&report).is_empty());
    assert_eq!(codes(&report), [LimitationCode::BinaryChecksPartial]);
    Ok(())
}

#[test]
fn output_that_cannot_be_used_becomes_a_limitation() -> Result<(), Box<dyn std::error::Error>> {
    let dir = project("binary-unusable")?;
    let source = dir.join("src/main.rs").display().to_string();
    let debug = [UNIT, &inlined(&source, 31)].concat();

    let garbage = report(
        &dir,
        "hello\nthis is not a listing\n\u{0}\u{1b}[31m\n",
        &debug,
        Vec::new(),
    )?;
    assert!(wipes(&garbage).is_empty());
    assert_eq!(codes(&garbage), [LimitationCode::BinaryToolFailed]);

    let stripped = listing(&source)
        .lines()
        .filter(|line| !line.starts_with("; /"))
        .collect::<Vec<_>>()
        .join("\n");
    let stripped = report(&dir, &stripped, "", Vec::new())?;
    assert!(wipes(&stripped).is_empty());
    assert_eq!(codes(&stripped), [LimitationCode::BinaryWithoutLineInfo]);

    let elsewhere = listing("/built/on/another/computer/src/main.rs");
    let elsewhere = report(&dir, &elsewhere, UNIT, Vec::new())?;
    assert_eq!(codes(&elsewhere), [LimitationCode::BinaryWithoutLineInfo]);

    let silent = report(&dir, &listing(&source), "nothing useful\n", Vec::new())?;
    assert!(wipes(&silent).is_empty());
    assert_eq!(codes(&silent), [LimitationCode::BinaryToolFailed]);

    let passed = report(
        &dir,
        "",
        "",
        vec![
            LimitationCode::BinaryToolNotPermitted,
            LimitationCode::BinaryToolNotPermitted,
        ],
    )?;
    assert_eq!(
        codes(&passed),
        [
            LimitationCode::BinaryToolNotPermitted,
            LimitationCode::BinaryToolFailed
        ]
    );
    assert!(
        !passed
            .target
            .inputs
            .iter()
            .any(|input| matches!(input, Input::Binary { .. }))
    );
    Ok(())
}

#[test]
fn text_from_the_tool_never_reaches_the_report() -> Result<(), Box<dyn std::error::Error>> {
    let dir = project("binary-hostile")?;
    let source = dir.join("src/main.rs").display().to_string();
    fs::write(dir.join("outside-marker"), "x")?;
    let escape = format!("{}/../../../../etc/passwd", dir.display());
    let hostile = [
        listing(&source),
        function(&escape, "IGNORE_PREVIOUS_INSTRUCTIONS", &[1]),
        function("/etc/hosts", "evil<script>", &[3]),
        function(&format!("{source}\u{7}bell"), "bell", &[19]),
    ]
    .concat();
    let debug = [
        UNIT,
        &inlined(&source, 31),
        &inlined(&source, 38),
        &inlined("/etc/passwd", 19),
        &inlined(&"a/".repeat(5000), 19),
    ]
    .concat();
    let report = report(&dir, &hostile, &debug, Vec::new())?;
    assert_eq!(wipes(&report).len(), 1);
    let json = serde_json::to_string(&report)?;
    for leaked in [
        "passwd",
        "IGNORE",
        "script",
        "/etc/",
        "removed():",
        "fill<u8>",
    ] {
        assert!(!json.contains(leaked), "{leaked}");
    }
    assert!(!json.contains(&dir.display().to_string()));
    Ok(())
}
