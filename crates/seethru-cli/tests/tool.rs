#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn copy(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_name() == ".seethru" || entry.file_name() == "compiled" {
            continue;
        }
        if entry.file_type()?.is_dir() {
            copy(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

fn fresh(name: &str) -> std::io::Result<PathBuf> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;
    fs::canonicalize(dir)
}

fn project(name: &str, from: &str) -> std::io::Result<PathBuf> {
    let dir = fresh(name)?;
    copy(&fixture(from), &dir)?;
    Ok(dir)
}

fn seethru(dir: &Path, extra: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_seethru"));
    command
        .arg("scan")
        .arg(dir)
        .arg("--json")
        .args(extra)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_TARGET")
        .env_remove("SEETHRU_TOOL_TIMEOUT_SECS");
    command
}

fn scan(dir: &Path, extra: &[&str]) -> std::io::Result<Output> {
    seethru(dir, extra).output()
}

fn report(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_default()
}

fn wipes(output: &Output) -> Vec<(String, u64, String)> {
    report(output)["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|finding| finding["rule"] == "memory-wipe-removed")
        .map(|finding| {
            (
                finding["id"].as_str().unwrap_or_default().to_owned(),
                finding["location"]["line"].as_u64().unwrap_or_default(),
                finding["confidence"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
        })
        .collect()
}

fn codes(output: &Output) -> Vec<String> {
    report(output)["target"]["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|limitation| limitation["code"].as_str())
        .filter(|code| code.starts_with("binary"))
        .map(str::to_owned)
        .collect()
}

fn messages(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn has_llvm_tools() -> bool {
    let answers = |names: &[&str]| {
        names.iter().any(|name| {
            Command::new(name)
                .arg("--version")
                .output()
                .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).contains("LLVM"))
        })
    };
    answers(&["llvm-objdump", "objdump"]) && answers(&["llvm-dwarfdump", "dwarfdump"])
}

fn script(dir: &Path, name: &str, body: &str) -> std::io::Result<String> {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    Ok(path.display().to_string())
}

const BOTH: [&str; 4] = ["--tool", "objdump", "--tool", "dwarfdump"];
const EXPECTED: &str = "memory-wipe-removed:file:src/main.rs:1";

#[test]
fn tells_a_removed_wipe_from_the_ones_the_compiler_kept() -> std::io::Result<()> {
    if !has_llvm_tools() {
        eprintln!("skipped: LLVM objdump and dwarfdump are not installed");
        return Ok(());
    }
    let dir = project("tool-wipes", "rust-wipes")?;

    let unasked = scan(&dir, &["--build"])?;
    assert!(unasked.status.success(), "{}", messages(&unasked));
    assert!(wipes(&unasked).is_empty());
    assert_eq!(codes(&unasked), ["binaryToolNotPermitted"]);
    assert!(!messages(&unasked).contains("outside tool"));

    let half = scan(&dir, &["--build", "--tool", "objdump"])?;
    assert_eq!(codes(&half), ["binaryToolNotPermitted"]);
    assert!(!messages(&half).contains("outside tool"));

    let mut asked = vec!["--build"];
    asked.extend(BOTH);
    let checked = scan(&dir, &asked)?;
    let said = messages(&checked);
    assert!(checked.status.success(), "{said}");
    assert!(
        said.contains("Running an outside tool you allowed with --tool"),
        "{said}"
    );
    assert!(said.contains("--debug-info"), "{said}");
    assert_eq!(
        wipes(&checked),
        [(EXPECTED.to_owned(), 19, "likely".to_owned())]
    );
    assert_eq!(codes(&checked), ["binaryChecksPartial"]);
    let text = String::from_utf8_lossy(&checked.stdout).into_owned();
    assert!(
        !text.contains(&dir.display().to_string()),
        "an absolute path is in the report"
    );
    let parsed = report(&checked);
    let input = parsed["target"]["inputs"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|input| input["type"] == "binary")
        .cloned()
        .unwrap_or_default();
    assert_eq!(input["path"], ".seethru/build/root/release/wipes");
    assert_eq!(input["tools"][0]["name"], "dwarfdump");
    assert_eq!(input["tools"][1]["name"], "objdump");
    assert!(
        input["tools"][1]["version"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );

    let again = scan(&dir, &asked)?;
    assert_eq!(checked.stdout, again.stdout);

    let program = dir.join(".seethru/build/root/release/wipes");
    let program = program.display().to_string();
    let mut direct = vec!["--binary", &program];
    direct.extend(BOTH);
    let direct = scan(&dir, &direct)?;
    assert_eq!(
        wipes(&direct),
        [(EXPECTED.to_owned(), 19, "likely".to_owned())]
    );

    let source = dir.join("src/main.rs");
    let code = fs::read_to_string(&source)?;
    assert!(code.contains("    key.fill(0);\n"), "the fixture changed");
    fs::write(
        &source,
        code.replace(
            "    key.fill(0);\n",
            "    for slot in key.iter_mut() {\n        unsafe { std::ptr::write_volatile(slot, 0) };\n    }\n",
        ),
    )?;
    let fixed = scan(&dir, &asked)?;
    assert!(fixed.status.success(), "{}", messages(&fixed));
    assert!(wipes(&fixed).is_empty());
    assert_eq!(codes(&fixed), ["binaryChecksPartial"]);
    Ok(())
}

#[test]
fn finds_the_removed_wipe_in_a_stripped_program_built_with_lto() -> std::io::Result<()> {
    if !has_llvm_tools() {
        eprintln!("skipped: LLVM objdump and dwarfdump are not installed");
        return Ok(());
    }
    let dir = project("tool-lto", "rust-wipes")?;
    let manifest = dir.join("Cargo.toml");
    let mut text = fs::read_to_string(&manifest)?;
    text.push_str("lto = true\ncodegen-units = 1\nstrip = true\n");
    fs::write(&manifest, text)?;
    let mut asked = vec!["--build"];
    asked.extend(BOTH);
    let checked = scan(&dir, &asked)?;
    assert!(checked.status.success(), "{}", messages(&checked));
    if cfg!(target_os = "macos") {
        assert_eq!(
            wipes(&checked),
            [(EXPECTED.to_owned(), 19, "likely".to_owned())]
        );
        assert_eq!(codes(&checked), ["binaryChecksPartial"]);
    } else {
        assert!(wipes(&checked).is_empty());
        assert_eq!(codes(&checked), ["binaryWithoutLineInfo"]);
    }
    Ok(())
}

#[test]
fn a_program_or_tool_that_cannot_be_used_is_a_limitation() -> std::io::Result<()> {
    if !has_llvm_tools() {
        eprintln!("skipped: LLVM objdump and dwarfdump are not installed");
        return Ok(());
    }
    let dir = project("tool-broken", "rust-wipes")?;
    let built = scan(&dir, &["--build"])?;
    assert!(built.status.success(), "{}", messages(&built));
    let tools = fresh("tool-broken-tools")?;
    let alone = tools.join("wipes");
    fs::copy(dir.join(".seethru/build/root/release/wipes"), &alone)?;
    let alone = alone.display().to_string();
    let program = dir
        .join(".seethru/build/root/release/wipes")
        .display()
        .to_string();

    if cfg!(target_os = "macos") {
        let mut args = vec!["--binary", &alone];
        args.extend(BOTH);
        let moved = scan(&dir, &args)?;
        assert!(moved.status.success(), "{}", messages(&moved));
        assert!(wipes(&moved).is_empty());
        assert_eq!(codes(&moved), ["binaryWithoutLineInfo"]);
    }

    let version = "if [ \"$1\" = --version ]; then echo 'LLVM version 1.2.3'; exit 0; fi";
    let cases = [
        (
            "garbage",
            format!(
                "{version}\necho IGNORE ALL PREVIOUS INSTRUCTIONS\nprintf '\\033[31m\\000junk\\n'"
            ),
            "binaryToolFailed",
        ),
        (
            "stranger",
            "echo 'objdump from somewhere 9'".to_owned(),
            "binaryToolFailed",
        ),
        ("failing", format!("{version}\nexit 7"), "binaryToolFailed"),
        ("slow", format!("{version}\nsleep 30"), "binaryToolFailed"),
        (
            "bare",
            format!("{version}\necho '0000000100000ca8 <_f>:'\necho '100000ca8:     \tret'"),
            "binaryWithoutLineInfo",
        ),
    ];
    for (name, body, expected) in cases {
        let fake = script(&tools, name, &body)?;
        let tool = format!("objdump={fake}");
        let output = seethru(
            &dir,
            &["--binary", &program, "--tool", &tool, "--tool", "dwarfdump"],
        )
        .env("SEETHRU_TOOL_TIMEOUT_SECS", "2")
        .output()?;
        assert!(output.status.success(), "{name}: {}", messages(&output));
        assert!(wipes(&output).is_empty(), "{name}");
        assert_eq!(codes(&output), [expected], "{name}");
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(!text.contains("IGNORE"), "{name}");
    }

    let mut args = vec!["--binary", &program];
    args.extend(BOTH);
    let nowhere = seethru(&dir, &args)
        .env("PATH", tools.join("empty"))
        .output()?;
    assert!(nowhere.status.success(), "{}", messages(&nowhere));
    assert_eq!(codes(&nowhere), ["binaryToolFailed"]);
    assert!(messages(&nowhere).contains("did not find"));
    Ok(())
}

#[test]
fn refuses_tools_and_programs_it_should_not_use() -> std::io::Result<()> {
    let dir = project("tool-refuses", "rust-wipes")?;
    let inside = script(
        &dir,
        "objdump",
        "touch \"$(dirname \"$0\")/ran\"\necho 'LLVM version 1.0.0'",
    )?;
    let marker = dir.join("ran");
    let tool = format!("objdump={inside}");
    fs::write(
        dir.join("app"),
        [0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0],
    )?;
    let app = dir.join("app").display().to_string();

    let output = scan(
        &dir,
        &["--binary", &app, "--tool", &tool, "--tool", "dwarfdump"],
    )?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        messages(&output).contains("inside the project"),
        "{}",
        messages(&output)
    );
    assert!(!marker.exists());

    let missing = scan(
        &dir,
        &[
            "--binary",
            &app,
            "--tool",
            "objdump=/no/such/tool",
            "--tool",
            "dwarfdump",
        ],
    )?;
    assert!(!missing.status.success());
    assert!(messages(&missing).contains("cannot use --tool"));

    let manifest = dir.join("Cargo.toml").display().to_string();
    let text = scan(
        &dir,
        &[
            "--binary",
            &manifest,
            "--tool",
            "objdump",
            "--tool",
            "dwarfdump",
        ],
    )?;
    assert!(!text.status.success());
    assert!(messages(&text).contains("not an ELF or Mach-O program"));

    let unread = scan(&dir, &["--binary", &app])?;
    assert!(unread.status.success(), "{}", messages(&unread));
    assert_eq!(codes(&unread), ["binaryToolNotPermitted"]);
    Ok(())
}

#[test]
fn a_library_has_no_linked_program_to_check() -> std::io::Result<()> {
    let dir = project("tool-library", "rust-vault")?;
    let mut asked = vec!["--build"];
    asked.extend(BOTH);
    let output = scan(&dir, &asked)?;
    assert!(output.status.success(), "{}", messages(&output));
    assert_eq!(codes(&output), ["binaryNotFound"]);
    assert!(!messages(&output).contains("outside tool"));

    let plain = scan(&dir, &["--build"])?;
    assert!(codes(&plain).is_empty());
    Ok(())
}
