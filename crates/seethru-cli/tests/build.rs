use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rust-vault")
}

fn copy(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

fn project(name: &str) -> std::io::Result<PathBuf> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    for part in ["Cargo.toml", "Cargo.lock"] {
        fs::create_dir_all(&dir)?;
        fs::copy(fixture().join(part), dir.join(part))?;
    }
    copy(&fixture().join("vault"), &dir.join("vault"))?;
    Ok(dir)
}

fn scan(dir: &Path, extra: &[&str]) -> std::io::Result<std::process::Output> {
    scan_for(dir, extra, None)
}

fn scan_for(
    dir: &Path,
    extra: &[&str],
    target: Option<&str>,
) -> std::io::Result<std::process::Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_seethru"));
    command
        .arg("scan")
        .arg(dir)
        .arg("--json")
        .args(extra)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_TARGET");
    if let Some(target) = target {
        command.env("CARGO_BUILD_TARGET", target);
    }
    command.output()
}

fn host_target() -> std::io::Result<String> {
    let output = Command::new("rustc").arg("-vV").output()?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap_or_default()
        .to_owned())
}

fn divisions(output: &std::process::Output) -> Vec<(String, String)> {
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_default();
    report["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|finding| finding["rule"] == "secret-dependent-division")
        .map(|finding| {
            (
                finding["id"].as_str().unwrap_or_default().to_owned(),
                finding["confidence"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
        })
        .collect()
}

#[test]
fn builds_a_rust_project_and_reads_what_it_built() -> std::io::Result<()> {
    let dir = project("build-finds")?;

    let plain = scan(&dir, &[])?;
    assert!(plain.status.success());
    assert!(divisions(&plain).is_empty());
    assert!(!dir.join(".seethru/build/root").exists());

    let built = scan(&dir, &["--build"])?;
    let messages = String::from_utf8_lossy(&built.stderr).into_owned();
    assert!(built.status.success(), "{messages}");
    assert!(messages.contains("Building with cargo"), "{messages}");
    assert_eq!(
        divisions(&built),
        [(
            "secret-dependent-division:file:vault/src/lib.rs:1".to_owned(),
            "likely".to_owned()
        )]
    );
    assert!(dir.join(".seethru/build/root/seethru-units").is_file());
    assert!(!dir.join("target").exists());

    let source = dir.join("vault/src/lib.rs");
    let text = fs::read_to_string(&source)?;
    assert!(text.contains(" % "), "the fixture no longer divides");
    fs::write(&source, text.replace(" % ", " & "))?;
    let fixed = scan(&dir, &["--build"])?;
    assert!(fixed.status.success());
    assert!(divisions(&fixed).is_empty());
    Ok(())
}

#[test]
fn output_of_an_earlier_target_is_not_read_again() -> std::io::Result<()> {
    let dir = project("build-targets")?;
    let host = host_target()?;
    assert!(!host.is_empty());

    let first = scan_for(&dir, &["--build"], Some(&host))?;
    assert!(first.status.success());
    assert_eq!(divisions(&first).len(), 1);
    assert!(dir.join(".seethru/build/root").join(&host).is_dir());

    let source = dir.join("vault/src/lib.rs");
    let text = fs::read_to_string(&source)?;
    fs::write(&source, text.replace(" % ", " & "))?;
    let second = scan(&dir, &["--build"])?;
    assert!(second.status.success());
    assert!(divisions(&second).is_empty());
    assert!(!dir.join(".seethru/build/root").join(&host).exists());
    Ok(())
}

#[test]
fn a_failed_build_stops_the_scan() -> std::io::Result<()> {
    let dir = project("build-fails")?;
    fs::write(dir.join("vault/src/lib.rs"), "pub fn broken( {\n")?;
    let output = scan(&dir, &["--build"])?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("the build failed"));
    Ok(())
}

#[test]
fn refuses_to_build_without_a_manifest_or_a_lock_file() -> std::io::Result<()> {
    let dir = project("build-refuses")?;
    fs::remove_file(dir.join("Cargo.lock"))?;
    let output = scan(&dir, &["--build"])?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Cargo.lock"));
    assert!(!dir.join(".seethru/build/root").exists());

    fs::remove_file(dir.join("Cargo.toml"))?;
    fs::remove_file(dir.join("vault/Cargo.toml"))?;
    let output = scan(&dir, &["--build"])?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Cargo.toml"));
    Ok(())
}

#[test]
fn builds_a_project_that_sits_in_a_subfolder() -> std::io::Result<()> {
    let inner = project("build-nested/app")?;
    let outer = inner.parent().unwrap_or(&inner).to_path_buf();
    let built = scan(&outer, &["--build"])?;
    let messages = String::from_utf8_lossy(&built.stderr).into_owned();
    assert!(built.status.success(), "{messages}");
    assert_eq!(
        divisions(&built),
        [(
            "secret-dependent-division:file:app/vault/src/lib.rs:1".to_owned(),
            "likely".to_owned()
        )]
    );
    assert!(outer.join(".seethru/build/app/seethru-units").is_file());
    Ok(())
}

#[test]
fn reads_a_program_that_compiles_but_cannot_be_linked() -> std::io::Result<()> {
    let dir = project("build-unlinked")?;
    let manifest = dir.join("vault/Cargo.toml");
    let mut text = fs::read_to_string(&manifest)?;
    text.push_str("\n[[bin]]\nname = \"probe\"\npath = \"src/probe.rs\"\n");
    fs::write(&manifest, text)?;
    fs::write(
        dir.join("vault/src/probe.rs"),
        "#![no_main]\n\n#[unsafe(no_mangle)]\npub extern \"C\" fn probe(vault: &mut vault::Vault, modulus: u32) -> u32 {\n    vault::open_once(vault, modulus)\n}\n",
    )?;
    let built = scan(&dir, &["--build"])?;
    let messages = String::from_utf8_lossy(&built.stderr).into_owned();
    assert!(built.status.success(), "{messages}");
    assert!(messages.contains("could not be linked"), "{messages}");
    assert_eq!(divisions(&built).len(), 1, "{messages}");
    Ok(())
}

#[test]
fn finds_the_check_a_real_compiler_left_for_an_outside_value() -> std::io::Result<()> {
    let dir = project("build-stops")?;
    let source = dir.join("vault/src/lib.rs");
    let mut text = fs::read_to_string(&source)?;
    let first = text.lines().count() + 4;
    text.push_str(
        "\n#[unsafe(no_mangle)]\npub extern \"C\" fn pick(table: &[u32; 8], index: usize, guarded: usize) -> u32 {\n    let open = table[index];\n    let safe = if guarded < 8 { table[guarded] } else { 0 };\n    open.wrapping_add(safe)\n}\n",
    );
    fs::write(&source, text)?;
    let built = scan(&dir, &["--build"])?;
    let messages = String::from_utf8_lossy(&built.stderr).into_owned();
    assert!(built.status.success(), "{messages}");
    let report: serde_json::Value = serde_json::from_slice(&built.stdout).unwrap_or_default();
    let lines: Vec<u64> = report["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|finding| finding["rule"] == "stop-on-outside-input")
        .filter_map(|finding| finding["location"]["line"].as_u64())
        .collect();
    assert_eq!(lines, [first as u64], "{messages}");
    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn reads_hand_written_assembly_in_a_library_that_has_no_program() -> std::io::Result<()> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("build-by-hand");
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    copy(&fixture().join("../rust-asm"), &dir)?;
    let built = scan(&dir, &["--build"])?;
    let messages = String::from_utf8_lossy(&built.stderr).into_owned();
    assert!(built.status.success(), "{messages}");
    assert_eq!(
        divisions(&built),
        [(
            "secret-dependent-division:file:src/lib.rs:asm:1".to_owned(),
            "review".to_owned()
        )],
        "{messages}"
    );
    let (divides, jumps) = if cfg!(target_arch = "x86_64") {
        (24, 43)
    } else {
        (28, 47)
    };
    let line = |line: u32, divides: bool, branches: bool, secret: bool| {
        serde_json::json!({
            "path": "src/lib.rs",
            "line": line,
            "divides": divides,
            "branches": branches,
            "secret": secret,
        })
    };
    let report: serde_json::Value = serde_json::from_slice(&built.stdout).unwrap_or_default();
    assert_eq!(
        report["target"]["machineCode"],
        serde_json::json!({
            "divisions": 2,
            "divisionsWithoutLine": 0,
            "divisionLines": [
                { "path": "src/lib.rs", "line": divides, "secret": true, "assembly": true },
                { "path": "src/lib.rs", "line": 62, "secret": false, "assembly": false },
            ],
            "assemblyBlocks": 3,
            "assemblyBlocksWithoutLine": 0,
            "assemblyLines": [
                line(divides, true, false, true),
                line(jumps, false, true, false),
                line(56, false, false, false),
            ],
        }),
        "{messages}"
    );
    Ok(())
}
