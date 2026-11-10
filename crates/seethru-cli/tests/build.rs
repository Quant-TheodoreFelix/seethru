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
    assert!(!dir.join(".seethru/build").exists());

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
    assert!(dir.join(".seethru/build/seethru-units").is_file());
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
    assert!(dir.join(".seethru/build").join(&host).is_dir());

    let source = dir.join("vault/src/lib.rs");
    let text = fs::read_to_string(&source)?;
    fs::write(&source, text.replace(" % ", " & "))?;
    let second = scan(&dir, &["--build"])?;
    assert!(second.status.success());
    assert!(divisions(&second).is_empty());
    assert!(!dir.join(".seethru/build").join(&host).exists());
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
    assert!(!dir.join(".seethru/build").exists());

    fs::remove_file(dir.join("Cargo.toml"))?;
    let output = scan(&dir, &["--build"])?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Cargo.toml"));
    Ok(())
}
