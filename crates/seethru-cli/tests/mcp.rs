#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

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

fn project(name: &str) -> std::io::Result<PathBuf> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    copy(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rust-wipes"),
        &dir,
    )?;
    fs::canonicalize(dir)
}

fn session(flags: &[&str], calls: &[Value]) -> std::io::Result<Vec<Value>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_seethru"))
        .arg("mcp")
        .args(flags)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_TARGET")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut text = String::new();
    text.push_str(
        &json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}
        }})
        .to_string(),
    );
    text.push('\n');
    text.push_str(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string());
    text.push('\n');
    for (at, (name, arguments)) in calls
        .iter()
        .map(|call| (call["name"].clone(), call["arguments"].clone()))
        .enumerate()
    {
        text.push_str(
            &json!({"jsonrpc": "2.0", "id": at + 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}})
            .to_string(),
        );
        text.push('\n');
    }
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or(Value::Null))
        .collect())
}

fn root_flag(dir: &Path) -> String {
    dir.display().to_string()
}

#[test]
fn an_agent_cannot_build_unless_the_user_started_the_server_with_the_flag()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = project("mcp-refused")?;
    let root = root_flag(&dir);
    let replies = session(
        &["--root", &root],
        &[
            json!({"name": "scan", "arguments": {"path": root, "build": true}}),
            json!({"name": "scan", "arguments": {"path": root}}),
            json!({"name": "scan", "arguments": {"path": "/"}}),
        ],
    )?;
    assert_eq!(replies.len(), 4, "{replies:?}");
    assert!(replies.iter().all(|reply| !reply.is_null()), "{replies:?}");
    assert_eq!(replies[1]["result"]["isError"], true, "{replies:?}");
    assert!(!dir.join(".seethru").exists());
    assert_ne!(replies[2]["result"]["isError"], true, "{replies:?}");
    assert_eq!(replies[3]["result"]["isError"], true, "{replies:?}");
    Ok(())
}

#[test]
fn a_permitted_build_and_tools_find_the_removed_wipe_over_mcp()
-> Result<(), Box<dyn std::error::Error>> {
    let found = |name: &str| {
        Command::new(name)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    };
    if !(found("objdump") || found("llvm-objdump"))
        || !(found("dwarfdump") || found("llvm-dwarfdump"))
    {
        return Ok(());
    }
    let dir = project("mcp-built")?;
    let root = root_flag(&dir);
    let replies = session(
        &[
            "--root",
            &root,
            "--allow-build",
            "--tool",
            "objdump",
            "--tool",
            "dwarfdump",
        ],
        &[json!({"name": "scan", "arguments": {
            "path": root, "build": true, "tools": ["objdump", "dwarfdump"]
        }})],
    )?;
    assert_eq!(replies.len(), 2, "{replies:?}");
    let result = &replies[1]["result"];
    assert_ne!(result["isError"], true, "{replies:?}");
    let text = result["content"][0]["text"].as_str().unwrap_or_default();
    assert!(
        text.contains("memory-wipe-removed:file:src/main.rs:1"),
        "{text}"
    );
    let body: Value = serde_json::from_str(text)?;
    let listed = format!(
        "{}{}{}",
        body["findings"], body["limitations"], body["machineCode"]
    );
    assert!(!listed.contains(&root), "{listed}");
    let machine = &body["machineCode"];
    assert!(machine["divisions"].is_u64(), "{machine}");
    assert!(machine["divisionLines"].is_array(), "{machine}");
    assert_eq!(machine["linesCapped"], false, "{machine}");
    Ok(())
}
