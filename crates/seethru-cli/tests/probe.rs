#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

type Routes = Arc<dyn Fn(&Seen) -> String + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    method: String,
    path: String,
    origin: Option<String>,
    at: Instant,
}

struct Server {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
}

impl Server {
    fn start(routes: Routes) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (log, flag) = (seen.clone(), stop.clone());
        thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = answer(stream, &routes, &log);
                    }
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Ok(Self { port, seen, stop })
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn answer(stream: TcpStream, routes: &Routes, log: &Mutex<Vec<Seen>>) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut first = String::new();
    reader.read_line(&mut first)?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut origin = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("origin")
        {
            origin = Some(value.trim().to_owned());
        }
    }
    let seen = Seen {
        method,
        path,
        origin,
        at: Instant::now(),
    };
    let reply = routes(&seen);
    if let Ok(mut log) = log.lock() {
        log.push(seen);
    }
    let mut stream = stream;
    stream.write_all(reply.as_bytes())?;
    stream.flush()
}

fn reply(status: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut text = format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    text.push_str("\r\n");
    text.push_str(body);
    text
}

fn has_curl() -> bool {
    Command::new("curl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn project(name: &str) -> std::io::Result<PathBuf> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(dir.join("src"))?;
    fs::write(dir.join("src/index.js"), "export const a = 1;\n")?;
    fs::canonicalize(dir)
}

fn seethru(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_seethru"))
        .args(args)
        .env_remove("SEETHRU_TOOL_TIMEOUT_SECS")
        .output()
}

fn own(dir: &Path, url: &str) -> std::io::Result<String> {
    let output = seethru(&["own", url, &dir.display().to_string()])?;
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    Ok(text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("seethru-ownership="))
        .unwrap_or_default()
        .to_owned())
}

fn probe(dir: &Path, url: &str, extra: &[&str]) -> std::io::Result<Output> {
    let dir = dir.display().to_string();
    let mut args = vec!["scan", dir.as_str(), "--json", "--probe", url];
    args.extend_from_slice(extra);
    seethru(&args)
}

fn report(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_default()
}

fn codes(output: &Output) -> Vec<String> {
    report(output)["target"]["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|limitation| limitation["code"].as_str().map(str::to_owned))
        .filter(|code| code.starts_with("probe") || code.starts_with("ownership"))
        .collect()
}

fn ids(output: &Output) -> Vec<String> {
    report(output)["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|finding| finding["id"].as_str().map(str::to_owned))
        .collect()
}

fn audit(dir: &Path) -> Vec<serde_json::Value> {
    fs::read_to_string(dir.join(".seethru/audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn secret() -> String {
    ["sk", "live", "51Hq8zXcVbNmAsDfGhJkLpOiUyTrEwQ"].join("_")
}

const WELL_KNOWN: &str = "/.well-known/seethru-ownership.txt";
const GOOD: [(&str, &str); 4] = [
    ("Content-Type", "text/html; charset=utf-8"),
    (
        "Content-Security-Policy",
        "default-src 'self'; frame-ancestors 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
];

fn app(line: Arc<Mutex<String>>, page: Vec<(&'static str, &'static str)>, cors: bool) -> Routes {
    Arc::new(move |seen: &Seen| {
        if seen.path == WELL_KNOWN {
            let line = line.lock().map(|line| line.clone()).unwrap_or_default();
            return reply(
                "200 OK",
                &[("Content-Type", "text/plain")],
                &format!("{line}\n"),
            );
        }
        let mut headers = page.clone();
        let origin = seen.origin.clone().unwrap_or_default();
        if cors && seen.origin.is_some() {
            headers.push(("Access-Control-Allow-Credentials", "true"));
        }
        let mut text = reply("200 OK", &headers, &format!("<html>{}</html>", secret()));
        if cors && seen.origin.is_some() {
            text = text.replacen(
                "\r\n",
                &format!(
                    "\r\nAccess-Control-Allow-Origin: {origin}\r\nSet-Cookie: session={}\r\n",
                    secret()
                ),
                1,
            );
        }
        text
    })
}

#[test]
fn nothing_is_sent_without_permission_a_token_or_a_confirmed_environment()
-> Result<(), Box<dyn std::error::Error>> {
    let line: Arc<Mutex<String>> = Arc::default();
    let server = Server::start(app(line.clone(), GOOD.to_vec(), false))?;
    let dir = project("probe-refused")?;
    let url = server.url();

    let no_token = probe(&dir, &url, &["--staging", "--tool", "curl"])?;
    assert!(no_token.status.success(), "{no_token:?}");
    assert_eq!(codes(&no_token), ["ownershipNotVerified"]);

    *line.lock().map_err(|_| "lock")? = own(&dir, &url)?;
    let no_tool = probe(&dir, &url, &["--staging"])?;
    assert!(no_tool.status.success(), "{no_tool:?}");
    assert_eq!(codes(&no_tool), ["probeToolNotPermitted"]);
    assert!(ids(&no_tool).is_empty());

    let unconfirmed = probe(&dir, &url, &["--production", "--tool", "curl"])?;
    assert_eq!(unconfirmed.status.code(), Some(2));
    let neither = probe(&dir, &url, &["--tool", "curl"])?;
    assert_eq!(neither.status.code(), Some(2));
    let plain = probe(&dir, "http://example.com", &["--staging", "--tool", "curl"])?;
    assert_eq!(plain.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&plain.stderr).contains("only allowed for an app on this computer")
    );

    assert!(server.seen().is_empty(), "{:?}", server.seen());
    assert!(audit(&dir).is_empty());
    Ok(())
}

#[test]
fn a_well_configured_app_is_read_slowly_and_every_request_is_in_the_audit_log()
-> Result<(), Box<dyn std::error::Error>> {
    if !has_curl() {
        return Ok(());
    }
    let line: Arc<Mutex<String>> = Arc::default();
    let server = Server::start(app(line.clone(), GOOD.to_vec(), false))?;
    let dir = project("probe-good")?;
    let url = server.url();
    *line.lock().map_err(|_| "lock")? = own(&dir, &url)?;
    assert_eq!(own(&dir, &url)?, *line.lock().map_err(|_| "lock")?);

    let checked = probe(&dir, &url, &["--staging", "--tool", "curl"])?;
    assert!(checked.status.success(), "{checked:?}");
    assert!(ids(&checked).is_empty(), "{:?}", ids(&checked));
    assert_eq!(codes(&checked), ["probeChecksPartial"]);

    let seen = server.seen();
    let paths: Vec<(&str, &str, bool)> = seen
        .iter()
        .map(|seen| {
            (
                seen.method.as_str(),
                seen.path.as_str(),
                seen.origin.is_some(),
            )
        })
        .collect();
    assert_eq!(
        paths,
        [
            ("GET", WELL_KNOWN, false),
            ("GET", "/", false),
            ("GET", "/", true)
        ]
    );
    for pair in seen.windows(2) {
        let gap = pair[1].at.duration_since(pair[0].at);
        assert!(gap >= Duration::from_millis(450), "{gap:?}");
    }

    let log = audit(&dir);
    assert_eq!(log[0]["phase"], "run");
    assert_eq!(log[0]["environment"], "staging");
    let sent: Vec<&serde_json::Value> = log
        .iter()
        .filter(|entry| entry["phase"] == "sending")
        .collect();
    let answered = log
        .iter()
        .filter(|entry| entry["phase"] == "answered")
        .count();
    assert_eq!(sent.len(), seen.len());
    assert_eq!(answered, seen.len());
    for (entry, seen) in sent.iter().zip(&seen) {
        assert_eq!(entry["path"], seen.path.as_str());
        assert_eq!(entry["method"], "GET");
    }
    let input = report(&checked)["target"]["inputs"]
        .as_array()
        .and_then(|inputs| {
            inputs
                .iter()
                .find(|input| input["type"] == "probe")
                .cloned()
        })
        .unwrap_or_default();
    assert_eq!(input["requests"], 3);
    assert_eq!(input["environment"], "staging");
    assert_eq!(input["tools"][0]["name"], "curl");

    let everything = format!(
        "{}{}{}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr),
        fs::read_to_string(dir.join(".seethru/audit.jsonl"))?
    );
    assert!(!everything.contains(&secret()));
    let stdout = String::from_utf8_lossy(&checked.stdout);
    assert!(!stdout.contains("127.0.0.1") && !stdout.contains(&server.port.to_string()));
    Ok(())
}

#[test]
fn missing_headers_and_open_cors_are_found_with_proof_and_no_page_content()
-> Result<(), Box<dyn std::error::Error>> {
    if !has_curl() {
        return Ok(());
    }
    let line: Arc<Mutex<String>> = Arc::default();
    let server = Server::start(app(line.clone(), vec![("Content-Type", "text/html")], true))?;
    let dir = project("probe-bad")?;
    let url = server.url();
    *line.lock().map_err(|_| "lock")? = own(&dir, &url)?;

    let checked = probe(
        &dir,
        &url,
        &["--production", "--confirm-production", "--tool", "curl"],
    )?;
    assert!(checked.status.success(), "{checked:?}");
    assert_eq!(
        ids(&checked),
        [
            "cors-allows-any-origin-with-credentials:app",
            "security-header-missing:header:content-security-policy",
            "security-header-missing:header:frame-protection",
            "security-header-missing:header:x-content-type-options",
        ]
    );
    let parsed = report(&checked);
    let cors = &parsed["findings"][0];
    assert_eq!(cors["severity"], "medium");
    assert_eq!(cors["origin"]["tools"][0], "curl");
    assert!(
        cors["fixPrompt"]["en"]
            .as_str()
            .is_some_and(|text| text.contains("Vary: Origin"))
    );
    assert!(
        parsed["findings"][2]["fixPrompt"]["ko"]
            .as_str()
            .is_some_and(|text| text.contains("frame-ancestors"))
    );
    let proof = cors["proof"].as_str().unwrap_or_default();
    assert_eq!(
        proof,
        "proof/cors-allows-any-origin-with-credentials-app.json"
    );
    let proof_text = fs::read_to_string(dir.join(".seethru").join(proof))?;
    assert!(proof_text.contains("access-control-allow-credentials"));
    assert!(proof_text.contains("\"environment\": \"production\""));
    assert_eq!(fs::read_dir(dir.join(".seethru/proof"))?.count(), 4);

    let everything = format!(
        "{}{}{}{}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr),
        fs::read_to_string(dir.join(".seethru/audit.jsonl"))?,
        fs::read_dir(dir.join(".seethru/proof"))?
            .flatten()
            .map(|entry| fs::read_to_string(entry.path()).unwrap_or_default())
            .collect::<String>()
    );
    assert!(!everything.contains(&secret()));
    assert!(!everything.to_ascii_lowercase().contains("set-cookie"));
    let stdout = String::from_utf8_lossy(&checked.stdout);
    assert!(!stdout.contains("127.0.0.1") && !stdout.contains(&server.port.to_string()));

    let again = probe(
        &dir,
        &url,
        &["--production", "--confirm-production", "--tool", "curl"],
    )?;
    assert_eq!(report(&again), parsed);
    Ok(())
}

#[test]
fn a_wrong_token_or_a_redirect_to_another_site_ends_the_run()
-> Result<(), Box<dyn std::error::Error>> {
    if !has_curl() {
        return Ok(());
    }
    let line: Arc<Mutex<String>> = Arc::default();
    let wrong = Server::start(app(line.clone(), vec![("Content-Type", "text/html")], true))?;
    let dir = project("probe-wrong")?;
    let _ = own(&dir, &wrong.url())?;
    *line.lock().map_err(|_| "lock")? = format!("seethru-ownership={}", "0".repeat(64));
    let checked = probe(&dir, &wrong.url(), &["--staging", "--tool", "curl"])?;
    assert!(checked.status.success(), "{checked:?}");
    assert_eq!(codes(&checked), ["ownershipNotVerified"]);
    assert!(ids(&checked).is_empty());
    let seen = wrong.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].path, WELL_KNOWN);

    let other = Server::start(Arc::new(|_: &Seen| reply("200 OK", &[], "other site")))?;
    let elsewhere = format!("{}/landing", other.url());
    let line: Arc<Mutex<String>> = Arc::default();
    let held = line.clone();
    let redirecting = Server::start(Arc::new(move |seen: &Seen| {
        if seen.path == WELL_KNOWN {
            let line = held.lock().map(|line| line.clone()).unwrap_or_default();
            reply("200 OK", &[], &line)
        } else {
            reply("302 Found", &[("Location", elsewhere.as_str())], "")
        }
    }))?;
    let dir = project("probe-redirect")?;
    *line.lock().map_err(|_| "lock")? = own(&dir, &redirecting.url())?;
    let checked = probe(&dir, &redirecting.url(), &["--staging", "--tool", "curl"])?;
    assert!(checked.status.success(), "{checked:?}");
    assert_eq!(
        codes(&checked),
        ["probeRedirectedOutside", "probeChecksPartial"]
    );
    assert!(ids(&checked).is_empty());
    assert_eq!(redirecting.seen().len(), 2);
    assert!(other.seen().is_empty(), "{:?}", other.seen());
    Ok(())
}

fn fake_curl(dir: &Path, script: &str) -> std::io::Result<PathBuf> {
    let tools = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "{}-tools",
        dir.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("probe")
    ));
    fs::create_dir_all(&tools)?;
    let path = tools.join("curl");
    fs::write(&path, format!("#!/bin/sh\n{script}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    fs::canonicalize(path)
}

#[test]
fn a_curl_that_is_missing_slow_or_prints_garbage_is_a_limitation()
-> Result<(), Box<dyn std::error::Error>> {
    let line: Arc<Mutex<String>> = Arc::default();
    let server = Server::start(app(line.clone(), GOOD.to_vec(), false))?;
    let url = server.url();
    let version = "if [ \"$1\" = --version ]; then echo 'curl 8.0.0 (test)'; exit 0; fi";

    let cases = [
        (
            "probe-not-curl",
            "echo hello".to_owned(),
            "probeToolFailed",
            None,
        ),
        (
            "probe-garbage",
            format!("{version}\necho 'HTTP/1.1 200 OK'; echo; echo not-what-was-asked"),
            "probeTargetNotResponding",
            None,
        ),
        (
            "probe-slow",
            format!("{version}\nsleep 30"),
            "probeTargetNotResponding",
            Some("1"),
        ),
        (
            "probe-fails",
            format!("{version}\nexit 7"),
            "probeTargetNotResponding",
            None,
        ),
    ];
    for (name, script, expected, timeout) in cases {
        let dir = project(name)?;
        *line.lock().map_err(|_| "lock")? = own(&dir, &url)?;
        let tool = format!("curl={}", fake_curl(&dir, &script)?.display());
        let mut command = Command::new(env!("CARGO_BIN_EXE_seethru"));
        command
            .args([
                "scan",
                &dir.display().to_string(),
                "--json",
                "--probe",
                &url,
            ])
            .args(["--staging", "--tool", &tool])
            .env_remove("SEETHRU_TOOL_TIMEOUT_SECS");
        if let Some(seconds) = timeout {
            command.env("SEETHRU_TOOL_TIMEOUT_SECS", seconds);
        }
        let started = Instant::now();
        let checked = command.output()?;
        assert!(checked.status.success(), "{name} {checked:?}");
        assert_eq!(codes(&checked), [expected], "{name}");
        assert!(ids(&checked).is_empty(), "{name}");
        assert!(started.elapsed() < Duration::from_secs(20), "{name}");
    }

    let dir = project("probe-no-curl")?;
    *line.lock().map_err(|_| "lock")? = own(&dir, &url)?;
    let missing = Command::new(env!("CARGO_BIN_EXE_seethru"))
        .args([
            "scan",
            &dir.display().to_string(),
            "--json",
            "--probe",
            &url,
        ])
        .args(["--staging", "--tool", "curl"])
        .env("PATH", "")
        .output()?;
    assert!(missing.status.success(), "{missing:?}");
    assert_eq!(codes(&missing), ["probeToolFailed"]);
    assert!(server.seen().is_empty(), "{:?}", server.seen());
    Ok(())
}

#[test]
fn a_line_copied_from_someone_elses_app_does_not_prove_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    if !has_curl() {
        return Ok(());
    }
    let line: Arc<Mutex<String>> = Arc::default();
    let server = Server::start(app(line.clone(), GOOD.to_vec(), false))?;
    let url = server.url();
    let owner = project("probe-owner")?;
    let published = own(&owner, &url)?;
    *line.lock().map_err(|_| "lock")? = published.clone();
    let secret_kept = fs::read_dir(owner.join(".seethru/ownership"))?
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_to_string(entry.path()).ok())
        .collect::<String>();
    let public = published
        .strip_prefix("seethru-ownership=")
        .unwrap_or_default();
    assert_eq!(public.len(), 64);
    assert!(!secret_kept.contains(public));

    let copier = project("probe-copier")?;
    let _ = own(&copier, &url)?;
    let store = copier.join(".seethru/ownership");
    let files: Vec<PathBuf> = fs::read_dir(&store)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    fs::write(&files[0], format!("{public}\n"))?;
    let checked = probe(&copier, &url, &["--staging", "--tool", "curl"])?;
    assert!(checked.status.success(), "{checked:?}");
    assert_eq!(codes(&checked), ["ownershipNotVerified"]);
    assert!(ids(&checked).is_empty());
    let seen = server.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].path, WELL_KNOWN);

    let checked = probe(&owner, &url, &["--staging", "--tool", "curl"])?;
    assert_eq!(codes(&checked), ["probeChecksPartial"]);
    Ok(())
}
