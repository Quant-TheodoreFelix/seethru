use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use seethru_analyzer::Observed;
use seethru_core::{Lang, LimitationCode, ToolUse};
use seethru_guard::{
    Audit, Clock, Entry, Environment, Raw, Target, Token, Transport, TransportError,
    WELL_KNOWN_PATH, Wire,
};
use seethru_probe::{Fact, Outcome};

use crate::tool::{self, Limits, Name, Permit, Tool};

type Failure = Box<dyn std::error::Error>;

const OWNERSHIP_DIR: &str = "ownership";
const PROOF_DIR: &str = "proof";
const AUDIT_FILE: &str = "audit.jsonl";
const MARKER: &str = "seethru-remote-ip:";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CURL_MAX_TIME: &str = "20";
const CURL_CONNECT_TIME: &str = "10";
const MAX_PAGE_BYTES: &str = "5242880";
const MAX_OUTPUT_BYTES: u64 = 256 * 1024;
const MAX_HEADERS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) target: Target,
    pub(crate) production: bool,
}

fn plain_dir(dir: &Path) -> io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_dir() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a directory", dir.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(dir),
        Err(error) => Err(error),
    }
}

fn plain_file(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a regular file", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn new_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn token_path(state: &Path, target: &Target) -> PathBuf {
    state
        .join(OWNERSHIP_DIR)
        .join(format!("{}.token", target.slug()))
}

fn stored_token(state: &Path, target: &Target) -> io::Result<Option<Token>> {
    let path = token_path(state, target);
    let kept =
        fs::symlink_metadata(state.join(OWNERSHIP_DIR)).is_ok_and(|meta| meta.file_type().is_dir());
    if !kept || !plain_file(&path)? {
        return Ok(None);
    }
    let mut text = String::new();
    File::open(&path)?.take(1024).read_to_string(&mut text)?;
    Ok(Token::parse(&text))
}

fn random_token() -> io::Result<Token> {
    #[cfg(unix)]
    {
        let mut bytes = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(Token::from_random(&bytes))
    }
    #[cfg(not(unix))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "seethru cannot make an ownership token on this system yet",
        ))
    }
}

pub(crate) fn own(
    state: &Path,
    target: &Target,
    lang: Lang,
    out: &mut impl Write,
) -> Result<(), Failure> {
    plain_dir(&state.join(OWNERSHIP_DIR))?;
    let token = match stored_token(state, target)? {
        Some(token) => token,
        None => {
            let path = token_path(state, target);
            if plain_file(&path)? {
                fs::remove_file(&path)?;
            }
            let token = random_token()?;
            let mut file = new_private_file(&path)?;
            writeln!(file, "{}", token.as_str())?;
            token
        }
    };
    let address = format!("{}{WELL_KNOWN_PATH}", target.origin());
    let line = token.file_line(target);
    let origin = target.origin();
    match lang {
        Lang::En => writeln!(
            out,
            "seethru only checks a running app after you show that it is yours.\n\n\
             1. Make the app answer at this address\n   {address}\n\
             2. with a text file that contains this one line\n   {line}\n\
             3. Deploy the app, then run\n   seethru scan PATH --probe {origin} --staging --tool curl\n\n\
             Nothing was sent anywhere. The line is safe to publish. The secret that\n\
             matches it stays on this computer in the .seethru/ownership folder, so a\n\
             person who reads the line cannot use it. It only works for this address.\n\
             Remove the file from the app when you no longer want checks."
        )?,
        Lang::Ko => writeln!(
            out,
            "seethru는 실행 중인 앱이 사용자의 것임을 확인한 뒤에만 점검해요.\n\n\
             1. 앱이 이 주소에서\n   {address}\n\
             2. 아래 한 줄이 들어 있는 텍스트 파일로 응답하게 하세요\n   {line}\n\
             3. 앱을 배포한 뒤 실행하세요\n   seethru scan 경로 --probe {origin} --staging --tool curl\n\n\
             아무 곳에도 요청을 보내지 않았어요. 이 줄은 공개돼도 괜찮아요. 이 줄과 짝이\n\
             되는 비밀 값은 이 컴퓨터의 .seethru/ownership 폴더에만 있어서, 줄을 본 사람이\n\
             대신 쓸 수 없어요. 이 주소에서만 통해요. 점검을 더 원하지 않으면 앱에서\n\
             파일을 지우세요."
        )?,
    }
    Ok(())
}

struct RealClock {
    start: Instant,
}

impl Clock for RealClock {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    fn unix_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs())
    }

    fn sleep(&mut self, time: Duration) {
        thread::sleep(time);
    }
}

struct FileAudit {
    file: File,
}

impl Audit for FileAudit {
    fn record(&mut self, entry: &Entry) -> io::Result<()> {
        writeln!(self.file, "{}", entry.line())?;
        self.file.sync_data()
    }
}

fn open_audit(state: &Path) -> io::Result<File> {
    let path = state.join(AUDIT_FILE);
    if plain_file(&path)? {
        OpenOptions::new().append(true).open(&path)
    } else {
        new_private_file(&path)
    }
}

pub(crate) fn parse(lines: &[String], want_body: bool) -> Result<Raw, TransportError> {
    let marker = lines
        .iter()
        .rposition(|line| line.starts_with(MARKER))
        .ok_or(TransportError::Garbled)?;
    let remote = lines[marker][MARKER.len()..].trim().parse::<IpAddr>().ok();
    let lines = &lines[..marker];
    let mut at = 0;
    let mut raw = Raw {
        remote,
        ..Raw::default()
    };
    loop {
        let first = lines.get(at).ok_or(TransportError::Garbled)?;
        let mut parts = first.trim_end().split(' ');
        let status = match (parts.next(), parts.next()) {
            (Some(version), Some(code)) if version.starts_with("HTTP/") && code.len() == 3 => {
                code.parse::<u16>().map_err(|_| TransportError::Garbled)?
            }
            _ => return Err(TransportError::Garbled),
        };
        at += 1;
        let mut headers = Vec::new();
        loop {
            let line = lines.get(at).ok_or(TransportError::Garbled)?.trim_end();
            at += 1;
            if line.is_empty() {
                break;
            }
            if headers.len() >= MAX_HEADERS {
                return Err(TransportError::Garbled);
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_owned(), value.trim().to_owned()));
            }
        }
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        raw.status = status;
        raw.headers = headers;
        break;
    }
    if want_body {
        raw.body = lines[at..].join("\n").into_bytes();
    }
    Ok(raw)
}

struct Curl<'a> {
    tool: &'a Tool,
    lang: Lang,
}

fn arguments(wire: &Wire<'_>) -> Vec<OsString> {
    let target = wire.target;
    let mut args: Vec<String> = ["-q", "--silent", "--globoff", "--path-as-is", "--proto"]
        .map(str::to_owned)
        .to_vec();
    args.push(format!("={}", target.scheme().as_str()));
    args.extend(
        [
            "--max-redirs",
            "0",
            "--noproxy",
            "*",
            "--max-time",
            CURL_MAX_TIME,
            "--connect-timeout",
            CURL_CONNECT_TIME,
            "--max-filesize",
        ]
        .map(str::to_owned),
    );
    args.push(match wire.body_limit {
        Some(limit) => limit.to_string(),
        None => MAX_PAGE_BYTES.to_owned(),
    });
    args.push("--user-agent".to_owned());
    args.push(format!("seethru/{}", env!("CARGO_PKG_VERSION")));
    args.push("--dump-header".to_owned());
    args.push("-".to_owned());
    args.push("--output".to_owned());
    args.push(if wire.body_limit.is_some() {
        "-".to_owned()
    } else {
        "/dev/null".to_owned()
    });
    if let Some(origin) = wire.origin {
        args.push("--header".to_owned());
        args.push(format!("Origin: {origin}"));
    }
    if let Some(pin) = wire
        .pin
        .filter(|_| target.host().parse::<IpAddr>().is_err())
    {
        let address = match pin {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        };
        args.push("--resolve".to_owned());
        args.push(format!("{}:{}:{address}", target.host(), target.port()));
    }
    args.push("--write-out".to_owned());
    args.push(format!("\\n{MARKER}%{{remote_ip}}\\n"));
    args.push("--".to_owned());
    args.push(target.url(wire.path));
    args.into_iter().map(OsString::from).collect()
}

impl Transport for Curl<'_> {
    fn send(&mut self, wire: &Wire<'_>) -> Result<Raw, TransportError> {
        let args = arguments(wire);
        tool::say(self.lang, &self.tool.program, &args);
        let limits = Limits {
            timeout: tool::timeout_or(REQUEST_TIMEOUT),
            max_bytes: MAX_OUTPUT_BYTES,
        };
        let mut lines = Vec::new();
        let ran = tool::run(&self.tool.program, &args, &limits, &mut |line| {
            lines.push(line.to_owned());
        });
        match ran {
            Ok(()) => parse(&lines, wire.body_limit.is_some()),
            Err(tool::RunError::TimedOut) => Err(TransportError::TimedOut),
            Err(_) => Err(TransportError::Failed),
        }
    }
}

fn proof_text(fact: &Fact, production: bool) -> String {
    let pairs = |list: &[(String, String)]| {
        list.iter()
            .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
            .collect::<Vec<_>>()
    };
    let steps: Vec<_> = fact
        .steps
        .iter()
        .map(|step| {
            serde_json::json!({
                "request": step.request,
                "method": step.method,
                "path": step.path,
                "sent": pairs(&step.sent),
                "status": step.status,
                "seen": pairs(&step.seen),
            })
        })
        .collect();
    let value = serde_json::json!({
        "finding": fact.id(),
        "environment": if production { "production" } else { "staging" },
        "auditLog": AUDIT_FILE,
        "steps": steps,
    });
    format!("{value:#}\n")
}

fn write_proofs(state: &Path, outcome: &Outcome, production: bool) -> io::Result<()> {
    let dir = state.join(PROOF_DIR);
    plain_dir(&dir)?;
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let is_proof = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.ends_with(".json"));
        if is_proof && entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
        }
    }
    for fact in &outcome.facts {
        let path = state.join(fact.proof_file());
        let mut file = new_private_file(&path)?;
        file.write_all(proof_text(fact, production).as_bytes())?;
    }
    Ok(())
}

fn stopped(code: LimitationCode) -> Observed {
    Observed {
        tool: None,
        production: false,
        outcome: Outcome {
            problems: vec![code],
            ..Outcome::default()
        },
    }
}

pub(crate) fn observe(
    root: &Path,
    state: &Path,
    plan: &Plan,
    confirmed: bool,
    permits: &[Permit],
    lang: Lang,
) -> Result<Observed, Failure> {
    let Some(permit) = permits.iter().find(|permit| permit.name == Name::Curl) else {
        return Ok(stopped(LimitationCode::ProbeToolNotPermitted));
    };
    let Some(token) = stored_token(state, &plan.target)? else {
        tool::note(
            lang,
            &format!(
                "seethru has no ownership token for {}. Run `seethru own {}` first. Nothing was sent.",
                plan.target.origin(),
                plan.target.origin()
            ),
            &format!(
                "{} 의 소유 확인 토큰이 없어요. 먼저 `seethru own {}` 을 실행하세요. 아무것도 보내지 않았어요.",
                plan.target.origin(),
                plan.target.origin()
            ),
        );
        return Ok(stopped(LimitationCode::OwnershipNotVerified));
    };
    let root = fs::canonicalize(root)?;
    let Some(curl) = tool::prepare(&root, permit, lang)? else {
        return Ok(stopped(LimitationCode::ProbeToolFailed));
    };
    let environment = if plan.production {
        Environment::Production { confirmed }
    } else {
        Environment::Staging
    };
    let mut file = open_audit(state)?;
    let mut clock = RealClock {
        start: Instant::now(),
    };
    let header = serde_json::json!({
        "time": clock.unix_seconds(),
        "phase": "run",
        "target": plan.target.origin(),
        "environment": if plan.production { "production" } else { "staging" },
        "tool": format!("curl {}", curl.version),
    });
    writeln!(file, "{header}")?;
    let mut audit = FileAudit { file };
    let mut transport = Curl { tool: &curl, lang };
    let outcome = seethru_probe::observe(
        plan.target.clone(),
        token,
        environment,
        &mut transport,
        &mut audit,
        &mut clock,
    );
    write_proofs(state, &outcome, plan.production)?;
    Ok(Observed {
        tool: Some(ToolUse {
            name: Name::Curl.as_str().to_owned(),
            version: curl.version.clone(),
        }),
        production: plan.production,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.split('\n').map(str::to_owned).collect()
    }

    #[test]
    fn reads_status_and_headers_and_ignores_a_body_that_imitates_the_marker() {
        let raw = parse(
            &lines(
                "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Frame-Options: DENY\r\n\r\nline one\nseethru-remote-ip:10.0.0.1\nlast\nseethru-remote-ip:127.0.0.1\n",
            ),
            true,
        );
        let raw = raw.unwrap_or_default();
        assert_eq!(raw.status, 200);
        assert_eq!(raw.remote, Some(IpAddr::from([127, 0, 0, 1])));
        assert_eq!(raw.headers.len(), 2);
        assert_eq!(
            String::from_utf8_lossy(&raw.body),
            "line one\nseethru-remote-ip:10.0.0.1\nlast"
        );
        let headers_only = parse(
            &lines("HTTP/2 404 \r\nserver: x\r\n\r\n\nseethru-remote-ip:::1\n"),
            false,
        )
        .unwrap_or_default();
        assert_eq!(headers_only.status, 404);
        assert!(headers_only.body.is_empty());
        assert_eq!(headers_only.remote, "::1".parse().ok());
    }

    #[test]
    fn refuses_output_that_is_not_an_answer() {
        for text in [
            "",
            "hello\n",
            "seethru-remote-ip:127.0.0.1\n",
            "HTTP/1.1 200 OK\r\nA: b\r\n",
            "HTTP/1.1 abc OK\r\n\r\nseethru-remote-ip:127.0.0.1\n",
            "garbage\r\n\r\nseethru-remote-ip:127.0.0.1\n",
        ] {
            assert!(parse(&lines(text), false).is_err(), "{text:?}");
        }
    }

    #[test]
    fn curl_is_told_to_stay_on_the_target() {
        let target = Target::parse("http://localhost:8080");
        let Ok(target) = target else {
            return;
        };
        let args: Vec<String> = arguments(&Wire {
            target: &target,
            path: "/",
            origin: Some("https://other.invalid"),
            body_limit: None,
            pin: target.address(),
        })
        .into_iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
        assert_eq!(args.first().map(String::as_str), Some("-q"));
        let pair = |name: &str| {
            args.iter()
                .position(|arg| arg == name)
                .and_then(|at| args.get(at + 1))
                .cloned()
        };
        assert_eq!(pair("--proto").as_deref(), Some("=http"));
        assert_eq!(pair("--max-redirs").as_deref(), Some("0"));
        assert_eq!(pair("--noproxy").as_deref(), Some("*"));
        assert_eq!(pair("--output").as_deref(), Some("/dev/null"));
        assert_eq!(
            pair("--resolve").as_deref(),
            Some("localhost:8080:127.0.0.1")
        );
        assert_eq!(pair("--").as_deref(), Some("http://localhost:8080/"));
        assert_eq!(
            args.last().map(String::as_str),
            Some("http://localhost:8080/")
        );
        assert!(!args.iter().any(|arg| {
            matches!(
                arg.as_str(),
                "-L" | "--location"
                    | "-d"
                    | "--data"
                    | "-X"
                    | "--request"
                    | "-u"
                    | "-b"
                    | "-k"
                    | "--insecure"
            )
        }));
    }
}
