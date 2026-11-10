use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use seethru_analyzer::{BinaryInput, CodeReader};
use seethru_core::{BinaryFormat, Lang, LimitationCode, ToolUse};

type Failure = Box<dyn std::error::Error>;

pub(crate) const TIMEOUT_ENV: &str = "SEETHRU_TOOL_TIMEOUT_SECS";
pub(crate) const MAX_BINARIES: usize = 16;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
const VERSION_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_OUTPUT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_VERSION_BYTES: u64 = 64 * 1024;
const MAX_LINE_BYTES: usize = 64 * 1024;
const TOOL_PATH: &str = "/usr/bin:/bin";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Name {
    Dwarfdump,
    Objdump,
}

impl Name {
    const ALL: [Self; 2] = [Self::Dwarfdump, Self::Objdump];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Dwarfdump => "dwarfdump",
            Self::Objdump => "objdump",
        }
    }

    fn programs(self) -> &'static [&'static str] {
        match self {
            Self::Dwarfdump => &["llvm-dwarfdump", "dwarfdump"],
            Self::Objdump => &["llvm-objdump", "objdump"],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Permit {
    pub(crate) name: Name,
    pub(crate) path: Option<PathBuf>,
}

pub(crate) fn permit(text: &OsStr) -> Result<Permit, String> {
    let text = text
        .to_str()
        .ok_or_else(|| "--tool needs readable text".to_owned())?;
    let (name, path) = match text.split_once('=') {
        Some((name, path)) => (name, Some(path)),
        None => (text, None),
    };
    let known = Name::ALL.iter().find(|known| known.as_str() == name);
    let Some(name) = known else {
        return Err(format!(
            "unknown tool '{name}'. seethru can run dwarfdump and objdump"
        ));
    };
    let path = match path {
        None => None,
        Some(path) if Path::new(path).is_absolute() => Some(PathBuf::from(path)),
        Some(path) => {
            return Err(format!(
                "--tool {}={path} must be a full path that starts at the root folder",
                name.as_str()
            ));
        }
    };
    Ok(Permit { name: *name, path })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flavor {
    Llvm,
    Gnu,
}

struct Tool {
    name: Name,
    program: PathBuf,
    flavor: Flavor,
    version: String,
}

#[derive(Debug)]
enum RunError {
    Start(io::Error),
    TimedOut,
    TooMuch,
    Failed,
}

struct Limits {
    timeout: Duration,
    max_bytes: u64,
}

enum Piece {
    Line(Vec<u8>),
    TooMuch,
}

fn pump(stdout: impl Read, max_bytes: u64, out: &SyncSender<Piece>) {
    let mut reader = BufReader::with_capacity(MAX_LINE_BYTES, stdout);
    let mut line: Vec<u8> = Vec::new();
    let mut overlong = false;
    let mut total = 0u64;
    loop {
        let Ok(available) = reader.fill_buf() else {
            return;
        };
        if available.is_empty() {
            break;
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let chunk = &available[..newline.unwrap_or(available.len())];
        if !overlong {
            if line.len() + chunk.len() <= MAX_LINE_BYTES {
                line.extend_from_slice(chunk);
            } else {
                overlong = true;
                line.clear();
            }
        }
        let used = chunk.len() + usize::from(newline.is_some());
        reader.consume(used);
        total = total.saturating_add(u64::try_from(used).unwrap_or(u64::MAX));
        if total > max_bytes {
            let _ = out.send(Piece::TooMuch);
            return;
        }
        if newline.is_some() {
            if !overlong && out.send(Piece::Line(std::mem::take(&mut line))).is_err() {
                return;
            }
            line.clear();
            overlong = false;
        }
    }
    if !line.is_empty() && !overlong {
        let _ = out.send(Piece::Line(line));
    }
}

fn run(
    program: &Path,
    args: &[OsString],
    limits: &Limits,
    sink: &mut dyn FnMut(&str),
) -> Result<(), RunError> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", TOOL_PATH)
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(RunError::Start)?;
    let deadline = Instant::now() + limits.timeout;
    let mut stopped = None;
    if let Some(stdout) = child.stdout.take() {
        let (sender, receiver) = sync_channel(1024);
        let max_bytes = limits.max_bytes;
        thread::spawn(move || pump(stdout, max_bytes, &sender));
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match receiver.recv_timeout(left) {
                Ok(Piece::Line(line)) => sink(&String::from_utf8_lossy(&line)),
                Ok(Piece::TooMuch) => {
                    stopped = Some(RunError::TooMuch);
                    break;
                }
                Err(RecvTimeoutError::Timeout) => {
                    stopped = Some(RunError::TimedOut);
                    break;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }
    if stopped.is_some() {
        let _ = child.kill();
    }
    let status = wait(&mut child, deadline + Duration::from_secs(5));
    match stopped {
        Some(error) => Err(error),
        None if status.is_some_and(|status| status.success()) => Ok(()),
        None if status.is_none() => Err(RunError::TimedOut),
        None => Err(RunError::Failed),
    }
}

fn wait(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn version_of(name: Name, text: &str) -> Option<(Flavor, String)> {
    let number = |from: &str| {
        let digits: String = from
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .take(32)
            .collect();
        digits
            .starts_with(|c: char| c.is_ascii_digit())
            .then(|| digits.trim_end_matches('.').to_owned())
    };
    if let Some(at) = text.find("LLVM version ") {
        return number(&text[at + "LLVM version ".len()..]).map(|version| (Flavor::Llvm, version));
    }
    let first = text.lines().next()?;
    if name == Name::Objdump && first.starts_with("GNU objdump") {
        return first
            .rsplit(' ')
            .next()
            .and_then(number)
            .map(|version| (Flavor::Gnu, format!("GNU {version}")));
    }
    None
}

fn inside(root: &Path, path: &Path) -> bool {
    path.starts_with(root)
}

fn is_program(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.is_file() && meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        meta.is_file()
    }
}

fn locate(root: &Path, permit: &Permit) -> Result<Option<PathBuf>, Failure> {
    let name = permit.name.as_str();
    if let Some(given) = &permit.path {
        let real = fs::canonicalize(given)
            .map_err(|error| format!("cannot use --tool {name}={}: {error}", given.display()))?;
        if !is_program(&real) {
            return Err(format!(
                "--tool {name}={} is not a program that can be run",
                given.display()
            )
            .into());
        }
        if inside(root, &real) {
            return Err(format!(
                "--tool {name}={} is inside the project being scanned. seethru does not run programs from the project it checks",
                given.display()
            )
            .into());
        }
        return Ok(Some(real));
    }
    let Some(search) = std::env::var_os("PATH") else {
        return Ok(None);
    };
    for dir in std::env::split_paths(&search) {
        if !dir.is_absolute() {
            continue;
        }
        for program in permit.name.programs() {
            let Ok(real) = fs::canonicalize(dir.join(program)) else {
                continue;
            };
            if is_program(&real) && !inside(root, &real) {
                return Ok(Some(real));
            }
        }
    }
    Ok(None)
}

fn say(lang: Lang, program: &Path, args: &[OsString]) {
    let mut command = program.display().to_string();
    for arg in args {
        command.push(' ');
        command.push_str(&arg.to_string_lossy());
    }
    let text = match lang {
        Lang::En => format!("Running an outside tool you allowed with --tool.\n  {command}"),
        Lang::Ko => format!("--tool로 허락한 외부 도구를 실행해요.\n  {command}"),
    };
    let _ = writeln!(io::stderr(), "{text}");
}

fn note(lang: Lang, en: &str, ko: &str) {
    let _ = writeln!(
        io::stderr(),
        "{}",
        match lang {
            Lang::En => en,
            Lang::Ko => ko,
        }
    );
}

fn prepare(root: &Path, permit: &Permit, lang: Lang) -> Result<Option<Tool>, Failure> {
    let name = permit.name.as_str();
    let Some(program) = locate(root, permit)? else {
        note(
            lang,
            &format!(
                "seethru did not find {name} on this computer. Install LLVM, or give the full path with --tool {name}=PATH."
            ),
            &format!(
                "이 컴퓨터에서 {name}를 찾지 못했어요. LLVM을 설치하거나 --tool {name}=경로 로 전체 경로를 알려 주세요."
            ),
        );
        return Ok(None);
    };
    let args = [OsString::from("--version")];
    say(lang, &program, &args);
    let mut text = String::new();
    let limits = Limits {
        timeout: VERSION_TIMEOUT,
        max_bytes: MAX_VERSION_BYTES,
    };
    let ran = run(&program, &args, &limits, &mut |line| {
        text.push_str(line);
        text.push('\n');
    });
    let known = ran.ok().and_then(|()| version_of(permit.name, &text));
    let Some((flavor, version)) = known else {
        note(
            lang,
            &format!(
                "{} did not answer like a version of {name} that seethru knows, so it was not used.",
                program.display()
            ),
            &format!(
                "{} 가 seethru가 아는 {name}처럼 답하지 않아서 쓰지 않았어요.",
                program.display()
            ),
        );
        return Ok(None);
    };
    Ok(Some(Tool {
        name: permit.name,
        program,
        flavor,
        version,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Linked {
    Program(BinaryFormat),
    Object,
    Universal,
    Other,
}

fn kind_of(header: &[u8]) -> Linked {
    let u16_at = |at: usize, little: bool| {
        header.get(at..at + 2).map(|bytes| {
            let bytes = [bytes[0], bytes[1]];
            if little {
                u16::from_le_bytes(bytes)
            } else {
                u16::from_be_bytes(bytes)
            }
        })
    };
    let u32_at = |at: usize, little: bool| {
        header.get(at..at + 4).map(|bytes| {
            let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
            if little {
                u32::from_le_bytes(bytes)
            } else {
                u32::from_be_bytes(bytes)
            }
        })
    };
    match header.get(..4) {
        Some([0x7f, b'E', b'L', b'F']) => {
            let little = header.get(5) != Some(&2);
            match u16_at(16, little) {
                Some(2 | 3) => Linked::Program(BinaryFormat::Elf),
                Some(1) => Linked::Object,
                _ => Linked::Other,
            }
        }
        Some([0xcf | 0xce, 0xfa, 0xed, 0xfe]) | Some([0xfe, 0xed, 0xfa, 0xcf | 0xce]) => {
            let little = header.first() != Some(&0xfe);
            match u32_at(12, little) {
                Some(2 | 6 | 8) => Linked::Program(BinaryFormat::MachO),
                Some(1) => Linked::Object,
                _ => Linked::Other,
            }
        }
        Some([0xca, 0xfe, 0xba, 0xbe | 0xbf]) => Linked::Universal,
        _ => Linked::Other,
    }
}

fn kind_at(path: &Path) -> Linked {
    let mut header = [0u8; 20];
    let read = fs::File::open(path).and_then(|mut file| file.read(&mut header));
    match read {
        Ok(count) => kind_of(&header[..count]),
        Err(_) => Linked::Other,
    }
}

fn only_file(dir: &Path, wanted: &dyn Fn(&str) -> bool) -> Option<PathBuf> {
    let mut found: Vec<PathBuf> = fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_name().to_str().is_some_and(wanted))
        .map(|entry| entry.path())
        .collect();
    found.sort();
    (found.len() == 1).then(|| found.remove(0))
}

fn debug_file(binary: &Path) -> Option<PathBuf> {
    let name = binary.file_name()?.to_str()?;
    let dir = binary.parent()?;
    let inner = Path::new("Contents").join("Resources").join("DWARF");
    let beside = dir.join(format!("{name}.dSYM")).join(&inner);
    if let Some(file) = only_file(&beside, &|_| true) {
        return Some(file);
    }
    let prefix = format!("{}-", name.replace('-', "_"));
    let bundle = only_file(&dir.join("deps"), &|entry| {
        entry.starts_with(&prefix) && entry.ends_with(".dSYM")
    })?;
    only_file(&bundle.join(inner), &|_| true)
}

fn built_in(release: &Path) -> Vec<(PathBuf, BinaryFormat)> {
    let Ok(entries) = fs::read_dir(release) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    paths
        .into_iter()
        .filter(|path| fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file()))
        .filter_map(|path| match kind_at(&path) {
            Linked::Program(format) => Some((path, format)),
            _ => None,
        })
        .collect()
}

fn given_binary(path: &Path) -> Result<(PathBuf, BinaryFormat), Failure> {
    let real = fs::canonicalize(path)
        .map_err(|error| format!("cannot read --binary {}: {error}", path.display()))?;
    if !real.is_file() {
        return Err(format!("--binary {} is not a file", path.display()).into());
    }
    match kind_at(&real) {
        Linked::Program(format) => Ok((real, format)),
        Linked::Object => Err(format!(
            "--binary {} is an object file from before the final link. Pass the linked program instead",
            path.display()
        )
        .into()),
        Linked::Universal => Err(format!(
            "--binary {} holds more than one architecture. Extract one with lipo and pass that",
            path.display()
        )
        .into()),
        Linked::Other => Err(format!(
            "--binary {} is not an ELF or Mach-O program",
            path.display()
        )
        .into()),
    }
}

fn timeout() -> Duration {
    std::env::var(TIMEOUT_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| (1..=86_400).contains(seconds))
        .map_or(DEFAULT_TIMEOUT, Duration::from_secs)
}

fn read_one(
    root: &Path,
    binary: &Path,
    format: BinaryFormat,
    tools: &[Tool],
    lang: Lang,
) -> Result<Option<BinaryInput>, Failure> {
    let debug = match format {
        BinaryFormat::MachO => debug_file(binary),
        BinaryFormat::Elf => Some(binary.to_path_buf()),
    };
    let Some(debug) = debug else {
        return Ok(None);
    };
    let mut reader = CodeReader::new(root)?;
    let limits = Limits {
        timeout: timeout(),
        max_bytes: MAX_OUTPUT_BYTES,
    };
    for tool in tools {
        let mut args: Vec<OsString> = Vec::new();
        match (tool.name, tool.flavor) {
            (Name::Dwarfdump, _) => {
                args.push("--debug-info".into());
                args.push(debug.clone().into());
            }
            (Name::Objdump, Flavor::Llvm) => {
                args.extend(
                    ["--disassemble", "--line-numbers", "--no-show-raw-insn"].map(Into::into),
                );
                if format == BinaryFormat::MachO {
                    let mut dsym = OsString::from("--dsym=");
                    dsym.push(&debug);
                    args.push(dsym);
                }
                args.push(binary.into());
            }
            (Name::Objdump, Flavor::Gnu) => {
                args.extend(["-d", "-l", "--no-show-raw-insn"].map(Into::into));
                args.push(binary.into());
            }
        }
        say(lang, &tool.program, &args);
        let ran = run(&tool.program, &args, &limits, &mut |line| match tool.name {
            Name::Dwarfdump => reader.debug_info(line),
            Name::Objdump => reader.disassembly(line),
        });
        if let Err(error) = ran {
            let why = match error {
                RunError::Start(error) => error.to_string(),
                RunError::TimedOut => format!(
                    "it did not finish in {} seconds. Set {TIMEOUT_ENV} to allow more",
                    limits.timeout.as_secs()
                ),
                RunError::TooMuch => "it printed more than seethru reads".to_owned(),
                RunError::Failed => "it ended with an error".to_owned(),
            };
            let _ = writeln!(
                io::stderr(),
                "{} could not read {}: {why}",
                tool.name.as_str(),
                binary.display()
            );
            return Err(Box::new(Unusable));
        }
    }
    Ok(Some(BinaryInput {
        path: binary.to_path_buf(),
        format,
        tools: tools
            .iter()
            .map(|tool| ToolUse {
                name: tool.name.as_str().to_owned(),
                version: tool.version.clone(),
            })
            .collect(),
        code: reader.finish(),
    }))
}

#[derive(Debug)]
struct Unusable;

impl std::fmt::Display for Unusable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the outside tool could not be used")
    }
}

impl std::error::Error for Unusable {}

#[derive(Default)]
pub(crate) struct Collected {
    pub(crate) binaries: Vec<BinaryInput>,
    pub(crate) problems: Vec<LimitationCode>,
}

pub(crate) fn collect(
    root: &Path,
    permits: &[Permit],
    given: &[PathBuf],
    built: Option<&[PathBuf]>,
    lang: Lang,
) -> Result<Collected, Failure> {
    let root = fs::canonicalize(root)?;
    let mut out = Collected::default();
    let mut binaries = Vec::new();
    for path in given {
        binaries.push(given_binary(path)?);
    }
    for deps in built.unwrap_or_default() {
        if let Some(release) = deps.parent() {
            binaries.extend(built_in(release));
        }
    }
    let mut seen = Vec::new();
    binaries.retain(|(path, _)| {
        let fresh = !seen.contains(path);
        seen.push(path.clone());
        fresh
    });
    if binaries.len() > MAX_BINARIES {
        return Err(format!(
            "{} built programs were found, and seethru reads at most {MAX_BINARIES} in one scan. Pass the ones to check with --binary and leave out --build",
            binaries.len()
        )
        .into());
    }
    if binaries.is_empty() {
        if built.is_some() && !permits.is_empty() {
            out.problems.push(LimitationCode::BinaryNotFound);
        }
        return Ok(out);
    }
    let allowed = |name: Name| permits.iter().any(|permit| permit.name == name);
    if !Name::ALL.iter().all(|name| allowed(*name)) {
        out.problems.push(LimitationCode::BinaryToolNotPermitted);
        return Ok(out);
    }
    let mut tools = Vec::new();
    for name in Name::ALL {
        let Some(permit) = permits.iter().find(|permit| permit.name == name) else {
            continue;
        };
        match prepare(&root, permit, lang)? {
            Some(tool) => tools.push(tool),
            None => {
                out.problems.push(LimitationCode::BinaryToolFailed);
                return Ok(out);
            }
        }
    }
    for (binary, format) in binaries {
        match read_one(&root, &binary, format, &tools, lang) {
            Ok(Some(input)) => out.binaries.push(input),
            Ok(None) => out.problems.push(LimitationCode::BinaryWithoutLineInfo),
            Err(error) if error.is::<Unusable>() => {
                out.problems.push(LimitationCode::BinaryToolFailed);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(script: &str, limits: &Limits) -> (Result<(), RunError>, Vec<String>) {
        let mut lines = Vec::new();
        let args = [OsString::from("-c"), OsString::from(script)];
        let ran = run(Path::new("/bin/sh"), &args, limits, &mut |line| {
            lines.push(line.to_owned());
        });
        (ran, lines)
    }

    fn limits(millis: u64, max_bytes: u64) -> Limits {
        Limits {
            timeout: Duration::from_millis(millis),
            max_bytes,
        }
    }

    #[test]
    fn parses_what_the_user_permits() {
        let parsed = permit(OsStr::new("objdump"));
        assert_eq!(
            parsed,
            Ok(Permit {
                name: Name::Objdump,
                path: None
            })
        );
        let parsed = permit(OsStr::new("dwarfdump=/opt/llvm/bin/llvm-dwarfdump"));
        assert_eq!(
            parsed.map(|permit| permit.path),
            Ok(Some(PathBuf::from("/opt/llvm/bin/llvm-dwarfdump")))
        );
        assert!(permit(OsStr::new("objdump=bin/objdump")).is_err());
        assert!(permit(OsStr::new("ghidra")).is_err());
        assert!(permit(OsStr::new("")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn passes_lines_on_and_drops_the_environment() {
        let (ran, lines) = shell(
            "printf 'a\\nb'; echo \"[$HOME]\"; pwd",
            &limits(10_000, 1024),
        );
        assert!(ran.is_ok(), "{ran:?}");
        assert_eq!(lines, ["a", "b[]", "/"]);
    }

    #[cfg(unix)]
    #[test]
    fn stops_a_tool_that_takes_too_long() {
        let started = Instant::now();
        let (ran, _) = shell("sleep 30", &limits(200, 1024));
        assert!(matches!(ran, Err(RunError::TimedOut)), "{ran:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn stops_a_tool_that_prints_too_much() {
        let (ran, lines) = shell("while :; do echo line; done", &limits(20_000, 4096));
        assert!(matches!(ran, Err(RunError::TooMuch)), "{ran:?}");
        assert!(lines.len() < 2000);
    }

    #[cfg(unix)]
    #[test]
    fn drops_a_line_that_is_too_long_and_reports_failure() {
        let (ran, lines) = shell(
            "head -c 200000 /dev/zero | tr '\\0' 'x'; echo; echo short; exit 3",
            &limits(20_000, 1024 * 1024),
        );
        assert!(matches!(ran, Err(RunError::Failed)), "{ran:?}");
        assert_eq!(lines, ["short"]);
    }

    #[test]
    fn reads_versions_it_knows() {
        let llvm = "Apple LLVM version 21.0.0\n  Optimized build.\n";
        assert_eq!(
            version_of(Name::Objdump, llvm),
            Some((Flavor::Llvm, "21.0.0".to_owned()))
        );
        let gnu = "GNU objdump (GNU Binutils for Ubuntu) 2.42\nCopyright";
        assert_eq!(
            version_of(Name::Objdump, gnu),
            Some((Flavor::Gnu, "GNU 2.42".to_owned()))
        );
        assert_eq!(version_of(Name::Dwarfdump, gnu), None);
        assert_eq!(version_of(Name::Objdump, "hello\n"), None);
        assert_eq!(version_of(Name::Objdump, "LLVM version `rm -rf`"), None);
    }

    #[test]
    fn tells_linked_programs_from_other_files() {
        let mut macho = vec![0xcf, 0xfa, 0xed, 0xfe];
        macho.extend([0u8; 8]);
        macho.extend(2u32.to_le_bytes());
        assert_eq!(kind_of(&macho), Linked::Program(BinaryFormat::MachO));
        macho[12] = 1;
        assert_eq!(kind_of(&macho), Linked::Object);
        let mut elf = vec![0x7f, b'E', b'L', b'F', 2, 1];
        elf.extend([0u8; 10]);
        elf.extend(3u16.to_le_bytes());
        assert_eq!(kind_of(&elf), Linked::Program(BinaryFormat::Elf));
        assert_eq!(kind_of(b"!<arch>\n"), Linked::Other);
        assert_eq!(kind_of(&[0xca, 0xfe, 0xba, 0xbe]), Linked::Universal);
        assert_eq!(kind_of(&[]), Linked::Other);
    }
}
