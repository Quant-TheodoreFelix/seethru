mod build;
mod mcp;
mod probe;
mod tool;

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use seethru_core::{Confidence, Lang, ScanReport, Severity};

const USAGE: &str = "\
seethru - see through your app before attackers do

Usage
  seethru scan [PATH] [--out FILE] [--json] [--lang LANG] [--no-config]
               [--build-output DIR] [--sarif FILE]... [--sarif-out FILE]
               [--compile-commands FILE] [--llvm-ir PATH]... [--build]
               [--binary FILE]... [--tool NAME[=PATH]]...
               [--probe URL (--staging | --production --confirm-production)]
  seethru own URL [PATH] [--lang LANG]
  seethru mcp [--root DIR]... [--allow-build] [--tool NAME[=PATH]]...
  seethru schema
  seethru --version

Commands
  scan     Analyze a project directory (default is the current directory)
  schema   Print the JSON Schema of the scan report

Options
  --out FILE   Where to write the HTML report (default is PATH/.seethru/report.html)
  --json       Print the scan report as JSON to stdout instead of writing HTML
  --lang LANG  Language of the summary and the report, en or ko (default is en)
  --no-config  Ignore seethru.toml in the scanned project
  --build-output DIR
               Read the Vite or Next build output in DIR, a folder inside the
               project. seethru never runs the build itself
  --sarif FILE Add the results an outside scanner wrote to FILE in SARIF 2.1.0.
               Can be given up to 8 times. seethru never runs the scanner
  --sarif-out FILE
               Also write what seethru found to FILE in SARIF 2.1.0
  --compile-commands FILE
               Read compile_commands.json from FILE, a file inside the project,
               to learn which C and C++ files are built. Nothing in it is run
  --llvm-ir PATH
               Read compiled output of a Rust project from PATH, a .ll file or
               a folder with .ll files and, next to them, .s files. Can be given
               more than once. seethru does not run the build unless --build
               is given
  --build      Build a Rust project with cargo and read the compiled output.
               This runs the project's build scripts and macros on this
               computer, so use it only on code you trust. Nothing is
               downloaded. The output goes to PATH/.seethru/build
  --binary FILE
               A linked program (ELF or Mach-O) that you built from this
               project, to check that memory wipes are still in it. Can be
               given more than once. Reading it needs --tool. With --build,
               seethru also checks the programs that build makes
  --tool NAME[=PATH]
               Allow seethru to run an outside tool on this computer. NAME is
               objdump or dwarfdump (the LLVM versions), and both are needed
               to read a built program. Nothing is run without this option.
               PATH is the full path of the tool when it is not on PATH. The
               tool gets 600 seconds, or SEETHRU_TOOL_TIMEOUT_SECS.
               NAME curl is for --probe
  --probe URL  Also check the running app at URL, such as
               https://staging.example.com. seethru first confirms the app is
               yours (see `seethru own`), then sends a few plain GET requests
               to that address only, slowly, and keeps no page content. Every
               request is written to PATH/.seethru/audit.jsonl before it is
               sent. Needs --tool curl and one of --staging or --production.
               http:// is accepted only for an app on this computer
  --staging    The app at URL is a test copy. Prefer this
  --production The app at URL is the one real users use. Also needs
               --confirm-production

Proving an app is yours
  seethru own URL [PATH]
               Prints the address and the one line the app must serve before
               seethru will check it. Sends nothing. The line is safe to
               publish. The secret it is made from stays on this computer in
               PATH/.seethru/ownership, and checks only work from there

MCP server (for coding agents, over standard input and output)
  --root DIR   A folder the agent may scan. Can be given more than once.
               Without it, only the current folder
  --allow-build
               Let the agent ask for a scan that builds the project
  --tool NAME[=PATH]
               Let the agent ask for a scan that runs this outside tool
  The agent cannot change these. Only the flags you start the server with
  decide what may run
";

const REPORT_DIR: &str = ".seethru";
const REPORT_FILE: &str = "report.html";

#[allow(clippy::large_enum_variant)]
enum Command {
    Scan {
        path: PathBuf,
        out: Option<PathBuf>,
        json: bool,
        lang: Lang,
        read_config: bool,
        build_output: Option<PathBuf>,
        sarif: Vec<PathBuf>,
        sarif_out: Option<PathBuf>,
        compile_commands: Option<PathBuf>,
        llvm_ir: Vec<PathBuf>,
        build: bool,
        binaries: Vec<PathBuf>,
        tools: Vec<tool::Permit>,
        probe: Option<probe::Plan>,
        confirmed: bool,
    },
    Own {
        target: seethru_guard::Target,
        path: PathBuf,
        lang: Lang,
    },
    Mcp {
        roots: Vec<PathBuf>,
        allow_build: bool,
        tools: Vec<tool::Permit>,
    },
    Schema,
    Version,
    Help,
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, lexopt::Error> {
    use lexopt::prelude::*;

    let mut parser = lexopt::Parser::from_args(args);
    let Some(first) = parser.next()? else {
        return Ok(Command::Help);
    };
    let command = match first {
        Short('h') | Long("help") => return Ok(Command::Help),
        Short('V') | Long("version") => return Ok(Command::Version),
        Value(value) => value.string()?,
        other => return Err(other.unexpected()),
    };
    match command.as_str() {
        "scan" => {
            let mut path = None;
            let mut out = None;
            let mut json = false;
            let mut lang = Lang::default();
            let mut read_config = true;
            let mut build_output = None;
            let mut sarif = Vec::new();
            let mut sarif_out: Option<PathBuf> = None;
            let mut compile_commands = None;
            let mut llvm_ir = Vec::new();
            let mut build = false;
            let mut binaries = Vec::new();
            let mut probe_url = None;
            let mut staging = false;
            let mut production = false;
            let mut confirmed = false;
            let mut tools: Vec<tool::Permit> = Vec::new();
            while let Some(arg) = parser.next()? {
                match arg {
                    Long("json") => json = true,
                    Long("build-output") => build_output = Some(PathBuf::from(parser.value()?)),
                    Long("sarif") => sarif.push(PathBuf::from(parser.value()?)),
                    Long("sarif-out") => sarif_out = Some(PathBuf::from(parser.value()?)),
                    Long("compile-commands") => {
                        compile_commands = Some(PathBuf::from(parser.value()?));
                    }
                    Long("llvm-ir") => llvm_ir.push(PathBuf::from(parser.value()?)),
                    Long("build") => build = true,
                    Long("binary") => binaries.push(PathBuf::from(parser.value()?)),
                    Long("probe") => probe_url = Some(parser.value()?.string()?),
                    Long("staging") => staging = true,
                    Long("production") => production = true,
                    Long("confirm-production") => confirmed = true,
                    Long("tool") => {
                        let permit = tool::permit(&parser.value()?)
                            .map_err(|message| lexopt::Error::Custom(message.into()))?;
                        if tools.iter().any(|known| known.name == permit.name) {
                            return Err(lexopt::Error::Custom(
                                format!("--tool {} was given twice", permit.name.as_str()).into(),
                            ));
                        }
                        tools.push(permit);
                    }
                    Long("no-config") => read_config = false,
                    Long("lang") => {
                        let code = parser.value()?.string()?;
                        lang = Lang::from_code(&code).ok_or_else(|| {
                            lexopt::Error::Custom(
                                format!("unknown language '{code}', use en or ko").into(),
                            )
                        })?;
                    }
                    Long("out") => out = Some(PathBuf::from(parser.value()?)),
                    Short('h') | Long("help") => return Ok(Command::Help),
                    Value(value) if path.is_none() => path = Some(PathBuf::from(value)),
                    other => return Err(other.unexpected()),
                }
            }
            if json && out.is_some() {
                return Err(lexopt::Error::Custom(
                    "--json and --out cannot be used together".into(),
                ));
            }
            if sarif_out
                .as_ref()
                .is_some_and(|target| sarif.contains(target) || out.as_ref() == Some(target))
            {
                return Err(lexopt::Error::Custom(
                    "--sarif-out must be a different file from --sarif and --out".into(),
                ));
            }
            let probe = match probe_url {
                None if staging || production || confirmed => {
                    return Err(lexopt::Error::Custom(
                        "--staging, --production and --confirm-production need --probe URL".into(),
                    ));
                }
                None => None,
                Some(url) => {
                    let target = seethru_guard::Target::parse(&url).map_err(|error| {
                        lexopt::Error::Custom(format!("--probe: {error}").into())
                    })?;
                    if staging == production {
                        return Err(lexopt::Error::Custom(
                            "--probe needs exactly one of --staging or --production. Say which kind of app the address is".into(),
                        ));
                    }
                    if staging && confirmed {
                        return Err(lexopt::Error::Custom(
                            "--confirm-production goes with --production".into(),
                        ));
                    }
                    if production && !confirmed {
                        return Err(lexopt::Error::Custom(
                            "--production checks the app real users use. If that is what you want, add --confirm-production. Nothing was sent".into(),
                        ));
                    }
                    Some(probe::Plan { target, production })
                }
            };
            if tools.iter().any(|permit| permit.name.reads_binaries())
                && binaries.is_empty()
                && !build
            {
                return Err(lexopt::Error::Custom(
                    "--tool has nothing to read. Add --binary FILE or --build".into(),
                ));
            }
            if tools.iter().any(|permit| !permit.name.reads_binaries()) && probe.is_none() {
                return Err(lexopt::Error::Custom(
                    "--tool curl has nothing to check. Add --probe URL".into(),
                ));
            }
            if binaries.len() > tool::MAX_BINARIES {
                return Err(lexopt::Error::Custom(
                    format!("--binary can be given at most {} times", tool::MAX_BINARIES).into(),
                ));
            }
            Ok(Command::Scan {
                path: path.unwrap_or_else(|| PathBuf::from(".")),
                out,
                json,
                lang,
                read_config,
                build_output,
                sarif,
                sarif_out,
                compile_commands,
                llvm_ir,
                build,
                binaries,
                tools,
                probe,
                confirmed,
            })
        }
        "own" => {
            let mut url = None;
            let mut path = None;
            let mut lang = Lang::default();
            while let Some(arg) = parser.next()? {
                match arg {
                    Long("lang") => {
                        let code = parser.value()?.string()?;
                        lang = Lang::from_code(&code).ok_or_else(|| {
                            lexopt::Error::Custom(format!("unknown language '{code}'").into())
                        })?;
                    }
                    Value(value) if url.is_none() => url = Some(value.string()?),
                    Value(value) if path.is_none() => path = Some(PathBuf::from(value)),
                    other => return Err(other.unexpected()),
                }
            }
            let url = url
                .ok_or_else(|| lexopt::Error::Custom("own needs the address of the app".into()))?;
            let target = seethru_guard::Target::parse(&url)
                .map_err(|error| lexopt::Error::Custom(format!("own: {error}").into()))?;
            Ok(Command::Own {
                target,
                path: path.unwrap_or_else(|| PathBuf::from(".")),
                lang,
            })
        }
        "mcp" => {
            let mut roots = Vec::new();
            let mut allow_build = false;
            let mut tools: Vec<tool::Permit> = Vec::new();
            while let Some(arg) = parser.next()? {
                match arg {
                    Long("root") => roots.push(PathBuf::from(parser.value()?)),
                    Long("allow-build") => allow_build = true,
                    Long("tool") => {
                        let permit = tool::permit(&parser.value()?)
                            .map_err(|message| lexopt::Error::Custom(message.into()))?;
                        if !permit.name.reads_binaries() {
                            return Err(lexopt::Error::Custom(
                                format!(
                                    "--tool {} is not available to the MCP server yet",
                                    permit.name.as_str()
                                )
                                .into(),
                            ));
                        }
                        if tools.iter().any(|known| known.name == permit.name) {
                            return Err(lexopt::Error::Custom(
                                format!("--tool {} was given twice", permit.name.as_str()).into(),
                            ));
                        }
                        tools.push(permit);
                    }
                    other => return Err(other.unexpected()),
                }
            }
            if !tools.is_empty() && !allow_build {
                return Err(lexopt::Error::Custom(
                    "--tool has nothing to read. Add --allow-build".into(),
                ));
            }
            Ok(Command::Mcp {
                roots,
                allow_build,
                tools,
            })
        }
        "schema" => match parser.next()? {
            None => Ok(Command::Schema),
            Some(other) => Err(other.unexpected()),
        },
        "help" => Ok(Command::Help),
        _ => Err(lexopt::Error::Custom(
            format!("unknown command '{command}'").into(),
        )),
    }
}

fn main() -> ExitCode {
    if std::env::var_os(build::WRAPPER_ENV).is_some() {
        return build::wrap(std::env::args_os().skip(1));
    }
    let command = match parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            let _ = writeln!(io::stderr(), "error: {error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if is_broken_pipe(error.as_ref()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr(), "error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn is_broken_pipe(error: &(dyn std::error::Error + 'static)) -> bool {
    if let Some(error) = error.downcast_ref::<io::Error>() {
        return error.kind() == io::ErrorKind::BrokenPipe;
    }
    if let Some(error) = error.downcast_ref::<serde_json::Error>() {
        return error.io_error_kind() == Some(io::ErrorKind::BrokenPipe);
    }
    false
}

fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    let mut stdout = io::stdout().lock();
    match command {
        Command::Own { target, path, lang } => {
            if !path.is_dir() {
                return Err(format!("{} is not a folder", path.display()).into());
            }
            probe::own(&state_dir(&path)?, &target, lang, &mut stdout)?;
        }
        Command::Mcp {
            roots,
            allow_build,
            tools,
        } => {
            let server = mcp::Server::new(roots, allow_build, tools)?;
            seethru_mcp::serve(io::stdin().lock(), &mut stdout, &server)?;
        }
        Command::Help => stdout.write_all(USAGE.as_bytes())?,
        Command::Version => writeln!(stdout, "seethru {}", env!("CARGO_PKG_VERSION"))?,
        Command::Schema => {
            serde_json::to_writer_pretty(&mut stdout, &seethru_core::report_schema())?;
            writeln!(stdout)?;
        }
        Command::Scan {
            path,
            out,
            json,
            lang,
            read_config,
            build_output,
            sarif,
            sarif_out,
            compile_commands,
            mut llvm_ir,
            build,
            binaries,
            tools,
            probe,
            confirmed,
        } => {
            let mut built = None;
            if build {
                let projects = seethru_analyzer::cargo_projects(&path, read_config)?;
                let dirs = build::build(&path, &state_dir(&path)?, &projects, lang)?;
                llvm_ir.extend(dirs.iter().cloned());
                built = Some(dirs);
            }
            let collected = tool::collect(&path, &tools, &binaries, built.as_deref(), lang)?;
            let observed = match &probe {
                None => None,
                Some(plan) => Some(probe::observe(
                    &path,
                    &state_dir(&path)?,
                    plan,
                    confirmed,
                    &tools,
                    lang,
                )?),
            };
            let options = seethru_analyzer::ScanOptions {
                read_config,
                build_output,
                sarif,
                compile_commands,
                llvm_ir,
                binaries: collected.binaries,
                binary_problems: collected.problems,
                observed,
            };
            let mut report = seethru_analyzer::scan_with(&path, options)?;
            seethru_fix::attach_fix_prompts(&mut report);
            if let Some(target) = &sarif_out {
                let sarif = seethru_report::render_sarif(&report, lang)?;
                write_report(target, &sarif)?;
                let left_out = seethru_report::sarif_left_out(&report);
                if left_out > 0 {
                    let note = match lang {
                        Lang::En => format!(
                            "note: {left_out} finding(s) on the running app are not in the SARIF file, because SARIF results need a file and line. They are in the report"
                        ),
                        Lang::Ko => format!(
                            "참고: 실행 중인 앱에서 찾은 문제 {left_out}개는 SARIF 파일에 넣지 않았어요. SARIF 결과에는 파일과 줄이 있어야 해요. 리포트에는 들어 있어요"
                        ),
                    };
                    let _ = writeln!(io::stderr(), "{note}");
                }
            }
            if json {
                serde_json::to_writer_pretty(&mut stdout, &report)?;
                writeln!(stdout)?;
            } else {
                print_summary(&mut stdout, &report, lang)?;
                let html = seethru_report::render_html(&report, lang)?;
                let target = match out {
                    Some(out) => out,
                    None => default_report_path(&path)?,
                };
                write_report(&target, &html)?;
                match lang {
                    Lang::En => writeln!(stdout, "\nReport written to {}", target.display())?,
                    Lang::Ko => writeln!(stdout, "\n리포트를 {}에 저장했어요", target.display())?,
                }
            }
        }
    }
    stdout.flush()?;
    Ok(())
}

fn default_report_path(root: &Path) -> io::Result<PathBuf> {
    Ok(state_dir(root)?.join(REPORT_FILE))
}

fn state_dir(root: &Path) -> io::Result<PathBuf> {
    let dir = root.join(REPORT_DIR);
    match fs::symlink_metadata(&dir) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a directory", dir.display()),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&dir)?;
            write_new_file(&dir.join(".gitignore"), "*\n")?;
        }
        Err(error) => return Err(error),
    }
    Ok(dir)
}

fn write_new_file(path: &Path, content: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(content.as_bytes())
}

fn write_report(path: &Path, html: &str) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a regular file", path.display()),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(html.as_bytes())?;
    file.sync_all()
}

fn severity_label(severity: Severity, lang: Lang) -> &'static str {
    match (lang, severity) {
        (Lang::En, Severity::Critical) => "critical",
        (Lang::En, Severity::High) => "high",
        (Lang::En, Severity::Medium) => "medium",
        (Lang::En, Severity::Low) => "low",
        (Lang::En, Severity::Info) => "info",
        (Lang::Ko, Severity::Critical) => "치명적",
        (Lang::Ko, Severity::High) => "높음",
        (Lang::Ko, Severity::Medium) => "중간",
        (Lang::Ko, Severity::Low) => "낮음",
        (Lang::Ko, Severity::Info) => "정보",
    }
}

fn confidence_note(confidence: Confidence, lang: Lang) -> &'static str {
    match (lang, confidence) {
        (_, Confidence::Certain) => "",
        (Lang::En, Confidence::Likely) => " (likely)",
        (Lang::En, Confidence::Review) => " (needs review)",
        (Lang::Ko, Confidence::Likely) => " (추정)",
        (Lang::Ko, Confidence::Review) => " (확인 필요)",
    }
}

fn print_summary(out: &mut impl Write, report: &ScanReport, lang: Lang) -> io::Result<()> {
    let target = &report.target;
    let excluded = target.files_excluded;
    match lang {
        Lang::En => {
            let files = if target.files_scanned == 1 {
                "file"
            } else {
                "files"
            };
            let excluded = if excluded > 0 {
                format!(", {excluded} excluded")
            } else {
                String::new()
            };
            writeln!(
                out,
                "seethru scan {} ({} {files}, {} skipped{excluded})",
                target.name, target.files_scanned, target.files_skipped
            )?;
        }
        Lang::Ko => {
            let excluded = if excluded > 0 {
                format!(", 제외 {excluded}개")
            } else {
                String::new()
            };
            writeln!(
                out,
                "seethru scan {} (파일 {}개, 건너뜀 {}개{excluded})",
                target.name, target.files_scanned, target.files_skipped
            )?;
        }
    }
    if let Some(config) = &target.config_file {
        match lang {
            Lang::En => writeln!(out, "settings from {config}")?,
            Lang::Ko => writeln!(out, "{config} 설정을 적용했어요")?,
        }
    }
    if target.truncated {
        let warning = match lang {
            Lang::En => "warning: scan stopped early because the project is too large",
            Lang::Ko => "경고: 프로젝트가 너무 커서 검사를 일찍 멈췄어요",
        };
        writeln!(out, "{warning}")?;
    }
    let s = &report.summary;
    let counts = [
        (Severity::Critical, s.critical),
        (Severity::High, s.high),
        (Severity::Medium, s.medium),
        (Severity::Low, s.low),
        (Severity::Info, s.info),
    ]
    .map(|(severity, count)| format!("{} {count}", severity_label(severity, lang)))
    .join("  ");
    let accepted = if s.accepted > 0 {
        match lang {
            Lang::En => format!("  accepted {}", s.accepted),
            Lang::Ko => format!("  허용함 {}", s.accepted),
        }
    } else {
        String::new()
    };
    writeln!(out, "{counts}{accepted}\n")?;
    let (open, accepted): (Vec<_>, Vec<_>) = report
        .findings
        .iter()
        .partition(|finding| finding.accepted.is_none());
    if open.is_empty() {
        let none = match (lang, target.limitations.is_empty()) {
            (Lang::En, true) => "No problems found",
            (Lang::Ko, true) => "발견한 문제가 없어요",
            (Lang::En, false) => "No problems found in what was checked",
            (Lang::Ko, false) => "확인한 범위에서는 발견한 문제가 없어요",
        };
        writeln!(out, "{none}")?;
    }
    for finding in open {
        let label = severity_label(finding.severity, lang);
        let label = match lang {
            Lang::En => label.to_uppercase(),
            Lang::Ko => label.to_owned(),
        };
        let note = confidence_note(finding.confidence, lang);
        writeln!(out, "[{label}] {}{note}", finding.title.get(lang))?;
        writeln!(out, "  {}", place(finding, lang))?;
    }
    if !accepted.is_empty() {
        let (heading, label, reason) = match lang {
            Lang::En => ("Accepted in seethru.toml", "ACCEPTED", "reason"),
            Lang::Ko => ("seethru.toml에서 허용한 문제", "허용함", "사유"),
        };
        writeln!(out, "\n{heading}")?;
        for finding in accepted {
            writeln!(out, "[{label}] {}", finding.title.get(lang))?;
            writeln!(out, "  {}", place(finding, lang))?;
            if let Some(acceptance) = &finding.accepted {
                writeln!(out, "  {reason}: {}", acceptance.reason)?;
            }
        }
    }
    if !target.limitations.is_empty() {
        let heading = match lang {
            Lang::En => "Not checked",
            Lang::Ko => "확인하지 못한 것",
        };
        writeln!(out, "\n{heading}")?;
        for limitation in &target.limitations {
            writeln!(out, "- {}", limitation.text.get(lang))?;
        }
    }
    Ok(())
}

fn place(finding: &seethru_core::Finding, lang: Lang) -> String {
    if let Some(l) = &finding.location {
        return format!("{}:{}:{}", l.path, l.line, l.column);
    }
    match (&finding.proof, lang) {
        (Some(proof), Lang::En) => {
            format!("the running app, proof in {REPORT_DIR}/{}", proof.as_str())
        }
        (Some(proof), Lang::Ko) => {
            format!("실행 중인 앱, 증거는 {REPORT_DIR}/{}", proof.as_str())
        }
        (None, _) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, parse, print_summary};
    use seethru_core::{
        Acceptance, Confidence, Finding, Lang, Limitation, LimitationCode, LocalizedText, NodeId,
        Origin, RuleId, SCHEMA_VERSION, ScanReport, Severity, Summary, TargetInfo, ToolInfo,
    };
    use std::ffi::OsString;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn scan_defaults_to_current_directory() {
        assert!(matches!(
            parse(args(&["scan"])),
            Ok(Command::Scan { ref path, out: None, json: false, lang: Lang::En, read_config: true, build_output: None, ref sarif, sarif_out: None, compile_commands: None, ref llvm_ir, build: false, ref binaries, ref tools, probe: None, confirmed: false }) if path.as_os_str() == "." && sarif.is_empty() && llvm_ir.is_empty() && binaries.is_empty() && tools.is_empty()
        ));
    }

    #[test]
    fn scan_accepts_path_and_json_flag_in_any_order() {
        assert!(matches!(
            parse(args(&["scan", "--json", "app"])),
            Ok(Command::Scan { ref path, out: None, json: true, .. }) if path.as_os_str() == "app"
        ));
    }

    #[test]
    fn scan_accepts_out_path() {
        assert!(matches!(
            parse(args(&["scan", "app", "--out", "r.html"])),
            Ok(Command::Scan { out: Some(ref out), json: false, .. }) if out.as_os_str() == "r.html"
        ));
        assert!(parse(args(&["scan", "--out"])).is_err());
        assert!(parse(args(&["scan", "--json", "--out", "r.html"])).is_err());
    }

    #[test]
    fn scan_accepts_a_language() {
        assert!(matches!(
            parse(args(&["scan", "--lang", "ko", "app"])),
            Ok(Command::Scan { lang: Lang::Ko, .. })
        ));
        assert!(matches!(
            parse(args(&["scan", "--lang=en"])),
            Ok(Command::Scan { lang: Lang::En, .. })
        ));
        assert!(parse(args(&["scan", "--lang"])).is_err());
        assert!(parse(args(&["scan", "--lang", "jp"])).is_err());
        assert!(parse(args(&["scan", "--lang", "KO"])).is_err());
    }

    #[test]
    fn scan_can_ignore_the_project_config() {
        assert!(matches!(
            parse(args(&["scan", "app"])),
            Ok(Command::Scan {
                read_config: true,
                ..
            })
        ));
        assert!(matches!(
            parse(args(&["scan", "--no-config", "app"])),
            Ok(Command::Scan {
                read_config: false,
                ..
            })
        ));
    }

    fn one_finding_report() -> ScanReport {
        let findings = vec![Finding {
            id: "f".to_owned(),
            rule: RuleId::SupabaseRlsDisabled,
            severity: Severity::Critical,
            confidence: Confidence::Certain,
            title: LocalizedText {
                en: "RLS is off".to_owned(),
                ko: "RLS가 꺼져 있어요".to_owned(),
            },
            explanation: LocalizedText::default(),
            node: NodeId::new("table:public.todos"),
            location: None,
            evidence: Vec::new(),
            origin: Origin::seethru(),
            cwe: Vec::new(),
            proof: None,
            fix_prompt: None,
            accepted: None,
        }];
        ScanReport {
            schema_version: SCHEMA_VERSION,
            tool: ToolInfo {
                name: "seethru".to_owned(),
                version: "0".to_owned(),
            },
            target: TargetInfo {
                name: "app".to_owned(),
                files_scanned: 1,
                files_skipped: 0,
                files_excluded: 0,
                truncated: false,
                config_file: None,
                ecosystems: Vec::new(),
                inputs: Vec::new(),
                limitations: Vec::new(),
            },
            summary: Summary::from_findings(&findings),
            nodes: Vec::new(),
            edges: Vec::new(),
            findings,
        }
    }

    fn summary(lang: Lang) -> String {
        let mut out = Vec::new();
        let printed = print_summary(&mut out, &one_finding_report(), lang);
        assert!(printed.is_ok(), "{printed:?}");
        String::from_utf8(out).unwrap_or_default()
    }

    #[test]
    fn summary_follows_the_chosen_language() {
        let en = summary(Lang::En);
        assert!(en.contains("(1 file, 0 skipped)"), "{en}");
        assert!(en.contains("critical 1  high 0"), "{en}");
        assert!(en.contains("[CRITICAL] RLS is off"), "{en}");
        let ko = summary(Lang::Ko);
        assert!(ko.contains("(파일 1개, 건너뜀 0개)"), "{ko}");
        assert!(ko.contains("치명적 1  높음 0"), "{ko}");
        assert!(ko.contains("[치명적] RLS가 꺼져 있어요"), "{ko}");
    }

    #[test]
    fn summary_notes_uncertain_findings_and_what_was_not_checked() {
        let mut report = one_finding_report();
        if let Some(finding) = report.findings.first_mut() {
            finding.confidence = Confidence::Likely;
        }
        report.target.limitations.push(Limitation {
            code: LimitationCode::BuildOutputNotRead,
            text: LocalizedText {
                en: "No build output was read.".to_owned(),
                ko: "빌드 결과물을 읽지 않았어요.".to_owned(),
            },
        });
        let mut out = Vec::new();
        assert!(print_summary(&mut out, &report, Lang::En).is_ok());
        let en = String::from_utf8(out).unwrap_or_default();
        assert!(en.contains("[CRITICAL] RLS is off (likely)"), "{en}");
        assert!(
            en.contains("\nNot checked\n- No build output was read.\n"),
            "{en}"
        );
        let mut out = Vec::new();
        assert!(print_summary(&mut out, &report, Lang::Ko).is_ok());
        let ko = String::from_utf8(out).unwrap_or_default();
        assert!(ko.contains("[치명적] RLS가 꺼져 있어요 (추정)"), "{ko}");
        assert!(
            ko.contains("\n확인하지 못한 것\n- 빌드 결과물을 읽지 않았어요.\n"),
            "{ko}"
        );
    }

    #[test]
    fn summary_says_where_the_proof_of_a_running_app_finding_is() {
        let mut report = one_finding_report();
        if let Some(finding) = report.findings.first_mut() {
            finding.location = None;
            finding.proof = Some(seethru_core::ProofRef::new("proof/a.json"));
        }
        let mut out = Vec::new();
        assert!(print_summary(&mut out, &report, Lang::En).is_ok());
        let en = String::from_utf8(out).unwrap_or_default();
        assert!(
            en.contains("\n  the running app, proof in .seethru/proof/a.json\n"),
            "{en}"
        );
        let mut out = Vec::new();
        assert!(print_summary(&mut out, &report, Lang::Ko).is_ok());
        let ko = String::from_utf8(out).unwrap_or_default();
        assert!(
            ko.contains("\n  실행 중인 앱, 증거는 .seethru/proof/a.json\n"),
            "{ko}"
        );
    }

    #[test]
    fn summary_lists_accepted_findings_apart_with_their_reason() {
        let mut report = one_finding_report();
        report.target.files_excluded = 3;
        report.target.config_file = Some("seethru.toml".to_owned());
        if let Some(finding) = report.findings.first_mut() {
            finding.accepted = Some(Acceptance {
                reason: "Demo table on purpose".to_owned(),
            });
        }
        report.summary = Summary::from_findings(&report.findings);
        let mut out = Vec::new();
        assert!(print_summary(&mut out, &report, Lang::En).is_ok());
        let en = String::from_utf8(out).unwrap_or_default();
        assert!(en.contains("(1 file, 0 skipped, 3 excluded)"), "{en}");
        assert!(en.contains("settings from seethru.toml"), "{en}");
        assert!(
            en.contains("critical 0  high 0  medium 0  low 0  info 0  accepted 1"),
            "{en}"
        );
        assert!(en.contains("No problems found"), "{en}");
        assert!(en.contains("[ACCEPTED] RLS is off"), "{en}");
        assert!(en.contains("reason: Demo table on purpose"), "{en}");
    }

    #[test]
    fn scan_accepts_a_build_output_folder() {
        assert!(matches!(
            parse(args(&["scan", "app", "--build-output", "app/dist"])),
            Ok(Command::Scan { build_output: Some(ref dir), .. }) if dir.as_os_str() == "app/dist"
        ));
        assert!(matches!(
            parse(args(&["scan", "app"])),
            Ok(Command::Scan {
                build_output: None,
                ..
            })
        ));
        assert!(parse(args(&["scan", "--build-output"])).is_err());
    }

    #[test]
    fn scan_accepts_compiled_output_more_than_once() {
        assert!(matches!(
            parse(args(&["scan", "app", "--llvm-ir", "target/a", "--llvm-ir=b.ll"])),
            Ok(Command::Scan { ref llvm_ir, .. })
                if llvm_ir.len() == 2 && llvm_ir[1].as_os_str() == "b.ll"
        ));
        assert!(parse(args(&["scan", "--llvm-ir"])).is_err());
    }

    #[test]
    fn scan_runs_outside_tools_only_when_they_are_named() {
        assert!(matches!(
            parse(args(&["scan", "--binary", "out/app", "--tool", "objdump", "--tool", "dwarfdump=/opt/bin/dwarfdump"])),
            Ok(Command::Scan { ref binaries, ref tools, build: false, .. })
                if binaries.len() == 1
                    && tools.len() == 2
                    && tools[1].path.as_deref() == Some(std::path::Path::new("/opt/bin/dwarfdump"))
        ));
        assert!(matches!(
            parse(args(&["scan", "--build", "--tool", "objdump"])),
            Ok(Command::Scan { build: true, ref tools, .. }) if tools.len() == 1
        ));
        assert!(matches!(
            parse(args(&["scan", "--binary", "out/app"])),
            Ok(Command::Scan { ref tools, .. }) if tools.is_empty()
        ));
        assert!(parse(args(&["scan", "--tool", "objdump"])).is_err());
        assert!(parse(args(&["scan", "--build", "--tool", "ghidra"])).is_err());
        assert!(parse(args(&["scan", "--build", "--tool", "objdump=bin/objdump"])).is_err());
        assert!(
            parse(args(&[
                "scan", "--build", "--tool", "objdump", "--tool", "objdump"
            ]))
            .is_err()
        );
        assert!(parse(args(&["scan", "--build", "--tool"])).is_err());
    }

    #[test]
    fn mcp_server_takes_its_permissions_from_launch_flags_only() {
        assert!(matches!(
            parse(args(&["mcp"])),
            Ok(Command::Mcp { ref roots, allow_build: false, ref tools }) if roots.is_empty() && tools.is_empty()
        ));
        assert!(matches!(
            parse(args(&["mcp", "--root", "a", "--root", "b", "--allow-build", "--tool", "objdump"])),
            Ok(Command::Mcp { ref roots, allow_build: true, ref tools }) if roots.len() == 2 && tools.len() == 1
        ));
        assert!(parse(args(&["mcp", "--tool", "objdump"])).is_err());
        assert!(parse(args(&["mcp", "--build"])).is_err());
        assert!(parse(args(&["mcp", "extra"])).is_err());
    }

    #[test]
    fn a_running_app_is_checked_only_with_a_named_environment() {
        assert!(matches!(
            parse(args(&["scan", "--probe", "https://staging.example.com", "--staging", "--tool", "curl"])),
            Ok(Command::Scan { probe: Some(ref plan), confirmed: false, ref tools, .. })
                if !plan.production && plan.target.origin() == "https://staging.example.com" && tools.len() == 1
        ));
        assert!(matches!(
            parse(args(&["scan", "--probe", "https://example.com", "--production", "--confirm-production"])),
            Ok(Command::Scan { probe: Some(ref plan), confirmed: true, .. }) if plan.production
        ));
        assert!(matches!(
            parse(args(&[
                "scan",
                "--probe",
                "http://localhost:3000",
                "--staging"
            ])),
            Ok(Command::Scan { probe: Some(_), .. })
        ));
        for refused in [
            &["scan", "--probe", "https://example.com"][..],
            &["scan", "--probe", "https://example.com", "--production"],
            &[
                "scan",
                "--probe",
                "https://example.com",
                "--staging",
                "--production",
                "--confirm-production",
            ],
            &[
                "scan",
                "--probe",
                "https://example.com",
                "--staging",
                "--confirm-production",
            ],
            &["scan", "--probe", "http://example.com", "--staging"],
            &["scan", "--probe", "http://192.168.0.10", "--staging"],
            &["scan", "--probe", "https://example.com/admin", "--staging"],
            &[
                "scan",
                "--probe",
                "https://user:pw@example.com",
                "--staging",
            ],
            &["scan", "--probe", "example.com", "--staging"],
            &["scan", "--staging"],
            &["scan", "--confirm-production"],
            &["scan", "--tool", "curl"],
            &[
                "scan",
                "--probe",
                "https://example.com",
                "--staging",
                "--tool",
                "objdump",
            ],
            &["mcp", "--allow-build", "--tool", "curl"],
        ] {
            assert!(parse(args(refused)).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn own_takes_an_address_and_a_folder() {
        assert!(matches!(
            parse(args(&["own", "https://staging.example.com", "app", "--lang", "ko"])),
            Ok(Command::Own { ref target, ref path, lang: Lang::Ko })
                if target.origin() == "https://staging.example.com" && path.as_os_str() == "app"
        ));
        assert!(matches!(
            parse(args(&["own", "http://127.0.0.1:8080"])),
            Ok(Command::Own { ref path, .. }) if path.as_os_str() == "."
        ));
        assert!(parse(args(&["own"])).is_err());
        assert!(parse(args(&["own", "http://example.com"])).is_err());
        assert!(parse(args(&["own", "https://example.com", "a", "b"])).is_err());
    }

    #[test]
    fn scan_builds_only_when_asked() {
        assert!(matches!(
            parse(args(&["scan", "app"])),
            Ok(Command::Scan { build: false, .. })
        ));
        assert!(matches!(
            parse(args(&["scan", "app", "--build", "--llvm-ir", "a.ll"])),
            Ok(Command::Scan { build: true, ref llvm_ir, .. }) if llvm_ir.len() == 1
        ));
        assert!(parse(args(&["scan", "--build=yes"])).is_err());
    }

    #[test]
    fn scan_accepts_sarif_files_in_and_out() {
        assert!(matches!(
            parse(args(&["scan", "app", "--sarif", "a.sarif", "--sarif=b.sarif", "--sarif-out", "o.sarif"])),
            Ok(Command::Scan { ref sarif, sarif_out: Some(ref target), .. })
                if sarif.len() == 2 && target.as_os_str() == "o.sarif"
        ));
        assert!(parse(args(&["scan", "--sarif"])).is_err());
        assert!(
            parse(args(&[
                "scan",
                "--sarif",
                "a.sarif",
                "--sarif-out",
                "a.sarif"
            ]))
            .is_err()
        );
        assert!(parse(args(&["scan", "--out", "r.html", "--sarif-out", "r.html"])).is_err());
    }

    #[test]
    fn rejects_unknown_input() {
        assert!(parse(args(&["scan", "a", "b"])).is_err());
        assert!(parse(args(&["scan", "--force"])).is_err());
        assert!(parse(args(&["attack"])).is_err());
        assert!(parse(args(&["schema", "extra"])).is_err());
    }
}
