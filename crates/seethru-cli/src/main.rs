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
";

const REPORT_DIR: &str = ".seethru";
const REPORT_FILE: &str = "report.html";

enum Command {
    Scan {
        path: PathBuf,
        out: Option<PathBuf>,
        json: bool,
        lang: Lang,
        read_config: bool,
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
            while let Some(arg) = parser.next()? {
                match arg {
                    Long("json") => json = true,
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
            Ok(Command::Scan {
                path: path.unwrap_or_else(|| PathBuf::from(".")),
                out,
                json,
                lang,
                read_config,
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
        } => {
            let options = seethru_analyzer::ScanOptions { read_config };
            let mut report = seethru_analyzer::scan_with(&path, options)?;
            seethru_fix::attach_fix_prompts(&mut report);
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
    Ok(dir.join(REPORT_FILE))
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
        let none = match lang {
            Lang::En => "No problems found",
            Lang::Ko => "발견한 문제가 없어요",
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
        writeln!(out, "  {}", place(finding))?;
    }
    if !accepted.is_empty() {
        let (heading, label, reason) = match lang {
            Lang::En => ("Accepted in seethru.toml", "ACCEPTED", "reason"),
            Lang::Ko => ("seethru.toml에서 허용한 문제", "허용함", "사유"),
        };
        writeln!(out, "\n{heading}")?;
        for finding in accepted {
            writeln!(out, "[{label}] {}", finding.title.get(lang))?;
            writeln!(out, "  {}", place(finding))?;
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

fn place(finding: &seethru_core::Finding) -> String {
    finding
        .location
        .as_ref()
        .map(|l| format!("{}:{}:{}", l.path, l.line, l.column))
        .unwrap_or_default()
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
            Ok(Command::Scan { ref path, out: None, json: false, lang: Lang::En, read_config: true }) if path.as_os_str() == "."
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
    fn rejects_unknown_input() {
        assert!(parse(args(&["scan", "a", "b"])).is_err());
        assert!(parse(args(&["scan", "--force"])).is_err());
        assert!(parse(args(&["attack"])).is_err());
        assert!(parse(args(&["schema", "extra"])).is_err());
    }
}
