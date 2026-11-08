use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use seethru_core::{ScanReport, Severity};

const USAGE: &str = "\
seethru - see through your app before attackers do

Usage
  seethru scan [PATH] [--out FILE] [--json]
  seethru schema
  seethru --version

Commands
  scan     Analyze a project directory (default is the current directory)
  schema   Print the JSON Schema of the scan report

Options
  --out FILE   Where to write the HTML report (default is PATH/.seethru/report.html)
  --json       Print the scan report as JSON to stdout instead of writing HTML
";

const REPORT_DIR: &str = ".seethru";
const REPORT_FILE: &str = "report.html";

enum Command {
    Scan {
        path: PathBuf,
        out: Option<PathBuf>,
        json: bool,
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
            while let Some(arg) = parser.next()? {
                match arg {
                    Long("json") => json = true,
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
        Command::Scan { path, out, json } => {
            let mut report = seethru_analyzer::scan(&path)?;
            seethru_fix::attach_fix_prompts(&mut report);
            if json {
                serde_json::to_writer_pretty(&mut stdout, &report)?;
                writeln!(stdout)?;
            } else {
                print_summary(&mut stdout, &report)?;
                let html = seethru_report::render_html(&report)?;
                let target = match out {
                    Some(out) => out,
                    None => default_report_path(&path)?,
                };
                write_report(&target, &html)?;
                writeln!(stdout, "\nReport written to {}", target.display())?;
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

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn print_summary(out: &mut impl Write, report: &ScanReport) -> io::Result<()> {
    let s = &report.summary;
    let files = if report.target.files_scanned == 1 {
        "file"
    } else {
        "files"
    };
    writeln!(
        out,
        "seethru scan {} ({} {files}, {} skipped)",
        report.target.name, report.target.files_scanned, report.target.files_skipped
    )?;
    if report.target.truncated {
        writeln!(
            out,
            "warning: scan stopped early because the project is too large"
        )?;
    }
    writeln!(
        out,
        "critical {}  high {}  medium {}  low {}  info {}\n",
        s.critical, s.high, s.medium, s.low, s.info
    )?;
    if report.findings.is_empty() {
        writeln!(out, "No problems found")?;
    }
    for finding in &report.findings {
        let place = finding
            .location
            .as_ref()
            .map(|l| format!("{}:{}:{}", l.path, l.line, l.column))
            .unwrap_or_default();
        writeln!(
            out,
            "[{}] {}",
            severity_label(finding.severity),
            finding.title
        )?;
        writeln!(out, "  {place}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Command, parse};
    use std::ffi::OsString;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn scan_defaults_to_current_directory() {
        assert!(matches!(
            parse(args(&["scan"])),
            Ok(Command::Scan { ref path, out: None, json: false }) if path.as_os_str() == "."
        ));
    }

    #[test]
    fn scan_accepts_path_and_json_flag_in_any_order() {
        assert!(matches!(
            parse(args(&["scan", "--json", "app"])),
            Ok(Command::Scan { ref path, out: None, json: true }) if path.as_os_str() == "app"
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
    fn rejects_unknown_input() {
        assert!(parse(args(&["scan", "a", "b"])).is_err());
        assert!(parse(args(&["scan", "--force"])).is_err());
        assert!(parse(args(&["attack"])).is_err());
        assert!(parse(args(&["schema", "extra"])).is_err());
    }
}
