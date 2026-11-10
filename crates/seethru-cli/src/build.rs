use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use seethru_core::Lang;

pub(crate) const WRAPPER_ENV: &str = "SEETHRU_RUSTC_WRAPPER";
const ROOT_ENV: &str = "SEETHRU_BUILD_ROOT";

const BUILD_DIR: &str = "build";
const UNITS_FILE: &str = "seethru-units";
const LOCK_COPY: &str = "seethru-lock";
const CARGO_ARGS: [&str; 4] = ["build", "--release", "--locked", "--offline"];
const EMIT: &str = "--emit=llvm-ir,asm";
const DEBUG_LINES: &str = "-Cdebuginfo=line-tables-only";
const PROFILE_DIRS: [&str; 2] = ["release", "debug"];
const LINKED_KINDS: [&str; 4] = ["bin", "cdylib", "staticlib", "dylib"];
const MAX_PROJECTS: usize = 8;

type Failure = Box<dyn std::error::Error>;

struct Compile {
    name: String,
    extra: String,
    out_dir: Option<PathBuf>,
    source: Option<PathBuf>,
    linked: bool,
}

impl Compile {
    fn has_output(&self) -> bool {
        let unit = format!("{}{}", self.name, self.extra);
        self.out_dir
            .as_ref()
            .and_then(|dir| fs::read_dir(dir).ok())
            .is_some_and(|entries| {
                entries.flatten().any(|entry| {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    name.ends_with(".ll") && is_output(&name, &unit)
                })
            })
    }

    fn is_inside(&self, root: &Path) -> bool {
        self.source
            .as_ref()
            .and_then(|source| fs::canonicalize(source).ok())
            .is_some_and(|source| source.starts_with(root))
    }
}

fn compile_of(args: &[OsString]) -> Option<Compile> {
    let mut name = None;
    let mut extra = String::new();
    let mut out_dir = None;
    let mut source = None;
    let mut links = false;
    let mut linked = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let text = arg.to_string_lossy();
        if text.starts_with("--print") {
            return None;
        }
        let (flag, mut value) = match text.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag, Some(value.to_owned())),
            _ => (text.as_ref(), None),
        };
        match flag {
            "--crate-name" | "--crate-type" | "--emit" | "--out-dir" | "-C" => {
                if value.is_none() {
                    value = iter.next().map(|next| next.to_string_lossy().into_owned());
                }
            }
            _ => {
                if source.is_none()
                    && Path::new(arg).extension().and_then(OsStr::to_str) == Some("rs")
                {
                    source = Some(PathBuf::from(arg));
                }
                continue;
            }
        }
        let value = value?;
        match flag {
            "--crate-name" => name = Some(value),
            "--crate-type" if value == "proc-macro" => return None,
            "--crate-type" => linked |= LINKED_KINDS.contains(&value.as_str()),
            "--emit" => links |= value.split(',').any(|kind| kind == "link"),
            "--out-dir" => out_dir = Some(PathBuf::from(value)),
            "-C" => {
                if let Some(suffix) = value.strip_prefix("extra-filename=") {
                    suffix.clone_into(&mut extra);
                }
            }
            _ => {}
        }
    }
    let name = name?;
    if !links || name.starts_with("build_script_") {
        return None;
    }
    Some(Compile {
        name,
        extra,
        out_dir,
        source,
        linked,
    })
}

fn is_output(file: &str, unit: &str) -> bool {
    let Some(rest) = file.strip_prefix(unit) else {
        return false;
    };
    rest.starts_with('.')
        && Path::new(file)
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|ext| ext == "ll" || ext == "s")
}

fn clear_outputs(compile: &Compile) {
    let Some(dir) = &compile.out_dir else {
        return;
    };
    let unit = format!("{}{}", compile.name, compile.extra);
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let is_file = entry.file_type().is_ok_and(|kind| kind.is_file());
        if is_file && is_output(&entry.file_name().to_string_lossy(), &unit) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

pub(crate) fn wrap(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    let mut args = args.into_iter();
    let Some(rustc) = args.next() else {
        return ExitCode::from(2);
    };
    let mut rest: Vec<OsString> = args.collect();
    let root = std::env::var_os(ROOT_ENV).map(PathBuf::from);
    let compile =
        compile_of(&rest).filter(|compile| root.is_some_and(|root| compile.is_inside(&root)));
    if let Some(compile) = &compile {
        clear_outputs(compile);
        rest.push(EMIT.into());
        rest.push(DEBUG_LINES.into());
    }
    match Command::new(&rustc).args(&rest).status() {
        Ok(status) if !status.success() && compile.as_ref().is_some_and(link_only_failed) => {
            ExitCode::SUCCESS
        }
        Ok(status) => {
            let code = status.code().and_then(|code| u8::try_from(code).ok());
            ExitCode::from(code.unwrap_or(1))
        }
        Err(error) => {
            let _ = writeln!(
                io::stderr(),
                "error: could not run {}: {error}",
                Path::new(&rustc).display()
            );
            ExitCode::FAILURE
        }
    }
}

fn link_only_failed(compile: &Compile) -> bool {
    if !compile.linked || !compile.has_output() {
        return false;
    }
    let _ = writeln!(
        io::stderr(),
        "seethru: {} was compiled but could not be linked. Its compiled code is read anyway, because the checks do not need the linked file.",
        compile.name
    );
    true
}

fn real_dir(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a directory", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
}

struct Output {
    read: Vec<PathBuf>,
    units: BTreeSet<String>,
}

fn output(build_dir: &Path) -> Output {
    let mut cross = Vec::new();
    if let Ok(entries) = fs::read_dir(build_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let is_profile = PROFILE_DIRS.iter().any(|dir| name == OsStr::new(dir));
            let deps = entry.path().join("release").join("deps");
            if !is_profile && real_dir(&deps).unwrap_or(false) {
                cross.push(deps);
            }
        }
    }
    cross.sort();
    let mut all = cross.clone();
    let host = build_dir.join("release").join("deps");
    if real_dir(&host).unwrap_or(false) {
        all.push(host.clone());
        if cross.is_empty() {
            cross.push(host);
        }
    }
    Output {
        units: units_in(&all),
        read: cross.into_iter().filter(|dir| has_units(dir)).collect(),
    }
}

fn has_units(dir: &Path) -> bool {
    !units_in(std::slice::from_ref(&dir.to_path_buf())).is_empty()
}

fn units_in(dirs: &[PathBuf]) -> BTreeSet<String> {
    let mut units = BTreeSet::new();
    for dir in dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if Path::new(&name).extension().and_then(OsStr::to_str) != Some("ll") {
                continue;
            }
            let unit = name.split('.').next().unwrap_or(&name);
            let dir_name = dir
                .parent()
                .and_then(Path::parent)
                .and_then(Path::file_name)
                .map(|part| part.to_string_lossy().into_owned())
                .unwrap_or_default();
            units.insert(format!("{dir_name}/{unit}"));
        }
    }
    units
}

fn listed(units: &BTreeSet<String>) -> String {
    units.iter().map(|unit| format!("{unit}\n")).collect()
}

fn announce(lang: Lang, build_dir: &Path, again: bool) {
    let command = format!(
        "cargo {} --target-dir {}",
        CARGO_ARGS.join(" "),
        build_dir.display()
    );
    let text = match (lang, again) {
        (Lang::En, false) => format!(
            "Building with cargo. This runs the project's build scripts and macros on this computer.\n  {command}"
        ),
        (Lang::Ko, false) => format!(
            "cargo로 빌드해요. 이 프로젝트의 빌드 스크립트와 매크로가 이 컴퓨터에서 실행돼요.\n  {command}"
        ),
        (Lang::En, true) => {
            "Build settings changed since the last build, so building again from scratch."
                .to_owned()
        }
        (Lang::Ko, true) => "지난 빌드와 설정이 달라져서 처음부터 다시 빌드해요.".to_owned(),
    };
    let _ = writeln!(io::stderr(), "{text}");
}

#[derive(Default)]
struct Seen {
    offline: bool,
    toolchain: bool,
}

fn cargo(scan_root: &Path, dir: &Path, build_dir: &Path, wrapper: &Path) -> Result<(), Failure> {
    let mut child = Command::new("cargo")
        .current_dir(dir)
        .args(CARGO_ARGS)
        .arg("--target-dir")
        .arg(build_dir)
        .env("RUSTC_WRAPPER", wrapper)
        .env(WRAPPER_ENV, "1")
        .env(ROOT_ENV, scan_root)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::from(io::stderr()))
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not run cargo: {error}"))?;
    let mut seen = Seen::default();
    if let Some(pipe) = child.stderr.take() {
        let mut reader = BufReader::new(pipe);
        let mut line = Vec::new();
        while reader
            .read_until(b'\n', &mut line)
            .is_ok_and(|read| read > 0)
        {
            let _ = io::stderr().write_all(&line);
            let text = String::from_utf8_lossy(&line);
            seen.offline |= text.contains("--offline") || text.contains("offline mode");
            seen.toolchain |= text.contains("is not installed");
            line.clear();
        }
    }
    if child.wait()?.success() {
        return Ok(());
    }
    let place = dir.display();
    let hint = if seen.toolchain {
        format!(
            "The Rust toolchain this project asks for is not installed. seethru never downloads, so install it yourself with `rustup toolchain install` in {place}, then scan again"
        )
    } else if seen.offline {
        format!(
            "Some dependencies are not on this computer. seethru never downloads, so run `cargo fetch` in {place} yourself, then scan again"
        )
    } else {
        format!(
            "The messages from cargo are above. If plain `cargo build --release` also fails in {place}, fix that first"
        )
    };
    Err(format!("the build failed, so nothing was scanned. {hint}").into())
}

fn slug(project: &str) -> String {
    if project.is_empty() {
        return "root".to_owned();
    }
    project
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn build_one(
    scan_root: &Path,
    project: &str,
    builds: &Path,
    wrapper: &Path,
    lang: Lang,
) -> Result<Vec<PathBuf>, Failure> {
    let dir = if project.is_empty() {
        scan_root.to_path_buf()
    } else {
        scan_root.join(project)
    };
    let lock_path = dir.join("Cargo.lock");
    if !regular_file(&lock_path) {
        return Err(format!(
            "--build needs a Cargo.lock in {}, because seethru builds with --locked and never downloads anything. Run `cargo generate-lockfile` there yourself, then scan again",
            dir.display()
        )
        .into());
    }
    let lock = fs::read(&lock_path)?;
    let build_dir = builds.join(slug(project));
    let units_file = build_dir.join(UNITS_FILE);
    let lock_copy = build_dir.join(LOCK_COPY);

    let mut fresh = !real_dir(&build_dir)?;
    if !fresh && fs::read(&lock_copy).ok().as_deref() != Some(lock.as_slice()) {
        fs::remove_dir_all(&build_dir)?;
        fresh = true;
    }
    announce(lang, &build_dir, false);
    cargo(scan_root, &dir, &build_dir, wrapper)?;
    let mut built = output(&build_dir);
    if !fresh && fs::read_to_string(&units_file).ok() != Some(listed(&built.units)) {
        announce(lang, &build_dir, true);
        fs::remove_dir_all(&build_dir)?;
        cargo(scan_root, &dir, &build_dir, wrapper)?;
        built = output(&build_dir);
    }
    fs::write(&units_file, listed(&built.units))?;
    fs::write(&lock_copy, &lock)?;
    Ok(built.read)
}

pub(crate) fn build(
    root: &Path,
    state_dir: &Path,
    projects: &[String],
    lang: Lang,
) -> Result<Vec<PathBuf>, Failure> {
    let root = fs::canonicalize(root)?;
    if projects.is_empty() {
        return Err(format!(
            "--build found no Cargo.toml in {}. Only Rust projects can be built",
            root.display()
        )
        .into());
    }
    if projects.len() > MAX_PROJECTS {
        return Err(format!(
            "--build found {} separate Cargo projects in {}, and builds at most {MAX_PROJECTS} in one scan. Scan one of their folders instead, such as {}",
            projects.len(),
            root.display(),
            root.join(&projects[0]).display()
        )
        .into());
    }
    let builds = fs::canonicalize(state_dir)?.join(BUILD_DIR);
    if !real_dir(&builds)? {
        fs::create_dir(&builds)?;
    }
    let wrapper = std::env::current_exe()?;
    let mut read = Vec::new();
    for project in projects {
        read.extend(build_one(&root, project, &builds, &wrapper, lang)?);
    }
    if read.is_empty() {
        return Err("the build finished but produced no compiled output to read".into());
    }
    Ok(read)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn only_real_crate_compiles_get_the_extra_output() {
        let lib = args(&[
            "--crate-name",
            "vault",
            "--edition=2024",
            "vault/src/lib.rs",
            "--crate-type",
            "lib",
            "--emit=dep-info,metadata,link",
            "-C",
            "opt-level=3",
            "-C",
            "extra-filename=-21ff0febabe1f1e9",
            "--out-dir",
            "/t/release/deps",
        ]);
        let compile = compile_of(&lib);
        assert!(compile.is_some());
        if let Some(compile) = compile {
            assert_eq!(compile.name, "vault");
            assert_eq!(compile.extra, "-21ff0febabe1f1e9");
            assert_eq!(compile.out_dir, Some(PathBuf::from("/t/release/deps")));
            assert_eq!(compile.source, Some(PathBuf::from("vault/src/lib.rs")));
            assert!(!compile.is_inside(Path::new("/nowhere")));
        }

        assert!(compile_of(&args(&["-vV"])).is_none());
        assert!(
            compile_of(&args(&[
                "-",
                "--crate-name",
                "___",
                "--print=file-names",
                "--crate-type",
                "bin"
            ]))
            .is_none()
        );
        assert!(
            compile_of(&args(&[
                "--crate-name",
                "build_script_build",
                "--crate-type",
                "bin",
                "--emit=dep-info,link"
            ]))
            .is_none()
        );
        assert!(
            compile_of(&args(&[
                "--crate-name",
                "derive",
                "--crate-type",
                "proc-macro",
                "--emit=dep-info,link"
            ]))
            .is_none()
        );
        assert!(
            compile_of(&args(&[
                "--crate-name",
                "vault",
                "--crate-type",
                "lib",
                "--emit=dep-info,metadata"
            ]))
            .is_none()
        );
    }

    #[test]
    fn build_folders_are_named_after_the_project_folder() {
        assert_eq!(slug(""), "root");
        assert_eq!(slug("core"), "core");
        assert_eq!(slug("apps/desktop/src-tauri"), "apps_desktop_src-tauri");
        assert_eq!(slug("a b/../c"), "a_b_.._c");
    }

    #[test]
    fn old_output_is_matched_by_unit_and_kind() {
        let unit = "mldsa-27b9e6cf43ba5764";
        assert!(is_output("mldsa-27b9e6cf43ba5764.ll", unit));
        assert!(is_output("mldsa-27b9e6cf43ba5764.s", unit));
        assert!(is_output(
            "mldsa-27b9e6cf43ba5764.mldsa.f736f07d9f58f66f-cgu.08.rcgu.ll",
            unit
        ));
        assert!(!is_output("mldsa-27b9e6cf43ba5764.d", unit));
        assert!(!is_output("mldsa-27b9e6cf43ba5764e.ll", unit));
        assert!(!is_output("libmldsa-27b9e6cf43ba5764.rlib", unit));
        assert!(!is_output("mldsa-0000000000000000.ll", unit));
    }
}
