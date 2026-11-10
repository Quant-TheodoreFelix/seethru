use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
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

type Failure = Box<dyn std::error::Error>;

struct Compile {
    name: String,
    extra: String,
    out_dir: Option<PathBuf>,
    source: Option<PathBuf>,
}

impl Compile {
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
    if let Some(compile) = compile_of(&rest)
        && root.is_some_and(|root| compile.is_inside(&root))
    {
        clear_outputs(&compile);
        rest.push(EMIT.into());
        rest.push(DEBUG_LINES.into());
    }
    match Command::new(&rustc).args(&rest).status() {
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

fn cargo(root: &Path, build_dir: &Path, wrapper: &Path) -> Result<(), Failure> {
    let status = Command::new("cargo")
        .current_dir(root)
        .args(CARGO_ARGS)
        .arg("--target-dir")
        .arg(build_dir)
        .env("RUSTC_WRAPPER", wrapper)
        .env(WRAPPER_ENV, "1")
        .env(ROOT_ENV, root)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::from(io::stderr()))
        .status()
        .map_err(|error| format!("could not run cargo: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("the build failed, so nothing was scanned. The messages from cargo are above".into())
    }
}

pub(crate) fn build(root: &Path, state_dir: &Path, lang: Lang) -> Result<Vec<PathBuf>, Failure> {
    let root = fs::canonicalize(root)?;
    if !regular_file(&root.join("Cargo.toml")) {
        return Err(format!(
            "--build needs a Cargo.toml in {}. Only Rust projects can be built",
            root.display()
        )
        .into());
    }
    let lock_path = root.join("Cargo.lock");
    if !regular_file(&lock_path) {
        return Err(
            "--build needs a Cargo.lock next to Cargo.toml, because seethru builds with --locked and never downloads anything"
                .into(),
        );
    }
    let lock = fs::read(&lock_path)?;
    let state_dir = fs::canonicalize(state_dir)?;
    let build_dir = state_dir.join(BUILD_DIR);
    let units_file = build_dir.join(UNITS_FILE);
    let lock_copy = build_dir.join(LOCK_COPY);
    let wrapper = std::env::current_exe()?;

    let mut fresh = !real_dir(&build_dir)?;
    if !fresh && fs::read(&lock_copy).ok().as_deref() != Some(lock.as_slice()) {
        fs::remove_dir_all(&build_dir)?;
        fresh = true;
    }
    announce(lang, &build_dir, false);
    cargo(&root, &build_dir, &wrapper)?;
    let mut built = output(&build_dir);
    if !fresh && fs::read_to_string(&units_file).ok() != Some(listed(&built.units)) {
        announce(lang, &build_dir, true);
        fs::remove_dir_all(&build_dir)?;
        cargo(&root, &build_dir, &wrapper)?;
        built = output(&build_dir);
    }
    if built.read.is_empty() {
        return Err("the build finished but produced no compiled output to read".into());
    }
    fs::write(&units_file, listed(&built.units))?;
    fs::write(&lock_copy, &lock)?;
    Ok(built.read)
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
