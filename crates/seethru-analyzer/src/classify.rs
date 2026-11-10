use std::collections::BTreeSet;

use seethru_core::{Artifact, Ecosystem, Runtime};

const SCRIPT_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"];

const NATIVE_EXTENSIONS: &[&str] = &["c", "h", "cc", "cpp", "cxx", "hpp", "hh", "hxx", "ino"];

const NATIVE_BUILD_FILES: &[&str] = &["CMakeLists.txt", "platformio.ini", "meson.build"];
const NOT_KCONFIG_SUFFIXES: &[&str] = &[".json", ".h", ".old", ".cmake", ".rename"];

const TEXT_EXTENSIONS: &[&str] = &[
    "json",
    "jsonc",
    "map",
    "html",
    "htm",
    "css",
    "vue",
    "svelte",
    "astro",
    "md",
    "mdx",
    "yml",
    "yaml",
    "toml",
    "txt",
    "ini",
    "conf",
    "cfg",
    "properties",
    "xml",
    "sh",
    "bash",
    "zsh",
    "py",
    "rb",
    "go",
    "rs",
    "java",
    "kt",
    "swift",
    "php",
    "cs",
    "dart",
    "tf",
    "tfvars",
];

const BUILD_DIRS_ANYWHERE: &[&str] = &[
    "dist",
    ".next",
    ".output",
    ".svelte-kit",
    ".vercel",
    ".nuxt",
];
const BUILD_DIRS_AT_ROOT: &[&str] = &["build", "out"];
const NEXT_DIST_DIR: &str = ".next";

const VITE_CONFIGS: &[&str] = &[
    "vite.config.ts",
    "vite.config.js",
    "vite.config.mts",
    "vite.config.mjs",
    "vite.config.cts",
    "vite.config.cjs",
];
const NEXT_CONFIGS: &[&str] = &[
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "next.config.cjs",
    "next-env.d.ts",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Content {
    Sql,
    Script,
    Env,
    Text,
    Native,
    Kconfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum FileRole {
    BrowserCode,
    ServerCode,
    EdgeFunction,
    UnknownCode,
    Migration,
    EnvFile,
    BuildOutput,
    ServerBuildOutput,
    BuildCache,
    NativeCode,
    FirmwareCode,
    BuildConfig,
    Other,
}

impl FileRole {
    pub(crate) fn runs_in_browser(self) -> bool {
        matches!(self, Self::BrowserCode | Self::BuildOutput)
    }

    pub(crate) fn is_build_output(self) -> bool {
        matches!(
            self,
            Self::BuildOutput | Self::ServerBuildOutput | Self::BuildCache
        )
    }

    pub(crate) fn runtime(self) -> Runtime {
        match self {
            Self::BrowserCode | Self::BuildOutput => Runtime::Browser,
            Self::ServerCode | Self::ServerBuildOutput => Runtime::Server,
            Self::BuildCache => Runtime::Build,
            Self::EdgeFunction => Runtime::Edge,
            Self::Migration => Runtime::Database,
            Self::FirmwareCode => Runtime::Firmware,
            Self::BuildConfig => Runtime::Build,
            Self::UnknownCode | Self::NativeCode | Self::EnvFile | Self::Other => Runtime::Unknown,
        }
    }

    pub(crate) fn artifact(self) -> Artifact {
        match self {
            Self::BrowserCode
            | Self::ServerCode
            | Self::EdgeFunction
            | Self::UnknownCode
            | Self::NativeCode
            | Self::FirmwareCode => Artifact::Source,
            Self::BuildConfig => Artifact::Config,
            Self::Migration => Artifact::Migration,
            Self::EnvFile => Artifact::Config,
            Self::BuildOutput | Self::ServerBuildOutput | Self::BuildCache => Artifact::BuildOutput,
            Self::Other => Artifact::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Class {
    pub role: FileRole,
    pub content: Content,
    pub served_as_is: bool,
}

#[derive(Default)]
pub(crate) struct ProjectHints {
    vite_roots: BTreeSet<String>,
    next_roots: BTreeSet<String>,
    esp_roots: BTreeSet<String>,
    zephyr_roots: BTreeSet<String>,
    pio_roots: BTreeSet<String>,
    arduino_roots: BTreeSet<String>,
    native_build_at_root: bool,
    cargo_roots: BTreeSet<String>,
}

pub(crate) fn is_wanted(rel_path: &str) -> bool {
    content_of(file_name(rel_path)).is_some()
}

impl ProjectHints {
    pub(crate) fn from_paths<'a>(paths: impl Iterator<Item = &'a str>) -> Self {
        let mut hints = Self::default();
        for path in paths.filter(|path| !is_build_output(path)) {
            let (dir, name) = split_dir(path);
            if VITE_CONFIGS.contains(&name) {
                hints.vite_roots.insert(dir.to_owned());
            } else if NEXT_CONFIGS.contains(&name) {
                hints.next_roots.insert(dir.to_owned());
            } else if name == "platformio.ini" {
                hints.pio_roots.insert(dir.to_owned());
            } else if is_kconfig(name) {
                if name.starts_with("sdkconfig") {
                    hints.esp_roots.insert(dir.to_owned());
                } else {
                    hints.zephyr_roots.insert(dir.to_owned());
                }
            } else if name.ends_with(".ino") {
                hints.arduino_roots.insert(dir.to_owned());
            } else if name == "Cargo.toml" {
                hints.cargo_roots.insert(dir.to_owned());
            }
            if dir.is_empty() && (NATIVE_BUILD_FILES.contains(&name) || is_kconfig(name)) {
                hints.native_build_at_root = true;
            }
        }
        hints
    }

    pub(crate) fn classify(&self, rel_path: &str) -> Option<Class> {
        let content = content_of(file_name(rel_path))?;
        let mut served_as_is = false;
        if self.native_build_at_root && is_native_build_dir(rel_path) {
            return None;
        }
        if self.is_cargo_output(rel_path) {
            return None;
        }
        let role = match content {
            Content::Sql => FileRole::Migration,
            Content::Env => FileRole::EnvFile,
            Content::Native | Content::Kconfig if is_build_output(rel_path) => return None,
            Content::Kconfig => FileRole::BuildConfig,
            Content::Native if self.firmware_root_for(rel_path).is_some() => FileRole::FirmwareCode,
            Content::Native => FileRole::NativeCode,
            Content::Script | Content::Text if is_build_output(rel_path) => {
                build_output_role(rel_path)
            }
            Content::Script | Content::Text if self.is_served_as_is(rel_path) => {
                served_as_is = true;
                FileRole::BrowserCode
            }
            Content::Script => self.script_role(rel_path),
            Content::Text => FileRole::Other,
        };
        Some(Class {
            role,
            content,
            served_as_is,
        })
    }

    pub(crate) fn ecosystems(&self) -> Vec<Ecosystem> {
        let mut found = Vec::new();
        if !self.next_roots.is_empty() {
            found.push(Ecosystem::Next);
        }
        if !self.vite_roots.is_empty() {
            found.push(Ecosystem::Vite);
        }
        for (roots, ecosystem) in [
            (&self.esp_roots, Ecosystem::EspIdf),
            (&self.zephyr_roots, Ecosystem::Zephyr),
            (&self.pio_roots, Ecosystem::PlatformIo),
            (&self.arduino_roots, Ecosystem::Arduino),
        ] {
            if !roots.is_empty() {
                found.push(ecosystem);
            }
        }
        found
    }

    fn is_cargo_output(&self, rel_path: &str) -> bool {
        self.cargo_roots.iter().any(|root| {
            has_root(rel_path, root) && strip_root(rel_path, root).starts_with("target/")
        })
    }

    pub(crate) fn firmware_root_for(&self, rel_path: &str) -> Option<&str> {
        [
            &self.esp_roots,
            &self.zephyr_roots,
            &self.pio_roots,
            &self.arduino_roots,
        ]
        .into_iter()
        .filter_map(|roots| deepest_root(roots, rel_path))
        .max_by_key(|root| root.len())
    }

    pub(crate) fn has_firmware(&self) -> bool {
        !(self.esp_roots.is_empty()
            && self.zephyr_roots.is_empty()
            && self.pio_roots.is_empty()
            && self.arduino_roots.is_empty())
    }

    pub(crate) fn has_many_next_roots(&self) -> bool {
        self.next_roots.len() > 1
    }

    pub(crate) fn next_root_for(&self, rel_dir: &str) -> Option<&str> {
        deepest_root(&self.next_roots, rel_dir)
    }

    pub(crate) fn vite_root_for(&self, rel_dir: &str) -> Option<&str> {
        deepest_root(&self.vite_roots, rel_dir)
    }

    pub(crate) fn roots(&self) -> Vec<String> {
        self.next_roots
            .iter()
            .chain(&self.vite_roots)
            .cloned()
            .collect()
    }

    fn is_served_as_is(&self, rel_path: &str) -> bool {
        self.next_roots.iter().chain(&self.vite_roots).any(|root| {
            strip_root(rel_path, root).starts_with("public/") && has_root(rel_path, root)
        }) || self
            .vite_roots
            .iter()
            .any(|root| has_root(rel_path, root) && strip_root(rel_path, root) == "index.html")
    }

    fn script_role(&self, rel_path: &str) -> FileRole {
        if has_prefix_dir(rel_path, "supabase/functions")
            || rel_path.contains("/supabase/functions/")
        {
            return FileRole::EdgeFunction;
        }
        if has_prefix_dir(rel_path, "netlify/functions") || rel_path.contains("/netlify/functions/")
        {
            return FileRole::ServerCode;
        }
        let next_root = deepest_root(&self.next_roots, rel_path);
        let vite_root = deepest_root(&self.vite_roots, rel_path);
        match (next_root, vite_root) {
            (Some(next), vite) if vite.is_none_or(|vite| next.len() >= vite.len()) => {
                next_role(strip_root(rel_path, next))
            }
            (_, Some(vite)) => vite_role(strip_root(rel_path, vite)),
            _ if rel_path.starts_with("api/") => FileRole::ServerCode,
            _ => FileRole::UnknownCode,
        }
    }
}

fn next_role(path: &str) -> FileRole {
    let path = path.strip_prefix("src/").unwrap_or(path);
    let name = file_name(path);
    let stem = name.split('.').next().unwrap_or(name);
    if path.starts_with("app/")
        || path.starts_with("pages/api/")
        || (path.starts_with("pages/") && stem == "_document")
        || (!path.contains('/') && (stem == "middleware" || stem == "instrumentation"))
    {
        FileRole::ServerCode
    } else if path.starts_with("pages/") {
        FileRole::BrowserCode
    } else if !path.contains('/') && name.contains(".config.") {
        FileRole::Other
    } else {
        FileRole::UnknownCode
    }
}

fn vite_role(path: &str) -> FileRole {
    if path.starts_with("src/") {
        FileRole::BrowserCode
    } else if path.starts_with("api/") || path.starts_with("server/") {
        FileRole::ServerCode
    } else if !path.contains('/') && file_name(path).contains(".config.") {
        FileRole::Other
    } else {
        FileRole::UnknownCode
    }
}

fn has_root(rel_path: &str, root: &str) -> bool {
    root.is_empty() || has_prefix_dir(rel_path, root)
}

fn content_of(name: &str) -> Option<Content> {
    if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
        return Some(Content::Env);
    }
    if is_kconfig(name) {
        return Some(Content::Kconfig);
    }
    let (_, ext) = name.rsplit_once('.')?;
    let ext = ext.to_ascii_lowercase();
    if NATIVE_EXTENSIONS.contains(&ext.as_str()) {
        return Some(Content::Native);
    }
    if ext == "sql" {
        Some(Content::Sql)
    } else if SCRIPT_EXTENSIONS.contains(&ext.as_str()) {
        Some(Content::Script)
    } else if TEXT_EXTENSIONS.contains(&ext.as_str()) {
        Some(Content::Text)
    } else {
        None
    }
}

pub(crate) fn is_native_source(rel_path: &str) -> bool {
    file_name(rel_path)
        .rsplit_once('.')
        .is_some_and(|(_, ext)| {
            let ext = ext.to_ascii_lowercase();
            NATIVE_EXTENSIONS.contains(&ext.as_str())
                && !matches!(ext.as_str(), "h" | "hpp" | "hh" | "hxx")
        })
}

pub(crate) fn is_kconfig(name: &str) -> bool {
    let sdkconfig = name == "sdkconfig"
        || (name.starts_with("sdkconfig.")
            && !NOT_KCONFIG_SUFFIXES
                .iter()
                .any(|suffix| name.ends_with(suffix)));
    let zephyr = name == "prj.conf" || (name.starts_with("prj_") && name.ends_with(".conf"));
    sdkconfig || zephyr
}

fn is_native_build_dir(rel_path: &str) -> bool {
    rel_path
        .split_once('/')
        .is_some_and(|(first, _)| BUILD_DIRS_AT_ROOT.contains(&first))
}

fn is_build_output(rel_path: &str) -> bool {
    let mut segments = rel_path.split('/');
    let Some(first) = segments.next() else {
        return false;
    };
    let dirs: Vec<&str> = std::iter::once(first).chain(segments).collect();
    let Some((_, dirs)) = dirs.split_last() else {
        return false;
    };
    dirs.first()
        .is_some_and(|first| BUILD_DIRS_AT_ROOT.contains(first))
        || dirs.iter().any(|dir| BUILD_DIRS_ANYWHERE.contains(dir))
}

fn build_output_role(rel_path: &str) -> FileRole {
    let dirs: Vec<&str> = split_dir(rel_path).0.split('/').collect();
    match dirs.iter().position(|dir| *dir == NEXT_DIST_DIR) {
        Some(index) => match dirs.get(index + 1) {
            Some(&"static") => FileRole::BuildOutput,
            Some(&"cache") => FileRole::BuildCache,
            _ => FileRole::ServerBuildOutput,
        },
        None => FileRole::BuildOutput,
    }
}

fn deepest_root<'a>(roots: &'a BTreeSet<String>, rel_path: &str) -> Option<&'a str> {
    roots
        .iter()
        .filter(|root| root.is_empty() || has_prefix_dir(rel_path, root))
        .max_by_key(|root| root.len())
        .map(String::as_str)
}

fn strip_root<'a>(rel_path: &'a str, root: &str) -> &'a str {
    if root.is_empty() {
        rel_path
    } else {
        rel_path
            .strip_prefix(root)
            .and_then(|rest| rest.strip_prefix('/'))
            .unwrap_or(rel_path)
    }
}

fn has_prefix_dir(rel_path: &str, dir: &str) -> bool {
    rel_path
        .strip_prefix(dir)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn split_dir(rel_path: &str) -> (&str, &str) {
    rel_path.rsplit_once('/').unwrap_or(("", rel_path))
}

pub(crate) fn file_name(rel_path: &str) -> &str {
    split_dir(rel_path).1
}

#[cfg(test)]
mod tests {
    use super::{Content, FileRole, ProjectHints};

    fn role(hints: &ProjectHints, path: &str) -> Option<FileRole> {
        hints.classify(path).map(|class| class.role)
    }

    #[test]
    fn vite_src_runs_in_browser() {
        let hints = ProjectHints::from_paths(["vite.config.ts", "src/App.tsx"].into_iter());
        assert_eq!(
            role(&hints, "src/lib/supabase.ts"),
            Some(FileRole::BrowserCode)
        );
        assert_eq!(role(&hints, "vite.config.ts"), Some(FileRole::Other));
        assert_eq!(role(&hints, "scripts/seed.ts"), Some(FileRole::UnknownCode));
    }

    #[test]
    fn nested_vite_project_is_detected() {
        let hints = ProjectHints::from_paths(["apps/web/vite.config.ts"].into_iter());
        assert_eq!(
            role(&hints, "apps/web/src/main.tsx"),
            Some(FileRole::BrowserCode)
        );
        assert_eq!(
            role(&hints, "apps/api/src/main.ts"),
            Some(FileRole::UnknownCode)
        );
    }

    #[test]
    fn next_server_paths_are_server_code() {
        let hints = ProjectHints::from_paths(["next.config.mjs"].into_iter());
        assert_eq!(
            role(&hints, "app/api/todos/route.ts"),
            Some(FileRole::ServerCode)
        );
        assert_eq!(
            role(&hints, "src/pages/api/hello.ts"),
            Some(FileRole::ServerCode)
        );
        assert_eq!(role(&hints, "middleware.ts"), Some(FileRole::ServerCode));
        assert_eq!(role(&hints, "app/page.tsx"), Some(FileRole::ServerCode));
        assert_eq!(
            role(&hints, "src/app/(shop)/cart/page.tsx"),
            Some(FileRole::ServerCode)
        );
        assert_eq!(role(&hints, "pages/index.tsx"), Some(FileRole::BrowserCode));
        assert_eq!(
            role(&hints, "pages/_document.tsx"),
            Some(FileRole::ServerCode)
        );
        assert_eq!(role(&hints, "lib/db.ts"), Some(FileRole::UnknownCode));
    }

    #[test]
    fn next_env_types_mark_a_next_project_without_a_config() {
        let hints = ProjectHints::from_paths(["next-env.d.ts"].into_iter());
        assert_eq!(
            role(&hints, "app/api/webhooks/route.ts"),
            Some(FileRole::ServerCode)
        );
        assert_eq!(role(&hints, "next-env.d.ts"), Some(FileRole::UnknownCode));
    }

    #[test]
    fn public_assets_and_server_folders_are_recognized() {
        let hints = ProjectHints::from_paths(["vite.config.ts"].into_iter());
        assert_eq!(
            role(&hints, "public/config.json"),
            Some(FileRole::BrowserCode)
        );
        assert_eq!(role(&hints, "index.html"), Some(FileRole::BrowserCode));
        assert_eq!(role(&hints, "docs/index.html"), Some(FileRole::Other));
        assert_eq!(role(&hints, "api/checkout.ts"), Some(FileRole::ServerCode));
        assert_eq!(role(&hints, "server/index.ts"), Some(FileRole::ServerCode));
        assert_eq!(
            role(&hints, "netlify/functions/pay.ts"),
            Some(FileRole::ServerCode)
        );
    }

    #[test]
    fn special_locations_override_framework() {
        let hints = ProjectHints::from_paths(["vite.config.ts"].into_iter());
        assert_eq!(
            role(&hints, "supabase/functions/hello/index.ts"),
            Some(FileRole::EdgeFunction)
        );
        assert_eq!(
            role(&hints, "supabase/migrations/0001_init.sql"),
            Some(FileRole::Migration)
        );
        assert_eq!(
            role(&hints, "dist/assets/index-abc.js"),
            Some(FileRole::BuildOutput)
        );
        assert_eq!(role(&hints, ".env.local"), Some(FileRole::EnvFile));
        assert_eq!(
            role(&hints, "src/build/util.ts"),
            Some(FileRole::BrowserCode)
        );
    }

    #[test]
    fn next_build_output_is_split_by_where_it_runs() {
        let hints = ProjectHints::from_paths(
            [
                "next.config.mjs",
                ".next/standalone/next.config.js",
                "apps/web/.next/standalone/apps/web/next.config.js",
            ]
            .into_iter(),
        );
        assert_eq!(hints.roots(), vec![String::new()]);
        assert_eq!(
            role(&hints, ".next/static/chunks/app/page-1a2b.js"),
            Some(FileRole::BuildOutput)
        );
        assert_eq!(
            role(&hints, ".next/static/chunks/app/page-1a2b.js.map"),
            Some(FileRole::BuildOutput)
        );
        assert_eq!(
            role(&hints, ".next/server/app/api/todos/route.js"),
            Some(FileRole::ServerBuildOutput)
        );
        assert_eq!(
            role(&hints, ".next/standalone/server.js"),
            Some(FileRole::ServerBuildOutput)
        );
        assert_eq!(
            role(&hints, ".next/required-server-files.json"),
            Some(FileRole::ServerBuildOutput)
        );
        assert_eq!(
            role(&hints, ".next/cache/fetch-cache/abc.json"),
            Some(FileRole::BuildCache)
        );
        assert_eq!(
            role(&hints, "apps/web/.next/server/chunks/1.js"),
            Some(FileRole::ServerBuildOutput)
        );
        assert!(!FileRole::ServerBuildOutput.runs_in_browser());
        assert!(!FileRole::BuildCache.runs_in_browser());
        assert!(FileRole::BuildOutput.runs_in_browser());
    }

    #[test]
    fn unknown_extensions_are_not_read() {
        let hints = ProjectHints::default();
        assert_eq!(hints.classify("logo.png"), None);
        assert_eq!(hints.classify("Makefile"), None);
        assert_eq!(
            hints.classify("README.md").map(|class| class.content),
            Some(Content::Text)
        );
    }
}
