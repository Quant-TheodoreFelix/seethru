use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use seethru_core::BuildTool;
use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::ScanError;
use crate::classify::ProjectHints;
use crate::sourcemap::{MapRef, SourceMap};
use crate::walk;

const MAX_CHUNK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MAP_BYTES: u64 = 32 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const STALE_TOLERANCE: Duration = Duration::from_secs(2);
const NEXT_MARKERS: &[&str] = &[
    "BUILD_ID",
    "build-manifest.json",
    "required-server-files.json",
];
const VITE_MANIFESTS: &[&str] = &[".vite/manifest.json", "manifest.json"];
const VITE_ASSETS_DIR: &str = "assets/";
const SCRIPT_SUFFIXES: &[&str] = &[".js", ".mjs", ".cjs"];
const CLIENT_REFERENCE_SUFFIX: &str = "_client-reference-manifest.js";
const RSC_MANIFEST_MARKER: &str = "__RSC_MANIFEST[";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BuildDir {
    pub abs: PathBuf,
    pub rel: String,
}

pub(crate) struct BuildOutput {
    pub tool: BuildTool,
    pub rel: String,
    pub root: String,
    pub stale: bool,
    pub partial: bool,
    pub complete: bool,
    pub browser: BTreeMap<String, String>,
    pub server: BTreeMap<String, String>,
    dir: BuildDir,
    sources: Sources,
}

struct Sources {
    root: String,
    relative_app_dir: Option<String>,
    scripts: BTreeSet<String>,
}

struct Budget {
    left: u64,
    oldest: Option<SystemTime>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ViteEntry {
    file: String,
    src: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct RequiredServerFiles {
    relative_app_dir: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct ClientReferenceManifest {
    client_modules: BTreeMap<String, IgnoredAny>,
}

pub(crate) fn locate(root: &Path, given: &Path) -> Result<BuildDir, ScanError> {
    let fail = |reason: &str| ScanError::BuildOutput(format!("{} {reason}", given.display()));
    let meta = fs::symlink_metadata(given).map_err(|_| fail("cannot be read"))?;
    if meta.file_type().is_symlink() {
        return Err(fail("is a symbolic link"));
    }
    if !meta.is_dir() {
        return Err(fail("is not a directory"));
    }
    let abs = fs::canonicalize(given).map_err(|_| fail("cannot be read"))?;
    let inside = abs
        .strip_prefix(root)
        .map_err(|_| fail("is outside the scanned project"))?;
    let mut parts = Vec::new();
    for component in inside.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .ok_or_else(|| fail("has a name that is not UTF-8"))?,
            ),
            _ => return Err(fail("is not a folder inside the scanned project")),
        }
    }
    if parts.is_empty() {
        return Err(fail(
            "is the scanned project itself, point at the build folder inside it",
        ));
    }
    let rel = parts.join("/");
    Ok(BuildDir { abs, rel })
}

pub(crate) fn read(
    root: &Path,
    dir: BuildDir,
    hints: &ProjectHints,
    scripts: &BTreeSet<String>,
) -> Result<BuildOutput, ScanError> {
    let has = |name: &str| {
        fs::symlink_metadata(dir.abs.join(name)).is_ok_and(|meta| meta.file_type().is_file())
    };
    let tool = if NEXT_MARKERS.iter().any(|name| has(name)) {
        BuildTool::Next
    } else if VITE_MANIFESTS.iter().any(|name| has(name)) || hints.vite_root_for(&dir.rel).is_some()
    {
        BuildTool::Vite
    } else {
        return Err(ScanError::BuildOutput(format!(
            "{} does not look like Vite or Next build output",
            dir.rel
        )));
    };
    let project_root = match tool {
        BuildTool::Next => hints.next_root_for(&dir.rel),
        BuildTool::Vite => hints.vite_root_for(&dir.rel),
    }
    .map_or_else(|| parent(&dir.rel).to_owned(), str::to_owned);

    let walked = walk::walk_with(
        &dir.abs,
        |rel| {
            rel == "BUILD_ID" || rel.ends_with(".map") || rel.ends_with(".json") || is_script(rel)
        },
        |rel| tool == BuildTool::Next && rel.starts_with("cache/"),
        MAX_MAP_BYTES,
    )?;
    let files: Vec<String> = walked
        .entries
        .into_iter()
        .map(|entry| entry.rel_path)
        .collect();
    let mut output = BuildOutput {
        tool,
        rel: dir.rel.clone(),
        root: project_root.clone(),
        stale: false,
        partial: walked.truncated,
        complete: false,
        browser: BTreeMap::new(),
        server: BTreeMap::new(),
        dir,
        sources: Sources {
            root: project_root,
            relative_app_dir: None,
            scripts: scripts.clone(),
        },
    };
    let mut budget = Budget {
        left: MAX_TOTAL_BYTES,
        oldest: None,
    };
    match tool {
        BuildTool::Vite => output.read_vite(&files, &mut budget),
        BuildTool::Next => output.read_next(&files, &mut budget),
    }
    if let Some(built) = budget.oldest
        && newest_script(root, &output.sources) > Some(built + STALE_TOLERANCE)
    {
        output.stale = true;
        output.complete = false;
        output.browser.clear();
        output.server.clear();
    }
    Ok(output)
}

impl BuildOutput {
    fn scan_rel(&self, build_rel: &str) -> String {
        format!("{}/{build_rel}", self.rel)
    }

    fn read_vite(&mut self, files: &[String], budget: &mut Budget) {
        let mut chunks: Option<BTreeSet<String>> = None;
        for name in VITE_MANIFESTS {
            if !files.iter().any(|file| file == name) {
                continue;
            }
            let Some(bytes) = budget.read(&self.dir.abs.join(name), MAX_MANIFEST_BYTES) else {
                continue;
            };
            let Ok(manifest) = serde_json::from_slice::<BTreeMap<String, ViteEntry>>(&bytes) else {
                continue;
            };
            let mut listed = BTreeSet::new();
            for (key, entry) in manifest {
                if is_script(&entry.file) {
                    listed.insert(entry.file.clone());
                }
                let src = entry.src.unwrap_or(key);
                if let Some(script) =
                    join(&self.sources.root, &src).and_then(|p| self.sources.known(p))
                {
                    let chunk = self.scan_rel(&entry.file);
                    self.browser.entry(script).or_insert(chunk);
                }
            }
            chunks = Some(listed);
            break;
        }
        let chunks: Vec<String> = match chunks {
            Some(listed) => listed.into_iter().collect(),
            None => {
                let scripts: Vec<&String> = files.iter().filter(|file| is_script(file)).collect();
                let in_assets: Vec<String> = scripts
                    .iter()
                    .filter(|file| file.starts_with(VITE_ASSETS_DIR))
                    .map(|file| (*file).clone())
                    .collect();
                if in_assets.is_empty() {
                    scripts.into_iter().cloned().collect()
                } else {
                    in_assets
                }
            }
        };
        let mut missing = 0usize;
        for chunk in &chunks {
            let found = self.chunk_sources(chunk, budget);
            match found {
                Some(sources) => {
                    let evidence = self.scan_rel(chunk);
                    for script in sources {
                        self.browser
                            .entry(script)
                            .or_insert_with(|| evidence.clone());
                    }
                }
                None => missing += 1,
            }
        }
        self.partial |= chunks.is_empty() || missing > 0;
        self.complete = !self.partial;
    }

    fn read_next(&mut self, files: &[String], budget: &mut Budget) {
        if let Some(bytes) = budget.read(
            &self.dir.abs.join("required-server-files.json"),
            MAX_MANIFEST_BYTES,
        ) && let Ok(required) = serde_json::from_slice::<RequiredServerFiles>(&bytes)
        {
            self.sources.relative_app_dir = required
                .relative_app_dir
                .filter(|dir| !dir.is_empty() && !dir.contains("..") && !dir.starts_with('/'));
        }
        let mut client_maps = 0usize;
        for file in files {
            if file.starts_with("server/app/") && file.ends_with(CLIENT_REFERENCE_SUFFIX) {
                let Some(bytes) = budget.read(&self.dir.abs.join(file), MAX_MAP_BYTES) else {
                    continue;
                };
                let evidence = self.scan_rel(file);
                for key in client_reference_keys(&bytes) {
                    if let Some(script) = self.sources.reference(&key) {
                        self.browser
                            .entry(script)
                            .or_insert_with(|| evidence.clone());
                    }
                }
            } else if is_script(file) && file.starts_with("static/") {
                if let Some(sources) = self.chunk_sources(file, budget) {
                    client_maps += 1;
                    let evidence = self.scan_rel(file);
                    for script in sources {
                        self.browser
                            .entry(script)
                            .or_insert_with(|| evidence.clone());
                    }
                }
            } else if is_script(file)
                && file.starts_with("server/")
                && let Some(sources) = self.chunk_sources(file, budget)
            {
                let evidence = self.scan_rel(file);
                for script in sources {
                    self.server
                        .entry(script)
                        .or_insert_with(|| evidence.clone());
                }
            }
        }
        self.partial |= client_maps == 0;
        self.complete = false;
    }

    fn chunk_sources(&self, chunk: &str, budget: &mut Budget) -> Option<BTreeSet<String>> {
        let (map, map_dir) = self.load_map(chunk, budget)?;
        Some(
            map.sources()
                .filter_map(|(source_root, source)| {
                    self.sources.resolve(source, source_root, &map_dir)
                })
                .collect(),
        )
    }

    fn load_map(&self, chunk: &str, budget: &mut Budget) -> Option<(SourceMap, String)> {
        let chunk_bytes = budget.read(&self.dir.abs.join(chunk), MAX_CHUNK_BYTES)?;
        let chunk_dir = parent(chunk);
        let (bytes, map_rel) = match crate::sourcemap::map_ref(&chunk_bytes) {
            Some(MapRef::Inline(bytes)) => (bytes, chunk.to_owned()),
            Some(MapRef::Path(reference)) => {
                let map_rel = join(chunk_dir, &reference)?;
                (
                    budget.read(&self.dir.abs.join(&map_rel), MAX_MAP_BYTES)?,
                    map_rel,
                )
            }
            None => {
                let map_rel = format!("{chunk}.map");
                (
                    budget.read(&self.dir.abs.join(&map_rel), MAX_MAP_BYTES)?,
                    map_rel,
                )
            }
        };
        let map = SourceMap::parse(&bytes)?;
        Some((
            map,
            self.scan_rel(parent(&map_rel))
                .trim_end_matches('/')
                .to_owned(),
        ))
    }

    pub(crate) fn locate(&self, chunk: &str, line: u32, column: u32) -> Option<(String, u32, u32)> {
        if self.stale {
            return None;
        }
        let build_rel = chunk.strip_prefix(&self.rel)?.strip_prefix('/')?;
        let mut budget = Budget {
            left: MAX_CHUNK_BYTES + MAX_MAP_BYTES,
            oldest: None,
        };
        let (map, map_dir) = self.load_map(build_rel, &mut budget)?;
        let mapped = map.lookup(line.checked_sub(1)?, column)?;
        let script = self
            .sources
            .resolve(mapped.source, mapped.source_root, &map_dir)?;
        Some((
            script,
            mapped.line.saturating_add(1),
            mapped.column.saturating_add(1),
        ))
    }
}

impl Budget {
    fn read(&mut self, path: &Path, max: u64) -> Option<Vec<u8>> {
        if self.left == 0 {
            return None;
        }
        let bytes = walk::read_bytes(path, max.min(self.left))?;
        self.left = self.left.saturating_sub(bytes.len() as u64);
        if let Ok(modified) = fs::symlink_metadata(path).and_then(|meta| meta.modified()) {
            self.oldest = Some(self.oldest.map_or(modified, |oldest| oldest.min(modified)));
        }
        Some(bytes)
    }
}

impl Sources {
    fn known(&self, path: String) -> Option<String> {
        self.scripts.contains(&path).then_some(path)
    }

    fn resolve(&self, raw: &str, source_root: Option<&str>, map_dir: &str) -> Option<String> {
        variants(raw).into_iter().find_map(|variant| {
            if variant.is_empty() || variant.contains('\0') || variant.contains("node_modules") {
                return None;
            }
            if let Some(rest) = variant.strip_prefix("webpack://") {
                let (_, path) = rest.split_once('/')?;
                let path = path.split('?').next()?;
                let path = path.strip_prefix("./")?;
                return join(&self.root, path).and_then(|p| self.known(p));
            }
            if let Some(rest) = variant.strip_prefix("turbopack:///") {
                return self.project(rest);
            }
            if is_absolute(&variant) {
                return self.suffix(&variant);
            }
            if variant.contains("://") {
                return None;
            }
            let base = match source_root {
                Some(root) if !root.is_empty() && !root.contains("://") && !is_absolute(root) => {
                    join(map_dir, root)?
                }
                _ => map_dir.to_owned(),
            };
            join(&base, &variant).and_then(|p| self.known(p))
        })
    }

    fn reference(&self, key: &str) -> Option<String> {
        let key = key.split('#').next()?;
        if key.contains("node_modules") {
            return None;
        }
        if key.starts_with("[project]/") {
            return self.project(key);
        }
        if is_absolute(key) {
            return self.suffix(key);
        }
        None
    }

    fn project(&self, path: &str) -> Option<String> {
        let path = path.strip_prefix("[project]/")?;
        let trimmed = path.split(' ').next().unwrap_or(path);
        [path, trimmed].into_iter().find_map(|path| {
            let mut candidates = vec![join(&self.root, path), join("", path)];
            if let Some(app_dir) = &self.relative_app_dir
                && let Some(rest) = path
                    .strip_prefix(app_dir.as_str())
                    .and_then(|rest| rest.strip_prefix('/'))
            {
                candidates.push(join(&self.root, rest));
            }
            candidates.into_iter().flatten().find_map(|p| self.known(p))
        })
    }

    fn suffix(&self, absolute: &str) -> Option<String> {
        let normalized = absolute.replace('\\', "/");
        normalized
            .match_indices('/')
            .map(|(index, _)| &normalized[index + 1..])
            .filter(|tail| !tail.is_empty())
            .find_map(|tail| self.known(tail.to_owned()))
    }
}

fn newest_script(root: &Path, sources: &Sources) -> Option<SystemTime> {
    sources
        .scripts
        .iter()
        .filter(|script| {
            sources.root.is_empty() || script.starts_with(&format!("{}/", sources.root))
        })
        .filter_map(|script| {
            fs::symlink_metadata(root.join(script))
                .and_then(|meta| meta.modified())
                .ok()
        })
        .max()
}

fn client_reference_keys(bytes: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let Some(at) = text.find(RSC_MANIFEST_MARKER) else {
        return Vec::new();
    };
    let after = &text[at + RSC_MANIFEST_MARKER.len()..];
    let mut keys = serde_json::Deserializer::from_str(after).into_iter::<String>();
    if !matches!(keys.next(), Some(Ok(_))) {
        return Vec::new();
    }
    let rest = after[keys.byte_offset()..].trim_start();
    let Some(rest) = rest
        .strip_prefix(']')
        .map(str::trim_start)
        .and_then(|rest| rest.strip_prefix('='))
    else {
        return Vec::new();
    };
    match serde_json::Deserializer::from_str(rest)
        .into_iter::<ClientReferenceManifest>()
        .next()
    {
        Some(Ok(manifest)) => manifest.client_modules.into_keys().collect(),
        _ => Vec::new(),
    }
}

fn variants(raw: &str) -> Vec<String> {
    let mut out = vec![raw.to_owned()];
    if let Some(decoded) = percent_decode(raw)
        && decoded != raw
    {
        out.push(decoded);
    }
    out
}

fn percent_decode(raw: &str) -> Option<String> {
    if !raw.contains('%') {
        return None;
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = raw.get(index + 1..index + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn is_script(path: &str) -> bool {
    SCRIPT_SUFFIXES.iter().any(|suffix| path.ends_with(suffix))
}

fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with('\\')
        || path
            .as_bytes()
            .get(1..3)
            .is_some_and(|rest| rest == b":\\" || rest == b":/")
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

pub(crate) fn join(base: &str, path: &str) -> Option<String> {
    let mut parts: Vec<&str> = base.split('/').filter(|part| !part.is_empty()).collect();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{Sources, client_reference_keys, join, percent_decode};

    fn sources(root: &str, app_dir: Option<&str>, scripts: &[&str]) -> Sources {
        Sources {
            root: root.to_owned(),
            relative_app_dir: app_dir.map(str::to_owned),
            scripts: scripts
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<BTreeSet<_>>(),
        }
    }

    #[test]
    fn joins_paths_without_leaving_the_base() {
        assert_eq!(
            join("dist/assets", "../../src/a.ts"),
            Some("src/a.ts".to_owned())
        );
        assert_eq!(join("dist", "../../etc/passwd"), None);
        assert_eq!(join("", "./src/./a.ts"), Some("src/a.ts".to_owned()));
        assert_eq!(join("", ""), None);
    }

    #[test]
    fn decodes_percent_escapes() {
        assert_eq!(
            percent_decode("src/app/%28shop%29/cart/page.jsx").as_deref(),
            Some("src/app/(shop)/cart/page.jsx")
        );
        assert_eq!(percent_decode("a%2"), None);
        assert_eq!(percent_decode("plain"), None);
    }

    #[test]
    fn resolves_sources_from_every_bundler_only_to_scanned_scripts() {
        let s = sources(
            "apps/web",
            Some("apps/web"),
            &[
                "apps/web/src/lib/admin.js",
                "apps/web/src/app/(shop)/cart/page.jsx",
                "src/lib/root.ts",
            ],
        );
        let at = |raw: &str, dir: &str| s.resolve(raw, None, dir);
        assert_eq!(
            at("../../src/lib/admin.js", "apps/web/dist/assets").as_deref(),
            Some("apps/web/src/lib/admin.js")
        );
        assert_eq!(
            at("webpack://_N_E/./src/lib/admin.js?3b7a", "x").as_deref(),
            Some("apps/web/src/lib/admin.js")
        );
        assert_eq!(at("webpack://_N_E/../../src/client/router.ts", "x"), None);
        assert_eq!(
            at("turbopack:///[project]/apps/web/src/lib/admin.js", "x").as_deref(),
            Some("apps/web/src/lib/admin.js")
        );
        assert_eq!(
            at("turbopack:///[project]/src/lib/admin.js", "x").as_deref(),
            Some("apps/web/src/lib/admin.js")
        );
        assert_eq!(
            at(
                "../../../../src/app/%28shop%29/cart/page.jsx",
                "apps/web/.next/server/chunks/ssr"
            )
            .as_deref(),
            Some("apps/web/src/app/(shop)/cart/page.jsx")
        );
        assert_eq!(
            at("/home/ci/repo/apps/web/src/lib/admin.js", "x").as_deref(),
            Some("apps/web/src/lib/admin.js")
        );
        assert_eq!(
            at("../../node_modules/react/index.js", "apps/web/dist/assets"),
            None
        );
        assert_eq!(at("https://evil.example/src/lib/root.ts", "x"), None);
        assert_eq!(at("../../src/lib/missing.ts", "apps/web/dist/assets"), None);
        assert_eq!(
            s.resolve("lib/admin.js", Some("../../src"), "apps/web/dist/assets")
                .as_deref(),
            Some("apps/web/src/lib/admin.js")
        );
        assert_eq!(
            s.reference("[project]/apps/web/src/lib/admin.js")
                .as_deref(),
            Some("apps/web/src/lib/admin.js")
        );
        assert_eq!(
            s.reference("C:\\ci\\apps\\web\\src\\lib\\admin.js")
                .as_deref(),
            Some("apps/web/src/lib/admin.js")
        );
        assert_eq!(s.reference("[project]/node_modules/next/dist/a.js"), None);
    }

    #[test]
    fn reads_client_reference_manifests_from_both_bundlers() {
        let turbopack = b"globalThis.__RSC_MANIFEST = globalThis.__RSC_MANIFEST || {};\nglobalThis.__RSC_MANIFEST[\"/blog/[slug]/page\"] = {\"moduleLoading\":{\"prefix\":\"\"},\"clientModules\":{\"[project]/src/components/TodoList.jsx\":{\"id\":1}}};\n";
        assert_eq!(
            client_reference_keys(turbopack),
            vec!["[project]/src/components/TodoList.jsx".to_owned()]
        );
        let webpack = b"globalThis.__RSC_MANIFEST=(globalThis.__RSC_MANIFEST||{});globalThis.__RSC_MANIFEST[\"/page\"]={\"ssrModuleMapping\":{},\"clientModules\":{\"/ci/app/src/components/TodoList.jsx\":{\"id\":224,\"name\":\"*\"}}};";
        assert_eq!(
            client_reference_keys(webpack),
            vec!["/ci/app/src/components/TodoList.jsx".to_owned()]
        );
        assert!(client_reference_keys(b"globalThis.__RSC_MANIFEST[\"/a\"]=oops").is_empty());
        assert!(client_reference_keys(b"nothing here").is_empty());
    }
}
