mod binary;
mod build_output;
mod cargo;
mod classify;
mod compiled;
mod config;
mod env;
mod external;
mod glob;
mod graph;
mod native;
mod observed;
mod resolve;
mod roles;
mod rules;
mod script;
mod secrets;
mod sourcemap;
mod supabase;
mod trace;
mod walk;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use seethru_core::{
    Basis, Channel, Confidence, CredentialDetail, Ecosystem, EdgeKind, EvidenceStep, Exposure,
    Input, LimitationCode, Location, Node, NodeId, NodeKind, RuleId, ScanReport, Severity,
    TargetInfo, Zone,
};

use build_output::BuildOutput;

use classify::{Class, Content, FileRole, ProjectHints};
use config::Config;
use graph::{Graph, Verdict, file_location, file_step, step};
use resolve::{ConfigText, Resolver};
use roles::{Assigned, Module};
use supabase::Migrations;

pub use binary::{BinaryCode, BinaryInput, CodeReader};
pub use config::CONFIG_FILE;
pub use observed::Observed;

const MAX_RESOLVER_CONFIG_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub enum ScanError {
    NotADirectory,
    Io(std::io::Error),
    Config(String),
    BuildOutput(String),
    Sarif(String),
    CompileCommands(String),
    CompiledOutput(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotADirectory => f.write_str("scan target is not a directory"),
            Self::Io(error) => write!(f, "cannot read scan target: {error}"),
            Self::Config(message) => write!(f, "cannot use {CONFIG_FILE}: {message}"),
            Self::BuildOutput(message) => write!(f, "cannot use the build output: {message}"),
            Self::Sarif(message) => write!(f, "cannot use the SARIF file: {message}"),
            Self::CompileCommands(message) => {
                write!(f, "cannot use the compile database: {message}")
            }
            Self::CompiledOutput(message) => {
                write!(f, "cannot use the compiled output: {message}")
            }
        }
    }
}

impl std::error::Error for ScanError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOptions {
    pub read_config: bool,
    pub build_output: Option<PathBuf>,
    pub sarif: Vec<PathBuf>,
    pub compile_commands: Option<PathBuf>,
    pub llvm_ir: Vec<PathBuf>,
    pub binaries: Vec<BinaryInput>,
    pub binary_problems: Vec<LimitationCode>,
    pub observed: Option<Observed>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            read_config: true,
            build_output: None,
            sarif: Vec::new(),
            compile_commands: None,
            llvm_ir: Vec::new(),
            binaries: Vec::new(),
            binary_problems: Vec::new(),
            observed: None,
        }
    }
}

pub fn scan(root: &Path) -> Result<ScanReport, ScanError> {
    scan_with(root, ScanOptions::default())
}

pub fn cargo_projects(root: &Path, read_config: bool) -> Result<Vec<String>, ScanError> {
    let root = std::fs::canonicalize(root).map_err(ScanError::Io)?;
    if !root.is_dir() {
        return Err(ScanError::NotADirectory);
    }
    let config = if read_config {
        Config::load(&root)?
    } else {
        None
    };
    let walked = walk::walk(&root, cargo::is_manifest, |rel_path| {
        config
            .as_ref()
            .is_some_and(|config| config.is_excluded(rel_path))
    })?;
    Ok(cargo::top_dirs(
        walked.entries.iter().map(|entry| entry.rel_path.as_str()),
    ))
}

pub fn scan_with(root: &Path, options: ScanOptions) -> Result<ScanReport, ScanError> {
    let given = std::path::absolute(root).map_err(ScanError::Io)?;
    let root = std::fs::canonicalize(root).map_err(ScanError::Io)?;
    if !root.is_dir() {
        return Err(ScanError::NotADirectory);
    }
    let config = if options.read_config {
        Config::load(&root)?
    } else {
        None
    };
    let build_dir = options
        .build_output
        .as_deref()
        .map(|given| build_output::locate(&root, given))
        .transpose()?;
    let build_list = options
        .compile_commands
        .as_deref()
        .map(|given| native::compile_db::read(&root, given))
        .transpose()?;
    let walked = walk::walk(&root, classify::is_wanted, |rel_path| {
        config
            .as_ref()
            .is_some_and(|config| config.is_excluded(rel_path))
    })?;
    let hints =
        ProjectHints::from_paths(walked.entries.iter().map(|entry| entry.rel_path.as_str()));

    let mut migrations = Migrations::default();
    let mut scripts = Vec::new();
    let mut modules = Vec::new();
    let mut secret_records = Vec::new();
    let mut configs = Vec::new();
    let mut script_paths = BTreeMap::new();
    let mut flows = Vec::new();
    let mut native_sources = Vec::new();
    let mut option_files = Vec::new();
    let mut manifests = Vec::new();
    let mut rust_sources = Vec::new();
    let mut scanned = 0u32;
    let mut skipped = walked.skipped;
    let mut uses_supabase = false;
    let mut has_sql = false;

    for entry in &walked.entries {
        let Some(class) = hints.classify(&entry.rel_path) else {
            continue;
        };
        let Some(text) = walk::read_text(&entry.abs_path) else {
            skipped = skipped.saturating_add(1);
            continue;
        };
        scanned = scanned.saturating_add(1);
        if class.content == Content::Script && !class.role.is_build_output() {
            script_paths.insert(entry.rel_path.clone(), class);
        }
        if class.content == Content::Sql {
            has_sql = true;
            migrations.apply_file(&entry.rel_path, &text);
            uses_supabase |=
                entry.rel_path.starts_with("supabase/") || entry.rel_path.contains("/supabase/");
        }
        if is_resolver_config(&entry.rel_path, class) && text.len() <= MAX_RESOLVER_CONFIG_BYTES {
            configs.push(ConfigText {
                rel_path: entry.rel_path.clone(),
                text: text.clone(),
            });
        }
        if class.content == Content::Script
            && !class.role.is_build_output()
            && let Some(mut facts) = script::analyze(&entry.rel_path, &text)
        {
            uses_supabase |= facts.uses_supabase;
            let lines = Lines::new(&text);
            modules.push(Module {
                rel_path: entry.rel_path.clone(),
                role: class.role,
                directive: facts.directive,
                server_only: facts.server_only,
                imports: std::mem::take(&mut facts.imports)
                    .into_iter()
                    .map(|import| roles::Import {
                        specifier: import.specifier,
                        location: lines.location(&entry.rel_path, import.offset),
                    })
                    .collect(),
            });
            flows.push(trace::Module {
                rel_path: entry.rel_path.clone(),
                role: class.role,
                directive: facts.directive,
                flow: std::mem::take(&mut facts.flow),
            });
            scripts.push(ScriptRecord::new(&entry.rel_path, &lines, facts));
        }
        if class.content == Content::Native {
            native_sources.push(native::Source {
                rel_path: entry.rel_path.clone(),
                role: class.role,
                root: hints
                    .firmware_root_for(&entry.rel_path)
                    .unwrap_or_default()
                    .to_owned(),
                facts: native::collect(&entry.rel_path, &text),
            });
        }
        if !options.binaries.is_empty() && entry.rel_path.ends_with(".rs") {
            let wipes = binary::find_wipes(&text);
            if !wipes.is_empty() {
                rust_sources.push(binary::Source {
                    path: entry.rel_path.clone(),
                    wipes,
                });
            }
        }
        if cargo::is_manifest(&entry.rel_path) {
            manifests.push(cargo::Manifest {
                rel_path: entry.rel_path.clone(),
                text: text.clone(),
            });
        }
        if class.content == Content::Kconfig {
            option_files.push((entry.rel_path.clone(), text.clone()));
        }
        if let Some(record) = SecretRecord::new(&entry.rel_path, class, &text) {
            secret_records.push(record);
        }
    }

    let module_paths: BTreeSet<String> = modules.iter().map(|m| m.rel_path.clone()).collect();
    let resolver = Resolver::new(&module_paths, hints.roots(), &configs);
    let mut roles = roles::assign(&modules, &resolver);
    let build = match build_dir {
        Some(dir) => {
            let scripts: BTreeSet<String> = script_paths.keys().cloned().collect();
            let build = build_output::read(&root, dir, &hints, &scripts)?;
            overlay(&build, &script_paths, &mut roles);
            Some(build)
        }
        None => None,
    };
    let assigned_of = |rel_path: &str, fallback: FileRole| {
        roles
            .get(rel_path)
            .cloned()
            .unwrap_or_else(|| Assigned::by_path(fallback))
    };

    let mut first_use: BTreeMap<String, Location> = BTreeMap::new();
    if uses_supabase {
        for record in &scripts {
            for (table, _, location) in &record.queries {
                if !migrations.is_view("public", table) {
                    first_use
                        .entry(table.clone())
                        .or_insert_with(|| location.clone());
                }
            }
        }
    }

    let mut graph = Graph::default();
    migrations.emit(&mut graph);
    for record in scripts {
        let assigned = assigned_of(&record.rel_path, FileRole::UnknownCode);
        record.emit(&mut graph, &assigned);
    }
    trace::emit(&flows, &resolver, &hints, &mut graph, &assigned_of);
    for (rel_path, text) in &option_files {
        native::emit_options(rel_path, text, &mut graph);
    }
    native::emit(&native_sources, &mut graph);
    let workspace = cargo::Workspace::read(&root, &manifests);
    workspace.emit(&mut graph);
    let compiled = if options.llvm_ir.is_empty() {
        None
    } else {
        let compiled = compiled::read(&root, &options.llvm_ir, &|rel_path| {
            config
                .as_ref()
                .is_some_and(|config| config.is_excluded(rel_path))
        })?;
        compiled::emit(&compiled, &mut graph, &|rel_path| {
            workspace.package_of(rel_path)
        });
        Some(compiled)
    };
    let checked = binary::emit(
        &root,
        &options.binaries,
        &options.binary_problems,
        &rust_sources,
        &mut graph,
        &|rel_path| workspace.package_of(rel_path),
    );
    let seen = options
        .observed
        .as_ref()
        .map(|observed| observed::emit(observed, &mut graph));
    if let Some(build) = &build {
        for route in &build.routes {
            let assigned = assigned_of(&route.source, FileRole::ServerCode);
            let file_id = graph.add_file(&route.source, assigned.role, assigned.basis);
            let entry_id = graph.add_node(Node {
                id: NodeId::new(trace::route_id(&hints, &route.source, &route.url)),
                label: route.url.clone(),
                kind: NodeKind::EntryPoint {
                    channel: Channel::HttpRoute,
                    exposure: Exposure::Unknown,
                },
                zone: Zone::Server,
                location: Some(file_location(&route.source)),
            });
            graph.add_edge(entry_id, file_id, EdgeKind::Invokes);
        }
    }
    for (table, location) in first_use {
        let table_id = NodeId::new(format!("table:public.{table}"));
        if graph.table_rls(&table_id) == Some(seethru_core::RlsStatus::Unknown) {
            let evidence = vec![
                file_step(&location.path, None, file_location(&location.path)),
                step(
                    &table,
                    Some(EdgeKind::Reads),
                    Some(table_id.clone()),
                    Some(location.clone()),
                ),
            ];
            graph.add_finding(
                Verdict {
                    rule: RuleId::SupabaseTableSchemaMissing,
                    severity: Severity::Info,
                    confidence: Confidence::Review,
                    from_build: false,
                },
                rules::table_schema_missing(&table),
                table_id,
                Some(location),
                evidence,
            );
        }
    }
    for record in secret_records {
        let assigned = assigned_of(&record.rel_path, record.class.role);
        let origins: Vec<Option<Built>> = record
            .hits
            .iter()
            .map(|hit| {
                let (path, line, column) = build.as_ref()?.locate(
                    &record.rel_path,
                    hit.location.line,
                    hit.utf16_column,
                )?;
                let assigned = assigned_of(&path, FileRole::UnknownCode);
                Some(Built {
                    location: Location { path, line, column },
                    assigned,
                })
            })
            .collect();
        record.emit(&mut graph, &assigned, origins);
    }

    let imported = if options.sarif.is_empty() {
        None
    } else {
        let imported = external::read_all(&root, &given, &options.sarif, &|rel_path| {
            config
                .as_ref()
                .is_some_and(|config| config.is_excluded(rel_path))
        })?;
        let dropped = external::emit(&imported, &mut graph, &|rel_path| {
            roles
                .get(rel_path)
                .map(|assigned| (assigned.role, assigned.basis))
        });
        Some((imported, dropped))
    };

    let mut ecosystems = hints.ecosystems();
    if uses_supabase {
        ecosystems.push(Ecosystem::Supabase);
    }
    if !workspace.is_empty() {
        ecosystems.push(Ecosystem::Cargo);
    }
    ecosystems.sort();
    let mut limitations = Vec::new();
    if ecosystems.is_empty() && modules.is_empty() && native_sources.is_empty() && !has_sql {
        limitations.push(rules::limitation(LimitationCode::ProjectKindNotRecognized));
    }
    let mut inputs = vec![Input::Source {}];
    match &build {
        None if !modules.is_empty() => {
            limitations.push(rules::limitation(LimitationCode::BuildOutputNotRead));
        }
        None => {}
        Some(build) => {
            inputs.push(Input::BuildOutput {
                path: build.rel.clone(),
                tool: build.tool,
            });
            if build.stale {
                limitations.push(rules::limitation(LimitationCode::BuildOutputStale));
            } else if build.partial {
                limitations.push(rules::limitation(
                    LimitationCode::BuildOutputWithoutSourceMaps,
                ));
            }
        }
    }
    if uses_supabase {
        limitations.push(rules::limitation(LimitationCode::DashboardPoliciesUnseen));
    }
    if hints.has_firmware() {
        limitations.push(rules::limitation(
            LimitationCode::FirmwareProtectionNotChecked,
        ));
    }
    if !native_sources.is_empty() {
        limitations.push(rules::limitation(LimitationCode::NativeCodePartlyRead));
    }
    match &compiled {
        None if !workspace.is_empty() => {
            limitations.push(rules::limitation(LimitationCode::CompiledOutputNotRead));
        }
        None => {}
        Some(compiled) => {
            inputs.extend(compiled.inputs.iter().cloned());
            limitations.push(rules::limitation(LimitationCode::CompiledChecksPartial));
            if !compiled.machine_code {
                limitations.push(rules::limitation(
                    LimitationCode::CompiledOutputWithoutMachineCode,
                ));
            }
            if compiled.unoptimized {
                limitations.push(rules::limitation(
                    LimitationCode::CompiledOutputNotOptimized,
                ));
            }
            if compiled.wipes == 0 {
                limitations.push(rules::limitation(
                    LimitationCode::CompiledOutputWithoutWipes,
                ));
            }
            if compiled.entries == 0 {
                limitations.push(rules::limitation(LimitationCode::OutsideEntriesNotFound));
            }
            if compiled.unknown_cpu {
                limitations.push(rules::limitation(
                    LimitationCode::MachineCodeProcessorNotKnown,
                ));
            }
            if compiled.file_assembly {
                limitations.push(rules::limitation(
                    LimitationCode::AssemblyOutsideFunctionsNotRead,
                ));
            }
            if compiled.partial {
                limitations.push(rules::limitation(LimitationCode::CompiledOutputPartlyRead));
            }
        }
    }
    inputs.extend(checked.inputs);
    limitations.extend(checked.limitations.into_iter().map(rules::limitation));
    if let Some(seen) = seen {
        inputs.extend(seen.inputs);
        limitations.extend(seen.limitations.into_iter().map(rules::limitation));
    }
    if let Some(compiled) = &build_list {
        inputs.push(Input::CompileDatabase {
            path: compiled.rel.clone(),
            files: u32::try_from(compiled.files.len()).unwrap_or(u32::MAX),
        });
    }
    if let Some((imported, dropped)) = imported {
        limitations.push(rules::limitation(LimitationCode::ExternalNotVerified));
        if imported.dropped || dropped {
            limitations.push(rules::limitation(LimitationCode::ExternalResultsDropped));
        }
        inputs.extend(imported.inputs);
    }

    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("project")
        .to_owned();
    let mut report = graph.finish(TargetInfo {
        name,
        files_scanned: scanned,
        files_skipped: skipped,
        files_excluded: walked.excluded,
        truncated: walked.truncated,
        config_file: config.as_ref().map(|_| CONFIG_FILE.to_owned()),
        ecosystems,
        inputs,
        limitations,
        machine_code: compiled.and_then(|compiled| compiled.machine),
    });
    if let Some(compiled) = build_list.filter(|compiled| !compiled.files.is_empty()) {
        for finding in &mut report.findings {
            let native = matches!(
                finding.rule,
                RuleId::SecretInNativeCode | RuleId::FirmwareOtaUnguarded
            );
            let built = finding.location.as_ref().is_none_or(|location| {
                !classify::is_native_source(&location.path)
                    || compiled.files.contains(&location.path)
            });
            if native && !built {
                finding.confidence = Confidence::Review;
            }
        }
    }
    if let Some(config) = &config {
        for finding in &mut report.findings {
            finding.accepted = config.acceptance(finding);
        }
        report.summary = seethru_core::Summary::from_findings(&report.findings);
    }
    Ok(report)
}

pub(crate) struct Lines<'a> {
    text: &'a str,
    starts: Vec<usize>,
}

impl<'a> Lines<'a> {
    pub(crate) fn new(text: &'a str) -> Self {
        let starts = std::iter::once(0)
            .chain(text.match_indices('\n').map(|(index, _)| index + 1))
            .collect();
        Self { text, starts }
    }

    pub(crate) fn position(&self, offset: usize) -> (u32, u32) {
        let offset = offset.min(self.text.len());
        let line = self.starts.partition_point(|start| *start <= offset);
        let line_start = line
            .checked_sub(1)
            .and_then(|index| self.starts.get(index))
            .copied()
            .unwrap_or(0);
        let column = self
            .text
            .get(line_start..offset)
            .map_or(0, |span| span.chars().count())
            .saturating_add(1);
        (
            u32::try_from(line.max(1)).unwrap_or(u32::MAX),
            u32::try_from(column).unwrap_or(u32::MAX),
        )
    }

    pub(crate) fn utf16_column(&self, offset: usize) -> u32 {
        let offset = offset.min(self.text.len());
        let line = self.starts.partition_point(|start| *start <= offset);
        let line_start = line
            .checked_sub(1)
            .and_then(|index| self.starts.get(index))
            .copied()
            .unwrap_or(0);
        let units = self
            .text
            .get(line_start..offset)
            .map_or(0, |span| span.encode_utf16().count());
        u32::try_from(units).unwrap_or(u32::MAX)
    }

    pub(crate) fn location(&self, rel_path: &str, offset: usize) -> Location {
        let (line, column) = self.position(offset);
        Location {
            path: rel_path.to_owned(),
            line,
            column,
        }
    }
}

fn overlay(
    build: &BuildOutput,
    scripts: &BTreeMap<String, Class>,
    roles: &mut BTreeMap<String, Assigned>,
) {
    if build.stale {
        return;
    }
    let prefix = format!("{}/", build.root);
    for (rel_path, class) in scripts {
        if !build.root.is_empty() && !rel_path.starts_with(&prefix) {
            continue;
        }
        let current = roles
            .get(rel_path)
            .cloned()
            .unwrap_or_else(|| Assigned::by_path(class.role));
        if roles::is_fixed(current.role) {
            continue;
        }
        let confirmed = if let Some(chunk) = build.browser.get(rel_path) {
            Assigned::by_build(FileRole::BrowserCode, Some(chunk.clone()))
        } else if let Some(chunk) = build.server.get(rel_path)
            && current.role != FileRole::BrowserCode
        {
            Assigned::by_build(FileRole::ServerCode, Some(chunk.clone()))
        } else if build.complete && current.role == FileRole::BrowserCode && !class.served_as_is {
            Assigned::by_build(FileRole::UnknownCode, None)
        } else {
            continue;
        };
        roles.insert(rel_path.clone(), confirmed);
    }
}

struct Built {
    location: Location,
    assigned: Assigned,
}

fn file_steps(rel_path: &str, assigned: &Assigned) -> Vec<EvidenceStep> {
    if let Some(chunk) = &assigned.built_into {
        return vec![
            file_step(chunk, None, file_location(chunk)),
            file_step(rel_path, Some(EdgeKind::BuiltFrom), file_location(rel_path)),
        ];
    }
    let mut steps = Vec::with_capacity(assigned.via.len() + 1);
    let mut via = None;
    let mut from: Option<&Location> = None;
    for hop in &assigned.via {
        let at = from
            .cloned()
            .unwrap_or_else(|| file_location(&hop.rel_path));
        steps.push(file_step(&hop.rel_path, via, at));
        via = Some(EdgeKind::Imports);
        from = Some(&hop.location);
    }
    let at = from.cloned().unwrap_or_else(|| file_location(rel_path));
    steps.push(file_step(rel_path, via, at));
    steps
}

fn is_resolver_config(rel_path: &str, class: Class) -> bool {
    let name = classify::file_name(rel_path);
    class.role == FileRole::Other
        && name.ends_with(".json")
        && (name == "package.json" || name.starts_with("tsconfig") || name.starts_with("jsconfig"))
}

struct SecretHit {
    kind: seethru_core::SecretKind,
    masked: seethru_core::MaskedSecret,
    location: Location,
    utf16_column: u32,
    public_var: Option<String>,
}

struct SecretRecord {
    rel_path: String,
    class: Class,
    real_env_file: bool,
    hits: Vec<SecretHit>,
}

impl SecretRecord {
    fn new(rel_path: &str, class: Class, text: &str) -> Option<Self> {
        let found = secrets::find(text);
        if found.is_empty() {
            return None;
        }
        let real_env_file =
            class.content == Content::Env && !env::is_template_file(classify::file_name(rel_path));
        let lines = Lines::new(text);
        let mut hits = Vec::new();
        let native = matches!(class.content, Content::Native | Content::Kconfig);
        for hit in found {
            if native
                && hit.kind == seethru_core::SecretKind::PrivateKey
                && !secrets::has_key_body(text, hit.offset)
            {
                continue;
            }
            let public_var = if real_env_file {
                match env::var_at(text, hit.offset) {
                    Some(var) if env::is_public(var) => Some(var.to_owned()),
                    _ => continue,
                }
            } else {
                None
            };
            hits.push(SecretHit {
                kind: hit.kind,
                masked: hit.masked,
                location: lines.location(rel_path, hit.offset),
                utf16_column: lines.utf16_column(hit.offset),
                public_var,
            });
        }
        Some(Self {
            rel_path: rel_path.to_owned(),
            class,
            real_env_file,
            hits,
        })
    }

    fn emit(self, graph: &mut Graph, assigned: &Assigned, origins: Vec<Option<Built>>) {
        let rel_path = self.rel_path.as_str();
        let role = assigned.role;
        let build_confirmed = assigned.basis == Basis::BuildOutput;
        let delivered_as_is =
            role == FileRole::BuildOutput || self.class.served_as_is || build_confirmed;
        let mut ordinals: BTreeMap<seethru_core::SecretKind, u32> = BTreeMap::new();
        let mut origins = origins.into_iter();
        for hit in self.hits {
            let origin = origins.next().flatten();
            let from_build = build_confirmed || origin.is_some();
            let ordinal = ordinals.entry(hit.kind).or_insert(0);
            *ordinal = ordinal.saturating_add(1);
            let secret_id = format!("secret:{rel_path}:{}:{ordinal}", hit.kind.as_str());
            let (verdict, explanation) = match (&hit.public_var, self.real_env_file) {
                (Some(var), true) => (
                    Verdict {
                        rule: RuleId::SecretInPublicEnvVar,
                        severity: Severity::Critical,
                        confidence: Confidence::Certain,
                        from_build: false,
                    },
                    rules::secret_in_public_env(hit.kind, var),
                ),
                _ if role.runs_in_browser() => (
                    Verdict {
                        rule: RuleId::SecretInBrowserCode,
                        severity: Severity::Critical,
                        confidence: if delivered_as_is {
                            Confidence::Certain
                        } else {
                            Confidence::Likely
                        },
                        from_build,
                    },
                    rules::secret_in_browser(hit.kind, rel_path),
                ),
                _ if matches!(
                    role,
                    FileRole::NativeCode | FileRole::FirmwareCode | FileRole::BuildConfig
                ) =>
                {
                    (
                        Verdict {
                            rule: RuleId::SecretInNativeCode,
                            severity: Severity::High,
                            confidence: Confidence::Certain,
                            from_build: false,
                        },
                        rules::secret_in_native(hit.kind, rel_path, role != FileRole::NativeCode),
                    )
                }
                _ => (
                    Verdict {
                        rule: RuleId::SecretInSourceCode,
                        severity: Severity::High,
                        confidence: Confidence::Certain,
                        from_build,
                    },
                    rules::secret_in_source(hit.kind, rel_path),
                ),
            };
            let file_id = graph.add_file(rel_path, role, assigned.basis);
            let mut evidence = match &origin {
                Some(built) => {
                    let source = &built.location.path;
                    let source_id =
                        graph.add_file(source, built.assigned.role, built.assigned.basis);
                    graph.add_edge(file_id.clone(), source_id, EdgeKind::BuiltFrom);
                    vec![
                        file_step(rel_path, None, hit.location.clone()),
                        file_step(source, Some(EdgeKind::BuiltFrom), built.location.clone()),
                    ]
                }
                None => file_steps(rel_path, assigned),
            };
            let zone = match &hit.public_var {
                Some(var) if env::is_public(var) => Zone::Client,
                Some(_) => Zone::Server,
                None => role.runtime().zone(),
            };
            let secret_id = graph.add_node(Node {
                id: NodeId::new(secret_id),
                label: hit.masked.as_str().to_owned(),
                kind: NodeKind::Credential {
                    detail: CredentialDetail::Secret {
                        secret_kind: hit.kind,
                        masked: hit.masked.clone(),
                    },
                },
                zone,
                location: Some(hit.location.clone()),
            });
            match hit.public_var {
                Some(var) => {
                    let env_id = graph.add_env_var(&var);
                    evidence.push(step(
                        &var,
                        Some(EdgeKind::Defines),
                        Some(env_id.clone()),
                        Some(hit.location.clone()),
                    ));
                    graph.add_edge(file_id, env_id.clone(), EdgeKind::Defines);
                    graph.add_edge(env_id, secret_id.clone(), EdgeKind::Contains);
                }
                None => graph.add_edge(file_id, secret_id.clone(), EdgeKind::Contains),
            }
            evidence.push(step(
                hit.masked.as_str(),
                Some(EdgeKind::Contains),
                Some(secret_id.clone()),
                Some(hit.location.clone()),
            ));
            graph.add_finding(
                verdict,
                explanation,
                secret_id,
                Some(hit.location),
                evidence,
            );
        }
    }
}

struct ScriptRecord {
    rel_path: String,
    env_reads: Vec<(String, Location)>,
    queries: Vec<(String, script::Access, Location)>,
}

impl ScriptRecord {
    fn new(rel_path: &str, lines: &Lines<'_>, facts: script::Facts) -> Self {
        let at = |offset: usize| lines.location(rel_path, offset);
        Self {
            rel_path: rel_path.to_owned(),
            env_reads: facts
                .env_reads
                .into_iter()
                .map(|read| {
                    let location = at(read.offset);
                    (read.name, location)
                })
                .collect(),
            queries: facts
                .queries
                .into_iter()
                .map(|query| {
                    let location = at(query.offset);
                    (query.table, query.access, location)
                })
                .collect(),
        }
    }

    fn emit(self, graph: &mut Graph, assigned: &Assigned) {
        if self.env_reads.is_empty() && self.queries.is_empty() {
            return;
        }
        let role = assigned.role;
        let file_id = graph.add_file(&self.rel_path, role, assigned.basis);
        for (table, access, _) in &self.queries {
            let table_id = graph.add_table("public", table);
            let kind = match access {
                script::Access::Read => EdgeKind::Reads,
                script::Access::Write => EdgeKind::Writes,
            };
            graph.add_edge(file_id.clone(), table_id, kind);
        }
        for (name, location) in self.env_reads {
            let env_id = graph.add_env_var(&name);
            graph.add_edge(file_id.clone(), env_id.clone(), EdgeKind::UsesConfig);
            let exposed_prefix = env::public_prefix(&name);
            if let (true, true, Some(prefix)) = (
                role.runs_in_browser(),
                script::is_service_role_env(&name),
                exposed_prefix,
            ) {
                let mut evidence = file_steps(&self.rel_path, assigned);
                evidence.push(step(
                    &name,
                    Some(EdgeKind::UsesConfig),
                    Some(env_id.clone()),
                    Some(location.clone()),
                ));
                graph.add_finding(
                    Verdict {
                        rule: RuleId::SupabaseServiceRoleInBrowser,
                        severity: Severity::Critical,
                        confidence: if assigned.basis == Basis::BuildOutput {
                            Confidence::Certain
                        } else {
                            Confidence::Likely
                        },
                        from_build: assigned.basis == Basis::BuildOutput,
                    },
                    rules::service_role_in_browser(&name, prefix),
                    env_id,
                    Some(location),
                    evidence,
                );
            }
        }
    }
}
