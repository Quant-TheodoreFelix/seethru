mod protocol;
mod tools;

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use seethru_analyzer::ScanOptions;
use seethru_core::{Lang, ScanReport};

pub use protocol::{LATEST_PROTOCOL_VERSION, MAX_LINE_BYTES, SUPPORTED_PROTOCOL_VERSIONS};
pub use tools::MAX_FINDINGS;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Permissions {
    pub build: bool,
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRequest {
    pub root: PathBuf,
    pub build: bool,
    pub tools: Vec<String>,
    pub lang: Lang,
}

pub trait Host {
    fn roots(&self) -> &[PathBuf];
    fn permissions(&self) -> &Permissions;
    fn scan(&self, request: &ScanRequest) -> Result<ScanReport, String>;
}

pub fn plain_scan(root: &Path) -> Result<ScanReport, String> {
    let mut report = seethru_analyzer::scan_with(root, ScanOptions::default())
        .map_err(|error| error.to_string())?;
    seethru_fix::attach_fix_prompts(&mut report);
    Ok(report)
}

#[derive(Debug, Clone, Default)]
pub struct PlainHost {
    roots: Vec<PathBuf>,
    permissions: Permissions,
}

impl PlainHost {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            permissions: Permissions::default(),
        }
    }
}

impl Host for PlainHost {
    fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    fn scan(&self, request: &ScanRequest) -> Result<ScanReport, String> {
        if request.build || !request.tools.is_empty() {
            return Err("this server only reads files".to_owned());
        }
        plain_scan(&request.root)
    }
}

pub fn serve(input: impl BufRead, output: impl Write, host: &dyn Host) -> io::Result<()> {
    protocol::run(input, output, host)
}
