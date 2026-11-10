use std::fs;
use std::io;
use std::path::PathBuf;

use seethru_core::ScanReport;
use seethru_mcp::{Host, Permissions, ScanRequest};

use crate::{build, state_dir, tool};

pub(crate) struct Server {
    roots: Vec<PathBuf>,
    permissions: Permissions,
    permits: Vec<tool::Permit>,
}

impl Server {
    pub(crate) fn new(
        roots: Vec<PathBuf>,
        allow_build: bool,
        permits: Vec<tool::Permit>,
    ) -> io::Result<Self> {
        let roots = if roots.is_empty() {
            vec![PathBuf::from(".")]
        } else {
            roots
        };
        let mut canonical = Vec::new();
        for root in roots {
            let root = fs::canonicalize(&root)?;
            if !root.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("--root {} is not a folder", root.display()),
                ));
            }
            if !canonical.contains(&root) {
                canonical.push(root);
            }
        }
        let permissions = Permissions {
            build: allow_build,
            tools: permits
                .iter()
                .map(|permit| permit.name.as_str().to_owned())
                .collect(),
        };
        Ok(Self {
            roots: canonical,
            permissions,
            permits,
        })
    }

    fn run(&self, request: &ScanRequest) -> Result<ScanReport, Box<dyn std::error::Error>> {
        if request.build && !self.permissions.build {
            return Err("the user did not allow builds for this server".into());
        }
        let mut permits = Vec::new();
        for name in &request.tools {
            let Some(permit) = self
                .permits
                .iter()
                .find(|permit| permit.name.as_str() == name)
            else {
                return Err(format!("the user did not allow the tool '{name}'").into());
            };
            if !permits.contains(permit) {
                permits.push(permit.clone());
            }
        }
        if !permits.is_empty() && !request.build {
            return Err("tools read the programs a build makes, so ask for a build too".into());
        }
        let mut llvm_ir = Vec::new();
        let mut built = None;
        if request.build {
            let projects = seethru_analyzer::cargo_projects(&request.root, true)?;
            let dirs = build::build(
                &request.root,
                &state_dir(&request.root)?,
                &projects,
                request.lang,
            )?;
            llvm_ir.extend(dirs.iter().cloned());
            built = Some(dirs);
        }
        let collected =
            tool::collect(&request.root, &permits, &[], built.as_deref(), request.lang)?;
        let options = seethru_analyzer::ScanOptions {
            llvm_ir,
            binaries: collected.binaries,
            binary_problems: collected.problems,
            ..seethru_analyzer::ScanOptions::default()
        };
        let mut report = seethru_analyzer::scan_with(&request.root, options)?;
        seethru_fix::attach_fix_prompts(&mut report);
        Ok(report)
    }
}

impl Host for Server {
    fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    fn scan(&self, request: &ScanRequest) -> Result<ScanReport, String> {
        self.run(request).map_err(|error| error.to_string())
    }
}
