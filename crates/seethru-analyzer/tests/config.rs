use std::fs;
use std::path::PathBuf;

use seethru_analyzer::{ScanError, ScanOptions};
use seethru_core::RuleId;

struct TempProject {
    root: PathBuf,
}

impl TempProject {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("seethru-config-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let created = fs::create_dir_all(&root);
        assert!(created.is_ok(), "{created:?}");
        Self { root }
    }

    fn write(&self, rel_path: &str, content: &str) {
        let path = self.root.join(rel_path);
        if let Some(parent) = path.parent() {
            let created = fs::create_dir_all(parent);
            assert!(created.is_ok(), "{created:?}");
        }
        let written = fs::write(path, content);
        assert!(written.is_ok(), "{written:?}");
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

const MIGRATION: &str = "\
create table public.products (id bigint primary key, name text);
alter table public.products enable row level security;
create policy \"Anyone can read products\" on public.products for select using (true);
create table public.notes (id bigint primary key, body text);
";

#[test]
fn project_config_excludes_paths_and_accepts_findings_but_keeps_them_visible() {
    let project = TempProject::new("accept");
    project.write("supabase/migrations/0001_init.sql", MIGRATION);
    project.write(
        "legacy/old.sql",
        "create table public.legacy (id bigint);\n",
    );
    project.write(
        "seethru.toml",
        "exclude = [\"legacy\"]\n\n[[accept]]\nrule = \"supabase-policy-unrestricted\"\nreason = \"The product list is public\"\n",
    );

    let result = seethru_analyzer::scan(&project.root);
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert_eq!(report.target.files_excluded, 1);
    assert_eq!(report.target.config_file.as_deref(), Some("seethru.toml"));
    assert!(
        report
            .nodes
            .iter()
            .all(|node| !node.id.as_str().contains("legacy"))
    );

    let accepted: Vec<(RuleId, &str)> = report
        .findings
        .iter()
        .filter_map(|finding| Some((finding.rule, finding.accepted.as_ref()?.reason.as_str())))
        .collect();
    assert_eq!(
        accepted,
        vec![(
            RuleId::SupabasePolicyUnrestricted,
            "The product list is public"
        )]
    );
    assert_eq!(report.summary.accepted, 1);
    assert_eq!(report.summary.critical, 1);
    assert_eq!(report.summary.medium, 0);

    let ignored = seethru_analyzer::scan_with(&project.root, ScanOptions { read_config: false });
    assert!(ignored.is_ok(), "{ignored:?}");
    let Ok(ignored) = ignored else { return };
    assert_eq!(ignored.target.files_excluded, 0);
    assert_eq!(ignored.target.config_file, None);
    assert_eq!(ignored.summary.accepted, 0);
    assert!(
        ignored
            .findings
            .iter()
            .all(|finding| finding.accepted.is_none())
    );
}

#[test]
fn a_broken_config_stops_the_scan_instead_of_being_skipped() {
    let project = TempProject::new("broken");
    project.write(
        "seethru.toml",
        "[[accept]]\nrule = \"supabase-rls-disabled\"\n",
    );
    let result = seethru_analyzer::scan(&project.root);
    assert!(matches!(result, Err(ScanError::Config(_))), "{result:?}");
}
