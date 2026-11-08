use seethru_core::{NodeKind, PolicyCommand, RlsStatus, RuleId, Severity, TargetInfo};

use super::Migrations;
use crate::graph::Graph;

fn run(files: &[(&str, &str)]) -> seethru_core::ScanReport {
    let mut migrations = Migrations::default();
    for (path, source) in files {
        migrations.apply_file(path, source);
    }
    let mut graph = Graph::default();
    migrations.emit(&mut graph);
    graph.finish(TargetInfo {
        name: "test".to_owned(),
        files_scanned: 0,
        files_skipped: 0,
        truncated: false,
    })
}

fn rls_of(report: &seethru_core::ScanReport, id: &str) -> Option<RlsStatus> {
    report
        .nodes
        .iter()
        .find(|node| node.id.as_str() == id)
        .and_then(|node| match node.kind {
            NodeKind::Table { rls, .. } => Some(rls),
            _ => None,
        })
}

fn findings(report: &seethru_core::ScanReport) -> Vec<(RuleId, Severity, &str)> {
    report
        .findings
        .iter()
        .map(|finding| (finding.rule, finding.severity, finding.node.as_str()))
        .collect()
}

#[test]
fn table_without_rls_is_critical() {
    let report = run(&[(
        "supabase/migrations/1_init.sql",
        "create table public.todos (id bigint primary key, title text);",
    )]);
    assert_eq!(
        rls_of(&report, "table:public.todos"),
        Some(RlsStatus::Disabled)
    );
    assert_eq!(
        findings(&report),
        vec![(
            RuleId::SupabaseRlsDisabled,
            Severity::Critical,
            "table:public.todos"
        )]
    );
    let finding = &report.findings[0];
    assert_eq!(finding.location.as_ref().map(|l| l.line), Some(1));
}

#[test]
fn enabling_rls_in_a_later_file_clears_the_finding() {
    let report = run(&[
        (
            "supabase/migrations/1_init.sql",
            "CREATE TABLE IF NOT EXISTS todos (id int);",
        ),
        (
            "supabase/migrations/2_rls.sql",
            "ALTER TABLE ONLY public.todos ENABLE ROW LEVEL SECURITY;",
        ),
    ]);
    assert_eq!(
        rls_of(&report, "table:public.todos"),
        Some(RlsStatus::Enabled)
    );
    assert!(report.findings.is_empty());
}

#[test]
fn disabling_rls_again_is_reported_at_the_disable_statement() {
    let report = run(&[(
        "schema.sql",
        "create table todos (id int);\nalter table todos enable row level security;\n\nalter table todos disable row level security;",
    )]);
    assert_eq!(
        rls_of(&report, "table:public.todos"),
        Some(RlsStatus::Disabled)
    );
    assert_eq!(
        report.findings[0].location.as_ref().map(|l| l.line),
        Some(4)
    );
}

#[test]
fn managed_and_private_schemas_are_not_reported() {
    let report = run(&[(
        "schema.sql",
        "create table auth.extra (id int); create table private.audit (id int);",
    )]);
    assert!(
        report
            .nodes
            .iter()
            .all(|node| node.id.as_str() != "table:auth.extra")
    );
    assert_eq!(
        rls_of(&report, "table:private.audit"),
        Some(RlsStatus::Disabled)
    );
    assert!(report.findings.is_empty());
}

#[test]
fn quoted_names_keep_case_and_unquoted_names_fold() {
    let report = run(&[(
        "a.sql",
        r#"create table "Profiles" (id int); create table Notes (id int);"#,
    )]);
    assert!(rls_of(&report, "table:public.Profiles").is_some());
    assert!(rls_of(&report, "table:public.notes").is_some());
}

#[test]
fn policy_using_true_for_anon_writes_is_critical() {
    let report = run(&[(
        "a.sql",
        r#"create table todos (id int);
alter table todos enable row level security;
create policy "Allow all" on public.todos for all to anon, authenticated using (true) with check (true);"#,
    )]);
    assert_eq!(
        findings(&report),
        vec![(
            RuleId::SupabasePolicyUnrestricted,
            Severity::Critical,
            "policy:public.todos/Allow all"
        )]
    );
    let policy = report
        .nodes
        .iter()
        .find(|node| node.id.as_str() == "policy:public.todos/Allow all");
    assert!(matches!(
        policy.map(|node| &node.kind),
        Some(NodeKind::Policy {
            command: PolicyCommand::All,
            unrestricted: true,
            ..
        })
    ));
    assert!(
        report
            .edges
            .iter()
            .any(|edge| edge.from.as_str() == "table:public.todos"
                && edge.to.as_str() == "policy:public.todos/Allow all")
    );
}

#[test]
fn policy_severity_depends_on_role_and_command() {
    let report = run(&[(
        "a.sql",
        r#"create table posts (id int);
alter table posts enable row level security;
create policy "read" on posts for select using ( ( true ) );
create policy "edit" on posts for update to authenticated using (true);
create policy "add" on posts for insert to authenticated with check (true);"#,
    )]);
    let mut got = findings(&report);
    got.sort();
    let mut want = vec![
        (
            RuleId::SupabasePolicyUnrestricted,
            Severity::Medium,
            "policy:public.posts/read",
        ),
        (
            RuleId::SupabasePolicyUnrestricted,
            Severity::High,
            "policy:public.posts/edit",
        ),
        (
            RuleId::SupabasePolicyUnrestricted,
            Severity::Medium,
            "policy:public.posts/add",
        ),
    ];
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn owner_checks_and_restrictive_policies_are_not_reported() {
    let report = run(&[(
        "a.sql",
        r#"create table todos (id int, user_id uuid);
alter table todos enable row level security;
create policy "own rows" on todos for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "gate" on todos as restrictive for select to anon using (true);
create policy "service" on todos for all to service_role using (true);"#,
    )]);
    assert!(report.findings.is_empty());
}

#[test]
fn dropped_policies_and_tables_disappear() {
    let report = run(&[(
        "a.sql",
        r#"create table todos (id int);
alter table todos enable row level security;
create policy "open" on todos using (true);
drop policy if exists "open" on todos;
create table scratch (id int);
drop table if exists scratch, other cascade;"#,
    )]);
    assert!(report.findings.is_empty());
    assert!(rls_of(&report, "table:public.scratch").is_none());
}

#[test]
fn renamed_tables_keep_their_state() {
    let report = run(&[(
        "a.sql",
        "create table todo (id int); alter table todo rename to todos;",
    )]);
    assert!(rls_of(&report, "table:public.todo").is_none());
    assert_eq!(
        rls_of(&report, "table:public.todos"),
        Some(RlsStatus::Disabled)
    );
}

#[test]
fn policies_on_unseen_tables_do_not_claim_rls_is_off() {
    let report = run(&[(
        "a.sql",
        r#"create policy "own" on todos using (auth.uid() = user_id);"#,
    )]);
    assert_eq!(
        rls_of(&report, "table:public.todos"),
        Some(RlsStatus::Unknown)
    );
    assert!(report.findings.is_empty());
}

#[test]
fn function_bodies_do_not_toggle_rls() {
    let report = run(&[(
        "a.sql",
        "create table todos (id int); alter table todos enable row level security;\ncreate function f() returns void language plpgsql as $$ begin alter table todos disable row level security; end $$;",
    )]);
    assert_eq!(
        rls_of(&report, "table:public.todos"),
        Some(RlsStatus::Enabled)
    );
}

#[test]
fn migration_file_defines_its_tables() {
    let report = run(&[(
        "supabase/migrations/1_init.sql",
        "create table todos (id int);",
    )]);
    assert!(report.edges.iter().any(|edge| edge.from.as_str()
        == "file:supabase/migrations/1_init.sql"
        && edge.to.as_str() == "table:public.todos"));
}
