use seethru_core::{
    AccessRuleDetail, BucketVisibility, Channel, Confidence, DataStoreDetail, EdgeKind, Exposure,
    NodeKind, PolicyCommand, RlsStatus, RuleId, RuleScope, Severity, TargetInfo,
};

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
        files_excluded: 0,
        truncated: false,
        config_file: None,
        ecosystems: Vec::new(),
        inputs: Vec::new(),
        limitations: Vec::new(),
        machine_code: None,
    })
}

fn rls_of(report: &seethru_core::ScanReport, id: &str) -> Option<RlsStatus> {
    report
        .nodes
        .iter()
        .find(|node| node.id.as_str() == id)
        .and_then(|node| match &node.kind {
            NodeKind::DataStore {
                detail: Some(DataStoreDetail::PostgresTable { rls, .. }),
            } => Some(*rls),
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
        Some(NodeKind::AccessRule {
            scope: RuleScope::Open,
            detail: Some(AccessRuleDetail::PostgresPolicy {
                command: PolicyCommand::All,
                ..
            }),
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

fn finding<'a>(
    report: &'a seethru_core::ScanReport,
    rule: RuleId,
    node: &str,
) -> Option<&'a seethru_core::Finding> {
    report
        .findings
        .iter()
        .find(|finding| finding.rule == rule && finding.node.as_str() == node)
}

fn node_kind<'a>(report: &'a seethru_core::ScanReport, id: &str) -> Option<&'a NodeKind> {
    report
        .nodes
        .iter()
        .find(|node| node.id.as_str() == id)
        .map(|node| &node.kind)
}

fn has_edge(report: &seethru_core::ScanReport, from: &str, to: &str, kind: EdgeKind) -> bool {
    report
        .edges
        .iter()
        .any(|edge| edge.from.as_str() == from && edge.to.as_str() == to && edge.kind == kind)
}

const STORAGE: &str = "supabase/migrations/2_storage.sql";

#[test]
fn storage_policy_that_only_names_the_bucket_is_reported() {
    let report = run(&[(
        STORAGE,
        "insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
         create policy \"Read avatars\" on storage.objects for select using (bucket_id = 'avatars');
         create policy \"Upload docs\" on storage.objects for insert with check (bucket_id = 'docs');
         create policy \"Signed in edit\" on storage.objects for update
           using (bucket_id = 'docs' and auth.uid() is not null);
         create policy \"Own docs\" on storage.objects for delete
           using (bucket_id = 'docs' and (storage.foldername(name))[1] = auth.uid()::text);",
    )]);
    let rule = RuleId::SupabaseStoragePolicyUnrestricted;
    let read = finding(&report, rule, "policy:storage.objects/Read avatars");
    assert_eq!(read.map(|f| f.severity), Some(Severity::Medium));
    assert_eq!(read.map(|f| f.confidence), Some(Confidence::Certain));
    assert_eq!(
        finding(&report, rule, "policy:storage.objects/Upload docs").map(|f| f.severity),
        Some(Severity::High)
    );
    assert_eq!(
        finding(&report, rule, "policy:storage.objects/Signed in edit").map(|f| f.severity),
        Some(Severity::High)
    );
    assert!(finding(&report, rule, "policy:storage.objects/Own docs").is_none());
    assert_eq!(
        node_kind(&report, "store:storageBucket:avatars"),
        Some(&NodeKind::DataStore {
            detail: Some(DataStoreDetail::StorageBucket {
                visibility: BucketVisibility::Public
            })
        })
    );
    assert_eq!(
        node_kind(&report, "store:storageBucket:docs"),
        Some(&NodeKind::DataStore {
            detail: Some(DataStoreDetail::StorageBucket {
                visibility: BucketVisibility::Unknown
            })
        })
    );
    assert!(has_edge(
        &report,
        "file:supabase/migrations/2_storage.sql",
        "store:storageBucket:avatars",
        EdgeKind::Defines
    ));
    assert!(has_edge(
        &report,
        "store:storageBucket:docs",
        "policy:storage.objects/Own docs",
        EdgeKind::GuardedBy
    ));
    let steps: Vec<Option<&str>> = read
        .map(|f| {
            f.evidence
                .iter()
                .map(|s| s.node.as_ref().map(|n| n.as_str()))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        steps,
        vec![
            Some("store:storageBucket:avatars"),
            Some("policy:storage.objects/Read avatars")
        ]
    );
}

#[test]
fn storage_policies_for_service_role_or_restrictive_are_not_reported() {
    let report = run(&[(
        STORAGE,
        "create policy \"Service\" on storage.objects for all to service_role using (true);
         create policy \"Gate\" on storage.objects as restrictive for select using (bucket_id = 'a');
         create policy \"Anon signed in\" on storage.objects for select to anon
           using (bucket_id = 'a' and auth.uid() is not null);",
    )]);
    assert!(
        report
            .findings
            .iter()
            .all(|f| f.rule != RuleId::SupabaseStoragePolicyUnrestricted),
        "{:?}",
        findings(&report)
    );
}

const API: &str = "supabase/migrations/3_api.sql";
const TABLES: &str = "create table public.orders (id bigint, user_id uuid);
     alter table public.orders enable row level security;";

#[test]
fn views_that_skip_rls_are_reported_by_who_can_read_them() {
    let report = run(&[(
        API,
        &format!(
            "{TABLES}
             create view public.order_totals as select o.user_id, count(*) from public.orders o group by 1;
             create view public.my_orders with (security_invoker = true) as select * from public.orders;
             create materialized view public.order_cache as select * from orders;
             create view public.members as select id, email from auth.users;
             create view public.staff_orders as select * from public.orders;
             revoke select on public.staff_orders from anon;
             create view public.hidden_orders as select * from public.orders;
             revoke all on public.hidden_orders from anon, authenticated;
             create view public.mine as select * from public.orders where user_id = auth.uid();"
        ),
    )]);
    let rule = RuleId::SupabaseViewBypassesRls;
    let severity = |id: &str| finding(&report, rule, id).map(|f| (f.severity, f.confidence));
    assert_eq!(
        severity("table:public.order_totals"),
        Some((Severity::High, Confidence::Certain))
    );
    assert_eq!(severity("table:public.my_orders"), None);
    assert_eq!(
        severity("table:public.order_cache"),
        Some((Severity::High, Confidence::Certain))
    );
    assert_eq!(
        severity("table:public.members"),
        Some((Severity::Critical, Confidence::Certain))
    );
    assert_eq!(
        severity("table:public.staff_orders"),
        Some((Severity::Medium, Confidence::Certain))
    );
    assert_eq!(severity("table:public.hidden_orders"), None);
    assert_eq!(
        severity("table:public.mine"),
        Some((Severity::Low, Confidence::Review))
    );
    assert_eq!(
        node_kind(&report, "table:public.order_cache"),
        Some(&NodeKind::DataStore {
            detail: Some(DataStoreDetail::PostgresView {
                schema: "public".to_owned(),
                security_invoker: false,
                materialized: true,
            })
        })
    );
    assert!(has_edge(
        &report,
        "file:supabase/migrations/3_api.sql",
        "table:public.order_totals",
        EdgeKind::Defines
    ));
    let steps: Vec<Option<&str>> = finding(&report, rule, "table:public.order_totals")
        .map(|f| {
            f.evidence
                .iter()
                .map(|s| s.node.as_ref().map(|n| n.as_str()))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        steps,
        vec![
            Some("file:supabase/migrations/3_api.sql"),
            Some("table:public.order_totals"),
            Some("table:public.orders")
        ]
    );
}

#[test]
fn security_definer_functions_are_reported_by_who_can_call_them() {
    let report = run(&[(
        API,
        &format!(
            "{TABLES}
             create function public.all_orders() returns setof public.orders
               language sql security definer as $$ select * from public.orders $$;
             create function public.staff_orders() returns setof public.orders
               language sql security definer as $$ select * from public.orders $$;
             revoke execute on function public.staff_orders from public, anon;
             create function public.internal_orders() returns setof public.orders
               language sql security definer as $$ select * from public.orders $$;
             revoke execute on function public.internal_orders() from public, anon, authenticated;
             create function public.anon_revoked() returns int
               language sql security definer as $$ select 1 $$;
             revoke execute on function public.anon_revoked from anon;
             create function public.is_owner(order_id bigint) returns boolean
               language sql security definer as $$
                 select exists (select 1 from public.orders where id = order_id and user_id = auth.uid())
               $$;
             create function public.owner_orders(order_id bigint) returns void
               language plpgsql security definer as $$
               begin
                 if not public.is_owner(order_id) then raise exception 'no'; end if;
                 delete from public.orders where id = order_id;
               end $$;
             create function public.order_exists(order_id bigint) returns boolean
               language sql security definer as $$
                 select exists (select 1 from public.orders where id = order_id)
               $$;
             create function public.order_flags() returns boolean[]
               language sql security definer as $$ select array[true] $$;
             create function public.handle_new_user() returns trigger
               language plpgsql security definer as $$ begin return new; end $$;
             create function public.count_orders() returns bigint
               language sql as $$ select count(*) from public.orders $$;"
        ),
    )]);
    let rule = RuleId::SupabaseFunctionBypassesRls;
    let verdict = |id: &str| finding(&report, rule, id).map(|f| (f.severity, f.confidence));
    assert_eq!(
        verdict("entry:rpc:public.all_orders"),
        Some((Severity::High, Confidence::Likely))
    );
    assert_eq!(
        verdict("entry:rpc:public.staff_orders"),
        Some((Severity::Medium, Confidence::Likely))
    );
    assert_eq!(verdict("entry:rpc:public.internal_orders"), None);
    assert_eq!(
        verdict("entry:rpc:public.anon_revoked"),
        Some((Severity::High, Confidence::Likely))
    );
    assert_eq!(
        verdict("entry:rpc:public.is_owner"),
        Some((Severity::Low, Confidence::Review))
    );
    assert_eq!(
        verdict("entry:rpc:public.owner_orders"),
        Some((Severity::Low, Confidence::Review))
    );
    assert_eq!(
        verdict("entry:rpc:public.order_exists"),
        Some((Severity::Low, Confidence::Review))
    );
    assert_eq!(
        verdict("entry:rpc:public.order_flags"),
        Some((Severity::High, Confidence::Likely))
    );
    assert!(node_kind(&report, "entry:rpc:public.handle_new_user").is_none());
    assert_eq!(verdict("entry:rpc:public.count_orders"), None);
    assert_eq!(
        node_kind(&report, "entry:rpc:public.internal_orders"),
        Some(&NodeKind::EntryPoint {
            channel: Channel::Rpc,
            exposure: Exposure::Internal
        })
    );
    assert!(has_edge(
        &report,
        "entry:rpc:public.internal_orders",
        "principal:supabase:postgres",
        EdgeKind::ActsAs
    ));
    assert!(!has_edge(
        &report,
        "entry:rpc:public.count_orders",
        "principal:supabase:postgres",
        EdgeKind::ActsAs
    ));
    assert!(has_edge(
        &report,
        "entry:rpc:public.count_orders",
        "file:supabase/migrations/3_api.sql",
        EdgeKind::Invokes
    ));
}

#[test]
fn functions_owned_by_other_roles_or_in_private_schemas_are_not_reported() {
    let report = run(&[(
        API,
        "create function public.limited() returns int language sql security definer as $$ select 1 $$;
         alter function public.limited() owner to app_reader;
         create schema private;
         create function private.helper() returns int language sql security definer as $$ select 1 $$;
         create function public.later() returns int language sql as $$ select 1 $$;
         alter function public.later() security definer;",
    )]);
    let rule = RuleId::SupabaseFunctionBypassesRls;
    assert!(finding(&report, rule, "entry:rpc:public.limited").is_none());
    assert!(node_kind(&report, "entry:rpc:private.helper").is_none());
    assert_eq!(
        finding(&report, rule, "entry:rpc:public.later").map(|f| f.severity),
        Some(Severity::High)
    );
}

#[test]
fn table_policy_that_only_checks_sign_in_is_open_to_any_signed_in_user() {
    let report = run(&[(
        "supabase/migrations/4_docs.sql",
        "create table public.docs (id bigint, owner uuid);
         alter table public.docs enable row level security;
         create policy \"Signed in read\" on public.docs for select using (auth.uid() is not null);
         create policy \"Role check\" on public.docs for delete
           using ((select auth.role()) = 'authenticated');
         create policy \"Anon only\" on public.docs for update to anon using (auth.uid() is not null);
         create policy \"Owner\" on public.docs for update using (auth.uid() = owner);",
    )]);
    let rule = RuleId::SupabasePolicyUnrestricted;
    let read = finding(&report, rule, "policy:public.docs/Signed in read");
    assert_eq!(read.map(|f| f.severity), Some(Severity::Low));
    assert!(
        read.is_some_and(|f| f
            .explanation
            .en
            .contains("only checks that the user is signed in")),
        "{read:?}"
    );
    assert_eq!(
        finding(&report, rule, "policy:public.docs/Role check").map(|f| f.severity),
        Some(Severity::High)
    );
    assert!(finding(&report, rule, "policy:public.docs/Anon only").is_none());
    assert!(finding(&report, rule, "policy:public.docs/Owner").is_none());
    assert!(matches!(
        node_kind(&report, "policy:public.docs/Signed in read"),
        Some(NodeKind::AccessRule {
            scope: RuleScope::Open,
            ..
        })
    ));
}
