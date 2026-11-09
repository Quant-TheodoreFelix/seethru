mod common;

use common::TempProject;
use seethru_core::{RuleId, Severity};

const CLIENT: &str = "import { createClient } from \"@supabase/supabase-js\";\n\
export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_ANON_KEY);\n";

const PAGE: &str = "import { supabase } from \"../lib/supabase\";\n\
export async function load() {\n\
  await supabase.from(\"orders\").select(\"*\");\n\
  await supabase.from(\"todos\").select(\"*\");\n\
  await supabase.from(\"profiles\").update({ name: \"a\" });\n\
  await supabase.from(\"order_totals\").select(\"*\");\n\
}\n";

const MIGRATION: &str = "\
create table public.todos (id bigint primary key, user_id uuid);
alter table public.todos enable row level security;
alter table public.profiles enable row level security;
create or replace view public.order_totals as select 1 as total;
";

#[test]
fn tables_used_in_code_without_a_schema_get_an_info_finding() {
    let project = TempProject::new("tables");
    project.write("vite.config.ts", "export default {};\n");
    project.write("src/lib/supabase.ts", CLIENT);
    project.write("src/pages/Orders.tsx", PAGE);
    project.write("supabase/migrations/0001_init.sql", MIGRATION);

    let result = seethru_analyzer::scan(&project.root);
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    let missing: Vec<(&str, Severity, u32)> = report
        .findings
        .iter()
        .filter(|finding| finding.rule == RuleId::SupabaseTableSchemaMissing)
        .map(|finding| {
            (
                finding.node.as_str(),
                finding.severity,
                finding
                    .location
                    .as_ref()
                    .map_or(0, |location| location.line),
            )
        })
        .collect();
    assert_eq!(missing, vec![("table:public.orders", Severity::Info, 3)]);
    assert_eq!(report.summary.info, 1);
}

#[test]
fn projects_without_supabase_do_not_get_schema_findings() {
    let project = TempProject::new("knex");
    project.write("vite.config.ts", "export default {};\n");
    project.write(
        "src/db.ts",
        "import knex from \"knex\";\nconst db = knex({});\nexport const users = () => db.from(\"users\").select(\"*\");\n",
    );
    let result = seethru_analyzer::scan(&project.root);
    assert!(result.is_ok(), "{result:?}");
    let Ok(report) = result else { return };
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.rule != RuleId::SupabaseTableSchemaMissing)
    );
}
