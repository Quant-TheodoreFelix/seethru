mod common;

use common::TempProject;
use seethru_core::{EdgeKind, Exposure, NodeKind, RuleId, ScanReport, Severity, Strength};

const ADMIN: &str = "import { createClient } from \"@supabase/supabase-js\";\n\
export const admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n";

const SERVER: &str = "import { createServerClient } from \"@supabase/ssr\";\n\
export async function createClient() {\n\
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, { cookies: {} });\n\
}\n";

const AUTH: &str = "import { createClient } from \"@/lib/server\";\n\
export async function requireUser() {\n\
  const supabase = await createClient();\n\
  const { data, error } = await supabase.auth.getUser();\n\
  if (error || !data.user) throw new Error(\"Unauthorized\");\n\
  return data.user;\n\
}\n\
export async function currentUser() {\n\
  const supabase = await createClient();\n\
  const user = (await supabase.auth.getUser()).data.user;\n\
  return user;\n\
}\n";

const HEAD: &str = "import { admin } from \"@/lib/admin\";\n\
import { createClient } from \"@/lib/server\";\n\
import { requireUser, currentUser } from \"@/lib/auth\";\n";

fn route(body: &str) -> String {
    format!("{HEAD}export async function POST(req: Request) {{\n{body}\n}}\n")
}

fn base(project: &TempProject) {
    project.write("package.json", "{\"name\":\"guards\"}\n");
    project.write("next.config.mjs", "export default {};\n");
    project.write(
        "tsconfig.json",
        "{\"compilerOptions\":{\"paths\":{\"@/*\":[\"./src/*\"]}}}\n",
    );
    project.write("src/lib/admin.ts", ADMIN);
    project.write("src/lib/server.ts", SERVER);
    project.write("src/lib/auth.ts", AUTH);
}

fn scan(project: &TempProject) -> Option<ScanReport> {
    let result = seethru_analyzer::scan(&project.root);
    assert!(result.is_ok(), "{result:?}");
    result.ok()
}

fn exposure(report: &ScanReport, id: &str) -> Option<Exposure> {
    report.nodes.iter().find_map(|node| match &node.kind {
        NodeKind::EntryPoint { exposure, .. } if node.id.as_str() == id => Some(*exposure),
        _ => None,
    })
}

fn unguarded(report: &ScanReport) -> Vec<(&str, Severity)> {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule == RuleId::SupabaseServiceRoleUnguarded)
        .map(|finding| (finding.node.as_str(), finding.severity))
        .collect()
}

#[test]
fn route_guards_decide_who_can_reach_the_service_role() {
    let project = TempProject::new("trace-guards");
    base(&project);
    let routes: &[(&str, &str)] = &[
        (
            "open",
            "  await admin.from(\"orders\").delete().eq(\"id\", 1);",
        ),
        (
            "inline",
            "  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  if (!user) return new Response(\"no\", { status: 401 });\n  await admin.from(\"orders\").delete().eq(\"user_id\", user.id);",
        ),
        (
            "helper",
            "  await requireUser();\n  await admin.from(\"orders\").update({ done: true });",
        ),
        (
            "tested",
            "  const user = await currentUser();\n  if (!user) return Response.json({}, { status: 401 });\n  await admin.from(\"orders\").insert({ user_id: user.id });",
        ),
        (
            "untested",
            "  await currentUser();\n  await admin.from(\"orders\").delete().eq(\"id\", 1);",
        ),
        (
            "weak",
            "  const supabase = await createClient();\n  const { data: { session } } = await supabase.auth.getSession();\n  if (!session) return new Response(\"no\");\n  await admin.from(\"orders\").delete().eq(\"id\", 1);",
        ),
        (
            "cron",
            "  if (req.headers.get(\"authorization\") !== `Bearer ${process.env.CRON_SECRET}`) {\n    return new Response(\"no\", { status: 401 });\n  }\n  await admin.from(\"orders\").delete().lt(\"id\", 10);",
        ),
        (
            "denied",
            "  if (!isAllowed(req)) return new Response(\"no\", { status: 403 });\n  await admin.from(\"orders\").delete().eq(\"id\", 1);",
        ),
        (
            "polarity",
            "  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  if (user) return Response.redirect(\"/\");\n  await admin.from(\"orders\").delete().eq(\"id\", 1);",
        ),
        (
            "partial",
            "  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  if (!user && req.url.includes(\"/x\")) return new Response(\"no\");\n  await admin.from(\"orders\").delete().eq(\"id\", 1);",
        ),
        (
            "branch",
            "  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  if (user) {\n    await admin.from(\"orders\").delete().eq(\"user_id\", user.id);\n  }",
        ),
        (
            "batch",
            "  const ids = [1, 2];\n  await Promise.all(ids.map((id) => admin.from(\"orders\").delete().eq(\"id\", id)));",
        ),
        (
            "shadow",
            "  const admin = await createClient();\n  await admin.from(\"orders\").delete().eq(\"id\", 1);",
        ),
        (
            "webhook",
            "  const body = await req.text();\n  let event;\n  try {\n    event = stripe.webhooks.constructEvent(body, req.headers.get(\"stripe-signature\")!, process.env.STRIPE_WEBHOOK_SECRET!);\n  } catch (err) {\n    return new Response(\"bad\", { status: 400 });\n  }\n  await syncOrder(event);",
        ),
        (
            "swallowed",
            "  const body = await req.text();\n  try {\n    stripe.webhooks.constructEvent(body, \"sig\", \"secret\");\n  } catch (err) {\n    console.log(err);\n  }\n  await syncOrder(body);",
        ),
        (
            "package",
            "  const { user } = await validateRequest();\n  if (!user) return new Response(\"no\");\n  await admin.from(\"orders\").delete().eq(\"id\", 1);",
        ),
    ];
    for (name, body) in routes {
        let mut text = route(body);
        if *name == "denied" {
            text.push_str(
                "function isAllowed(req: Request) {\n  return req.headers.get(\"x-key\") === \"1\";\n}\n",
            );
        }
        if *name == "webhook" || *name == "swallowed" {
            text = format!(
                "import Stripe from \"stripe\";\nimport {{ syncOrder }} from \"@/lib/sync\";\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);\n{text}"
            );
        }
        if *name == "package" {
            text = format!("import {{ validateRequest }} from \"lucia-helpers\";\n{text}");
        }
        project.write(&format!("src/app/api/{name}/route.ts"), &text);
    }
    project.write(
        "src/lib/sync.ts",
        "import { admin } from \"./admin\";\nexport async function syncOrder(event: unknown) {\n  await admin.from(\"orders\").upsert({ event });\n}\n",
    );
    let Some(report) = scan(&project) else { return };
    let expect = [
        ("open", Exposure::Public),
        ("inline", Exposure::Authenticated),
        ("helper", Exposure::Authenticated),
        ("tested", Exposure::Authenticated),
        ("untested", Exposure::Unknown),
        ("weak", Exposure::Authenticated),
        ("cron", Exposure::Authenticated),
        ("denied", Exposure::Unknown),
        ("polarity", Exposure::Unknown),
        ("partial", Exposure::Unknown),
        ("branch", Exposure::Authenticated),
        ("batch", Exposure::Public),
        ("shadow", Exposure::Unknown),
        ("package", Exposure::Unknown),
        ("webhook", Exposure::Authenticated),
        ("swallowed", Exposure::Public),
    ];
    for (name, wanted) in expect {
        let id = format!("entry:httpRoute:/api/{name}");
        assert_eq!(exposure(&report, &id), Some(wanted), "{id}");
    }
    assert_eq!(
        unguarded(&report),
        vec![
            ("entry:httpRoute:/api/batch", Severity::High),
            ("entry:httpRoute:/api/open", Severity::High),
            ("entry:httpRoute:/api/swallowed", Severity::High),
        ]
    );

    let guard = |entry: &str, guard: &str| {
        report.edges.iter().any(|edge| {
            edge.kind == EdgeKind::GuardedBy
                && edge.from.as_str() == entry
                && edge.to.as_str() == guard
        })
    };
    assert!(guard(
        "entry:httpRoute:/api/inline",
        "guard:src/app/api/inline/route.ts#POST"
    ));
    assert!(guard(
        "entry:httpRoute:/api/helper",
        "guard:src/lib/auth.ts#requireUser"
    ));
    assert!(guard(
        "entry:httpRoute:/api/tested",
        "guard:src/lib/auth.ts#currentUser"
    ));
    let weak = report
        .nodes
        .iter()
        .find(|node| node.id.as_str() == "guard:src/app/api/weak/route.ts#POST");
    assert!(matches!(
        weak.map(|node| &node.kind),
        Some(NodeKind::AccessRule {
            strength: Some(Strength::Weak),
            ..
        })
    ));
    assert!(report.edges.iter().any(|edge| {
        edge.kind == EdgeKind::ActsAs
            && edge.from.as_str() == "file:src/lib/admin.ts"
            && edge.to.as_str() == "principal:supabase:service_role"
    }));
}

#[test]
fn tracing_follows_helpers_reexports_and_entry_kinds() {
    let project = TempProject::new("trace-kinds");
    base(&project);
    project.write(
        "src/lib/factory.ts",
        "import { createClient } from \"@supabase/supabase-js\";\n\
export function createAdminClient() {\n\
  return createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n\
}\n",
    );
    project.write(
        "src/lib/orders.ts",
        "import { createAdminClient } from \"./factory\";\n\
export async function removeOrder(id: string) {\n\
  const db = createAdminClient();\n\
  await db.from(\"orders\").delete().eq(\"id\", id);\n\
}\n",
    );
    project.write(
        "src/lib/index.ts",
        "export { admin as db } from \"./admin\";\n",
    );
    project.write(
        "src/app/api/factory/route.ts",
        "import { removeOrder } from \"@/lib/orders\";\n\
export async function DELETE(req: Request) {\n\
  const { id } = await req.json();\n\
  await removeOrder(id);\n\
  return Response.json({ ok: true });\n\
}\n",
    );
    project.write(
        "src/app/api/reexport/route.ts",
        "import { db } from \"@/lib\";\n\
export async function GET() {\n\
  return Response.json(await db.from(\"orders\").select(\"*\"));\n\
}\n",
    );
    project.write(
        "src/pages/api/legacy.ts",
        "import { admin } from \"@/lib/admin\";\n\
export default async function handler(req: unknown, res: { status(code: number): { end(): void } }) {\n\
  await admin.from(\"orders\").delete().neq(\"id\", 0);\n\
  res.status(200).end();\n\
}\n",
    );
    project.write(
        "src/app/actions.ts",
        "\"use server\";\n\
import { redirect } from \"next/navigation\";\n\
import { admin } from \"@/lib/admin\";\n\
import { createClient } from \"@/lib/server\";\n\
export async function removeAll() {\n\
  const supabase = await createClient();\n\
  const { data: { user } } = await supabase.auth.getUser();\n\
  if (!user) redirect(\"/login\");\n\
  await admin.from(\"orders\").delete().neq(\"id\", 0);\n\
}\n\
export async function openAction() {\n\
  await admin.auth.admin.deleteUser(\"x\");\n\
}\n",
    );
    project.write(
        "supabase/functions/cleanup/index.ts",
        "import { createClient } from \"npm:@supabase/supabase-js@2\";\n\
Deno.serve(async (req) => {\n\
  if (req.method === \"OPTIONS\") return new Response(\"ok\");\n\
  const admin = createClient(Deno.env.get(\"SUPABASE_URL\")!, Deno.env.get(\"SUPABASE_SERVICE_ROLE_KEY\")!);\n\
  await admin.from(\"orders\").delete().lt(\"id\", 10);\n\
  return new Response(\"done\");\n\
});\n",
    );
    project.write(
        "supabase/functions/_shared/cors.ts",
        "export const cors = {};\n",
    );
    project.write("scripts/seed.ts", ADMIN);
    let body: String = "Q7mZr2Kx9VbT4nWc8LpY3hGd6FsJ5aEuR1tN0kHqXvBzMjC"
        .chars()
        .cycle()
        .skip(5)
        .take(32)
        .collect();
    let key = ["sb", "_secret_", &body].concat();
    project.write(
        "src/lib/literal.ts",
        &format!(
            "import {{ createClient }} from \"@supabase/supabase-js\";\nexport const hard = createClient(\"https://x.supabase.co\", \"{key}\");\n"
        ),
    );
    project.write(
        "src/app/api/literal/route.ts",
        "import { hard } from \"@/lib/literal\";\nexport async function GET() {\n  return Response.json(await hard.storage.from(\"docs\").list());\n}\n",
    );
    let Some(report) = scan(&project) else { return };
    assert_eq!(
        unguarded(&report),
        vec![
            (
                "entry:serverAction:src/app/actions.ts#openAction",
                Severity::High
            ),
            ("entry:httpRoute:/api/factory", Severity::High),
            ("entry:httpRoute:/api/legacy", Severity::High),
            ("entry:httpRoute:/functions/v1/cleanup", Severity::High),
            ("entry:httpRoute:/api/literal", Severity::Medium),
            ("entry:httpRoute:/api/reexport", Severity::Medium),
        ]
    );
    assert_eq!(
        exposure(&report, "entry:serverAction:src/app/actions.ts#removeAll"),
        Some(Exposure::Authenticated)
    );
    let factory = report
        .findings
        .iter()
        .find(|finding| finding.node.as_str() == "entry:httpRoute:/api/factory");
    let labels: Vec<&str> = factory
        .map(|finding| {
            finding
                .evidence
                .iter()
                .map(|step| step.label.as_str())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        labels,
        vec![
            "DELETE /api/factory",
            "route.ts",
            "removeOrder()",
            "service_role",
            "orders"
        ]
    );
    let client_at = factory
        .and_then(|finding| finding.evidence.get(3))
        .and_then(|step| step.location.as_ref())
        .map(|location| (location.path.as_str(), location.line));
    assert_eq!(client_at, Some(("src/lib/factory.ts", 3)));
    assert!(
        !report
            .nodes
            .iter()
            .any(|node| node.id.as_str().contains("functions/v1/_shared"))
    );
}

#[test]
fn middleware_with_a_guard_makes_matched_routes_unknown() {
    let project = TempProject::new("trace-middleware");
    base(&project);
    project.write(
        "src/app/api/open/route.ts",
        &route("  await admin.from(\"orders\").delete().eq(\"id\", 1);"),
    );
    project.write(
        "src/app/dashboard/delete/route.ts",
        &route("  await admin.from(\"orders\").delete().eq(\"id\", 1);"),
    );
    project.write(
        "src/middleware.ts",
        "import { NextResponse } from \"next/server\";\n\
import { createClient } from \"@/lib/server\";\n\
export async function middleware() {\n\
  const supabase = await createClient();\n\
  const { data: { user } } = await supabase.auth.getUser();\n\
  if (!user) return NextResponse.redirect(\"/login\");\n\
  return NextResponse.next();\n\
}\n\
export const config = { matcher: [\"/((?!api|_next/static|favicon.ico).*)\"] };\n",
    );
    let Some(report) = scan(&project) else { return };
    assert_eq!(
        exposure(&report, "entry:httpRoute:/api/open"),
        Some(Exposure::Public)
    );
    assert_eq!(
        exposure(&report, "entry:httpRoute:/dashboard/delete"),
        Some(Exposure::Unknown)
    );

    let refresh = TempProject::new("trace-refresh");
    base(&refresh);
    refresh.write(
        "src/app/dashboard/delete/route.ts",
        &route("  await admin.from(\"orders\").delete().eq(\"id\", 1);"),
    );
    refresh.write(
        "src/middleware.ts",
        "import { createClient } from \"@/lib/server\";\n\
export async function middleware() {\n\
  const supabase = await createClient();\n\
  await supabase.auth.getUser();\n\
}\n",
    );
    let Some(report) = scan(&refresh) else { return };
    assert_eq!(
        exposure(&report, "entry:httpRoute:/dashboard/delete"),
        Some(Exposure::Public)
    );
}
