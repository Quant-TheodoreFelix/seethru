use std::collections::BTreeSet;

use seethru_core::{
    AccessRuleDetail, CredentialDetail, DataStoreDetail, EdgeKind, Finding, Lang, LocalizedText,
    Location, Node, NodeKind, PolicyCommand, RuleId, ScanReport, SecretKind,
};

const MAX_NAME_CHARS: usize = 120;
const MAX_RELATED_FILES: usize = 8;

const CLOSING_EN: &str = "Keep the change as small as you can so nothing else breaks, and when you are done, tell me briefly which files you changed and why.";
const CLOSING_KO: &str =
    "기존 기능이 깨지지 않게 최소한으로 고치고, 끝나면 바꾼 파일과 이유를 짧게 알려 줘.";

pub fn attach_fix_prompts(report: &mut ScanReport) {
    let prompts: Vec<LocalizedText> = report
        .findings
        .iter()
        .map(|finding| LocalizedText {
            en: fix_prompt(report, finding, Lang::En),
            ko: fix_prompt(report, finding, Lang::Ko),
        })
        .collect();
    for (finding, prompt) in report.findings.iter_mut().zip(prompts) {
        finding.fix_prompt = Some(prompt);
    }
}

pub fn fix_prompt(report: &ScanReport, finding: &Finding, lang: Lang) -> String {
    let node = report.nodes.iter().find(|node| node.id == finding.node);
    let label = node.map(|n| n.label.as_str()).unwrap_or_default();
    let place = finding
        .location
        .as_ref()
        .map(|location| place(location, lang))
        .unwrap_or_default();
    let body = match (finding.rule, node.map(|node| &node.kind)) {
        (
            RuleId::SupabaseRlsDisabled,
            Some(NodeKind::DataStore {
                detail: Some(DataStoreDetail::PostgresTable { schema, .. }),
            }),
        ) => rls_disabled(report, finding, schema, label, &place, lang),
        (
            RuleId::SupabaseTableSchemaMissing,
            Some(NodeKind::DataStore {
                detail: Some(DataStoreDetail::PostgresTable { schema, .. }),
            }),
        ) => table_schema_missing(report, finding, schema, label, &place, lang),
        (
            RuleId::SupabasePolicyUnrestricted,
            Some(NodeKind::AccessRule {
                detail: Some(AccessRuleDetail::PostgresPolicy { command, roles }),
                ..
            }),
        ) => {
            let table = table_of_policy(report, finding).unwrap_or_default();
            let roles = roles
                .iter()
                .map(|role| clean(role))
                .collect::<Vec<_>>()
                .join(", ");
            policy_unrestricted(&table, &clean(label), *command, &roles, &place, lang)
        }
        (RuleId::SupabaseServiceRoleInBrowser, Some(_)) => {
            let readers = related_files(report, finding, &[EdgeKind::UsesConfig], lang);
            service_role_in_browser(&clean(label), &place, &readers, lang)
        }
        (
            RuleId::SupabaseStoragePolicyUnrestricted,
            Some(NodeKind::AccessRule {
                detail: Some(AccessRuleDetail::PostgresPolicy { command, roles }),
                ..
            }),
        ) => {
            let roles = roles
                .iter()
                .map(|role| clean(role))
                .collect::<Vec<_>>()
                .join(", ");
            let buckets = buckets_of_policy(report, finding);
            storage_policy_unrestricted(&clean(label), *command, &roles, &buckets, &place, lang)
        }
        (
            RuleId::SupabaseViewBypassesRls,
            Some(NodeKind::DataStore {
                detail:
                    Some(DataStoreDetail::PostgresView {
                        schema,
                        materialized,
                        ..
                    }),
            }),
        ) => {
            let name = label.rsplit('.').next().unwrap_or(label);
            let view = format!("{}.{}", clean(schema), clean(name));
            let users = related_files(report, finding, &[EdgeKind::Reads, EdgeKind::Writes], lang);
            view_bypasses_rls(&view, *materialized, &place, &users, lang)
        }
        (
            RuleId::SecretInBrowserCode | RuleId::SecretInSourceCode | RuleId::SecretInPublicEnvVar,
            Some(NodeKind::Credential {
                detail: CredentialDetail::Secret { secret_kind, .. },
            }),
        ) => secret(finding.rule, *secret_kind, &place, lang),
        _ => format!("{}{place}", clean(finding.title.get(lang))),
    };
    let closing = match lang {
        Lang::En => CLOSING_EN,
        Lang::Ko => CLOSING_KO,
    };
    format!("{body}\n{closing}")
}

fn rls_disabled(
    report: &ScanReport,
    finding: &Finding,
    schema: &str,
    label: &str,
    place: &str,
    lang: Lang,
) -> String {
    let name = label.rsplit('.').next().unwrap_or(label);
    let table = format!("{}.{}", clean(schema), clean(name));
    let users = related_files(report, finding, &[EdgeKind::Reads, EdgeKind::Writes], lang);
    match lang {
        Lang::En => format!(
            "RLS (row level security) is off for the Supabase `{table}` table, so anyone with the anon key can read and change every row.{place}{users}\n\
             1. Create a new migration file that adds `alter table {table} enable row level security;`.\n\
             2. Look at the code that uses this table and add policies to the same file so signed-in users can read and write only their own rows. For example, use the owner column as in `using ((select auth.uid()) = user_id)`.\n\
             3. Do not edit migration files that have already been applied."
        ),
        Lang::Ko => format!(
            "Supabase `{table}` 테이블에 RLS(행 수준 보안)가 꺼져 있어서 anon 키만 있으면 누구나 모든 행을 읽고 고칠 수 있어.{place}{users}\n\
             1. 새 마이그레이션 파일을 만들어서 `alter table {table} enable row level security;`를 추가해 줘.\n\
             2. 이 테이블을 쓰는 코드를 보고, 로그인한 사용자가 자기 행만 읽고 쓸 수 있는 정책을 같은 파일에 만들어 줘. 예를 들면 `using ((select auth.uid()) = user_id)`처럼 소유자 컬럼을 써.\n\
             3. 이미 적용된 마이그레이션 파일은 고치지 마."
        ),
    }
}

fn table_schema_missing(
    report: &ScanReport,
    finding: &Finding,
    schema: &str,
    label: &str,
    place: &str,
    lang: Lang,
) -> String {
    let name = label.rsplit('.').next().unwrap_or(label);
    let table = format!("{}.{}", clean(schema), clean(name));
    let users = related_files(report, finding, &[EdgeKind::Reads, EdgeKind::Writes], lang);
    match lang {
        Lang::En => format!(
            "The Supabase `{table}` table is used in code, but no migration in this repo creates it or turns on row level security (RLS), so it is not clear whether RLS protects it.{place}{users}\n\
             1. Create a new migration file that adds `alter table {table} enable row level security;`. It is safe to run even if RLS is already on.\n\
             2. Look at the code that uses this table and add policies to the same file so signed-in users can read and write only their own rows. For example, use the owner column as in `using ((select auth.uid()) = user_id)`.\n\
             3. If the Supabase CLI is linked to this project, save the current schema in the repo with `supabase db dump --schema public`.\n\
             Tell me which policies you added so I can compare them with the ones already in the Supabase dashboard."
        ),
        Lang::Ko => format!(
            "Supabase `{table}` 테이블을 코드에서 쓰고 있지만 저장소의 마이그레이션 어디에도 이 테이블을 만들거나 RLS(행 수준 보안)를 켜는 부분이 없어서, RLS가 보호하고 있는지 알 수 없어.{place}{users}\n\
             1. 새 마이그레이션 파일을 만들어서 `alter table {table} enable row level security;`를 추가해 줘. RLS가 이미 켜져 있어도 문제없이 실행돼.\n\
             2. 이 테이블을 쓰는 코드를 보고, 로그인한 사용자가 자기 행만 읽고 쓸 수 있는 정책을 같은 파일에 만들어 줘. 예를 들면 `using ((select auth.uid()) = user_id)`처럼 소유자 컬럼을 써.\n\
             3. Supabase CLI가 이 프로젝트에 연결되어 있다면 `supabase db dump --schema public`으로 지금 스키마를 저장소에 저장해 줘.\n\
             어떤 정책을 추가했는지 알려 주면 Supabase 대시보드에 이미 있는 정책과 비교해 볼게."
        ),
    }
}

fn policy_unrestricted(
    table: &str,
    policy: &str,
    command: PolicyCommand,
    roles: &str,
    place: &str,
    lang: Lang,
) -> String {
    let command = command_name(command);
    match lang {
        Lang::En => format!(
            "The `{policy}` policy on the Supabase `{table}` table (`{command}` for {roles}) has a condition that is always `true`, so every row is open.{place}\n\
             1. Create a new migration file that drops this policy with `drop policy` and creates it again with a condition that lets signed-in users work only with their own rows. For example, use the owner column of the table as in `using ((select auth.uid()) = user_id)`.\n\
             2. Do not edit migration files that have already been applied.\n\
             3. If this policy shares the table with everyone on purpose, do not change it and tell me so."
        ),
        Lang::Ko => format!(
            "Supabase `{table}` 테이블의 `{policy}` 정책(`{command}`, 대상 {roles})은 조건이 항상 참(`true`)이라서 모든 행이 열려 있어.{place}\n\
             1. 새 마이그레이션 파일을 만들어서 이 정책을 지우고(`drop policy`), 로그인한 사용자가 자기 행만 다룰 수 있는 조건으로 다시 만들어 줘. 예를 들면 `using ((select auth.uid()) = user_id)`처럼 테이블의 소유자 컬럼을 써.\n\
             2. 이미 적용된 마이그레이션 파일은 고치지 마.\n\
             3. 모두에게 공개하려고 일부러 만든 정책이라면 바꾸지 말고 그렇다고 알려 줘."
        ),
    }
}

fn storage_policy_unrestricted(
    policy: &str,
    command: PolicyCommand,
    roles: &str,
    buckets: &str,
    place: &str,
    lang: Lang,
) -> String {
    let command = command_name(command);
    match lang {
        Lang::En => {
            let scope = if buckets.is_empty() {
                "every file in Supabase Storage".to_owned()
            } else if buckets.contains(", ") {
                format!("every file in the {buckets} buckets")
            } else {
                format!("every file in the {buckets} bucket")
            };
            format!(
                "The `{policy}` policy on Supabase Storage (`{command}` for {roles}) does not check whose file it is, so {scope} is open.{place}\n\
                 1. Create a new migration file that drops this policy with `drop policy` on `storage.objects` and creates it again with a condition that lets each user reach only their own files. For example, keep files in a folder named after the user ID and add `(storage.foldername(name))[1] = (select auth.uid())::text`.\n\
                 2. If the upload code does not put files in such a folder yet, change it so it does.\n\
                 3. Do not edit migration files that have already been applied.\n\
                 4. If these files are meant to be public, do not change the policy and tell me so."
            )
        }
        Lang::Ko => {
            let scope = if buckets.is_empty() {
                "Supabase Storage의 모든 파일".to_owned()
            } else {
                format!("{buckets} 버킷의 모든 파일")
            };
            format!(
                "Supabase Storage의 `{policy}` 정책(`{command}`, 대상 {roles})은 누구의 파일인지 확인하지 않아서 {scope}이 열려 있어.{place}\n\
                 1. 새 마이그레이션 파일을 만들어서 `storage.objects`의 이 정책을 지우고(`drop policy`), 사용자가 자기 파일만 다룰 수 있는 조건으로 다시 만들어 줘. 예를 들면 파일을 사용자 ID 이름의 폴더에 두고 `(storage.foldername(name))[1] = (select auth.uid())::text` 조건을 써.\n\
                 2. 업로드 코드가 아직 그런 폴더에 파일을 두지 않는다면 그렇게 바꿔 줘.\n\
                 3. 이미 적용된 마이그레이션 파일은 고치지 마.\n\
                 4. 모두에게 공개하려고 일부러 만든 파일이라면 정책을 바꾸지 말고 그렇다고 알려 줘."
            )
        }
    }
}

fn view_bypasses_rls(
    view: &str,
    materialized: bool,
    place: &str,
    users: &str,
    lang: Lang,
) -> String {
    match (lang, materialized) {
        (Lang::En, false) => format!(
            "The Supabase view `{view}` runs with the rights of the account that created it, so it skips the RLS policies of the tables it reads, and anyone who can use the API can read every row it returns.{place}{users}\n\
             1. Create a new migration file that adds `alter view {view} set (security_invoker = true);` so the view follows the RLS policies of the person who reads it.\n\
             2. Check that the tables behind the view have policies that let the right users read their rows, because the view will now return only what RLS allows.\n\
             3. If no one outside the database should read this view, also add `revoke select on {view} from anon, authenticated;`.\n\
             4. Do not edit migration files that have already been applied."
        ),
        (Lang::En, true) => format!(
            "The Supabase materialized view `{view}` keeps its own copy of the rows and has no RLS, so anyone who can use the API can read every row in it.{place}{users}\n\
             1. Create a new migration file that adds `revoke select on {view} from anon, authenticated;`, or move the view to a schema that the API does not expose.\n\
             2. If the app needs these rows, read them through a normal view with `security_invoker = true` or a function that checks the caller.\n\
             3. Do not edit migration files that have already been applied."
        ),
        (Lang::Ko, false) => format!(
            "Supabase 뷰 `{view}`는 만든 계정의 권한으로 실행돼서 뷰가 읽는 테이블의 RLS 정책을 건너뛰고, API를 쓸 수 있는 사람은 누구나 이 뷰가 돌려주는 모든 행을 읽을 수 있어.{place}{users}\n\
             1. 새 마이그레이션 파일을 만들어서 `alter view {view} set (security_invoker = true);`를 추가해 줘. 그러면 뷰가 읽는 사람 기준으로 RLS 정책을 따르게 돼.\n\
             2. 이제 뷰는 RLS가 허용하는 행만 돌려주니까, 뷰가 읽는 테이블에 알맞은 사용자가 자기 행을 읽을 수 있는 정책이 있는지 확인해 줘.\n\
             3. 데이터베이스 바깥에서 이 뷰를 읽을 필요가 없다면 `revoke select on {view} from anon, authenticated;`도 추가해 줘.\n\
             4. 이미 적용된 마이그레이션 파일은 고치지 마."
        ),
        (Lang::Ko, true) => format!(
            "Supabase materialized view `{view}`는 행을 따로 복사해 두고 RLS가 없어서, API를 쓸 수 있는 사람은 누구나 이 뷰의 모든 행을 읽을 수 있어.{place}{users}\n\
             1. 새 마이그레이션 파일을 만들어서 `revoke select on {view} from anon, authenticated;`를 추가하거나, API가 공개하지 않는 스키마로 뷰를 옮겨 줘.\n\
             2. 앱에서 이 행이 필요하다면 `security_invoker = true`인 일반 뷰나 부른 사람을 확인하는 함수를 거쳐 읽게 해 줘.\n\
             3. 이미 적용된 마이그레이션 파일은 고치지 마."
        ),
    }
}

fn service_role_in_browser(var: &str, place: &str, readers: &str, lang: Lang) -> String {
    match lang {
        Lang::En => format!(
            "Code that runs in the browser reads the `{var}` env variable, which holds the Supabase service_role key.{place}{readers}\n\
             1. Move the work that needs the service_role key to server code such as a Supabase Edge Function.\n\
             2. Change the browser code so it reaches data only with the publishable (anon) key and RLS policies.\n\
             3. Remove the public prefix from the env variable name and read it only on the server.\n\
             I will revoke the key in the Supabase dashboard and issue a new one myself."
        ),
        Lang::Ko => format!(
            "브라우저에서 실행되는 코드가 Supabase service_role 키를 담은 `{var}` 환경변수를 읽고 있어.{place}{readers}\n\
             1. service_role 키가 필요한 작업을 Supabase Edge Function 같은 서버 쪽 코드로 옮겨 줘.\n\
             2. 브라우저 코드는 publishable 키(anon 키)와 RLS 정책만으로 데이터에 접근하게 바꿔 줘.\n\
             3. 환경변수 이름에서 공개 접두사를 빼고 서버에서만 읽게 해 줘.\n\
             키 자체는 내가 Supabase 대시보드에서 폐기하고 다시 발급할게."
        ),
    }
}

fn secret(rule: RuleId, kind: SecretKind, place: &str, lang: Lang) -> String {
    let what = secret_name(kind, lang);
    match lang {
        Lang::En => {
            let first = match rule {
                RuleId::SecretInPublicEnvVar => format!(
                    "An env variable with a public prefix holds {what}, so the value is built into browser code.{place}\n\
                     1. Move the code that uses this value to the server, such as an API route or an Edge Function.\n\
                     2. Remove the public prefix from the env variable name and read it only on the server."
                ),
                RuleId::SecretInBrowserCode => format!(
                    "Code that is sent to the browser contains {what}.{place}\n\
                     1. Remove the value from the code and move the work that needs it to the server, such as an API route or an Edge Function.\n\
                     2. Make the server code read the value from an env variable that is not committed."
                ),
                _ => format!(
                    "A code or config file contains {what}.{place}\n\
                     1. Remove the value from the file and read it from an env variable instead.\n\
                     2. Check that the env file that will hold the real value is listed in `.gitignore`."
                ),
            };
            format!(
                "{first}\n\
                 3. You do not need to remove the value from the git history. I will revoke the key and issue a new one myself.\n\
                 The value itself is left out of this request on purpose."
            )
        }
        Lang::Ko => {
            let first = match rule {
                RuleId::SecretInPublicEnvVar => format!(
                    "공개 접두사가 붙은 환경변수에 {what} 값이 들어 있어서 빌드할 때 브라우저 코드에 포함돼.{place}\n\
                     1. 이 값을 쓰는 코드를 서버 쪽(API 라우트나 Edge Function)으로 옮겨 줘.\n\
                     2. 환경변수 이름에서 공개 접두사를 빼고 서버에서만 읽게 해 줘."
                ),
                RuleId::SecretInBrowserCode => format!(
                    "브라우저로 전달되는 코드에 {what} 값이 직접 들어 있어.{place}\n\
                     1. 이 값을 코드에서 지우고, 이 값이 필요한 작업을 서버 쪽(API 라우트나 Edge Function)으로 옮겨 줘.\n\
                     2. 서버 코드는 커밋하지 않는 환경변수에서 값을 읽게 해 줘."
                ),
                _ => format!(
                    "코드나 설정 파일에 {what} 값이 직접 적혀 있어.{place}\n\
                     1. 이 값을 파일에서 지우고 환경변수에서 읽도록 바꿔 줘.\n\
                     2. 실제 값이 들어갈 환경변수 파일이 `.gitignore`에 들어 있는지 확인해 줘."
                ),
            };
            format!(
                "{first}\n\
                 3. git 기록에 남은 값은 지우지 않아도 돼. 키는 내가 직접 폐기하고 다시 발급할게.\n\
                 값 자체는 보안을 위해 이 요청에 넣지 않았어."
            )
        }
    }
}

fn secret_name(kind: SecretKind, lang: Lang) -> &'static str {
    let (en, ko) = match kind {
        SecretKind::SupabaseServiceRoleKey => {
            ("a Supabase service_role key", "Supabase service_role 키")
        }
        SecretKind::SupabaseSecretKey => ("a Supabase secret key", "Supabase 비밀 키"),
        SecretKind::DatabaseUrl => (
            "a database URL with a password",
            "DB 비밀번호가 포함된 접속 주소",
        ),
        SecretKind::StripeSecretKey => ("a Stripe secret key", "Stripe 비밀 키"),
        SecretKind::OpenAiApiKey => ("an OpenAI API key", "OpenAI API 키"),
        SecretKind::AnthropicApiKey => ("an Anthropic API key", "Anthropic API 키"),
        SecretKind::AwsAccessKeyId => ("an AWS access key", "AWS 액세스 키"),
        SecretKind::GithubToken => ("a GitHub token", "GitHub 토큰"),
        SecretKind::PrivateKey => ("a private key", "개인 키"),
    };
    match lang {
        Lang::En => en,
        Lang::Ko => ko,
    }
}

fn command_name(command: PolicyCommand) -> &'static str {
    match command {
        PolicyCommand::All => "all",
        PolicyCommand::Select => "select",
        PolicyCommand::Insert => "insert",
        PolicyCommand::Update => "update",
        PolicyCommand::Delete => "delete",
    }
}

fn place(location: &Location, lang: Lang) -> String {
    let path = clean(&location.path);
    match lang {
        Lang::En => format!(" It is at `{path}:{}`.", location.line),
        Lang::Ko => format!(" 위치는 `{path}:{}`이야.", location.line),
    }
}

fn table_of_policy(report: &ScanReport, finding: &Finding) -> Option<String> {
    report
        .edges
        .iter()
        .find(|edge| edge.kind == EdgeKind::GuardedBy && edge.to == finding.node)
        .and_then(|edge| report.nodes.iter().find(|node| node.id == edge.from))
        .map(|node: &Node| clean(&node.label))
}

fn buckets_of_policy(report: &ScanReport, finding: &Finding) -> String {
    report
        .edges
        .iter()
        .filter(|edge| edge.kind == EdgeKind::GuardedBy && edge.to == finding.node)
        .filter_map(|edge| report.nodes.iter().find(|node| node.id == edge.from))
        .filter(|node| {
            matches!(
                node.kind,
                NodeKind::DataStore {
                    detail: Some(DataStoreDetail::StorageBucket { .. })
                }
            )
        })
        .map(|node| format!("`{}`", clean(&node.label)))
        .take(MAX_RELATED_FILES)
        .collect::<Vec<_>>()
        .join(", ")
}

fn related_files(report: &ScanReport, finding: &Finding, kinds: &[EdgeKind], lang: Lang) -> String {
    let files: BTreeSet<String> = report
        .edges
        .iter()
        .filter(|edge| kinds.contains(&edge.kind) && edge.to == finding.node)
        .filter_map(|edge| report.nodes.iter().find(|node| node.id == edge.from))
        .filter_map(|node| node.location.as_ref())
        .map(|location| format!("`{}`", clean(&location.path)))
        .take(MAX_RELATED_FILES)
        .collect();
    if files.is_empty() {
        return String::new();
    }
    let files = files.into_iter().collect::<Vec<_>>().join(", ");
    match lang {
        Lang::En => format!(" Related files: {files}."),
        Lang::Ko => format!(" 관련 파일은 {files}이야."),
    }
}

fn clean(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .filter(|c| !c.is_control() && *c != '`')
        .take(MAX_NAME_CHARS)
        .collect();
    if raw.chars().count() > MAX_NAME_CHARS {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests;
