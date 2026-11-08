use std::collections::BTreeSet;

use seethru_core::{EdgeKind, Finding, Location, Node, NodeKind, RuleId, ScanReport, SecretKind};

const MAX_NAME_CHARS: usize = 120;
const MAX_RELATED_FILES: usize = 8;

const CLOSING: &str =
    "기존 기능이 깨지지 않게 최소한으로 고치고, 끝나면 바꾼 파일과 이유를 짧게 알려 줘.";

pub fn attach_fix_prompts(report: &mut ScanReport) {
    let prompts: Vec<String> = report
        .findings
        .iter()
        .map(|finding| fix_prompt(report, finding))
        .collect();
    for (finding, prompt) in report.findings.iter_mut().zip(prompts) {
        finding.fix_prompt = Some(prompt);
    }
}

pub fn fix_prompt(report: &ScanReport, finding: &Finding) -> String {
    let node = report.nodes.iter().find(|node| node.id == finding.node);
    let place = finding.location.as_ref().map(place).unwrap_or_default();
    let body = match (finding.rule, node.map(|node| &node.kind)) {
        (RuleId::SupabaseRlsDisabled, Some(NodeKind::Table { schema, .. })) => rls_disabled(
            report,
            finding,
            schema,
            node.map(|n| n.label.as_str()).unwrap_or_default(),
            &place,
        ),
        (RuleId::SupabasePolicyUnrestricted, Some(NodeKind::Policy { command, roles, .. })) => {
            let table = table_of_policy(report, finding).unwrap_or_default();
            let policy = node.map(|n| n.label.as_str()).unwrap_or_default();
            format!(
                "Supabase `{table}` 테이블의 `{}` 정책({}, 대상 {})은 조건이 항상 참(`true`)이라서 모든 행이 열려 있어.{place}\n\
                 1. 새 마이그레이션 파일을 만들어서 이 정책을 지우고(`drop policy`), 로그인한 사용자가 자기 행만 다룰 수 있는 조건으로 다시 만들어 줘. 예를 들면 `using ((select auth.uid()) = user_id)`처럼 테이블의 소유자 컬럼을 써.\n\
                 2. 이미 적용된 마이그레이션 파일은 고치지 마.\n\
                 3. 모두에게 공개하려고 일부러 만든 정책이라면 바꾸지 말고 그렇다고 알려 줘.",
                clean(policy),
                command_name(*command),
                roles
                    .iter()
                    .map(|role| clean(role))
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        }
        (RuleId::SupabaseServiceRoleInBrowser, Some(_)) => {
            let var = node.map(|n| n.label.as_str()).unwrap_or_default();
            let readers = related_files(report, finding, &[EdgeKind::Reads]);
            format!(
                "브라우저에서 실행되는 코드가 Supabase service_role 키를 담은 `{}` 환경변수를 읽고 있어.{place}{readers}\n\
                 1. service_role 키가 필요한 작업을 Supabase Edge Function 같은 서버 쪽 코드로 옮겨 줘.\n\
                 2. 브라우저 코드는 publishable 키(anon 키)와 RLS 정책만으로 데이터에 접근하게 바꿔 줘.\n\
                 3. 환경변수 이름에서 공개 접두사를 빼고 서버에서만 읽게 해 줘.\n\
                 키 자체는 내가 Supabase 대시보드에서 폐기하고 다시 발급할게.",
                clean(var)
            )
        }
        (
            RuleId::SecretInBrowserCode | RuleId::SecretInSourceCode | RuleId::SecretInPublicEnvVar,
            Some(NodeKind::Secret { secret_kind, .. }),
        ) => secret(finding.rule, *secret_kind, &place),
        _ => format!("{}{place}", clean(&finding.title)),
    };
    format!("{body}\n{CLOSING}")
}

fn rls_disabled(
    report: &ScanReport,
    finding: &Finding,
    schema: &str,
    label: &str,
    place: &str,
) -> String {
    let name = label.rsplit('.').next().unwrap_or(label);
    let table = format!("{}.{}", clean(schema), clean(name));
    let users = related_files(report, finding, &[EdgeKind::Queries, EdgeKind::Writes]);
    format!(
        "Supabase `{table}` 테이블에 RLS(행 수준 보안)가 꺼져 있어서 anon 키만 있으면 누구나 모든 행을 읽고 고칠 수 있어.{place}{users}\n\
         1. 새 마이그레이션 파일을 만들어서 `alter table {table} enable row level security;`를 추가해 줘.\n\
         2. 이 테이블을 쓰는 코드를 보고, 로그인한 사용자가 자기 행만 읽고 쓸 수 있는 정책을 같은 파일에 만들어 줘. 예를 들면 `using ((select auth.uid()) = user_id)`처럼 소유자 컬럼을 써.\n\
         3. 이미 적용된 마이그레이션 파일은 고치지 마."
    )
}

fn secret(rule: RuleId, kind: SecretKind, place: &str) -> String {
    let what = secret_name(kind);
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

fn secret_name(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::SupabaseServiceRoleKey => "Supabase service_role 키",
        SecretKind::SupabaseSecretKey => "Supabase 비밀 키",
        SecretKind::DatabaseUrl => "DB 비밀번호가 포함된 접속 주소",
        SecretKind::StripeSecretKey => "Stripe 비밀 키",
        SecretKind::OpenAiApiKey => "OpenAI API 키",
        SecretKind::AnthropicApiKey => "Anthropic API 키",
        SecretKind::AwsAccessKeyId => "AWS 액세스 키",
        SecretKind::GithubToken => "GitHub 토큰",
        SecretKind::PrivateKey => "개인 키",
    }
}

fn command_name(command: seethru_core::PolicyCommand) -> &'static str {
    match command {
        seethru_core::PolicyCommand::All => "모든 작업",
        seethru_core::PolicyCommand::Select => "읽기",
        seethru_core::PolicyCommand::Insert => "추가",
        seethru_core::PolicyCommand::Update => "수정",
        seethru_core::PolicyCommand::Delete => "삭제",
    }
}

fn place(location: &Location) -> String {
    format!(" 위치는 `{}:{}`이야.", clean(&location.path), location.line)
}

fn table_of_policy(report: &ScanReport, finding: &Finding) -> Option<String> {
    report
        .edges
        .iter()
        .find(|edge| edge.kind == EdgeKind::GuardedBy && edge.to == finding.node)
        .and_then(|edge| report.nodes.iter().find(|node| node.id == edge.from))
        .map(|node: &Node| clean(&node.label))
}

fn related_files(report: &ScanReport, finding: &Finding, kinds: &[EdgeKind]) -> String {
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
        String::new()
    } else {
        format!(
            " 관련 파일은 {}이야.",
            files.into_iter().collect::<Vec<_>>().join(", ")
        )
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
