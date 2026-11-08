use seethru_core::{PolicyCommand, SecretKind};

const MAX_LABEL_CHARS: usize = 80;

pub(crate) struct Text {
    pub title: String,
    pub explanation: String,
}

pub(crate) fn display_name(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .filter(|c| !c.is_control() && *c != '`')
        .take(MAX_LABEL_CHARS)
        .collect();
    if raw.chars().count() > MAX_LABEL_CHARS {
        out.push_str("...");
    }
    out
}

pub(crate) fn rls_disabled(table: &str) -> Text {
    let table = display_name(table);
    Text {
        title: format!("`{table}` 테이블에 RLS가 꺼져 있어요"),
        explanation: format!(
            "RLS(행 수준 보안)가 꺼진 테이블은 누구나 모든 행을 읽고, 고치고, 지울 수 있어요. \
             앱에 들어 있는 Supabase anon 키는 브라우저에 그대로 공개되기 때문에, \
             이 키만 있으면 로그인하지 않은 사람도 `{table}` 테이블 전체에 접근할 수 있어요."
        ),
    }
}

pub(crate) fn policy_unrestricted(
    table: &str,
    policy: &str,
    anyone: bool,
    command: PolicyCommand,
) -> Text {
    let table = display_name(table);
    let policy = display_name(policy);
    let who = if anyone {
        "로그인하지 않은 사람을 포함한 누구나"
    } else {
        "로그인한 사용자라면 누구나"
    };
    let what = match command {
        PolicyCommand::All => "모든 행을 읽고, 고치고, 지울 수 있어요",
        PolicyCommand::Select => "모든 행을 읽을 수 있어요",
        PolicyCommand::Insert => "아무 내용이나 새 행으로 추가할 수 있어요",
        PolicyCommand::Update => "다른 사람의 행까지 고칠 수 있어요",
        PolicyCommand::Delete => "다른 사람의 행까지 지울 수 있어요",
    };
    Text {
        title: format!("`{table}` 테이블의 `{policy}` 정책이 모든 행을 열어 두고 있어요"),
        explanation: format!(
            "이 정책은 조건이 항상 참(true)이라서 {who} `{table}` 테이블에서 {what}. \
             보통은 `auth.uid() = user_id`처럼 본인 행만 허용하는 조건이 필요해요. \
             모두에게 공개하려고 일부러 만든 정책이라면 그대로 두어도 괜찮아요."
        ),
    }
}

pub(crate) fn secret_label(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::SupabaseServiceRoleKey => "Supabase service_role 키",
        SecretKind::SupabaseSecretKey => "Supabase 비밀 키",
        SecretKind::DatabaseUrl => "DB 비밀번호가 들어 있는 접속 주소",
        SecretKind::StripeSecretKey => "Stripe 비밀 키",
        SecretKind::OpenAiApiKey => "OpenAI API 키",
        SecretKind::AnthropicApiKey => "Anthropic API 키",
        SecretKind::AwsAccessKeyId => "AWS 액세스 키",
        SecretKind::GithubToken => "GitHub 토큰",
        SecretKind::PrivateKey => "개인 키",
    }
}

fn secret_risk(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::SupabaseServiceRoleKey | SecretKind::SupabaseSecretKey => {
            "이 키는 RLS를 무시하고 데이터베이스의 모든 데이터를 읽고, 고치고, 지울 수 있는 관리자 키예요."
        }
        SecretKind::DatabaseUrl => {
            "이 주소만 있으면 데이터베이스에 직접 접속해 모든 데이터를 다룰 수 있어요."
        }
        SecretKind::StripeSecretKey => "이 키로 결제를 만들거나 환불하고 고객 정보를 볼 수 있어요.",
        SecretKind::OpenAiApiKey | SecretKind::AnthropicApiKey => {
            "다른 사람이 이 키로 AI API를 호출하면 요금이 내 계정으로 청구돼요."
        }
        SecretKind::AwsAccessKeyId => "이 키에 연결된 권한만큼 AWS 자원을 마음대로 쓸 수 있어요.",
        SecretKind::GithubToken => "이 토큰의 권한만큼 저장소 코드를 읽거나 바꿀 수 있어요.",
        SecretKind::PrivateKey => "이 키로 서명하거나 암호화된 통신을 풀 수 있어요.",
    }
}

const ROTATE: &str = "키를 지금 바로 폐기하고 새로 발급하세요. 코드에서 지우는 것만으로는 이미 노출된 키를 되돌릴 수 없어요.";

pub(crate) fn secret_in_browser(kind: SecretKind, file: &str) -> Text {
    let file = display_name(file);
    Text {
        title: format!(
            "브라우저로 전달되는 `{file}` 파일에 비밀 값({})이 들어 있어요",
            secret_label(kind)
        ),
        explanation: format!(
            "이 파일은 방문자의 브라우저로 그대로 전달돼요. 개발자 도구만 열면 누구나 이 값을 꺼낼 수 있어요. {} {ROTATE} \
             새 키는 서버나 Edge Function에서만 쓰도록 옮겨야 해요.",
            secret_risk(kind)
        ),
    }
}

pub(crate) fn secret_in_public_env(kind: SecretKind, var: &str) -> Text {
    let var = display_name(var);
    Text {
        title: format!(
            "`{var}` 환경변수에 비밀 값({})이 들어 있어요",
            secret_label(kind)
        ),
        explanation: format!(
            "이름이 공개 접두사로 시작하는 환경변수는 빌드할 때 브라우저 코드에 그대로 들어가요. {} {ROTATE} \
             새 키는 공개 접두사가 없는 이름으로 바꾸고 서버 쪽 코드에서만 읽어야 해요.",
            secret_risk(kind)
        ),
    }
}

pub(crate) fn secret_in_source(kind: SecretKind, file: &str) -> Text {
    let file = display_name(file);
    Text {
        title: format!(
            "`{file}` 파일에 비밀 값({})이 직접 적혀 있어요",
            secret_label(kind)
        ),
        explanation: format!(
            "코드나 설정 파일에 적힌 값은 저장소를 볼 수 있는 모든 사람에게 노출돼요. {} {ROTATE} \
             새 키는 커밋하지 않는 환경변수 파일이나 배포 환경의 비밀 설정에 넣으세요.",
            secret_risk(kind)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::display_name;

    #[test]
    fn display_name_strips_control_characters_and_backticks() {
        assert_eq!(display_name("to`do\ns"), "todos");
    }

    #[test]
    fn display_name_truncates_long_input() {
        let long = "a".repeat(200);
        let shown = display_name(&long);
        assert!(shown.ends_with("..."));
        assert_eq!(shown.chars().count(), 83);
    }
}
