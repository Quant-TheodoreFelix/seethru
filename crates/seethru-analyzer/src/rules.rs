use seethru_core::{Lang, LocalizedText, PolicyCommand, SecretKind};

const MAX_LABEL_CHARS: usize = 80;

pub(crate) struct Text {
    pub title: LocalizedText,
    pub explanation: LocalizedText,
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
        title: LocalizedText {
            en: format!("RLS is off for the `{table}` table"),
            ko: format!("`{table}` 테이블에 RLS가 꺼져 있어요"),
        },
        explanation: LocalizedText {
            en: format!(
                "With RLS (row level security) off, anyone can read, change and delete every row in this table. \
                 The Supabase anon key in your app is public in the browser, \
                 so anyone who has it can reach the whole `{table}` table without signing in."
            ),
            ko: format!(
                "RLS(행 수준 보안)가 꺼진 테이블은 누구나 모든 행을 읽고, 고치고, 지울 수 있어요. \
                 앱에 들어 있는 Supabase anon 키는 브라우저에 그대로 공개되기 때문에, \
                 이 키만 있으면 로그인하지 않은 사람도 `{table}` 테이블 전체에 접근할 수 있어요."
            ),
        },
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
    let (who_en, who_ko) = if anyone {
        (
            "anyone, even people who are not signed in,",
            "로그인하지 않은 사람을 포함한 누구나",
        )
    } else {
        ("any signed-in user", "로그인한 사용자라면 누구나")
    };
    let (what_en, what_ko) = match command {
        PolicyCommand::All => (
            "read, change and delete every row",
            "모든 행을 읽고, 고치고, 지울 수 있어요",
        ),
        PolicyCommand::Select => ("read every row", "모든 행을 읽을 수 있어요"),
        PolicyCommand::Insert => (
            "add any row they like",
            "아무 내용이나 새 행으로 추가할 수 있어요",
        ),
        PolicyCommand::Update => (
            "change rows that belong to other people",
            "다른 사람의 행까지 고칠 수 있어요",
        ),
        PolicyCommand::Delete => (
            "delete rows that belong to other people",
            "다른 사람의 행까지 지울 수 있어요",
        ),
    };
    Text {
        title: LocalizedText {
            en: format!("The `{policy}` policy opens every row of the `{table}` table"),
            ko: format!("`{table}` 테이블의 `{policy}` 정책이 모든 행을 열어 두고 있어요"),
        },
        explanation: LocalizedText {
            en: format!(
                "The condition of this policy is always true, so {who_en} can {what_en} in the `{table}` table. \
                 The condition should usually allow only the user's own rows, such as `auth.uid() = user_id`. \
                 If you made this policy to share the table with everyone on purpose, you can leave it as it is."
            ),
            ko: format!(
                "이 정책은 조건이 항상 참(true)이라서 {who_ko} `{table}` 테이블에서 {what_ko}. \
                 보통은 `auth.uid() = user_id`처럼 본인 행만 허용하는 조건이 필요해요. \
                 모두에게 공개하려고 일부러 만든 정책이라면 그대로 두어도 괜찮아요."
            ),
        },
    }
}

pub(crate) fn service_role_in_browser(var: &str, prefix: &str) -> Text {
    let var = display_name(var);
    let prefix = display_name(prefix);
    let rotate_en = rotate(Lang::En);
    let rotate_ko = rotate(Lang::Ko);
    Text {
        title: LocalizedText {
            en: format!("Browser code reads the `{var}` env variable"),
            ko: format!("브라우저 코드가 `{var}` 환경변수를 읽고 있어요"),
        },
        explanation: LocalizedText {
            en: format!(
                "Env variables that start with `{prefix}` are copied into browser code when the app is built. \
                 The service_role key is an admin key that skips RLS, so anyone who finds it in the browser \
                 can read, change and delete your whole database. {rotate_en} \
                 Move admin work to server code such as an Edge Function."
            ),
            ko: format!(
                "`{prefix}`로 시작하는 환경변수는 빌드할 때 브라우저 코드에 그대로 들어가요. \
                 service_role 키는 RLS를 무시하는 관리자 키라서, 이 키가 브라우저에 있으면 누구나 데이터베이스 전체를 \
                 읽고, 고치고, 지울 수 있어요. {rotate_ko} 관리자 작업은 Edge Function 같은 서버 쪽 코드로 옮기세요."
            ),
        },
    }
}

fn secret_label(kind: SecretKind, lang: Lang) -> &'static str {
    let (en, ko) = match kind {
        SecretKind::SupabaseServiceRoleKey => {
            ("a Supabase service_role key", "Supabase service_role 키")
        }
        SecretKind::SupabaseSecretKey => ("a Supabase secret key", "Supabase 비밀 키"),
        SecretKind::DatabaseUrl => (
            "a database URL with a password",
            "DB 비밀번호가 들어 있는 접속 주소",
        ),
        SecretKind::StripeSecretKey => ("a Stripe secret key", "Stripe 비밀 키"),
        SecretKind::OpenAiApiKey => ("an OpenAI API key", "OpenAI API 키"),
        SecretKind::AnthropicApiKey => ("an Anthropic API key", "Anthropic API 키"),
        SecretKind::AwsAccessKeyId => ("an AWS access key", "AWS 액세스 키"),
        SecretKind::GithubToken => ("a GitHub token", "GitHub 토큰"),
        SecretKind::PrivateKey => ("a private key", "개인 키"),
    };
    pick(lang, en, ko)
}

fn secret_risk(kind: SecretKind, lang: Lang) -> &'static str {
    let (en, ko) = match kind {
        SecretKind::SupabaseServiceRoleKey | SecretKind::SupabaseSecretKey => (
            "This admin key skips RLS and can read, change and delete all data in your database.",
            "이 키는 RLS를 무시하고 데이터베이스의 모든 데이터를 읽고, 고치고, 지울 수 있는 관리자 키예요.",
        ),
        SecretKind::DatabaseUrl => (
            "Anyone with this URL can connect to your database directly and do anything with the data.",
            "이 주소만 있으면 데이터베이스에 직접 접속해 모든 데이터를 다룰 수 있어요.",
        ),
        SecretKind::StripeSecretKey => (
            "This key can create charges, issue refunds and read customer details.",
            "이 키로 결제를 만들거나 환불하고 고객 정보를 볼 수 있어요.",
        ),
        SecretKind::OpenAiApiKey | SecretKind::AnthropicApiKey => (
            "Anyone can call the AI API with this key and the bill goes to your account.",
            "다른 사람이 이 키로 AI API를 호출하면 요금이 내 계정으로 청구돼요.",
        ),
        SecretKind::AwsAccessKeyId => (
            "This key can use your AWS resources with every permission it was given.",
            "이 키에 연결된 권한만큼 AWS 자원을 마음대로 쓸 수 있어요.",
        ),
        SecretKind::GithubToken => (
            "This token can read or change repository code with every permission it was given.",
            "이 토큰의 권한만큼 저장소 코드를 읽거나 바꿀 수 있어요.",
        ),
        SecretKind::PrivateKey => (
            "This key can sign data or decrypt protected traffic.",
            "이 키로 서명하거나 암호화된 통신을 풀 수 있어요.",
        ),
    };
    pick(lang, en, ko)
}

fn rotate(lang: Lang) -> &'static str {
    pick(
        lang,
        "Revoke the key now and issue a new one. Deleting it from the code cannot undo a key that has already leaked.",
        "키를 지금 바로 폐기하고 새로 발급하세요. 코드에서 지우는 것만으로는 이미 노출된 키를 되돌릴 수 없어요.",
    )
}

fn pick(lang: Lang, en: &'static str, ko: &'static str) -> &'static str {
    match lang {
        Lang::En => en,
        Lang::Ko => ko,
    }
}

fn secret_text(kind: SecretKind, title: [String; 2], why: [&str; 2], fix: [&str; 2]) -> Text {
    let [title_en, title_ko] = title;
    let [why_en, why_ko] = why;
    let [fix_en, fix_ko] = fix;
    Text {
        title: LocalizedText {
            en: title_en,
            ko: title_ko,
        },
        explanation: LocalizedText {
            en: format!(
                "{why_en} {} {} {fix_en}",
                secret_risk(kind, Lang::En),
                rotate(Lang::En)
            ),
            ko: format!(
                "{why_ko} {} {} {fix_ko}",
                secret_risk(kind, Lang::Ko),
                rotate(Lang::Ko)
            ),
        },
    }
}

pub(crate) fn secret_in_browser(kind: SecretKind, file: &str) -> Text {
    let file = display_name(file);
    secret_text(
        kind,
        [
            format!(
                "`{file}` sends {} to the browser",
                secret_label(kind, Lang::En)
            ),
            format!(
                "브라우저로 전달되는 `{file}` 파일에 비밀 값({})이 들어 있어요",
                secret_label(kind, Lang::Ko)
            ),
        ],
        [
            "This file is delivered to the browser of every visitor, and anyone can pull the value out with the developer tools.",
            "이 파일은 방문자의 브라우저로 그대로 전달돼요. 개발자 도구만 열면 누구나 이 값을 꺼낼 수 있어요.",
        ],
        [
            "Use the new key only on a server or in an Edge Function.",
            "새 키는 서버나 Edge Function에서만 쓰도록 옮겨야 해요.",
        ],
    )
}

pub(crate) fn secret_in_public_env(kind: SecretKind, var: &str) -> Text {
    let var = display_name(var);
    secret_text(
        kind,
        [
            format!(
                "The `{var}` env variable holds {}",
                secret_label(kind, Lang::En)
            ),
            format!(
                "`{var}` 환경변수에 비밀 값({})이 들어 있어요",
                secret_label(kind, Lang::Ko)
            ),
        ],
        [
            "Env variables whose names start with a public prefix are copied into browser code when the app is built.",
            "이름이 공개 접두사로 시작하는 환경변수는 빌드할 때 브라우저 코드에 그대로 들어가요.",
        ],
        [
            "Give the new key a name without the public prefix and read it only in server code.",
            "새 키는 공개 접두사가 없는 이름으로 바꾸고 서버 쪽 코드에서만 읽어야 해요.",
        ],
    )
}

pub(crate) fn secret_in_source(kind: SecretKind, file: &str) -> Text {
    let file = display_name(file);
    secret_text(
        kind,
        [
            format!(
                "`{file}` has {} written in it",
                secret_label(kind, Lang::En)
            ),
            format!(
                "`{file}` 파일에 비밀 값({})이 직접 적혀 있어요",
                secret_label(kind, Lang::Ko)
            ),
        ],
        [
            "Values written in code or config files are visible to everyone who can see the repository.",
            "코드나 설정 파일에 적힌 값은 저장소를 볼 수 있는 모든 사람에게 노출돼요.",
        ],
        [
            "Keep the new key in an env file that is not committed or in the secret settings of your host.",
            "새 키는 커밋하지 않는 환경변수 파일이나 배포 환경의 비밀 설정에 넣으세요.",
        ],
    )
}

#[cfg(test)]
mod tests {
    use seethru_core::{PolicyCommand, SecretKind};

    use super::{
        Text, display_name, policy_unrestricted, rls_disabled, secret_in_browser,
        secret_in_public_env, secret_in_source, service_role_in_browser,
    };

    const SECRET_KINDS: [SecretKind; 9] = [
        SecretKind::SupabaseServiceRoleKey,
        SecretKind::SupabaseSecretKey,
        SecretKind::DatabaseUrl,
        SecretKind::StripeSecretKey,
        SecretKind::OpenAiApiKey,
        SecretKind::AnthropicApiKey,
        SecretKind::AwsAccessKeyId,
        SecretKind::GithubToken,
        SecretKind::PrivateKey,
    ];

    const COMMANDS: [PolicyCommand; 5] = [
        PolicyCommand::All,
        PolicyCommand::Select,
        PolicyCommand::Insert,
        PolicyCommand::Update,
        PolicyCommand::Delete,
    ];

    fn every_text() -> Vec<Text> {
        let mut texts = vec![
            rls_disabled("todos"),
            service_role_in_browser("VITE_SUPABASE_SERVICE_ROLE_KEY", "VITE_"),
        ];
        for command in COMMANDS {
            for anyone in [true, false] {
                texts.push(policy_unrestricted("posts", "Edit posts", anyone, command));
            }
        }
        for kind in SECRET_KINDS {
            texts.push(secret_in_browser(kind, "dist/app.js"));
            texts.push(secret_in_public_env(kind, "VITE_KEY"));
            texts.push(secret_in_source(kind, "src/pay.ts"));
        }
        texts
    }

    fn has_hangul(text: &str) -> bool {
        text.chars().any(|c| ('\u{AC00}'..='\u{D7A3}').contains(&c))
    }

    fn names(text: &str) -> Vec<&str> {
        let mut names: Vec<&str> = text.split('`').skip(1).step_by(2).collect();
        names.sort_unstable();
        names
    }

    #[test]
    fn every_text_is_written_in_english_and_korean_with_the_same_names() {
        for text in every_text() {
            for part in [&text.title, &text.explanation] {
                assert!(!part.en.is_empty() && !has_hangul(&part.en), "{part:?}");
                assert!(has_hangul(&part.ko), "{part:?}");
                assert_eq!(names(&part.en), names(&part.ko), "{part:?}");
                assert!(!part.ko.contains('\u{2014}'), "{part:?}");
            }
        }
    }

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
