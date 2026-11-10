use seethru_core::{Lang, Limitation, LimitationCode, LocalizedText, PolicyCommand, SecretKind};

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
    login_only: bool,
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
                "{} so {who_en} can {what_en} in the `{table}` table. \
                 The condition should usually allow only the user's own rows, such as `auth.uid() = user_id`. \
                 If you made this policy to share the table with everyone on purpose, you can leave it as it is.",
                if login_only {
                    "The condition of this policy only checks that the user is signed in,"
                } else {
                    "The condition of this policy is always true,"
                }
            ),
            ko: format!(
                "{} {who_ko} `{table}` 테이블에서 {what_ko}. \
                 보통은 `auth.uid() = user_id`처럼 본인 행만 허용하는 조건이 필요해요. \
                 모두에게 공개하려고 일부러 만든 정책이라면 그대로 두어도 괜찮아요.",
                if login_only {
                    "이 정책은 조건이 로그인했는지만 확인해서"
                } else {
                    "이 정책은 조건이 항상 참(true)이라서"
                }
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

pub(crate) fn table_schema_missing(table: &str) -> Text {
    let table = display_name(table);
    Text {
        title: LocalizedText {
            en: format!("The `{table}` table has no schema in this repo"),
            ko: format!("`{table}` 테이블의 스키마가 저장소에 없어요"),
        },
        explanation: LocalizedText {
            en: format!(
                "Your code uses the `{table}` table, but no SQL file in this repo creates it or turns RLS on, \
                 so seethru cannot tell whether RLS protects it. A table made in the Supabase dashboard \
                 is open to anyone with the anon key until RLS is turned on. Check the table in the dashboard, \
                 or save the schema in the repo with `supabase db dump` so seethru can check it."
            ),
            ko: format!(
                "코드에서 `{table}` 테이블을 쓰지만 저장소의 SQL 파일 어디에도 이 테이블을 만들거나 RLS를 켜는 부분이 없어서, \
                 RLS가 보호하고 있는지 알 수 없어요. Supabase 대시보드에서 만든 테이블은 RLS를 켜기 전까지 \
                 anon 키만 있으면 누구나 접근할 수 있어요. 대시보드에서 이 테이블을 확인하거나, \
                 `supabase db dump`로 스키마를 저장소에 저장하면 seethru가 검사할 수 있어요."
            ),
        },
    }
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

fn who(anyone: bool) -> (&'static str, &'static str) {
    if anyone {
        (
            "anyone, even people who are not signed in,",
            "로그인하지 않은 사람을 포함한 누구나",
        )
    } else {
        ("any signed-in user", "로그인한 사용자라면 누구나")
    }
}

pub(crate) struct FunctionFacts {
    pub anyone: bool,
    pub checks_caller: bool,
    pub yes_or_no: bool,
}

pub(crate) fn function_bypasses_rls(function: &str, facts: &FunctionFacts) -> Text {
    let function = display_name(function);
    let (who_en, who_ko) = who(facts.anyone);
    let (title_en, title_ko) = if facts.anyone {
        (
            format!("Anyone can call the `{function}` function, which skips RLS"),
            format!("누구나 RLS를 건너뛰는 `{function}` 함수를 부를 수 있어요"),
        )
    } else {
        (
            format!("Any signed-in user can call the `{function}` function, which skips RLS"),
            format!("로그인한 사용자라면 누구나 RLS를 건너뛰는 `{function}` 함수를 부를 수 있어요"),
        )
    };
    let (caller_en, caller_ko) = if facts.checks_caller {
        (
            "The function looks at who is calling it, for example with `auth.uid()`, so it may already be safe. Check that it refuses callers who should not use it.",
            "이 함수는 `auth.uid()` 같은 방법으로 누가 부르는지 확인하고 있어서 이미 안전할 수도 있어요. 쓰면 안 되는 사람이 부르면 거절하는지 확인하세요.",
        )
    } else if facts.yes_or_no {
        (
            "The function only answers yes or no, so callers learn little from one call, but they can still use it to find out whether rows they cannot see exist.",
            "이 함수는 예 또는 아니오만 돌려줘서 한 번 불러서 알 수 있는 것은 적지만, 볼 수 없는 행이 있는지 알아내는 데는 쓸 수 있어요.",
        )
    } else {
        (
            "The function does not check who is calling it, so callers can use it to read or change data that RLS would block.",
            "이 함수는 누가 부르는지 확인하지 않아서, RLS가 막는 데이터도 이 함수를 거치면 읽거나 고칠 수 있어요.",
        )
    };
    Text {
        title: LocalizedText {
            en: title_en,
            ko: title_ko,
        },
        explanation: LocalizedText {
            en: format!(
                "This function is made with `security definer`, so it runs with the rights of the account that created it, \
                 and RLS does not apply to anything it reads or changes. {} can call it through the Supabase API with `rpc()`. \
                 {caller_en} If only the database itself should use the function, for example a trigger or a policy, \
                 take away the right to call it from outside. Otherwise make it `security invoker` so RLS applies, \
                 or check the caller inside the function.",
                capitalized(who_en)
            ),
            ko: format!(
                "이 함수는 `security definer`로 만들어져서 만든 계정의 권한으로 실행되고, 함수 안에서 읽고 고치는 데이터에는 RLS가 적용되지 않아요. \
                 {who_ko} Supabase API의 `rpc()`로 이 함수를 부를 수 있어요. {caller_ko} \
                 트리거나 정책처럼 데이터베이스 안에서만 쓰는 함수라면 바깥에서 부를 수 없게 실행 권한을 거두세요. \
                 그렇지 않다면 `security invoker`로 바꿔 RLS가 적용되게 하거나, 함수 안에서 부른 사람을 확인하세요."
            ),
        },
    }
}

pub(crate) struct ViewFacts {
    pub anyone: bool,
    pub materialized: bool,
    pub auth_users: bool,
    pub checks_caller: bool,
}

pub(crate) fn view_bypasses_rls(view: &str, facts: &ViewFacts) -> Text {
    let view = display_name(view);
    let (who_en, who_ko) = who(facts.anyone);
    let (title_en, title_ko) = if facts.auth_users {
        (
            format!("The `{view}` view shows the accounts of your users"),
            format!("`{view}` 뷰가 회원 계정 정보를 보여 주고 있어요"),
        )
    } else {
        (
            format!("The `{view}` view shows rows that RLS would hide"),
            format!("`{view}` 뷰가 RLS가 가려야 할 행을 보여 주고 있어요"),
        )
    };
    let (how_en, how_ko) = if facts.materialized {
        (
            format!(
                "A materialized view keeps its own copy of the rows and has no RLS, so {who_en} can read every row in it through the Supabase API."
            ),
            format!(
                "materialized view는 행을 따로 복사해 두고 RLS가 없어서, {who_ko} Supabase API로 이 뷰의 모든 행을 읽을 수 있어요."
            ),
        )
    } else {
        (
            format!(
                "A view runs with the rights of the account that created it unless it is made with `security_invoker`, \
                 so the RLS policies of the tables behind it do not apply. {} can read it through the Supabase API and see every row it returns.",
                capitalized(who_en)
            ),
            format!(
                "뷰는 `security_invoker`로 만들지 않으면 만든 계정의 권한으로 실행돼서, 뷰가 읽는 테이블의 RLS 정책이 적용되지 않아요. \
                 {who_ko} Supabase API로 이 뷰를 읽어 뷰가 돌려주는 모든 행을 볼 수 있어요."
            ),
        )
    };
    let (users_en, users_ko) = if facts.auth_users {
        (
            " It reads `auth.users`, which holds the email address and other account details of every user.",
            " 이 뷰는 모든 회원의 이메일 주소 같은 계정 정보가 담긴 `auth.users`를 읽어요.",
        )
    } else {
        ("", "")
    };
    let (caller_en, caller_ko) = if facts.checks_caller {
        (
            " The view looks at who is asking, for example with `auth.uid()`, so it may already show each user only their own rows. Check that it does.",
            " 이 뷰는 `auth.uid()` 같은 방법으로 누가 읽는지 확인하고 있어서 이미 본인 행만 보여 줄 수도 있어요. 정말 그런지 확인하세요.",
        )
    } else {
        ("", "")
    };
    let (fix_en, fix_ko) = if facts.materialized {
        (
            " Move it to a schema that the API does not expose, or take away the right to read it from signed-out and signed-in users.",
            " API가 공개하지 않는 스키마로 옮기거나, 로그인하지 않은 사용자와 로그인한 사용자에게서 읽기 권한을 거두세요.",
        )
    } else {
        (
            " Make it again with `security_invoker` so RLS applies to the person who reads it, or take away the right to read it.",
            " `security_invoker`로 다시 만들어 읽는 사람 기준으로 RLS가 적용되게 하거나, 읽기 권한을 거두세요.",
        )
    };
    Text {
        title: LocalizedText {
            en: title_en,
            ko: title_ko,
        },
        explanation: LocalizedText {
            en: format!("{how_en}{users_en}{caller_en}{fix_en}"),
            ko: format!("{how_ko}{users_ko}{caller_ko}{fix_ko}"),
        },
    }
}

pub(crate) fn storage_policy_unrestricted(
    policy: &str,
    buckets: &[String],
    anyone: bool,
    command: PolicyCommand,
) -> Text {
    let policy = display_name(policy);
    let (who_en, who_ko) = who(anyone);
    let names: Vec<String> = buckets
        .iter()
        .map(|bucket| format!("`{}`", display_name(bucket)))
        .collect();
    let (where_en, where_ko) = match names.as_slice() {
        [] => ("every bucket".to_owned(), "모든 버킷".to_owned()),
        [one] => (format!("the {one} bucket"), format!("{one} 버킷")),
        many => (
            format!("the {} buckets", many.join(", ")),
            format!("{} 버킷", many.join(", ")),
        ),
    };
    let (what_en, what_ko) = match command {
        PolicyCommand::All => (
            "download, replace and delete every file",
            "모든 파일을 내려받고, 바꾸고, 지울 수 있어요",
        ),
        PolicyCommand::Select => ("download every file", "모든 파일을 내려받을 수 있어요"),
        PolicyCommand::Insert => ("upload any file", "아무 파일이나 올릴 수 있어요"),
        PolicyCommand::Update => (
            "replace files that belong to other people",
            "다른 사람의 파일까지 바꿀 수 있어요",
        ),
        PolicyCommand::Delete => (
            "delete files that belong to other people",
            "다른 사람의 파일까지 지울 수 있어요",
        ),
    };
    Text {
        title: LocalizedText {
            en: format!("The `{policy}` policy opens every file in {where_en}"),
            ko: format!("`{policy}` 정책이 {where_ko}의 모든 파일을 열어 두고 있어요"),
        },
        explanation: LocalizedText {
            en: format!(
                "This storage policy does not check whose file it is, so {who_en} can {what_en} in {where_en}. \
                 The condition should usually allow only the user's own files, for example files in a folder named after the user. \
                 If the files are meant to be shared with everyone, you can leave it as it is."
            ),
            ko: format!(
                "이 스토리지 정책은 누구의 파일인지 확인하지 않아서 {who_ko} {where_ko}에서 {what_ko}. \
                 보통은 사용자 이름으로 된 폴더처럼 본인 파일만 허용하는 조건이 필요해요. \
                 모두에게 공개하려고 일부러 만든 정책이라면 그대로 두어도 괜찮아요."
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKind {
    Route,
    ServerAction,
    EdgeFunction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reached<'a> {
    ReadTable(&'a str),
    WriteTable(&'a str),
    ReadBucket(&'a str),
    WriteBucket(&'a str),
    Rpc(&'a str),
    Admin(&'a str),
}

pub(crate) fn service_role_unguarded(
    kind: EntryKind,
    entry: &str,
    reached: Reached<'_>,
    more: usize,
) -> Text {
    let entry = display_name(entry);
    let (what_en, what_ko) = match reached {
        Reached::ReadTable(table) => {
            let table = display_name(table);
            (
                format!("read rows from `{table}`"),
                format!("`{table}` 테이블의 행을 읽어요"),
            )
        }
        Reached::WriteTable(table) => {
            let table = display_name(table);
            (
                format!("change rows in `{table}`"),
                format!("`{table}` 테이블의 행을 바꿔요"),
            )
        }
        Reached::ReadBucket(bucket) => {
            let bucket = display_name(bucket);
            (
                format!("read files in the `{bucket}` bucket"),
                format!("`{bucket}` 버킷의 파일을 읽어요"),
            )
        }
        Reached::WriteBucket(bucket) => {
            let bucket = display_name(bucket);
            (
                format!("change files in the `{bucket}` bucket"),
                format!("`{bucket}` 버킷의 파일을 바꿔요"),
            )
        }
        Reached::Rpc(function) => {
            let function = display_name(function);
            (
                format!("call the `{function}` database function"),
                format!("`{function}` 데이터베이스 함수를 불러요"),
            )
        }
        Reached::Admin(method) => {
            let method = display_name(method);
            (
                format!("use `auth.admin.{method}`, which manages user accounts"),
                format!("사용자 계정을 관리하는 `auth.admin.{method}`를 써요"),
            )
        }
    };
    let (how_en, how_ko) = match kind {
        EntryKind::Route => (
            "Anyone who sends a request to this URL can do it.",
            "이 URL로 요청을 보내는 사람은 누구나 이 일을 할 수 있어요.",
        ),
        EntryKind::ServerAction => (
            "Anyone can call a server action with a plain POST request, even when no page shows the button.",
            "server action은 버튼을 보여 주는 페이지가 없어도 누구나 POST 요청 하나로 부를 수 있어요.",
        ),
        EntryKind::EdgeFunction => (
            "Supabase lets a request in when it carries your project's public key, so that alone does not tell who is calling. Anyone can do it.",
            "Supabase는 요청에 프로젝트의 공개 키만 있어도 들여보내서, 그것만으로는 누가 부르는지 알 수 없어요. 누구나 이 일을 할 수 있어요.",
        ),
    };
    let (more_en, more_ko) = match more {
        0 => (String::new(), String::new()),
        1 => (
            " It also reaches 1 other database call made with that key.".to_owned(),
            " 같은 키로 하는 데이터베이스 호출이 1개 더 있어요.".to_owned(),
        ),
        count => (
            format!(" It also reaches {count} other database calls made with that key."),
            format!(" 같은 키로 하는 데이터베이스 호출이 {count}개 더 있어요."),
        ),
    };
    Text {
        title: LocalizedText {
            en: format!("`{entry}` uses the service_role key without checking who is calling"),
            ko: format!("`{entry}`가 누가 부르는지 확인하지 않고 service_role 키를 써요"),
        },
        explanation: LocalizedText {
            en: format!(
                "`{entry}` runs code that uses the Supabase service_role key, which skips Row Level Security, \
                 to {what_en}. No check of who is calling was found before that happens. {how_en}{more_en} \
                 Check the signed-in user first, for example with `supabase.auth.getUser()`, and stop when there is none. \
                 If this must stay open, like a webhook, check the request's signature before touching data."
            ),
            ko: format!(
                "`{entry}`는 Row Level Security를 건너뛰는 Supabase service_role 키로 {what_ko}. \
                 그 전에 누가 부르는지 확인하는 코드를 찾지 못했어요. {how_ko}{more_ko} \
                 `supabase.auth.getUser()` 같은 방법으로 로그인한 사용자를 먼저 확인하고, 없으면 멈추세요. \
                 웹훅처럼 열어 둬야 한다면 데이터를 건드리기 전에 요청의 서명을 확인하세요."
            ),
        },
    }
}

const CWE_NAMES: &[(&[u32], &str, &str)] = &[
    (
        &[22, 23, 36],
        "a file path that can be steered outside its folder",
        "폴더 밖으로 벗어날 수 있는 파일 경로",
    ),
    (&[77, 78, 88], "command injection", "명령 주입"),
    (
        &[79, 80],
        "cross-site scripting",
        "교차 사이트 스크립팅(XSS)",
    ),
    (&[89], "SQL injection", "SQL 주입"),
    (&[94, 95], "code injection", "코드 주입"),
    (
        &[119, 120, 121, 122, 125, 787, 788],
        "memory access outside a buffer",
        "버퍼를 벗어난 메모리 접근",
    ),
    (
        &[134],
        "a format string that input can control",
        "입력이 바꿀 수 있는 형식 문자열",
    ),
    (&[190, 191], "a number overflow", "정수 넘침"),
    (&[200, 209, 532], "information exposure", "정보 노출"),
    (
        &[287, 306],
        "a missing or broken sign-in check",
        "빠졌거나 잘못된 로그인 확인",
    ),
    (
        &[295, 297],
        "a missing certificate check",
        "인증서 확인 누락",
    ),
    (&[326, 327, 328], "weak cryptography", "약한 암호 사용"),
    (&[330, 338], "weak random numbers", "예측할 수 있는 난수"),
    (
        &[352],
        "cross-site request forgery",
        "사이트 간 요청 위조(CSRF)",
    ),
    (&[415, 416], "use of freed memory", "해제한 메모리 사용"),
    (&[476], "use of an empty pointer", "빈 포인터 사용"),
    (
        &[502],
        "unsafe loading of untrusted data",
        "믿을 수 없는 데이터의 안전하지 않은 해석",
    ),
    (&[601], "an open redirect", "열린 리다이렉트"),
    (&[611], "unsafe XML loading", "안전하지 않은 XML 해석"),
    (
        &[798, 259, 321],
        "a secret written into the code",
        "코드에 적힌 비밀 값",
    ),
    (
        &[862, 863, 285, 639],
        "a missing permission check",
        "권한 확인 누락",
    ),
    (
        &[918],
        "server-side request forgery",
        "서버 쪽 요청 위조(SSRF)",
    ),
];

pub(crate) fn cwe_name(cwe: &[u32]) -> Option<(&'static str, &'static str)> {
    cwe.iter().find_map(|number| {
        CWE_NAMES
            .iter()
            .find(|(numbers, _, _)| numbers.contains(number))
            .map(|(_, en, ko)| (*en, *ko))
    })
}

pub(crate) fn external(engine: &str, rule: &str, cwe: &[u32], path: &str, line: u32) -> Text {
    let file = display_name(crate::classify::file_name(path));
    let path = display_name(path);
    let (title_en, title_ko) = match cwe_name(cwe) {
        Some((en, ko)) => (
            format!("An outside scanner ({engine}) reported possible {en} in `{file}`"),
            format!("외부 검사 도구({engine})가 `{file}`에서 {ko} 가능성을 알렸어요"),
        ),
        None => (
            format!("An outside scanner ({engine}) reported a possible problem in `{file}`"),
            format!("외부 검사 도구({engine})가 `{file}`에서 문제 가능성을 알렸어요"),
        ),
    };
    let numbers = cwe
        .iter()
        .map(|number| format!("CWE-{number}"))
        .collect::<Vec<_>>()
        .join(", ");
    let (class_en, class_ko) = if numbers.is_empty() {
        (String::new(), String::new())
    } else {
        (
            format!(" It classed the problem as {numbers}."),
            format!(" 문제 종류는 {numbers}로 분류했어요."),
        )
    };
    Text {
        title: LocalizedText {
            en: title_en,
            ko: title_ko,
        },
        explanation: LocalizedText {
            en: format!(
                "The scanner {engine} flagged line {line} of `{path}` with its rule `{rule}`.{class_en} This result comes from that scanner and seethru did not check it itself. Treat it as a lead and look at the code before you change anything."
            ),
            ko: format!(
                "검사 도구 {engine}가 `{path}`의 {line}번째 줄을 자기 규칙 `{rule}`로 알렸어요.{class_ko} 이 결과는 그 도구가 낸 것이고 seethru가 직접 확인한 것은 아니에요. 단서로 삼고, 고치기 전에 코드를 먼저 확인하세요."
            ),
        },
    }
}

pub(crate) struct RiskyOption {
    pub key: &'static str,
    pub severity: seethru_core::Severity,
    pub rule: seethru_core::RuleId,
    en: &'static str,
    ko: &'static str,
}

const fn risky(key: &'static str, high: bool, en: &'static str, ko: &'static str) -> RiskyOption {
    RiskyOption {
        key,
        severity: if high {
            seethru_core::Severity::High
        } else {
            seethru_core::Severity::Medium
        },
        rule: seethru_core::RuleId::FirmwareInsecureOptionOn,
        en,
        ko,
    }
}

pub(crate) const RISKY_OPTIONS: &[RiskyOption] = &[
    risky(
        "CONFIG_SECURE_BOOT_INSECURE",
        true,
        "It allows secure boot settings that are meant only for testing, so the device may start firmware that is not yours.",
        "테스트용으로만 쓰는 secure boot 설정을 허용해서, 기기가 내 것이 아닌 펌웨어로 시작할 수 있어요.",
    ),
    risky(
        "CONFIG_SECURE_BOOT_ALLOW_JTAG",
        true,
        "It leaves the JTAG debug port open, so someone holding the device can read and change what runs on it.",
        "JTAG 디버그 포트를 열어 두어서, 기기를 손에 넣은 사람이 실행 중인 내용을 읽고 바꿀 수 있어요.",
    ),
    risky(
        "CONFIG_SECURE_BOOT_ALLOW_ROM_BASIC",
        true,
        "It leaves the built-in ROM console available, which gives someone holding the device a way around secure boot.",
        "칩에 내장된 ROM 콘솔을 쓸 수 있게 두어서, 기기를 손에 넣은 사람이 secure boot를 피해 갈 수 있어요.",
    ),
    risky(
        "CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC",
        true,
        "It lets the serial bootloader write encrypted flash, so someone with a cable can replace the firmware.",
        "시리얼 부트로더가 암호화된 flash에 쓸 수 있게 해서, 케이블만 있으면 펌웨어를 바꿀 수 있어요.",
    ),
    risky(
        "CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_DEC",
        true,
        "It lets the serial bootloader decrypt flash, so someone with a cable can read the firmware and the secrets stored in it.",
        "시리얼 부트로더가 flash를 복호화할 수 있게 해서, 케이블만 있으면 펌웨어와 그 안의 비밀 값을 읽을 수 있어요.",
    ),
    risky(
        "CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_CACHE",
        true,
        "It keeps the flash cache on in the serial bootloader, which helps someone with a cable read encrypted flash.",
        "시리얼 부트로더에서 flash 캐시를 켜 두어서, 케이블로 암호화된 flash를 읽기 쉬워져요.",
    ),
    risky(
        "CONFIG_SECURE_INSECURE_ALLOW_DL_MODE",
        false,
        "It keeps the serial download mode open even though security features are on.",
        "보안 기능을 켰는데도 시리얼 다운로드 모드를 열어 둬요.",
    ),
    risky(
        "CONFIG_BT_NIMBLE_SM_SC_DEBUG_KEYS",
        true,
        "It makes Bluetooth pairing use a debug key that everyone knows, so nearby people can read the connection.",
        "Bluetooth 페어링이 누구나 아는 디버그 키를 쓰게 해서, 근처 사람이 연결 내용을 읽을 수 있어요.",
    ),
    risky(
        "CONFIG_BT_USE_DEBUG_KEYS",
        true,
        "It makes Bluetooth pairing use a debug key that everyone knows, so nearby people can read the connection.",
        "Bluetooth 페어링이 누구나 아는 디버그 키를 쓰게 해서, 근처 사람이 연결 내용을 읽을 수 있어요.",
    ),
    risky(
        "CONFIG_BT_STORE_DEBUG_KEYS",
        false,
        "It lets the device keep Bluetooth pairings that were made with a debug key everyone knows.",
        "누구나 아는 디버그 키로 맺은 Bluetooth 페어링을 기기가 저장하게 해요.",
    ),
    risky(
        "CONFIG_BT_SMP_ALLOW_UNAUTH_OVERWRITE",
        false,
        "It lets a new Bluetooth pairing that was not verified replace an existing one, so a nearby device can take over a trusted pairing.",
        "확인되지 않은 새 Bluetooth 페어링이 기존 페어링을 덮어쓸 수 있어서, 근처 기기가 신뢰된 페어링을 가로챌 수 있어요.",
    ),
    RiskyOption {
        key: "CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP",
        severity: seethru_core::Severity::High,
        rule: seethru_core::RuleId::FirmwareOtaOverHttp,
        en: "It lets firmware updates download over plain HTTP, so someone on the same network can swap the update for their own.",
        ko: "펌웨어 업데이트를 암호화되지 않은 HTTP로 받을 수 있게 해서, 같은 네트워크의 누군가가 업데이트를 자기 것으로 바꿔치기할 수 있어요.",
    },
    RiskyOption {
        key: "CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY",
        severity: seethru_core::Severity::High,
        rule: seethru_core::RuleId::FirmwareTlsVerificationOff,
        en: "It lets the device skip checking the server's certificate, so a fake server would be accepted.",
        ko: "기기가 서버 인증서 확인을 건너뛸 수 있게 해서, 가짜 서버도 받아들이게 돼요.",
    },
];

pub(crate) fn risky_option(option: &RiskyOption, file: &str) -> Text {
    let key = option.key;
    let file = display_name(file);
    Text {
        title: LocalizedText {
            en: format!("`{key}` is turned on in `{file}`"),
            ko: format!("`{file}`에서 `{key}`가 켜져 있어요"),
        },
        explanation: LocalizedText {
            en: format!(
                "{} If this is only for development, keep it out of the settings you ship.",
                option.en
            ),
            ko: format!(
                "{} 개발할 때만 쓰는 설정이라면 배포하는 설정에서는 빼세요.",
                option.ko
            ),
        },
    }
}

pub(crate) fn secret_in_native(kind: SecretKind, file: &str, firmware: bool) -> Text {
    let file = display_name(file);
    let (reach_en, reach_ko) = if firmware {
        (
            "Firmware is copied onto every device, and anyone who holds a device or the firmware file can read values written in it.",
            "펌웨어는 모든 기기에 그대로 들어가고, 기기나 펌웨어 파일을 가진 사람은 그 안에 적힌 값을 읽을 수 있어요.",
        )
    } else {
        (
            "Values written in a program are visible to everyone who can see the repository or who receives the built program.",
            "프로그램에 적힌 값은 저장소를 볼 수 있거나 빌드된 프로그램을 받은 모든 사람에게 노출돼요.",
        )
    };
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
        [reach_en, reach_ko],
        [
            "Do not build the new key into the program. Load it at run time from storage that is not in the repository.",
            "새 키는 프로그램에 넣어 빌드하지 말고, 저장소에 없는 저장 공간에서 실행할 때 읽게 하세요.",
        ],
    )
}

pub(crate) fn ota_unguarded(entry: &str, more: usize) -> Text {
    let entry = display_name(entry);
    let (more_en, more_ko) = if more > 0 {
        (
            format!(" {more} more code paths from this entry point do the same."),
            format!(" 이 진입점에서 같은 일을 하는 코드 경로가 {more}개 더 있어요."),
        )
    } else {
        (String::new(), String::new())
    };
    Text {
        title: LocalizedText {
            en: format!("`{entry}` accepts new firmware without checking who is sending it"),
            ko: format!("`{entry}`가 누가 보내는지 확인하지 않고 새 펌웨어를 받아요"),
        },
        explanation: LocalizedText {
            en: format!(
                "The handler for `{entry}` writes a firmware update to the device, and no check of the caller was found before that happens. Anyone who can reach the device over the network may be able to replace its firmware.{more_en} Who can reach the device, and whether the chip enforces update signatures, cannot be seen from the code."
            ),
            ko: format!(
                "`{entry}`의 처리 함수가 기기에 펌웨어 업데이트를 쓰는데, 그 전에 부른 쪽을 확인하는 코드를 찾지 못했어요. 네트워크로 기기에 닿을 수 있는 사람이면 누구나 펌웨어를 바꿀 수 있어요.{more_ko} 누가 기기에 닿을 수 있는지, 칩에서 업데이트 서명을 강제하는지는 코드만으로 알 수 없어요."
            ),
        },
    }
}

pub(crate) fn secret_dependent_division(file: &str, line: u32, confirmed: bool) -> Text {
    let file = display_name(file);
    let (seen_en, seen_ko) = if confirmed {
        (
            "The machine code that was built has a division instruction for this line.",
            "빌드된 기계어에 이 줄의 나눗셈 명령이 들어 있어요.",
        )
    } else {
        (
            "No machine code could be matched to this line, so check whether the compiler kept the division.",
            "이 줄에 맞는 기계어를 찾지 못했으니, 컴파일러가 나눗셈을 그대로 뒀는지 확인하세요.",
        )
    };
    Text {
        title: LocalizedText {
            en: format!("A secret value is divided at line {line} of `{file}`"),
            ko: format!("`{file}` {line}번째 줄에서 비밀 값으로 나눗셈을 해요"),
        },
        explanation: LocalizedText {
            en: format!(
                "How long a processor takes to divide depends on the numbers it is given. The compiled code divides a value that comes from memory the program wipes after use, and that is how seethru recognizes a secret. Someone who can measure how long this code takes may learn part of the secret. {seen_en} If the value is not secret, accept this finding in `seethru.toml` with a reason."
            ),
            ko: format!(
                "프로세서가 나눗셈에 쓰는 시간은 숫자에 따라 달라져요. 컴파일된 코드가 프로그램이 쓰고 나서 지우는 메모리에서 나온 값을 나누고 있고, seethru는 그렇게 지우는 값을 비밀로 봐요. 이 코드가 걸리는 시간을 잴 수 있는 사람은 비밀의 일부를 알아낼 수 있어요. {seen_ko} 비밀이 아닌 값이라면 `seethru.toml`에 사유를 적고 이 탐지를 받아들이세요."
            ),
        },
    }
}

pub(crate) fn cargo_dependency_not_pinned(name: &str, manifest: &str, git: bool) -> Text {
    let name = display_name(name);
    let manifest = display_name(manifest);
    let (how_en, how_ko) = if git {
        (
            format!(
                "`{name}` is downloaded from a git repository without a fixed commit, and this project has no `Cargo.lock`. A build can pull code that was pushed after you last looked at it. Fix it to one commit with `rev`, or commit `Cargo.lock`."
            ),
            format!(
                "`{name}`을 git 저장소에서 받는데 커밋이 고정돼 있지 않고, 이 프로젝트에는 `Cargo.lock`도 없어요. 빌드할 때마다 마지막으로 확인한 뒤에 올라온 코드를 받을 수 있어요. `rev`로 커밋 하나에 고정하거나 `Cargo.lock`을 커밋하세요."
            ),
        )
    } else {
        (
            format!(
                "`{name}` accepts any version, and this project has no `Cargo.lock`. A build can pull a version nobody has looked at. Write the version you tested, or commit `Cargo.lock`."
            ),
            format!(
                "`{name}`이 아무 버전이나 받게 돼 있고, 이 프로젝트에는 `Cargo.lock`도 없어요. 빌드할 때 아무도 확인하지 않은 버전을 받을 수 있어요. 확인한 버전을 적거나 `Cargo.lock`을 커밋하세요."
            ),
        )
    };
    Text {
        title: LocalizedText {
            en: format!("`{name}` in `{manifest}` is not fixed to one version"),
            ko: format!("`{manifest}`의 `{name}`이 한 버전으로 고정돼 있지 않아요"),
        },
        explanation: LocalizedText {
            en: how_en,
            ko: how_ko,
        },
    }
}

pub(crate) fn limitation(code: LimitationCode) -> Limitation {
    let (en, ko) = match code {
        LimitationCode::BuildOutputNotRead => (
            "No build output was read, so whether a file reaches the browser is judged from folder names, `\"use client\"` and imports.",
            "빌드 결과물을 읽지 않았기 때문에, 파일이 브라우저로 가는지는 폴더 이름, `\"use client\"`, import로 판단했어요.",
        ),
        LimitationCode::BuildOutputStale => (
            "The build output is older than the source code, so it was not used. Build again and rerun the scan.",
            "빌드 결과물이 소스 코드보다 오래돼서 쓰지 않았어요. 다시 빌드한 뒤 검사하세요.",
        ),
        LimitationCode::BuildOutputWithoutSourceMaps => (
            "Some bundles in the build output have no source map, so only some files could be confirmed. Build with source maps on to confirm the rest.",
            "빌드 결과물에 소스맵이 없는 번들이 있어서 일부 파일만 확인했어요. 소스맵을 켜고 빌드하면 나머지도 확인할 수 있어요.",
        ),
        LimitationCode::DashboardPoliciesUnseen => (
            "Tables and policies made in the Supabase dashboard are not in this repo, so they were not checked.",
            "Supabase 대시보드에서 만든 테이블과 정책은 저장소에 없어서 확인하지 못했어요.",
        ),
        LimitationCode::FirmwareProtectionNotChecked => (
            "For firmware, only settings that are written in the project files were checked. Whether secure boot and flash encryption are on in the shipped device, and whether its fuses were burned, cannot be seen from the files.",
            "펌웨어는 프로젝트 파일에 적힌 설정만 확인했어요. 실제 기기에서 secure boot와 flash 암호화가 켜져 있는지, 퓨즈가 구워졌는지는 파일만으로 알 수 없어요.",
        ),
        LimitationCode::NativeCodePartlyRead => (
            "C and C++ files were read without building them, so macros, function pointers and generated code were not followed. Missing findings there do not mean the code is safe.",
            "C와 C++ 파일은 빌드하지 않고 읽었기 때문에 매크로, 함수 포인터, 생성된 코드는 따라가지 못했어요. 그 부분에 탐지가 없다고 안전하다는 뜻은 아니에요.",
        ),
        LimitationCode::ProjectKindNotRecognized => (
            "seethru did not recognize what kind of project this is, so it only looked for secret values written in files. No findings here does not mean the project is safe.",
            "seethru가 이 프로젝트의 종류를 알아보지 못해서 파일에 적힌 비밀 값만 찾았어요. 탐지가 없다고 안전하다는 뜻은 아니에요.",
        ),
        LimitationCode::CompiledOutputNotRead => (
            "This is a Rust project, and only its source and Cargo files were read. Whether a secret value affects timing can only be checked in compiled output. Build with `RUSTFLAGS=\"--emit=llvm-ir,asm -C debuginfo=line-tables-only\" cargo build --release` and pass the output folder with `--llvm-ir`. seethru never runs the build itself.",
            "Rust 프로젝트인데 소스와 Cargo 파일만 읽었어요. 비밀 값이 실행 시간에 영향을 주는지는 컴파일 결과에서만 확인할 수 있어요. `RUSTFLAGS=\"--emit=llvm-ir,asm -C debuginfo=line-tables-only\" cargo build --release`로 빌드한 뒤 결과 폴더를 `--llvm-ir`로 넘기세요. seethru는 빌드를 직접 실행하지 않아요.",
        ),
        LimitationCode::CompiledChecksPartial => (
            "In compiled output, seethru only checks whether a secret value reaches a division. Branches and table lookups that depend on a secret, and whether memory wipes survive the compiler, are not checked yet. A value counts as secret only when the code wipes the memory it is kept in with a call written in the code, such as `zeroize()`. Memory that a type wipes by itself when it is dropped does not count. Output of a library is from before the final link, so the shipped program can differ.",
            "컴파일 결과에서는 비밀 값이 나눗셈에 닿는지만 확인해요. 비밀에 따라 갈리는 분기와 표 조회, 메모리 소거가 컴파일 뒤에도 남는지는 아직 확인하지 않아요. 코드에 적힌 호출(예: `zeroize()`)로 쓰고 나서 지우는 메모리에 든 값만 비밀로 봐요. 타입이 drop될 때 알아서 지우는 메모리는 세지 않아요. 라이브러리의 결과는 최종 링크 전 단계라 실제 배포되는 프로그램과 다를 수 있어요.",
        ),
        LimitationCode::CompiledOutputWithoutMachineCode => (
            "Some compiled files had no machine code listing (`.s`) next to them, so findings there could not be confirmed and need review.",
            "컴파일 결과 중 일부는 옆에 기계어 목록(`.s`)이 없어서, 그 부분의 탐지는 확정하지 못했고 직접 확인이 필요해요.",
        ),
        LimitationCode::CompiledOutputNotOptimized => (
            "The compiled output looks like a debug build. Check a release build, because that is what ships and the compiler changes the code a lot on the way.",
            "컴파일 결과가 디버그 빌드로 보여요. 실제로 배포하는 것은 릴리스 빌드이고 컴파일러가 그 과정에서 코드를 많이 바꾸니, 릴리스 빌드로 확인하세요.",
        ),
        LimitationCode::CompiledOutputWithoutWipes => (
            "The compiled output has no memory wipe that is written as a call in the code, so nothing was treated as secret and nothing could be checked. This is normal when secrets are only wiped by their type on drop.",
            "컴파일 결과에 코드에 적힌 호출로 메모리를 지우는 곳이 없어서, 비밀로 본 값이 없고 확인한 것도 없어요. 비밀을 타입이 drop될 때만 지우는 코드에서는 이렇게 나와요.",
        ),
        LimitationCode::CompiledOutputPartlyRead => (
            "Part of the compiled output was left out because it was too large, could not be read, or points at files outside this project.",
            "컴파일 결과 중 일부는 너무 크거나 읽을 수 없거나 이 프로젝트 밖의 파일을 가리켜서 뺐어요.",
        ),
        LimitationCode::ExternalNotVerified => (
            "Results from outside scanners are shown as that scanner reported them. seethru did not check them itself.",
            "외부 검사 도구의 결과는 그 도구가 알린 그대로 보여 줘요. seethru가 직접 확인한 것은 아니에요.",
        ),
        LimitationCode::ExternalResultsDropped => (
            "Some results from outside scanners were left out because they point outside this project, at excluded files, or could not be read.",
            "외부 검사 도구의 결과 중 일부는 이 프로젝트 밖이나 제외한 파일을 가리키거나 읽을 수 없어서 뺐어요.",
        ),
    };
    Limitation {
        code,
        text: LocalizedText {
            en: en.to_owned(),
            ko: ko.to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use seethru_core::{PolicyCommand, SecretKind};

    use super::{
        EntryKind, FunctionFacts, Reached, Text, ViewFacts, display_name, function_bypasses_rls,
        policy_unrestricted, rls_disabled, secret_in_browser, secret_in_public_env,
        secret_in_source, service_role_in_browser, service_role_unguarded,
        storage_policy_unrestricted, table_schema_missing, view_bypasses_rls,
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
            table_schema_missing("orders"),
            service_role_in_browser("VITE_SUPABASE_SERVICE_ROLE_KEY", "VITE_"),
            super::external("semgrep", "c.lang.exec", &[78], "src/net.c", 4),
            super::secret_in_native(SecretKind::PrivateKey, "main/key.c", true),
            super::secret_in_native(SecretKind::GithubToken, "src/api.c", false),
            super::ota_unguarded("POST /api/update", 0),
            super::ota_unguarded("/update", 2),
            super::external("joern", "call-to-gets", &[], "main.c", 1),
            super::external("gcc", "x", &[99_999], "main.c", 1),
            super::secret_dependent_division("vault/src/lib.rs", 12, true),
            super::secret_dependent_division("vault/src/lib.rs", 12, false),
            super::cargo_dependency_not_pinned("helper", "Cargo.toml", true),
            super::cargo_dependency_not_pinned("helper", "app/Cargo.toml", false),
        ];
        for option in super::RISKY_OPTIONS {
            texts.push(super::risky_option(option, "sdkconfig.defaults"));
        }
        for command in COMMANDS {
            for anyone in [true, false] {
                for login_only in [true, false] {
                    texts.push(policy_unrestricted(
                        "posts",
                        "Edit posts",
                        anyone,
                        command,
                        login_only,
                    ));
                }
            }
        }
        for anyone in [true, false] {
            for checks_caller in [true, false] {
                for yes_or_no in [true, false] {
                    let facts = FunctionFacts {
                        anyone,
                        checks_caller,
                        yes_or_no,
                    };
                    texts.push(function_bypasses_rls("get_orders", &facts));
                }
                for materialized in [true, false] {
                    for auth_users in [true, false] {
                        let facts = ViewFacts {
                            anyone,
                            materialized,
                            auth_users,
                            checks_caller,
                        };
                        texts.push(view_bypasses_rls("order_totals", &facts));
                    }
                }
            }
            for command in COMMANDS {
                for buckets in [
                    Vec::new(),
                    vec!["avatars".to_owned()],
                    vec!["avatars".to_owned(), "docs".to_owned()],
                ] {
                    texts.push(storage_policy_unrestricted(
                        "Public files",
                        &buckets,
                        anyone,
                        command,
                    ));
                }
            }
        }
        for kind in SECRET_KINDS {
            texts.push(secret_in_browser(kind, "dist/app.js"));
            texts.push(secret_in_public_env(kind, "VITE_KEY"));
            texts.push(secret_in_source(kind, "src/pay.ts"));
        }
        for kind in [
            EntryKind::Route,
            EntryKind::ServerAction,
            EntryKind::EdgeFunction,
        ] {
            for reached in [
                Reached::ReadTable("todos"),
                Reached::WriteTable("todos"),
                Reached::ReadBucket("avatars"),
                Reached::WriteBucket("avatars"),
                Reached::Rpc("match_items"),
                Reached::Admin("deleteUser"),
            ] {
                for more in [0, 1, 3] {
                    texts.push(service_role_unguarded(
                        kind,
                        "DELETE /api/todos",
                        reached,
                        more,
                    ));
                }
            }
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
                assert!(
                    !part
                        .en
                        .split(". ")
                        .skip(1)
                        .any(|sentence| sentence.starts_with(|c: char| c.is_ascii_lowercase())),
                    "{part:?}"
                );
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
