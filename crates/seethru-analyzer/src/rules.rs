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
        ];
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
