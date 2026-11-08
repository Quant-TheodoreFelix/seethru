use seethru_core::PolicyCommand;

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
