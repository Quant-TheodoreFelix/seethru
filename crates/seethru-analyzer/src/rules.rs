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
        title: format!("RLS is off for the `{table}` table"),
        explanation: format!(
            "With RLS (row level security) off, anyone can read, change and delete every row in this table. \
             The Supabase anon key in your app is public in the browser, \
             so anyone who has it can reach the whole `{table}` table without signing in."
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
        "anyone, even people who are not signed in,"
    } else {
        "any signed-in user"
    };
    let what = match command {
        PolicyCommand::All => "read, change and delete every row",
        PolicyCommand::Select => "read every row",
        PolicyCommand::Insert => "add any row they like",
        PolicyCommand::Update => "change rows that belong to other people",
        PolicyCommand::Delete => "delete rows that belong to other people",
    };
    Text {
        title: format!("The `{policy}` policy opens every row of the `{table}` table"),
        explanation: format!(
            "The condition of this policy is always true, so {who} can {what} in the `{table}` table. \
             The condition should usually allow only the user's own rows, such as `auth.uid() = user_id`. \
             If you made this policy to share the table with everyone on purpose, you can leave it as it is."
        ),
    }
}

pub(crate) fn service_role_in_browser(var: &str, prefix: &str) -> Text {
    let var = display_name(var);
    let prefix = display_name(prefix);
    Text {
        title: format!("Browser code reads the `{var}` env variable"),
        explanation: format!(
            "Env variables that start with `{prefix}` are copied into browser code when the app is built. \
             The service_role key is an admin key that skips RLS, so anyone who finds it in the browser \
             can read, change and delete your whole database. {ROTATE} \
             Move admin work to server code such as an Edge Function."
        ),
    }
}

pub(crate) fn secret_label(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::SupabaseServiceRoleKey => "a Supabase service_role key",
        SecretKind::SupabaseSecretKey => "a Supabase secret key",
        SecretKind::DatabaseUrl => "a database URL with a password",
        SecretKind::StripeSecretKey => "a Stripe secret key",
        SecretKind::OpenAiApiKey => "an OpenAI API key",
        SecretKind::AnthropicApiKey => "an Anthropic API key",
        SecretKind::AwsAccessKeyId => "an AWS access key",
        SecretKind::GithubToken => "a GitHub token",
        SecretKind::PrivateKey => "a private key",
    }
}

fn secret_risk(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::SupabaseServiceRoleKey | SecretKind::SupabaseSecretKey => {
            "This admin key skips RLS and can read, change and delete all data in your database."
        }
        SecretKind::DatabaseUrl => {
            "Anyone with this URL can connect to your database directly and do anything with the data."
        }
        SecretKind::StripeSecretKey => {
            "This key can create charges, issue refunds and read customer details."
        }
        SecretKind::OpenAiApiKey | SecretKind::AnthropicApiKey => {
            "Anyone can call the AI API with this key and the bill goes to your account."
        }
        SecretKind::AwsAccessKeyId => {
            "This key can use your AWS resources with every permission it was given."
        }
        SecretKind::GithubToken => {
            "This token can read or change repository code with every permission it was given."
        }
        SecretKind::PrivateKey => "This key can sign data or decrypt protected traffic.",
    }
}

const ROTATE: &str = "Revoke the key now and issue a new one. Deleting it from the code cannot undo a key that has already leaked.";

pub(crate) fn secret_in_browser(kind: SecretKind, file: &str) -> Text {
    let file = display_name(file);
    Text {
        title: format!("`{file}` sends {} to the browser", secret_label(kind)),
        explanation: format!(
            "This file is delivered to the browser of every visitor, and anyone can pull the value out with the developer tools. \
             {} {ROTATE} Use the new key only on a server or in an Edge Function.",
            secret_risk(kind)
        ),
    }
}

pub(crate) fn secret_in_public_env(kind: SecretKind, var: &str) -> Text {
    let var = display_name(var);
    Text {
        title: format!("The `{var}` env variable holds {}", secret_label(kind)),
        explanation: format!(
            "Env variables whose names start with a public prefix are copied into browser code when the app is built. \
             {} {ROTATE} Give the new key a name without the public prefix and read it only in server code.",
            secret_risk(kind)
        ),
    }
}

pub(crate) fn secret_in_source(kind: SecretKind, file: &str) -> Text {
    let file = display_name(file);
    Text {
        title: format!("`{file}` has {} written in it", secret_label(kind)),
        explanation: format!(
            "Values written in code or config files are visible to everyone who can see the repository. \
             {} {ROTATE} Keep the new key in an env file that is not committed or in the secret settings of your host.",
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
