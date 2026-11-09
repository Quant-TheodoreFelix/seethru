use std::collections::BTreeSet;

use seethru_core::{EdgeKind, Finding, Location, Node, NodeKind, RuleId, ScanReport, SecretKind};

const MAX_NAME_CHARS: usize = 120;
const MAX_RELATED_FILES: usize = 8;

const CLOSING: &str = "Keep the change as small as you can so nothing else breaks, and when you are done, tell me briefly which files you changed and why.";

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
                "The `{}` policy on the Supabase `{table}` table (`{}` for {}) has a condition that is always `true`, so every row is open.{place}\n\
                 1. Create a new migration file that drops this policy with `drop policy` and creates it again with a condition that lets signed-in users work only with their own rows. For example, use the owner column of the table as in `using ((select auth.uid()) = user_id)`.\n\
                 2. Do not edit migration files that have already been applied.\n\
                 3. If this policy shares the table with everyone on purpose, do not change it and tell me so.",
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
                "Code that runs in the browser reads the `{}` env variable, which holds the Supabase service_role key.{place}{readers}\n\
                 1. Move the work that needs the service_role key to server code such as a Supabase Edge Function.\n\
                 2. Change the browser code so it reaches data only with the publishable (anon) key and RLS policies.\n\
                 3. Remove the public prefix from the env variable name and read it only on the server.\n\
                 I will revoke the key in the Supabase dashboard and issue a new one myself.",
                clean(var)
            )
        }
        (
            RuleId::SecretInBrowserCode | RuleId::SecretInSourceCode | RuleId::SecretInPublicEnvVar,
            Some(NodeKind::Secret { secret_kind, .. }),
        ) => secret(finding.rule, *secret_kind, &place),
        _ => format!("{}{place}", clean(&finding.title.en)),
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
        "RLS (row level security) is off for the Supabase `{table}` table, so anyone with the anon key can read and change every row.{place}{users}\n\
         1. Create a new migration file that adds `alter table {table} enable row level security;`.\n\
         2. Look at the code that uses this table and add policies to the same file so signed-in users can read and write only their own rows. For example, use the owner column as in `using ((select auth.uid()) = user_id)`.\n\
         3. Do not edit migration files that have already been applied."
    )
}

fn secret(rule: RuleId, kind: SecretKind, place: &str) -> String {
    let what = secret_name(kind);
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

fn secret_name(kind: SecretKind) -> &'static str {
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

fn command_name(command: seethru_core::PolicyCommand) -> &'static str {
    match command {
        seethru_core::PolicyCommand::All => "all",
        seethru_core::PolicyCommand::Select => "select",
        seethru_core::PolicyCommand::Insert => "insert",
        seethru_core::PolicyCommand::Update => "update",
        seethru_core::PolicyCommand::Delete => "delete",
    }
}

fn place(location: &Location) -> String {
    format!(" It is at `{}:{}`.", clean(&location.path), location.line)
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
            " Related files: {}.",
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
