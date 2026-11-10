use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use seethru_core::{MaskedSecret, SecretKind};

const MIN_DISTINCT_CHARS: usize = 8;
const PLACEHOLDER_MARKERS: &[&str] = &[
    "xxxx",
    "your",
    "example",
    "dummy",
    "placeholder",
    "changeme",
    "redacted",
    "replace",
    "insert",
    "fake",
];
const LOCAL_DB_HOSTS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "[::1]",
    "host.docker.internal",
    "db",
    "postgres",
];
const MAX_JWT_SEGMENT: usize = 8192;
const LOCAL_DEMO_ISSUER: &str = "supabase-demo";
const MAX_PEM_LABEL: usize = 40;
const MAX_PEM_SCAN: usize = 8192;
const MIN_PEM_PAYLOAD: usize = 64;

#[derive(Debug, Clone, Copy)]
enum Charset {
    Alnum,
    Token,
    Upper,
}

impl Charset {
    fn accepts(self, c: char) -> bool {
        match self {
            Self::Alnum => c.is_ascii_alphanumeric(),
            Self::Token => c.is_ascii_alphanumeric() || c == '_' || c == '-',
            Self::Upper => c.is_ascii_uppercase() || c.is_ascii_digit(),
        }
    }
}

struct PrefixRule {
    prefix: &'static str,
    kind: SecretKind,
    charset: Charset,
    min_len: usize,
    max_len: usize,
}

const PREFIX_RULES: &[PrefixRule] = &[
    PrefixRule {
        prefix: "sb_secret_",
        kind: SecretKind::SupabaseSecretKey,
        charset: Charset::Token,
        min_len: 20,
        max_len: 200,
    },
    PrefixRule {
        prefix: "sk_live_",
        kind: SecretKind::StripeSecretKey,
        charset: Charset::Alnum,
        min_len: 20,
        max_len: 255,
    },
    PrefixRule {
        prefix: "rk_live_",
        kind: SecretKind::StripeSecretKey,
        charset: Charset::Alnum,
        min_len: 20,
        max_len: 255,
    },
    PrefixRule {
        prefix: "sk-ant-",
        kind: SecretKind::AnthropicApiKey,
        charset: Charset::Token,
        min_len: 32,
        max_len: 255,
    },
    PrefixRule {
        prefix: "sk-proj-",
        kind: SecretKind::OpenAiApiKey,
        charset: Charset::Token,
        min_len: 32,
        max_len: 400,
    },
    PrefixRule {
        prefix: "sk-svcacct-",
        kind: SecretKind::OpenAiApiKey,
        charset: Charset::Token,
        min_len: 32,
        max_len: 400,
    },
    PrefixRule {
        prefix: "sk-admin-",
        kind: SecretKind::OpenAiApiKey,
        charset: Charset::Token,
        min_len: 32,
        max_len: 400,
    },
    PrefixRule {
        prefix: "AKIA",
        kind: SecretKind::AwsAccessKeyId,
        charset: Charset::Upper,
        min_len: 16,
        max_len: 16,
    },
    PrefixRule {
        prefix: "ghp_",
        kind: SecretKind::GithubToken,
        charset: Charset::Alnum,
        min_len: 36,
        max_len: 36,
    },
    PrefixRule {
        prefix: "gho_",
        kind: SecretKind::GithubToken,
        charset: Charset::Alnum,
        min_len: 36,
        max_len: 36,
    },
    PrefixRule {
        prefix: "ghu_",
        kind: SecretKind::GithubToken,
        charset: Charset::Alnum,
        min_len: 36,
        max_len: 36,
    },
    PrefixRule {
        prefix: "ghs_",
        kind: SecretKind::GithubToken,
        charset: Charset::Alnum,
        min_len: 36,
        max_len: 36,
    },
    PrefixRule {
        prefix: "ghr_",
        kind: SecretKind::GithubToken,
        charset: Charset::Alnum,
        min_len: 36,
        max_len: 36,
    },
    PrefixRule {
        prefix: "github_pat_",
        kind: SecretKind::GithubToken,
        charset: Charset::Token,
        min_len: 60,
        max_len: 255,
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hit {
    pub kind: SecretKind,
    pub offset: usize,
    pub masked: MaskedSecret,
}

pub(crate) fn find(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    for rule in PREFIX_RULES {
        for (offset, _) in text.match_indices(rule.prefix) {
            if let Some(hit) = prefix_hit(text, offset, rule) {
                hits.push(hit);
            }
        }
    }
    for (offset, _) in text.match_indices("eyJ") {
        if let Some(hit) = jwt_hit(text, offset) {
            hits.push(hit);
        }
    }
    for scheme in ["postgres://", "postgresql://"] {
        for (offset, _) in text.match_indices(scheme) {
            if let Some(hit) = database_url_hit(text, offset, scheme) {
                hits.push(hit);
            }
        }
    }
    for (offset, _) in text.match_indices("-----BEGIN ") {
        if let Some(hit) = private_key_hit(text, offset) {
            hits.push(hit);
        }
    }
    hits.sort_by_key(|hit| hit.offset);
    hits.dedup_by_key(|hit| hit.offset);
    hits
}

fn preceded_by_word_char(text: &str, offset: usize) -> bool {
    text[..offset]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn prefix_hit(text: &str, offset: usize, rule: &PrefixRule) -> Option<Hit> {
    if preceded_by_word_char(text, offset) {
        return None;
    }
    let body_start = offset + rule.prefix.len();
    let body_len = text[body_start..]
        .chars()
        .take_while(|c| rule.charset.accepts(*c))
        .count();
    if body_len < rule.min_len || body_len > rule.max_len {
        return None;
    }
    let followed_by_word_char = text[body_start + body_len..]
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    if followed_by_word_char {
        return None;
    }
    let body = &text[body_start..body_start + body_len];
    if looks_like_placeholder(body) {
        return None;
    }
    let raw = &text[offset..body_start + body_len];
    Some(Hit {
        kind: rule.kind,
        offset,
        masked: MaskedSecret::mask(raw, rule.prefix.len()),
    })
}

fn looks_like_placeholder(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    if PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return true;
    }
    let mut distinct: Vec<char> = body.chars().collect();
    distinct.sort_unstable();
    distinct.dedup();
    distinct.len() < MIN_DISTINCT_CHARS
}

fn jwt_hit(text: &str, offset: usize) -> Option<Hit> {
    if preceded_by_word_char(text, offset) {
        return None;
    }
    let token_len = text[offset..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .count();
    let token = &text[offset..offset + token_len];
    let mut parts = token.split('.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || signature.len() < 16 || payload.len() > MAX_JWT_SEGMENT {
        return None;
    }
    let header: serde_json::Value = decode_segment(header)?;
    header.get("alg")?;
    let payload: serde_json::Value = decode_segment(payload)?;
    if payload.get("role")?.as_str()? != "service_role" {
        return None;
    }
    if payload.get("iss").and_then(serde_json::Value::as_str) == Some(LOCAL_DEMO_ISSUER) {
        return None;
    }
    Some(Hit {
        kind: SecretKind::SupabaseServiceRoleKey,
        offset,
        masked: MaskedSecret::mask(token, 3),
    })
}

fn decode_segment(segment: &str) -> Option<serde_json::Value> {
    let bytes = URL_SAFE_NO_PAD.decode(segment.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn database_url_hit(text: &str, offset: usize, scheme: &str) -> Option<Hit> {
    let rest = &text[offset + scheme.len()..];
    let end = rest
        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ')' | '>' | ','))
        .unwrap_or(rest.len());
    let url = &rest[..end];
    let authority = url.split(['/', '?', '#']).next().unwrap_or(url);
    let at = authority.rfind('@')?;
    let (user, password) = authority[..at].split_once(':')?;
    let host_port = &authority[at + 1..];
    let host = host_port
        .rsplit_once(':')
        .map_or(host_port, |(host, _)| host);
    let templated = password.contains(['[', '<', '{', '$', '*']);
    if password.len() < 6
        || templated
        || looks_like_placeholder(password)
        || LOCAL_DB_HOSTS.contains(&host.to_ascii_lowercase().as_str())
    {
        return None;
    }
    Some(Hit {
        kind: SecretKind::DatabaseUrl,
        offset,
        masked: MaskedSecret::with_context(
            &format!("{scheme}{user}:"),
            password,
            &format!("@{host_port}"),
        ),
    })
}

fn private_key_hit(text: &str, offset: usize) -> Option<Hit> {
    let label_start = offset + "-----BEGIN ".len();
    let label_len = text[label_start..].find("-----")?;
    if label_len > MAX_PEM_LABEL {
        return None;
    }
    let label = &text[label_start..label_start + label_len];
    if !label.ends_with("PRIVATE KEY") && !label.ends_with("PRIVATE KEY BLOCK") {
        return None;
    }
    let header_end = label_start + label_len + "-----".len();
    let body = &text[header_end..];
    let body = &body[..body.find("-----END").unwrap_or(body.len())];
    let payload = body
        .chars()
        .take(MAX_PEM_SCAN)
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/'))
        .count();
    if payload < MIN_PEM_PAYLOAD {
        return None;
    }
    Some(Hit {
        kind: SecretKind::PrivateKey,
        offset,
        masked: MaskedSecret::with_context(&text[offset..header_end], "", ""),
    })
}

pub(crate) fn has_key_body(text: &str, offset: usize) -> bool {
    let Some(rest) = text.get(offset + "-----BEGIN ".len()..) else {
        return false;
    };
    let Some(header) = rest.find("-----") else {
        return false;
    };
    let Some(body) = rest.get(header + "-----".len()..) else {
        return false;
    };
    let Some(end) = body.find("-----END").filter(|end| *end <= MAX_PEM_SCAN) else {
        return false;
    };
    let mut payload = 0usize;
    let mut other = 0usize;
    for c in body[..end].chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=') {
            payload += 1;
        } else if !(c.is_whitespace() || matches!(c, '"' | '\\')) {
            other += 1;
        }
    }
    payload >= MIN_PEM_PAYLOAD && other * 20 <= payload
}

#[cfg(test)]
mod tests;
