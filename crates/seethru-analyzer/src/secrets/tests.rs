use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use seethru_core::SecretKind;

use super::find;

fn random_body(len: usize) -> String {
    let alphabet = "Q7mZr2Kx9VbT4nWc8LpY3hGd6FsJ5aEuR1tN0kHqXvBzMjC";
    alphabet.chars().cycle().skip(5).take(len).collect()
}

fn jwt(role: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload =
        format!(r#"{{"iss":"supabase","ref":"seethrutestonly","role":"{role}","iat":1,"exp":2}}"#);
    let payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    format!("{header}.{payload}.{}", random_body(43))
}

fn kinds(text: &str) -> Vec<SecretKind> {
    find(text).into_iter().map(|hit| hit.kind).collect()
}

#[test]
fn detects_prefixed_keys_and_masks_them() {
    let stripe = ["sk", "_live_", &random_body(32)].concat();
    let text = format!("const key = \"{stripe}\";");
    let hits = find(&text);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].kind, SecretKind::StripeSecretKey);
    assert_eq!(hits[0].offset, 13);
    assert!(hits[0].masked.as_str().starts_with("sk_live_****"));
    assert!(!hits[0].masked.as_str().contains(&stripe[8..20]));
}

#[test]
fn detects_each_supported_provider() {
    let samples = [
        (
            ["sb", "_secret_", &random_body(32)].concat(),
            SecretKind::SupabaseSecretKey,
        ),
        (
            ["sk-", "ant-api03-", &random_body(80)].concat(),
            SecretKind::AnthropicApiKey,
        ),
        (
            ["sk-", "proj-", &random_body(64)].concat(),
            SecretKind::OpenAiApiKey,
        ),
        (
            ["AK", "IA", &random_body(16).to_ascii_uppercase()].concat(),
            SecretKind::AwsAccessKeyId,
        ),
        (
            ["gh", "p_", &random_body(36)].concat(),
            SecretKind::GithubToken,
        ),
        (
            ["github", "_pat_", &random_body(70)].concat(),
            SecretKind::GithubToken,
        ),
    ];
    for (value, kind) in samples {
        assert_eq!(kinds(&format!("x = '{value}'")), vec![kind], "{kind:?}");
    }
}

#[test]
fn detects_supabase_service_role_jwt_but_not_anon_key() {
    assert_eq!(
        kinds(&jwt("service_role")),
        vec![SecretKind::SupabaseServiceRoleKey]
    );
    assert!(kinds(&jwt("anon")).is_empty());
    assert!(kinds("eyJhbGciOi.not-a-jwt.x").is_empty());
}

#[test]
fn detects_remote_database_urls_with_passwords() {
    let password = random_body(20);
    let url =
        format!("postgresql://postgres:{password}@db.seethrutestonly.supabase.co:5432/postgres");
    let hits = find(&format!("DATABASE_URL={url}"));
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].kind, SecretKind::DatabaseUrl);
    assert_eq!(
        hits[0].masked.as_str(),
        format!(
            "postgresql://postgres:****{}@db.seethrutestonly.supabase.co:5432",
            &password[16..]
        )
    );
}

#[test]
fn ignores_local_and_templated_database_urls() {
    assert!(kinds("postgresql://postgres:postgres@127.0.0.1:54322/postgres").is_empty());
    assert!(kinds("postgresql://postgres:Zk29fjQwLp7x@localhost:5432/db").is_empty());
    assert!(
        kinds("postgresql://postgres:[YOUR-PASSWORD]@db.abc.supabase.co:5432/postgres").is_empty()
    );
    assert!(kinds("postgres://user:${DB_PASSWORD}@db.example.net/app").is_empty());
}

#[test]
fn detects_private_keys_in_files_and_escaped_strings() {
    let body = random_body(64);
    let pem = format!(
        "-----BEGIN RSA {}-----\n{body}\n{body}\n-----END RSA PRIVATE KEY-----",
        "PRIVATE KEY"
    );
    let hits = find(&pem);
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].masked.as_str(),
        "-----BEGIN RSA PRIVATE KEY-----****"
    );

    let escaped = format!(
        r#"{{"private_key":"-----BEGIN {}-----\n{body}\n-----END PRIVATE KEY-----\n"}}"#,
        "PRIVATE KEY"
    );
    assert_eq!(kinds(&escaped), vec![SecretKind::PrivateKey]);
    assert!(kinds("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----").is_empty());
}

#[test]
fn ignores_placeholders_and_embedded_matches() {
    assert!(kinds(&["sk", "_live_", &"x".repeat(32)].concat()).is_empty());
    assert!(kinds(&["sk", "_live_", "your", &random_body(28)].concat()).is_empty());
    assert!(kinds(&["AK", "IA", "IOSFODNN7EXAMPLE"].concat()).is_empty());
    assert!(kinds(&["my", "sk", "_live_", &random_body(32)].concat()).is_empty());
    assert!(kinds(&["gh", "p_", &random_body(36), "Z"].concat()).is_empty());
    assert!(kinds(&["sk", "_test_", &random_body(32)].concat()).is_empty());
}

#[test]
fn raw_values_never_appear_in_masks() {
    let raw = [
        ["sb", "_secret_", &random_body(40)].concat(),
        jwt("service_role"),
        ["sk-", "proj-", &random_body(64)].concat(),
    ];
    for value in raw {
        for hit in find(&value) {
            assert!(!hit.masked.as_str().contains(&value), "{value}");
            assert!(hit.masked.as_str().len() < value.len() / 2 + 16);
        }
    }
}
