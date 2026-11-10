pub(crate) const HTTP_METHODS: &[&str] =
    &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

pub(crate) const EXIT_CALLS: &[&str] = &[
    "redirect",
    "permanentRedirect",
    "notFound",
    "unauthorized",
    "forbidden",
];

pub(crate) const TABLE_OPS: &[(&str, bool)] = &[
    ("select", false),
    ("insert", true),
    ("update", true),
    ("upsert", true),
    ("delete", true),
];

pub(crate) const STORAGE_OPS: &[(&str, bool)] = &[
    ("upload", true),
    ("update", true),
    ("remove", true),
    ("move", true),
    ("copy", true),
    ("download", false),
    ("list", false),
    ("createSignedUrl", false),
    ("createSignedUrls", false),
];

const AUTH_WORDS: &[&str] = &[
    "auth",
    "session",
    "user",
    "token",
    "verify",
    "signature",
    "protect",
    "perm",
    "role",
    "admin",
    "guard",
    "jwt",
    "login",
    "check",
    "access",
    "clerk",
];

pub(crate) fn auth_like(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    AUTH_WORDS.iter().any(|word| lower.contains(word))
}

pub(crate) fn is_secret_name(name: &str) -> bool {
    ["SECRET", "TOKEN", "KEY", "PASSWORD"]
        .iter()
        .any(|part| name.to_ascii_uppercase().contains(part))
}

pub(crate) fn is_supabase_js(specifier: &str) -> bool {
    specifier.contains("@supabase/supabase-js")
}

pub(crate) fn is_supabase_ssr(specifier: &str) -> bool {
    specifier.contains("@supabase/ssr")
}

pub(crate) fn is_next_auth(specifier: &str) -> bool {
    specifier == "next-auth" || specifier.starts_with("next-auth/")
}

pub(crate) fn is_clerk(specifier: &str) -> bool {
    specifier.starts_with("@clerk/")
}

pub(crate) fn is_jose(specifier: &str) -> bool {
    specifier == "jose"
        || specifier.starts_with("npm:jose")
        || specifier.contains("/jose@")
        || specifier.contains("deno.land/x/jose")
}

pub(crate) fn is_jsonwebtoken(specifier: &str) -> bool {
    specifier == "jsonwebtoken" || specifier.starts_with("npm:jsonwebtoken")
}

pub(crate) fn is_project_specifier(specifier: &str) -> bool {
    specifier.starts_with('.') || specifier.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::{auth_like, is_secret_name};

    #[test]
    fn auth_like_names_cover_common_helpers() {
        assert!(auth_like("requireUser"));
        assert!(auth_like("withAuth"));
        assert!(auth_like("verifySignature"));
        assert!(auth_like("clerkMiddleware"));
        assert!(!auth_like("json"));
        assert!(!auth_like("createMiddleware"));
        assert!(is_secret_name("CRON_SECRET"));
        assert!(!is_secret_name("NEXT_PUBLIC_SITE_URL"));
    }
}
