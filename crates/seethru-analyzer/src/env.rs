pub(crate) const PUBLIC_PREFIXES: &[&str] = &[
    "VITE_",
    "NEXT_PUBLIC_",
    "EXPO_PUBLIC_",
    "REACT_APP_",
    "NUXT_PUBLIC_",
    "GATSBY_",
    "VUE_APP_",
    "PUBLIC_",
];

const TEMPLATE_SUFFIXES: &[&str] = &["example", "sample", "template", "dist", "defaults"];

pub(crate) fn is_public(name: &str) -> bool {
    public_prefix(name).is_some()
}

pub(crate) fn public_prefix(name: &str) -> Option<&'static str> {
    PUBLIC_PREFIXES
        .iter()
        .find(|prefix| name.starts_with(*prefix))
        .copied()
}

pub(crate) fn is_template_file(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    TEMPLATE_SUFFIXES
        .iter()
        .any(|suffix| lower.ends_with(&format!(".{suffix}")))
}

pub(crate) fn var_at(text: &str, offset: usize) -> Option<&str> {
    let line_start = text[..offset].rfind('\n').map_or(0, |n| n + 1);
    let line = text[line_start..offset].trim_start();
    let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
    let (name, _) = line.split_once('=')?;
    let name = name.trim_end();
    let valid = !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.starts_with(|c: char| c.is_ascii_digit());
    valid.then_some(name)
}

#[cfg(test)]
mod tests {
    use super::{is_public, is_template_file, var_at};

    #[test]
    fn finds_the_variable_that_holds_an_offset() {
        let text = "A=1\nexport VITE_KEY = \"abc\"\nB=2";
        let offset = text.find("abc").unwrap_or_default();
        assert_eq!(var_at(text, offset), Some("VITE_KEY"));
        assert_eq!(var_at("# comment abc", 10), None);
    }

    #[test]
    fn recognizes_public_prefixes_and_templates() {
        assert!(is_public("NEXT_PUBLIC_SUPABASE_URL"));
        assert!(!is_public("SUPABASE_SERVICE_ROLE_KEY"));
        assert!(is_template_file(".env.example"));
        assert!(!is_template_file(".env.local"));
    }
}
