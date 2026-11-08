use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const MASK: &str = "****";
const TAIL_LEN: usize = 4;
const MIN_LEN_FOR_TAIL: usize = 20;

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct MaskedSecret(String);

impl MaskedSecret {
    pub fn mask(raw: &str, public_prefix_len: usize) -> Self {
        let chars: Vec<char> = raw.chars().collect();
        let len = chars.len();
        let prefix_len = public_prefix_len.min(len / 3);
        let tail_len = if len >= MIN_LEN_FOR_TAIL { TAIL_LEN } else { 0 };
        let mut out = String::with_capacity(prefix_len + MASK.len() + tail_len);
        out.extend(&chars[..prefix_len]);
        out.push_str(MASK);
        out.extend(&chars[len - tail_len..]);
        Self(out)
    }

    pub fn with_context(before: &str, secret: &str, after: &str) -> Self {
        let inner = Self::mask(secret, 0);
        Self(format!("{before}{}{after}", inner.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::MaskedSecret;

    #[test]
    fn keeps_only_prefix_and_tail() {
        let raw = ["sk", "_live_", "ABCDEFGHIJKLMNOPQRSTUVWX", "1234"].concat();
        let masked = MaskedSecret::mask(&raw, 8);
        assert_eq!(masked.as_str(), "sk_live_****1234");
    }

    #[test]
    fn short_values_reveal_at_most_a_third() {
        let masked = MaskedSecret::mask("abcdefghi", 8);
        assert_eq!(masked.as_str(), "abc****");
    }

    #[test]
    fn context_stays_visible_around_the_masked_part() {
        let masked =
            MaskedSecret::with_context("postgres://app:", "s3cretpassword", "@db.example.com");
        assert_eq!(masked.as_str(), "postgres://app:****@db.example.com");
    }

    #[test]
    fn empty_value_is_fully_masked() {
        assert_eq!(MaskedSecret::mask("", 4).as_str(), "****");
    }

    #[test]
    fn multibyte_values_do_not_split_characters() {
        let masked = MaskedSecret::mask("비밀번호비밀번호비밀번호비밀번호비밀번호", 2);
        assert_eq!(masked.as_str(), "비밀****비밀번호");
    }
}
