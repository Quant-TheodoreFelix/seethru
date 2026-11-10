use sha2::{Digest, Sha256};

use crate::Target;

pub const WELL_KNOWN_PATH: &str = "/.well-known/seethru-ownership.txt";
const PREFIX: &str = "seethru-ownership=";
const DOMAIN: &str = "seethru-ownership-v1";
const HEX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    pub fn from_random(bytes: &[u8; 32]) -> Self {
        let mut hex = String::with_capacity(HEX_LEN);
        for byte in bytes {
            hex.push_str(&format!("{byte:02x}"));
        }
        Self(hex)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        (text.len() == HEX_LEN
            && text
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)))
        .then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn file_line(&self, target: &Target) -> String {
        let mut hasher = Sha256::new();
        for part in [DOMAIN, target.origin().as_str(), self.0.as_str()] {
            hasher.update(part.as_bytes());
            hasher.update(b"\n");
        }
        let mut line = String::with_capacity(PREFIX.len() + HEX_LEN);
        line.push_str(PREFIX);
        for byte in hasher.finalize() {
            line.push_str(&format!("{byte:02x}"));
        }
        line
    }

    pub fn proves(&self, target: &Target, body: &[u8]) -> bool {
        let Ok(text) = std::str::from_utf8(body) else {
            return false;
        };
        let wanted = self.file_line(target);
        text.lines().any(|line| {
            let line = line.trim();
            line.len() == wanted.len()
                && line
                    .bytes()
                    .zip(wanted.bytes())
                    .fold(0u8, |sum, (a, b)| sum | (a ^ b))
                    == 0
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(text: &str) -> Option<Target> {
        Target::parse(text).ok()
    }

    #[test]
    fn a_token_is_proved_only_by_its_own_line() {
        let Some(app) = target("https://app.example") else {
            return;
        };
        let token = Token::from_random(&[7u8; 32]);
        let other = Token::from_random(&[8u8; 32]);
        let line = token.file_line(&app);
        assert_eq!(token.as_str().len(), 64);
        assert_eq!(line.len(), PREFIX.len() + 64);
        assert_eq!(Token::parse(token.as_str()), Some(token.clone()));
        assert!(token.proves(&app, format!("{line}\n").as_bytes()));
        assert!(token.proves(&app, format!("# note\r\n  {line}  \r\n").as_bytes()));
        assert!(!token.proves(&app, other.file_line(&app).as_bytes()));
        assert!(!token.proves(&app, token.as_str().as_bytes()));
        assert!(!token.proves(&app, format!("x{line}").as_bytes()));
        assert!(!token.proves(&app, b""));
        assert!(!token.proves(&app, &[0xff, 0xfe]));
        assert_eq!(Token::parse("abc"), None);
        assert_eq!(Token::parse(&"G".repeat(64)), None);
    }

    #[test]
    fn the_published_line_cannot_be_reused_by_someone_who_reads_it() {
        let Some(app) = target("https://app.example") else {
            return;
        };
        let token = Token::from_random(&[7u8; 32]);
        let line = token.file_line(&app);
        assert!(!line.contains(token.as_str()));
        let copied = line.strip_prefix(PREFIX).and_then(Token::parse);
        assert!(copied.is_some());
        assert!(copied.is_some_and(|copied| !copied.proves(&app, line.as_bytes())));
        assert!(!token.proves(&app, format!("{PREFIX}{}", token.as_str()).as_bytes()));
    }

    #[test]
    fn a_line_made_for_one_address_does_not_prove_another() {
        let token = Token::from_random(&[7u8; 32]);
        let (Some(staging), Some(live), Some(other_port)) = (
            target("https://staging.app.example"),
            target("https://app.example"),
            target("https://staging.app.example:8443"),
        ) else {
            return;
        };
        let line = token.file_line(&staging);
        assert!(token.proves(&staging, line.as_bytes()));
        assert!(!token.proves(&live, line.as_bytes()));
        assert!(!token.proves(&other_port, line.as_bytes()));
    }
}
