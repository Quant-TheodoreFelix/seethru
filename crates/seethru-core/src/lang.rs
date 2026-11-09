use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Lang {
    #[default]
    En,
    Ko,
}

impl Lang {
    pub const ALL: [Self; 2] = [Self::En, Self::Ko];

    pub fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ko => "ko",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|lang| lang.code() == code)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalizedText {
    pub en: String,
    pub ko: String,
}

impl LocalizedText {
    pub fn get(&self, lang: Lang) -> &str {
        match lang {
            Lang::En => &self.en,
            Lang::Ko => &self.ko,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Lang, LocalizedText};

    #[test]
    fn codes_round_trip() {
        for lang in Lang::ALL {
            assert_eq!(Lang::from_code(lang.code()), Some(lang));
        }
        assert_eq!(Lang::from_code("KO"), None);
        assert_eq!(Lang::from_code("ko-KR"), None);
        assert_eq!(Lang::default(), Lang::En);
    }

    #[test]
    fn picks_the_text_for_each_language() {
        let text = LocalizedText {
            en: "hello".to_owned(),
            ko: "안녕".to_owned(),
        };
        assert_eq!(text.get(Lang::En), "hello");
        assert_eq!(text.get(Lang::Ko), "안녕");
    }
}
