use std::fs;
use std::path::Path;

use seethru_core::{Acceptance, Finding, RuleId};
use serde::Deserialize;

use crate::ScanError;
use crate::glob::Glob;

pub const CONFIG_FILE: &str = "seethru.toml";

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_EXCLUDES: usize = 256;
const MAX_ACCEPTS: usize = 1_000;
const MAX_REASON_CHARS: usize = 500;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    accept: Vec<RawAccept>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAccept {
    id: Option<String>,
    rule: Option<RuleId>,
    path: Option<String>,
    engine: Option<String>,
    #[serde(rename = "external-rule")]
    external_rule: Option<String>,
    reason: String,
}

struct Accept {
    id: Option<String>,
    rule: Option<RuleId>,
    path: Option<Glob>,
    engine: Option<String>,
    external_rule: Option<String>,
    reason: String,
}

#[derive(Default)]
pub(crate) struct Config {
    exclude: Vec<Glob>,
    accept: Vec<Accept>,
}

impl Config {
    pub(crate) fn load(root: &Path) -> Result<Option<Self>, ScanError> {
        let path = root.join(CONFIG_FILE);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(ScanError::Io(error)),
        };
        if !meta.file_type().is_file() {
            return Err(config_error("it must be a regular file"));
        }
        if meta.len() > MAX_CONFIG_BYTES {
            return Err(config_error("it is larger than 64 KB"));
        }
        let text = fs::read_to_string(&path).map_err(ScanError::Io)?;
        Self::parse(&text).map(Some)
    }

    pub(crate) fn parse(text: &str) -> Result<Self, ScanError> {
        let raw: RawConfig = toml::from_str(text).map_err(|error| {
            let message = error.message().trim();
            match error.span() {
                Some(span) => {
                    let line = text[..span.start.min(text.len())].matches('\n').count() + 1;
                    config_error(&format!("line {line}, {message}"))
                }
                None => config_error(message),
            }
        })?;
        if raw.exclude.len() > MAX_EXCLUDES || raw.accept.len() > MAX_ACCEPTS {
            return Err(config_error("it has too many entries"));
        }
        let exclude = raw
            .exclude
            .iter()
            .map(|pattern| Glob::new(pattern))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|message| config_error(&message))?;
        let mut accept = Vec::with_capacity(raw.accept.len());
        for (index, entry) in raw.accept.into_iter().enumerate() {
            let number = index + 1;
            let reason = entry.reason.trim().to_owned();
            if reason.is_empty() || reason.chars().count() > MAX_REASON_CHARS {
                return Err(config_error(&format!(
                    "accept entry {number} needs a reason of 1 to {MAX_REASON_CHARS} characters"
                )));
            }
            let narrowed = entry.id.is_some()
                || entry.path.is_some()
                || entry.engine.is_some()
                || entry.external_rule.is_some();
            if entry.rule.is_none() && !narrowed {
                return Err(config_error(&format!(
                    "accept entry {number} needs an id, a rule, a path, an engine or an external-rule"
                )));
            }
            if entry.rule == Some(RuleId::External) && !narrowed {
                return Err(config_error(&format!(
                    "accept entry {number} would hide every outside scanner result, add an engine, an external-rule, a path or an id"
                )));
            }
            let path = entry
                .path
                .as_deref()
                .map(Glob::new)
                .transpose()
                .map_err(|message| config_error(&message))?;
            accept.push(Accept {
                id: entry.id,
                rule: entry.rule,
                path,
                engine: entry.engine,
                external_rule: entry.external_rule,
                reason: reason.chars().filter(|c| !c.is_control()).collect(),
            });
        }
        Ok(Self { exclude, accept })
    }

    pub(crate) fn is_excluded(&self, rel_path: &str) -> bool {
        self.exclude.iter().any(|glob| glob.matches(rel_path))
    }

    pub(crate) fn acceptance(&self, finding: &Finding) -> Option<Acceptance> {
        self.accept
            .iter()
            .find(|entry| {
                entry.id.as_ref().is_none_or(|id| *id == finding.id)
                    && entry.rule.is_none_or(|rule| rule == finding.rule)
                    && entry.engine.as_ref().is_none_or(|engine| {
                        finding.rule == RuleId::External && *engine == finding.origin.engine
                    })
                    && entry.external_rule.as_ref().is_none_or(|rule| {
                        finding.rule == RuleId::External
                            && finding.origin.rule.as_ref() == Some(rule)
                    })
                    && entry.path.as_ref().is_none_or(|glob| {
                        finding
                            .location
                            .as_ref()
                            .is_some_and(|location| glob.matches(&location.path))
                    })
            })
            .map(|entry| Acceptance {
                reason: entry.reason.clone(),
            })
    }
}

fn config_error(message: &str) -> ScanError {
    ScanError::Config(message.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use seethru_core::{
        Confidence, Finding, LocalizedText, Location, NodeId, Origin, RuleId, Severity,
    };

    use super::Config;

    fn finding(rule: RuleId, path: &str) -> Finding {
        Finding {
            id: format!("{}:node", rule.as_str()),
            rule,
            severity: Severity::Medium,
            confidence: Confidence::Certain,
            title: LocalizedText::default(),
            explanation: LocalizedText::default(),
            node: NodeId::new("node"),
            location: Some(Location {
                path: path.to_owned(),
                line: 1,
                column: 1,
            }),
            evidence: Vec::new(),
            origin: Origin::seethru(),
            cwe: Vec::new(),
            proof: None,
            fix_prompt: None,
            accepted: None,
        }
    }

    #[test]
    fn excludes_paths_and_accepts_findings_with_a_reason() {
        let config = Config::parse(
            r#"
            exclude = ["legacy", "**/*.test.ts"]

            [[accept]]
            rule = "supabase-policy-unrestricted"
            path = "supabase/migrations/*_init.sql"
            reason = "Products are public on purpose"

            [[accept]]
            id = "secret-in-source-code:node"
            reason = "  Test key that only works in the sandbox  "
            "#,
        );
        assert!(config.is_ok());
        let Ok(config) = config else { return };
        assert!(config.is_excluded("legacy/app.ts"));
        assert!(config.is_excluded("src/db.test.ts"));
        assert!(!config.is_excluded("src/db.ts"));

        let policy = finding(
            RuleId::SupabasePolicyUnrestricted,
            "supabase/migrations/0001_init.sql",
        );
        assert_eq!(
            config.acceptance(&policy).map(|a| a.reason),
            Some("Products are public on purpose".to_owned())
        );
        let other_file = finding(
            RuleId::SupabasePolicyUnrestricted,
            "supabase/migrations/0002_posts.sql",
        );
        assert!(config.acceptance(&other_file).is_none());
        let secret = finding(RuleId::SecretInSourceCode, "src/pay.ts");
        assert_eq!(
            config.acceptance(&secret).map(|a| a.reason),
            Some("Test key that only works in the sandbox".to_owned())
        );
    }

    #[test]
    fn rejects_entries_that_could_hide_findings_by_mistake() {
        let typo = Config::parse("exclude = []\nexcludes = [\"typo\"]\n");
        assert!(
            matches!(&typo, Err(crate::ScanError::Config(message)) if message.starts_with("line 2,")),
            "{:?}",
            typo.err()
        );
        for text in [
            "[[accept]]\nrule = \"supabase-rls-disabled\"\n",
            "[[accept]]\nrule = \"supabase-rls-disabled\"\nreason = \"   \"\n",
            "[[accept]]\nreason = \"everything\"\n",
            "[[accept]]\nrule = \"no-such-rule\"\nreason = \"x\"\n",
            "exclude = [\"../outside\"]\n",
            "excludes = [\"typo\"]\n",
            "[[accept]]\nrule = \"supabase-rls-disabled\"\nreason = \"x\"\nseverity = \"low\"\n",
        ] {
            assert!(Config::parse(text).is_err(), "{text}");
        }
    }
}
