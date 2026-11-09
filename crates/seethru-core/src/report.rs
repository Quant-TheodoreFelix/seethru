use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{LocalizedText, MaskedSecret};

pub const SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanReport {
    pub schema_version: u32,
    pub tool: ToolInfo,
    pub target: TargetInfo,
    pub summary: Summary,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetInfo {
    pub name: String,
    pub files_scanned: u32,
    pub files_skipped: u32,
    pub files_excluded: u32,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_file: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Summary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
    pub accepted: u32,
}

impl Summary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self::default();
        for finding in findings {
            if finding.accepted.is_some() {
                summary.accepted = summary.accepted.saturating_add(1);
                continue;
            }
            let slot = match finding.severity {
                Severity::Critical => &mut summary.critical,
                Severity::High => &mut summary.high,
                Severity::Medium => &mut summary.medium,
                Severity::Low => &mut summary.low,
                Severity::Info => &mut summary.info,
            };
            *slot = slot.saturating_add(1);
        }
        summary
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Location {
    pub path: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Node {
    pub id: NodeId,
    pub label: String,
    pub kind: NodeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum NodeKind {
    File {
        role: FileRole,
    },
    Table {
        schema: String,
        rls: RlsStatus,
    },
    Policy {
        command: PolicyCommand,
        roles: Vec<String>,
        unrestricted: bool,
    },
    EnvVar {
        exposed_to_browser: bool,
    },
    Secret {
        secret_kind: SecretKind,
        masked: MaskedSecret,
    },
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum FileRole {
    BrowserCode,
    ServerCode,
    EdgeFunction,
    UnknownCode,
    Migration,
    EnvFile,
    BuildOutput,
    Other,
}

impl FileRole {
    pub fn runs_in_browser(self) -> bool {
        matches!(self, Self::BrowserCode | Self::BuildOutput)
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum RlsStatus {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum PolicyCommand {
    All,
    Select,
    Insert,
    Update,
    Delete,
}

impl PolicyCommand {
    pub fn writes(self) -> bool {
        !matches!(self, Self::Select)
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum SecretKind {
    SupabaseServiceRoleKey,
    SupabaseSecretKey,
    DatabaseUrl,
    StripeSecretKey,
    OpenAiApiKey,
    AnthropicApiKey,
    AwsAccessKeyId,
    GithubToken,
    PrivateKey,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum EdgeKind {
    Defines,
    GuardedBy,
    Queries,
    Writes,
    Reads,
    Contains,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum RuleId {
    SupabaseRlsDisabled,
    SupabasePolicyUnrestricted,
    SupabaseServiceRoleInBrowser,
    SecretInBrowserCode,
    SecretInSourceCode,
    SecretInPublicEnvVar,
    SupabaseTableSchemaMissing,
}

impl RuleId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SupabaseRlsDisabled => "supabase-rls-disabled",
            Self::SupabasePolicyUnrestricted => "supabase-policy-unrestricted",
            Self::SupabaseServiceRoleInBrowser => "supabase-service-role-in-browser",
            Self::SecretInBrowserCode => "secret-in-browser-code",
            Self::SecretInSourceCode => "secret-in-source-code",
            Self::SecretInPublicEnvVar => "secret-in-public-env-var",
            Self::SupabaseTableSchemaMissing => "supabase-table-schema-missing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub rule: RuleId,
    pub severity: Severity,
    pub title: LocalizedText,
    pub explanation: LocalizedText,
    pub node: NodeId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_prompt: Option<LocalizedText>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<Acceptance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Acceptance {
    pub reason: String,
}
