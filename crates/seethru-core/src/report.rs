use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{LocalizedText, MaskedSecret};

pub const SCHEMA_VERSION: u32 = 9;

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
    pub ecosystems: Vec<Ecosystem>,
    pub inputs: Vec<Input>,
    pub limitations: Vec<Limitation>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum Ecosystem {
    Next,
    Vite,
    Supabase,
    EspIdf,
    Zephyr,
    PlatformIo,
    Arduino,
    Cargo,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Input {
    Source {},
    BuildOutput {
        path: String,
        tool: BuildTool,
    },
    Sarif {
        path: String,
        engine: String,
        results: u32,
        dropped: u32,
    },
    CompileDatabase {
        path: String,
        files: u32,
    },
    CompiledOutput {
        path: String,
        files: u32,
        functions: u32,
        machine_code: bool,
    },
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum BuildTool {
    Vite,
    Next,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum InputKind {
    Source,
    BuildOutput,
    Sarif,
    CompileDatabase,
    CompiledOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Limitation {
    pub code: LimitationCode,
    pub text: LocalizedText,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum LimitationCode {
    BuildOutputNotRead,
    BuildOutputStale,
    BuildOutputWithoutSourceMaps,
    DashboardPoliciesUnseen,
    ExternalNotVerified,
    ExternalResultsDropped,
    FirmwareProtectionNotChecked,
    NativeCodePartlyRead,
    ProjectKindNotRecognized,
    CompiledOutputNotRead,
    CompiledChecksPartial,
    CompiledOutputWithoutMachineCode,
    CompiledOutputNotOptimized,
    CompiledOutputPartlyRead,
    CompiledOutputWithoutWipes,
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
    pub zone: Zone,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum Zone {
    Client,
    Server,
    Database,
    Device,
    BuildTime,
    ThirdParty,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NodeKind {
    Component {
        runtime: Runtime,
        artifact: Artifact,
        unit: Unit,
        basis: Basis,
    },
    EntryPoint {
        channel: Channel,
        exposure: Exposure,
    },
    DataStore {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<DataStoreDetail>,
    },
    AccessRule {
        scope: RuleScope,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        strength: Option<Strength>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<AccessRuleDetail>,
    },
    Principal {},
    Credential {
        detail: CredentialDetail,
    },
    Config {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<ConfigDetail>,
    },
    Service {},
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum Runtime {
    Browser,
    Server,
    Edge,
    Mobile,
    Native,
    Firmware,
    Database,
    Build,
    Unknown,
}

impl Runtime {
    pub fn zone(self) -> Zone {
        match self {
            Self::Browser | Self::Mobile | Self::Native => Zone::Client,
            Self::Server | Self::Edge => Zone::Server,
            Self::Firmware => Zone::Device,
            Self::Database => Zone::Database,
            Self::Build => Zone::BuildTime,
            Self::Unknown => Zone::Unknown,
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum Artifact {
    Source,
    BuildOutput,
    Migration,
    Config,
    Binary,
    Other,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum Unit {
    File,
    Function,
    Image,
    Package,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum Basis {
    Path,
    Directive,
    Imports,
    BuildOutput,
    Engine,
    Dynamic,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum Channel {
    HttpRoute,
    ServerAction,
    Rpc,
    Cli,
    Ipc,
    Queue,
    Schedule,
    Serial,
    Ble,
    Socket,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum Exposure {
    Public,
    Authenticated,
    Internal,
    Unknown,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum RuleScope {
    Open,
    Conditional,
    Unknown,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum Strength {
    Verified,
    Weak,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DataStoreDetail {
    PostgresTable {
        schema: String,
        rls: RlsStatus,
    },
    PostgresView {
        schema: String,
        security_invoker: bool,
        materialized: bool,
    },
    StorageBucket {
        visibility: BucketVisibility,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AccessRuleDetail {
    PostgresPolicy {
        command: PolicyCommand,
        roles: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ConfigDetail {
    EnvVar { exposed_to_client: bool },
    BuildOption { value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CredentialDetail {
    Secret {
        secret_kind: SecretKind,
        masked: MaskedSecret,
    },
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
pub enum BucketVisibility {
    Public,
    Private,
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

impl SecretKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SupabaseServiceRoleKey => "supabaseServiceRoleKey",
            Self::SupabaseSecretKey => "supabaseSecretKey",
            Self::DatabaseUrl => "databaseUrl",
            Self::StripeSecretKey => "stripeSecretKey",
            Self::OpenAiApiKey => "openAiApiKey",
            Self::AnthropicApiKey => "anthropicApiKey",
            Self::AwsAccessKeyId => "awsAccessKeyId",
            Self::GithubToken => "githubToken",
            Self::PrivateKey => "privateKey",
        }
    }
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
    Imports,
    Calls,
    BuiltFrom,
    Invokes,
    Reads,
    Writes,
    UsesConfig,
    Defines,
    GuardedBy,
    ActsAs,
    AppliesTo,
    Contains,
    Unlocks,
    ConnectsTo,
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
#[serde(rename_all = "camelCase")]
pub enum Confidence {
    Certain,
    Likely,
    Review,
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
    SupabaseFunctionBypassesRls,
    SupabaseViewBypassesRls,
    SupabaseStoragePolicyUnrestricted,
    SupabaseServiceRoleUnguarded,
    External,
    FirmwareInsecureOptionOn,
    FirmwareOtaOverHttp,
    FirmwareTlsVerificationOff,
    FirmwareOtaUnguarded,
    SecretInNativeCode,
    SecretDependentDivision,
    CargoDependencyNotPinned,
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
            Self::SupabaseFunctionBypassesRls => "supabase-function-bypasses-rls",
            Self::SupabaseViewBypassesRls => "supabase-view-bypasses-rls",
            Self::SupabaseStoragePolicyUnrestricted => "supabase-storage-policy-unrestricted",
            Self::SupabaseServiceRoleUnguarded => "supabase-service-role-unguarded",
            Self::External => "external",
            Self::FirmwareInsecureOptionOn => "firmware-insecure-option-on",
            Self::FirmwareOtaOverHttp => "firmware-ota-over-http",
            Self::FirmwareTlsVerificationOff => "firmware-tls-verification-off",
            Self::FirmwareOtaUnguarded => "firmware-ota-unguarded",
            Self::SecretInNativeCode => "secret-in-native-code",
            Self::SecretDependentDivision => "secret-dependent-division",
            Self::CargoDependencyNotPinned => "cargo-dependency-not-pinned",
        }
    }

    pub fn cwe(self) -> &'static [u32] {
        match self {
            Self::SupabaseRlsDisabled => &[862],
            Self::SupabasePolicyUnrestricted | Self::SupabaseStoragePolicyUnrestricted => &[285],
            Self::SupabaseFunctionBypassesRls | Self::SupabaseViewBypassesRls => &[250],
            Self::SupabaseServiceRoleInBrowser
            | Self::SecretInBrowserCode
            | Self::SecretInSourceCode
            | Self::SecretInPublicEnvVar
            | Self::SecretInNativeCode => &[798],
            Self::FirmwareInsecureOptionOn => &[489],
            Self::FirmwareOtaOverHttp => &[319, 494],
            Self::FirmwareTlsVerificationOff => &[295],
            Self::FirmwareOtaUnguarded => &[306, 494],
            Self::SecretDependentDivision => &[208],
            Self::CargoDependencyNotPinned => &[829],
            Self::SupabaseServiceRoleUnguarded => &[306, 862],
            Self::SupabaseTableSchemaMissing | Self::External => &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub rule: RuleId,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: LocalizedText,
    pub explanation: LocalizedText,
    pub node: NodeId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    pub evidence: Vec<EvidenceStep>,
    pub origin: Origin,
    pub cwe: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<ProofRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_prompt: Option<LocalizedText>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<Acceptance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceStep {
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<EdgeKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Origin {
    pub engine: String,
    pub inputs: Vec<InputKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

impl Origin {
    pub fn seethru() -> Self {
        Self {
            engine: "seethru".to_owned(),
            inputs: vec![InputKind::Source],
            rule: None,
        }
    }

    pub fn seethru_with_compiled_output() -> Self {
        Self {
            engine: "seethru".to_owned(),
            inputs: vec![InputKind::Source, InputKind::CompiledOutput],
            rule: None,
        }
    }

    pub fn seethru_with_build_output() -> Self {
        Self {
            engine: "seethru".to_owned(),
            inputs: vec![InputKind::Source, InputKind::BuildOutput],
            rule: None,
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct ProofRef(String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Acceptance {
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::{Node, NodeKind, RlsStatus, Zone};

    #[test]
    fn node_kinds_reject_unknown_fields() {
        let table = r#"{"id":"table:public.a","label":"a","zone":"database","kind":{"type":"dataStore","detail":{"type":"postgresTable","schema":"public","rls":"enabled"}}}"#;
        let parsed: Result<Node, _> = serde_json::from_str(table);
        assert!(
            matches!(
                parsed,
                Ok(Node {
                    zone: Zone::Database,
                    kind: NodeKind::DataStore { detail: Some(_) },
                    ..
                })
            ),
            "{parsed:?}"
        );
        let extra_in_kind = table.replace(r#""type":"dataStore","#, r#""type":"dataStore","x":1,"#);
        assert!(serde_json::from_str::<Node>(&extra_in_kind).is_err());
        let extra_in_detail = table.replace(r#""rls":"enabled""#, r#""rls":"enabled","x":1"#);
        assert!(serde_json::from_str::<Node>(&extra_in_detail).is_err());
        let extra_on_node = table.replace(r#""label":"a","#, r#""label":"a","x":1,"#);
        assert!(serde_json::from_str::<Node>(&extra_on_node).is_err());
        let unit_variant = r#"{"id":"principal:supabase:anon","label":"anon","zone":"database","kind":{"type":"principal"}}"#;
        assert!(serde_json::from_str::<Node>(unit_variant).is_ok());
        let unit_with_extra = r#"{"id":"principal:supabase:anon","label":"anon","zone":"database","kind":{"type":"principal","x":1}}"#;
        assert!(serde_json::from_str::<Node>(unit_with_extra).is_err());
        let _ = RlsStatus::Enabled;
    }
}
