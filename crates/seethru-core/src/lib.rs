mod lang;
mod report;
mod secret;

pub use lang::{Lang, LocalizedText};
pub use report::{
    Acceptance, AccessRuleDetail, Artifact, Basis, Channel, Confidence, ConfigDetail,
    CredentialDetail, DataStoreDetail, Ecosystem, Edge, EdgeKind, EvidenceStep, Exposure, Finding,
    Input, InputKind, Limitation, LimitationCode, Location, Node, NodeId, NodeKind, Origin,
    PolicyCommand, ProofRef, RlsStatus, RuleId, RuleScope, Runtime, SCHEMA_VERSION, ScanReport,
    SecretKind, Severity, Strength, Summary, TargetInfo, ToolInfo, Unit, Zone,
};
pub use secret::MaskedSecret;

pub fn report_schema() -> serde_json::Value {
    let schema = schemars::schema_for!(ScanReport);
    schema.to_value()
}
