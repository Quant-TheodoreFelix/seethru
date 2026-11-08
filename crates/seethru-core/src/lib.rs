mod report;
mod secret;

pub use report::{
    Edge, EdgeKind, FileRole, Finding, Location, Node, NodeId, NodeKind, PolicyCommand, RlsStatus,
    RuleId, SCHEMA_VERSION, ScanReport, SecretKind, Severity, Summary, TargetInfo, ToolInfo,
};
pub use secret::MaskedSecret;

pub fn report_schema() -> serde_json::Value {
    let schema = schemars::schema_for!(ScanReport);
    schema.to_value()
}
