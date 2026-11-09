use seethru_core::{
    AccessRuleDetail, Basis, Confidence, DataStoreDetail, EdgeKind, Node, NodeId, NodeKind,
    PolicyCommand, RlsStatus, RuleId, RuleScope, Severity, Zone,
};

use super::{
    ANONYMOUS_ROLES, DEFAULT_SCHEMA, EXPOSED_SCHEMAS, MANAGED_SCHEMAS, Migrations, Policy,
    SIGNED_IN_ROLES, TableKey,
};
use crate::classify::FileRole;
use crate::graph::{Graph, Verdict, file_location, file_step, step};
use crate::rules;

impl Migrations {
    pub(crate) fn emit(self, graph: &mut Graph) {
        for (key, table) in &self.tables {
            if MANAGED_SCHEMAS.contains(&key.schema.as_str()) {
                continue;
            }
            let table_id = table_id(key);
            let label = table_label(key);
            graph.add_node(Node {
                id: table_id.clone(),
                label: label.clone(),
                kind: NodeKind::DataStore {
                    detail: Some(DataStoreDetail::PostgresTable {
                        schema: key.schema.clone(),
                        rls: table.rls,
                    }),
                },
                zone: Zone::Database,
                location: table
                    .defined_at
                    .clone()
                    .or_else(|| table.rls_changed_at.clone()),
            });
            let mut evidence = Vec::new();
            if let Some(path) = self.defined_in.get(key) {
                let file_id = graph.add_file(path, FileRole::Migration, Basis::Path);
                graph.add_edge(file_id, table_id.clone(), EdgeKind::Defines);
                evidence.push(file_step(path, None, file_location(path)));
            }
            let exposed = EXPOSED_SCHEMAS.contains(&key.schema.as_str());
            if exposed && table.rls == RlsStatus::Disabled {
                let text = rules::rls_disabled(&label);
                let at = table
                    .rls_changed_at
                    .clone()
                    .or_else(|| table.defined_at.clone());
                evidence.push(step(
                    &label,
                    evidence.first().map(|_| EdgeKind::Defines),
                    Some(table_id.clone()),
                    at.clone(),
                ));
                graph.add_finding(
                    Verdict {
                        rule: RuleId::SupabaseRlsDisabled,
                        severity: Severity::Critical,
                        confidence: Confidence::Certain,
                        from_build: false,
                    },
                    text,
                    table_id,
                    at,
                    evidence,
                );
            }
        }

        for ((key, name), policy) in &self.policies {
            if MANAGED_SCHEMAS.contains(&key.schema.as_str()) {
                continue;
            }
            let reach = policy_reach(policy);
            let policy_id = NodeId::new(format!("policy:{}.{}/{}", key.schema, key.name, name));
            graph.add_node(Node {
                id: policy_id.clone(),
                label: name.clone(),
                kind: NodeKind::AccessRule {
                    scope: if policy_open(policy) {
                        RuleScope::Open
                    } else {
                        RuleScope::Conditional
                    },
                    strength: None,
                    detail: Some(AccessRuleDetail::PostgresPolicy {
                        command: policy.command,
                        roles: policy.roles.clone(),
                    }),
                },
                zone: Zone::Database,
                location: Some(policy.location.clone()),
            });
            graph.add_edge(table_id(key), policy_id.clone(), EdgeKind::GuardedBy);

            let exposed = EXPOSED_SCHEMAS.contains(&key.schema.as_str());
            if let (true, Some(reach)) = (exposed, reach) {
                let severity = policy_severity(reach, policy.command);
                let text = rules::policy_unrestricted(
                    &table_label(key),
                    name,
                    reach == Reach::Anyone,
                    policy.command,
                );
                let mut evidence = Vec::new();
                if let Some(table) = self.tables.get(key) {
                    evidence.push(step(
                        &table_label(key),
                        None,
                        Some(table_id(key)),
                        table
                            .defined_at
                            .clone()
                            .or_else(|| table.rls_changed_at.clone()),
                    ));
                }
                evidence.push(step(
                    name,
                    evidence.first().map(|_| EdgeKind::GuardedBy),
                    Some(policy_id.clone()),
                    Some(policy.location.clone()),
                ));
                graph.add_finding(
                    Verdict {
                        rule: RuleId::SupabasePolicyUnrestricted,
                        severity,
                        confidence: Confidence::Certain,
                        from_build: false,
                    },
                    text,
                    policy_id,
                    Some(policy.location.clone()),
                    evidence,
                );
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    Anyone,
    SignedIn,
}

fn policy_open(policy: &Policy) -> bool {
    let condition = match policy.command {
        PolicyCommand::Insert => &policy.check,
        PolicyCommand::Select
        | PolicyCommand::Update
        | PolicyCommand::Delete
        | PolicyCommand::All => &policy.using,
    };
    condition.open && !condition.signed_in && condition.buckets.is_empty()
}

fn policy_reach(policy: &Policy) -> Option<Reach> {
    if !policy.permissive || !policy_open(policy) {
        return None;
    }
    let has = |roles: &[&str]| {
        policy
            .roles
            .iter()
            .any(|role| roles.contains(&role.as_str()))
    };
    if has(ANONYMOUS_ROLES) {
        Some(Reach::Anyone)
    } else if has(SIGNED_IN_ROLES) {
        Some(Reach::SignedIn)
    } else {
        None
    }
}

fn policy_severity(reach: Reach, command: PolicyCommand) -> Severity {
    match (reach, command) {
        (Reach::Anyone, PolicyCommand::All | PolicyCommand::Update | PolicyCommand::Delete) => {
            Severity::Critical
        }
        (Reach::Anyone, PolicyCommand::Insert) => Severity::High,
        (Reach::Anyone, PolicyCommand::Select) => Severity::Medium,
        (Reach::SignedIn, PolicyCommand::All | PolicyCommand::Update | PolicyCommand::Delete) => {
            Severity::High
        }
        (Reach::SignedIn, PolicyCommand::Insert) => Severity::Medium,
        (Reach::SignedIn, PolicyCommand::Select) => Severity::Low,
    }
}

fn table_id(key: &TableKey) -> NodeId {
    NodeId::new(format!("table:{}.{}", key.schema, key.name))
}

fn table_label(key: &TableKey) -> String {
    if key.schema == DEFAULT_SCHEMA {
        key.name.clone()
    } else {
        format!("{}.{}", key.schema, key.name)
    }
}
