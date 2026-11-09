use seethru_core::{
    AccessRuleDetail, Basis, BucketVisibility, Confidence, DataStoreDetail, EdgeKind, Node, NodeId,
    NodeKind, PolicyCommand, RlsStatus, RuleId, RuleScope, Severity, Zone,
};

use super::{
    ANONYMOUS_ROLES, Condition, DEFAULT_SCHEMA, EXPOSED_SCHEMAS, MANAGED_SCHEMAS, Migrations,
    Policy, SIGNED_IN_ROLES, TableKey, View,
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

        self.emit_buckets(graph);
        self.emit_views(graph);
        for ((key, name), policy) in &self.policies {
            if key.schema == "storage" && key.name == "objects" {
                self.emit_storage_policy(graph, name, policy);
                continue;
            }
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

    fn emit_buckets(&self, graph: &mut Graph) {
        for (id, bucket) in &self.buckets {
            let bucket_id = self.bucket_node(graph, id);
            if let Some(at) = &bucket.defined_at {
                let file_id = graph.add_file(&at.path, FileRole::Migration, Basis::Path);
                graph.add_edge(file_id, bucket_id, EdgeKind::Defines);
            }
        }
    }

    fn bucket_node(&self, graph: &mut Graph, id: &str) -> NodeId {
        let bucket = self.buckets.get(id);
        graph.add_node(Node {
            id: bucket_id(id),
            label: id.to_owned(),
            kind: NodeKind::DataStore {
                detail: Some(DataStoreDetail::StorageBucket {
                    visibility: bucket
                        .map_or(BucketVisibility::Unknown, |bucket| bucket.visibility),
                }),
            },
            zone: Zone::Database,
            location: bucket.and_then(|bucket| bucket.defined_at.clone()),
        })
    }

    fn emit_storage_policy(&self, graph: &mut Graph, name: &str, policy: &Policy) {
        let condition = deciding_condition(policy);
        let policy_id = NodeId::new(format!("policy:storage.objects/{name}"));
        graph.add_node(Node {
            id: policy_id.clone(),
            label: name.to_owned(),
            kind: NodeKind::AccessRule {
                scope: if condition.open {
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
        for bucket in policy.using.buckets.union(&policy.check.buckets) {
            let bucket_id = self.bucket_node(graph, bucket);
            graph.add_edge(bucket_id, policy_id.clone(), EdgeKind::GuardedBy);
        }
        if !policy.permissive || !condition.open {
            return;
        }
        let Some(reach) = reach_of(&policy.roles, condition.signed_in) else {
            return;
        };
        let buckets: Vec<String> = condition.buckets.iter().cloned().collect();
        let mut evidence = Vec::new();
        if let Some(first) = buckets.first() {
            evidence.push(step(
                first,
                None,
                Some(bucket_id(first)),
                self.buckets
                    .get(first)
                    .and_then(|bucket| bucket.defined_at.clone()),
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
                rule: RuleId::SupabaseStoragePolicyUnrestricted,
                severity: policy_severity(reach, policy.command),
                confidence: Confidence::Certain,
                from_build: false,
            },
            rules::storage_policy_unrestricted(
                name,
                &buckets,
                reach == Reach::Anyone,
                policy.command,
            ),
            policy_id,
            Some(policy.location.clone()),
            evidence,
        );
    }

    fn emit_views(&self, graph: &mut Graph) {
        for (key, view) in &self.views {
            if MANAGED_SCHEMAS.contains(&key.schema.as_str()) {
                continue;
            }
            let view_id = table_id(key);
            let label = table_label(key);
            graph.add_node(Node {
                id: view_id.clone(),
                label: label.clone(),
                kind: NodeKind::DataStore {
                    detail: Some(DataStoreDetail::PostgresView {
                        schema: key.schema.clone(),
                        security_invoker: view.security_invoker,
                        materialized: view.materialized,
                    }),
                },
                zone: Zone::Database,
                location: Some(view.defined_at.clone()),
            });
            let path = &view.defined_at.path;
            let file_id = graph.add_file(path, FileRole::Migration, Basis::Path);
            graph.add_edge(file_id, view_id.clone(), EdgeKind::Defines);
            if let Some(verdict) = view_verdict(key, view) {
                let facts = rules::ViewFacts {
                    anyone: view.readers.anyone(),
                    materialized: view.materialized,
                    auth_users: reads_auth_users(view),
                    checks_caller: view.checks_caller,
                };
                let mut evidence = vec![
                    file_step(path, None, file_location(path)),
                    step(
                        &label,
                        Some(EdgeKind::Defines),
                        Some(view_id.clone()),
                        Some(view.defined_at.clone()),
                    ),
                ];
                for read in view.reads.iter().take(MAX_VIEW_READS) {
                    evidence.push(step(
                        &table_label(read),
                        Some(EdgeKind::Reads),
                        Some(table_id(read)),
                        Some(view.defined_at.clone()),
                    ));
                }
                graph.add_finding(
                    verdict,
                    rules::view_bypasses_rls(&label, &facts),
                    view_id,
                    Some(view.defined_at.clone()),
                    evidence,
                );
            }
        }
    }
}

const MAX_VIEW_READS: usize = 8;

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

fn bucket_id(id: &str) -> NodeId {
    NodeId::new(format!("store:storageBucket:{id}"))
}

fn deciding_condition(policy: &Policy) -> &Condition {
    match policy.command {
        PolicyCommand::Insert => &policy.check,
        PolicyCommand::Select
        | PolicyCommand::Update
        | PolicyCommand::Delete
        | PolicyCommand::All => &policy.using,
    }
}

fn reach_of(roles: &[String], signed_in: bool) -> Option<Reach> {
    let has = |names: &[&str]| roles.iter().any(|role| names.contains(&role.as_str()));
    if signed_in {
        (has(&["public"]) || has(SIGNED_IN_ROLES)).then_some(Reach::SignedIn)
    } else if has(ANONYMOUS_ROLES) {
        Some(Reach::Anyone)
    } else if has(SIGNED_IN_ROLES) {
        Some(Reach::SignedIn)
    } else {
        None
    }
}

fn reads_auth_users(view: &View) -> bool {
    view.reads
        .iter()
        .any(|read| read.schema == "auth" && read.name == "users")
}

fn view_verdict(key: &TableKey, view: &View) -> Option<Verdict> {
    let bypasses = view.materialized || !view.security_invoker;
    if !EXPOSED_SCHEMAS.contains(&key.schema.as_str()) || !bypasses || !view.owner_is_admin {
        return None;
    }
    let anyone = view.readers.anyone();
    if !anyone && !view.readers.signed_in() {
        return None;
    }
    let (severity, confidence) = if view.checks_caller {
        (Severity::Low, Confidence::Review)
    } else if reads_auth_users(view) {
        (Severity::Critical, Confidence::Certain)
    } else if anyone {
        (Severity::High, Confidence::Certain)
    } else {
        (Severity::Medium, Confidence::Certain)
    };
    Some(Verdict {
        rule: RuleId::SupabaseViewBypassesRls,
        severity,
        confidence,
        from_build: false,
    })
}
