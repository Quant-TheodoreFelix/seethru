use std::collections::{BTreeMap, BTreeSet};

use seethru_core::{
    Basis, Confidence, ConfigDetail, DataStoreDetail, Edge, EdgeKind, EvidenceStep, Finding,
    Location, Node, NodeId, NodeKind, Origin, RlsStatus, RuleId, SCHEMA_VERSION, ScanReport,
    Severity, Summary, TargetInfo, ToolInfo, Unit, Zone,
};

use crate::classify::{FileRole, file_name};
use crate::rules::Text;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Verdict {
    pub rule: RuleId,
    pub severity: Severity,
    pub confidence: Confidence,
    pub from_build: bool,
}

#[derive(Default)]
pub(crate) struct Graph {
    nodes: BTreeMap<NodeId, Node>,
    edges: BTreeSet<Edge>,
    findings: BTreeMap<String, Finding>,
}

impl Graph {
    pub(crate) fn add_node(&mut self, node: Node) -> NodeId {
        let id = node.id.clone();
        self.nodes.entry(id.clone()).or_insert(node);
        id
    }

    pub(crate) fn add_file(&mut self, rel_path: &str, role: FileRole, basis: Basis) -> NodeId {
        let runtime = role.runtime();
        self.add_node(Node {
            id: file_id(rel_path),
            label: file_name(rel_path).to_owned(),
            kind: NodeKind::Component {
                runtime,
                artifact: role.artifact(),
                unit: Unit::File,
                basis,
            },
            zone: runtime.zone(),
            location: Some(file_location(rel_path)),
        })
    }

    pub(crate) fn add_env_var(&mut self, name: &str) -> NodeId {
        let exposed = crate::env::is_public(name);
        self.add_node(Node {
            id: NodeId::new(format!("env:{name}")),
            label: name.to_owned(),
            kind: NodeKind::Config {
                detail: Some(ConfigDetail::EnvVar {
                    exposed_to_client: exposed,
                }),
            },
            zone: if exposed { Zone::Client } else { Zone::Server },
            location: None,
        })
    }

    pub(crate) fn add_table(&mut self, schema: &str, name: &str) -> NodeId {
        let label = if schema == "public" {
            name.to_owned()
        } else {
            format!("{schema}.{name}")
        };
        self.add_node(Node {
            id: NodeId::new(format!("table:{schema}.{name}")),
            label,
            kind: NodeKind::DataStore {
                detail: Some(DataStoreDetail::PostgresTable {
                    schema: schema.to_owned(),
                    rls: RlsStatus::Unknown,
                }),
            },
            zone: Zone::Database,
            location: None,
        })
    }

    pub(crate) fn table_rls(&self, id: &NodeId) -> Option<RlsStatus> {
        match &self.nodes.get(id)?.kind {
            NodeKind::DataStore {
                detail: Some(DataStoreDetail::PostgresTable { rls, .. }),
            } => Some(*rls),
            _ => None,
        }
    }

    pub(crate) fn add_edge(&mut self, from: NodeId, to: NodeId, kind: EdgeKind) {
        self.edges.insert(Edge { from, to, kind });
    }

    pub(crate) fn add_finding(
        &mut self,
        verdict: Verdict,
        text: Text,
        node: NodeId,
        location: Option<Location>,
        evidence: Vec<EvidenceStep>,
    ) {
        let Verdict {
            rule,
            severity,
            confidence,
            from_build,
        } = verdict;
        let id = format!("{}:{}", rule.as_str(), node);
        self.findings.entry(id.clone()).or_insert(Finding {
            id,
            rule,
            severity,
            confidence,
            title: text.title,
            explanation: text.explanation,
            node,
            location,
            evidence,
            origin: if from_build {
                Origin::seethru_with_build_output()
            } else {
                Origin::seethru()
            },
            cwe: rule.cwe().to_vec(),
            proof: None,
            fix_prompt: None,
            accepted: None,
        });
    }

    pub(crate) fn has_node(&self, id: &NodeId) -> bool {
        self.nodes.contains_key(id)
    }

    pub(crate) fn finding_count(&self) -> usize {
        self.findings.len()
    }

    pub(crate) fn add_external(&mut self, finding: Finding) {
        self.findings.entry(finding.id.clone()).or_insert(finding);
    }

    pub(crate) fn finish(self, target: TargetInfo) -> ScanReport {
        let edges: Vec<Edge> = self
            .edges
            .into_iter()
            .filter(|edge| self.nodes.contains_key(&edge.from) && self.nodes.contains_key(&edge.to))
            .collect();
        let mut findings: Vec<Finding> = self
            .findings
            .into_values()
            .filter(|finding| self.nodes.contains_key(&finding.node))
            .collect();
        for finding in &mut findings {
            for step in &mut finding.evidence {
                if step
                    .node
                    .as_ref()
                    .is_some_and(|id| !self.nodes.contains_key(id))
                {
                    step.node = None;
                }
            }
        }
        findings.sort_by(|a, b| {
            (a.severity, a.rule, &a.location, &a.id).cmp(&(b.severity, b.rule, &b.location, &b.id))
        });
        ScanReport {
            schema_version: SCHEMA_VERSION,
            tool: ToolInfo {
                name: "seethru".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            target,
            summary: Summary::from_findings(&findings),
            nodes: self.nodes.into_values().collect(),
            edges,
            findings,
        }
    }
}

pub(crate) fn file_id(rel_path: &str) -> NodeId {
    NodeId::new(format!("file:{rel_path}"))
}

pub(crate) fn file_location(rel_path: &str) -> Location {
    Location {
        path: rel_path.to_owned(),
        line: 1,
        column: 1,
    }
}

pub(crate) fn step(
    label: &str,
    via: Option<EdgeKind>,
    node: Option<NodeId>,
    location: Option<Location>,
) -> EvidenceStep {
    EvidenceStep {
        label: label.to_owned(),
        via,
        node,
        location,
    }
}

pub(crate) fn file_step(rel_path: &str, via: Option<EdgeKind>, at: Location) -> EvidenceStep {
    step(file_name(rel_path), via, Some(file_id(rel_path)), Some(at))
}
