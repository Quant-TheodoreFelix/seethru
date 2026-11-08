use std::collections::{BTreeMap, BTreeSet};

use seethru_core::{
    Edge, EdgeKind, FileRole, Finding, Location, Node, NodeId, NodeKind, RuleId, SCHEMA_VERSION,
    ScanReport, Severity, Summary, TargetInfo, ToolInfo,
};

use crate::classify::file_name;
use crate::rules::Text;

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

    pub(crate) fn add_file(&mut self, rel_path: &str, role: FileRole) -> NodeId {
        self.add_node(Node {
            id: file_id(rel_path),
            label: file_name(rel_path).to_owned(),
            kind: NodeKind::File { role },
            location: Some(Location {
                path: rel_path.to_owned(),
                line: 1,
                column: 1,
            }),
        })
    }

    pub(crate) fn add_env_var(&mut self, name: &str) -> NodeId {
        self.add_node(Node {
            id: NodeId::new(format!("env:{name}")),
            label: name.to_owned(),
            kind: NodeKind::EnvVar {
                exposed_to_browser: crate::env::is_public(name),
            },
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
            kind: NodeKind::Table {
                schema: schema.to_owned(),
                rls: seethru_core::RlsStatus::Unknown,
            },
            location: None,
        })
    }

    pub(crate) fn add_edge(&mut self, from: NodeId, to: NodeId, kind: EdgeKind) {
        self.edges.insert(Edge { from, to, kind });
    }

    pub(crate) fn add_finding(
        &mut self,
        rule: RuleId,
        severity: Severity,
        text: Text,
        node: NodeId,
        location: Option<Location>,
    ) {
        let id = format!("{}:{}", rule.as_str(), node);
        self.findings.entry(id.clone()).or_insert(Finding {
            id,
            rule,
            severity,
            title: text.title,
            explanation: text.explanation,
            node,
            location,
            fix_prompt: None,
        });
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
