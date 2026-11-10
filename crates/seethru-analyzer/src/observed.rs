use seethru_core::{
    Channel, Confidence, EvidenceStep, Exposure, Finding, Input, LimitationCode, Node, NodeId,
    NodeKind, Origin, ProbeEnvironment, ProofRef, RuleId, Severity, ToolUse, Zone,
};
use seethru_probe::{Cors, Kind, Outcome};

use crate::graph::Graph;
use crate::rules;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub tool: Option<ToolUse>,
    pub production: bool,
    pub outcome: Outcome,
}

pub(crate) struct Checked {
    pub inputs: Vec<Input>,
    pub limitations: Vec<LimitationCode>,
}

const NODE: &str = "entry:deployed-app";

pub(crate) fn emit(observed: &Observed, graph: &mut Graph) -> Checked {
    let mut limitations = observed.outcome.problems.clone();
    let mut inputs = Vec::new();
    let Some(tool) = &observed.tool else {
        return Checked {
            inputs,
            limitations,
        };
    };
    if observed.outcome.requests > 0 {
        inputs.push(Input::Probe {
            environment: if observed.production {
                ProbeEnvironment::Production
            } else {
                ProbeEnvironment::Staging
            },
            tools: vec![tool.clone()],
            requests: observed.outcome.requests,
        });
    }
    if !observed.outcome.verified {
        return Checked {
            inputs,
            limitations,
        };
    }
    limitations.push(LimitationCode::ProbeChecksPartial);
    if observed.outcome.facts.is_empty() {
        return Checked {
            inputs,
            limitations,
        };
    }
    let node = graph.add_node(Node {
        id: NodeId::new(NODE),
        label: "Running app".to_owned(),
        kind: NodeKind::EntryPoint {
            channel: Channel::HttpRoute,
            exposure: Exposure::Public,
        },
        zone: Zone::Server,
        location: None,
    });
    for fact in &observed.outcome.facts {
        let (rule, severity, confidence, text) = match fact.kind {
            Kind::HeaderMissing(header) => (
                RuleId::SecurityHeaderMissing,
                Severity::Low,
                Confidence::Certain,
                rules::security_header_missing(header),
            ),
            Kind::CorsOpen(cors) => (
                RuleId::CorsAllowsAnyOriginWithCredentials,
                match cors {
                    Cors::ReflectsWithCredentials => Severity::Medium,
                    Cors::WildcardWithCredentials => Severity::Low,
                },
                match cors {
                    Cors::ReflectsWithCredentials => Confidence::Likely,
                    Cors::WildcardWithCredentials => Confidence::Review,
                },
                rules::cors_open(cors),
            ),
        };
        let evidence = fact
            .steps
            .iter()
            .map(|step| EvidenceStep {
                label: format!("{} {} -> {}", step.method, step.path, step.status),
                via: None,
                node: Some(node.clone()),
                location: None,
            })
            .collect();
        graph.add_external(Finding {
            id: fact.id(),
            rule,
            severity,
            confidence,
            title: text.title,
            explanation: text.explanation,
            node: node.clone(),
            location: None,
            evidence,
            origin: Origin::seethru_with_probe(vec![tool.name.clone()]),
            cwe: rule.cwe().to_vec(),
            proof: Some(ProofRef::new(fact.proof_file())),
            fix_prompt: None,
            accepted: None,
        });
    }
    Checked {
        inputs,
        limitations,
    }
}
