use std::collections::BTreeMap;

use seethru_core::{
    Confidence, EvidenceStep, Finding, Lang, Location, RuleId, ScanReport, Severity,
};
use serde_json::{Value, json};

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const MAX_FLOW_STEPS: usize = 100;

pub fn render_sarif(report: &ScanReport, lang: Lang) -> Result<String, serde_json::Error> {
    let findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule != RuleId::External)
        .collect();
    let mut worst: BTreeMap<RuleId, Severity> = BTreeMap::new();
    for finding in &findings {
        let slot = worst.entry(finding.rule).or_insert(finding.severity);
        *slot = (*slot).min(finding.severity);
    }
    let order: Vec<RuleId> = worst.keys().copied().collect();
    let rules: Vec<Value> = worst
        .iter()
        .map(|(rule, severity)| rule_entry(*rule, *severity, lang))
        .collect();
    let results: Vec<Value> = findings
        .iter()
        .map(|finding| {
            let index = order.iter().position(|rule| *rule == finding.rule);
            result_entry(report, finding, index, lang)
        })
        .collect();
    let log = json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": report.tool.name,
                    "version": report.tool.version,
                    "rules": rules,
                }
            },
            "automationDetails": { "id": "seethru/" },
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&log)
}

fn rule_entry(rule: RuleId, severity: Severity, lang: Lang) -> Value {
    let text = rule_text(rule, lang);
    let mut tags = vec![Value::from("security")];
    tags.extend(
        rule.cwe()
            .iter()
            .map(|number| Value::from(format!("external/cwe/cwe-{number:03}"))),
    );
    let mut properties = json!({ "tags": tags });
    if let (Some(score), Some(map)) = (score(severity), properties.as_object_mut()) {
        map.insert("security-severity".to_owned(), Value::from(score));
    }
    json!({
        "id": rule.as_str(),
        "name": rule.as_str(),
        "shortDescription": { "text": text },
        "fullDescription": { "text": text },
        "help": { "text": text },
        "defaultConfiguration": { "level": level(severity) },
        "properties": properties,
    })
}

fn result_entry(report: &ScanReport, finding: &Finding, index: Option<usize>, lang: Lang) -> Value {
    let mut result = json!({
        "ruleId": finding.rule.as_str(),
        "level": level(finding.severity),
        "message": {
            "text": format!("{} {}", finding.title.get(lang), finding.explanation.get(lang))
        },
        "partialFingerprints": { "seethruFindingId/v1": finding.id },
        "properties": {
            "seethru/severity": severity_name(finding.severity),
            "seethru/confidence": confidence_name(finding.confidence),
        },
    });
    let Some(map) = result.as_object_mut() else {
        return result;
    };
    if let Some(index) = index {
        map.insert("ruleIndex".to_owned(), Value::from(index));
    }
    let place = finding.location.as_ref().or_else(|| {
        report
            .nodes
            .iter()
            .find(|node| node.id == finding.node)
            .and_then(|node| node.location.as_ref())
    });
    if let Some(place) = place {
        map.insert("locations".to_owned(), json!([location(place, None)]));
    }
    let steps: Vec<Value> = finding
        .evidence
        .iter()
        .filter_map(flow_step)
        .take(MAX_FLOW_STEPS)
        .collect();
    if steps.len() >= 2 {
        map.insert(
            "codeFlows".to_owned(),
            json!([{ "threadFlows": [{ "locations": steps }] }]),
        );
    }
    if let Some(accepted) = &finding.accepted {
        map.insert(
            "suppressions".to_owned(),
            json!([{ "kind": "external", "status": "accepted", "justification": accepted.reason }]),
        );
    }
    result
}

fn flow_step(step: &EvidenceStep) -> Option<Value> {
    let place = step.location.as_ref()?;
    Some(json!({ "location": location(place, Some(&step.label)) }))
}

fn location(place: &Location, label: Option<&str>) -> Value {
    let mut value = json!({
        "physicalLocation": {
            "artifactLocation": { "uri": uri(&place.path), "uriBaseId": "%SRCROOT%" },
            "region": { "startLine": place.line.max(1), "startColumn": place.column.max(1) },
        }
    });
    if let (Some(label), Some(map)) = (label, value.as_object_mut()) {
        map.insert("message".to_owned(), json!({ "text": label }));
    }
    value
}

fn uri(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn score(severity: Severity) -> Option<&'static str> {
    match severity {
        Severity::Critical => Some("9.5"),
        Severity::High => Some("8.0"),
        Severity::Medium => Some("5.5"),
        Severity::Low => Some("2.0"),
        Severity::Info => None,
    }
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Certain => "certain",
        Confidence::Likely => "likely",
        Confidence::Review => "review",
    }
}

fn rule_text(rule: RuleId, lang: Lang) -> &'static str {
    let (en, ko) = match rule {
        RuleId::SupabaseRlsDisabled => (
            "A table in the public schema has row level security turned off.",
            "public 스키마의 테이블에 RLS가 꺼져 있어요.",
        ),
        RuleId::SupabasePolicyUnrestricted => (
            "A policy opens every row to anyone, or to every signed-in user.",
            "정책이 누구나, 또는 로그인한 모든 사용자에게 모든 행을 열어요.",
        ),
        RuleId::SupabaseServiceRoleInBrowser => (
            "Browser code reads the service_role key through a public environment variable.",
            "브라우저 코드가 공개 환경변수로 service_role 키를 읽어요.",
        ),
        RuleId::SecretInBrowserCode => (
            "A secret value is in code or a file that is sent to the browser.",
            "브라우저로 전달되는 코드나 파일에 비밀 값이 있어요.",
        ),
        RuleId::SecretInSourceCode => (
            "A secret value is written in a file that stays on the server.",
            "브라우저로 가지 않는 파일에 비밀 값이 적혀 있어요.",
        ),
        RuleId::SecretInPublicEnvVar => (
            "A secret value is in an environment variable with a public prefix.",
            "공개 접두사가 붙은 환경변수에 비밀 값이 있어요.",
        ),
        RuleId::SupabaseTableSchemaMissing => (
            "The code uses a table that no SQL file in the repo creates, so its row level security could not be checked.",
            "코드에서 쓰는 테이블을 만드는 SQL이 저장소에 없어서 RLS를 확인하지 못했어요.",
        ),
        RuleId::SupabaseFunctionBypassesRls => (
            "A security definer function that anyone or any signed-in user can call runs without row level security.",
            "누구나 또는 로그인한 사용자가 부를 수 있는 security definer 함수가 RLS 없이 실행돼요.",
        ),
        RuleId::SupabaseViewBypassesRls => (
            "A view skips row level security and can be read by anyone or any signed-in user.",
            "뷰가 RLS를 건너뛰고 누구나 또는 로그인한 사용자에게 읽혀요.",
        ),
        RuleId::SupabaseStoragePolicyUnrestricted => (
            "A storage policy opens every file in a bucket to anyone, or to every signed-in user.",
            "Storage 정책이 버킷의 모든 파일을 누구나, 또는 로그인한 모든 사용자에게 열어요.",
        ),
        RuleId::SupabaseServiceRoleUnguarded => (
            "A route, server action or Edge Function uses the service_role key without checking who is calling.",
            "route, server action, Edge Function이 누가 부르는지 확인하지 않고 service_role 키를 써요.",
        ),
        RuleId::FirmwareInsecureOptionOn => (
            "A firmware setting that is meant only for testing is turned on.",
            "테스트용으로만 쓰는 펌웨어 설정이 켜져 있어요.",
        ),
        RuleId::FirmwareOtaOverHttp => (
            "Firmware updates are allowed to download over plain HTTP.",
            "펌웨어 업데이트를 암호화되지 않은 HTTP로 받을 수 있어요.",
        ),
        RuleId::FirmwareTlsVerificationOff => (
            "The firmware is allowed to skip checking the server's certificate.",
            "펌웨어가 서버 인증서 확인을 건너뛸 수 있어요.",
        ),
        RuleId::FirmwareOtaUnguarded => (
            "An entry point of the firmware accepts a firmware update without checking who is sending it.",
            "펌웨어의 진입점이 누가 보내는지 확인하지 않고 펌웨어 업데이트를 받아요.",
        ),
        RuleId::SecretInNativeCode => (
            "A secret value is written in C or C++ code that is built into a program or firmware.",
            "프로그램이나 펌웨어로 빌드되는 C, C++ 코드에 비밀 값이 적혀 있어요.",
        ),
        RuleId::SecretDependentDivision => (
            "Compiled code divides a value that comes from memory the program wipes after use, so the time it takes can reveal a secret.",
            "컴파일된 코드가 프로그램이 쓰고 나서 지우는 메모리에서 나온 값을 나눠서, 걸리는 시간으로 비밀이 드러날 수 있어요.",
        ),
        RuleId::StopOnOutsideInput => (
            "Compiled code keeps a check that panics, and the value it tests comes from an exported entry point, so a caller may be able to stop the program.",
            "컴파일된 코드에 panic하는 검사가 남아 있고 그 값이 외부 진입점에서 들어와서, 호출자가 프로그램을 멈출 수 있어요.",
        ),
        RuleId::MemoryWipeRemoved => (
            "Code that clears a secret from memory is written in the source, but the program that was built has no code for it.",
            "비밀을 메모리에서 지우는 코드가 소스에는 있는데, 빌드된 프로그램에는 그 코드가 없어요.",
        ),
        RuleId::CargoDependencyNotPinned => (
            "A Cargo dependency is not fixed to one version and the project has no Cargo.lock.",
            "Cargo 의존성이 한 버전으로 고정돼 있지 않고 프로젝트에 Cargo.lock이 없어요.",
        ),
        RuleId::External => (
            "A result reported by an outside scanner.",
            "외부 검사 도구가 알린 결과예요.",
        ),
    };
    match lang {
        Lang::En => en,
        Lang::Ko => ko,
    }
}
