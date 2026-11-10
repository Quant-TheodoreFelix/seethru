use std::path::PathBuf;

use seethru_core::{Acceptance, Lang, RuleId};
use serde_json::Value;

#[test]
fn sarif_output_lists_built_in_findings_with_rules_locations_and_flows() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/supabase-next");
    let scanned = seethru_analyzer::scan(&root);
    assert!(scanned.is_ok(), "{scanned:?}");
    let Ok(mut report) = scanned else { return };
    assert!(!report.findings.is_empty());
    if let Some(first) = report.findings.first_mut() {
        first.accepted = Some(Acceptance {
            reason: "Known and planned".to_owned(),
        });
    }
    let mut outside = report.findings[0].clone();
    outside.id = "external:semgrep:x:file:a.c:1".to_owned();
    outside.rule = RuleId::External;
    report.findings.push(outside);

    let rendered = seethru_report::render_sarif(&report, Lang::En);
    assert!(rendered.is_ok(), "{rendered:?}");
    let Ok(text) = rendered else { return };
    assert_eq!(
        seethru_report::render_sarif(&report, Lang::En).ok(),
        Some(text.clone())
    );
    let parsed: Result<Value, _> = serde_json::from_str(&text);
    assert!(parsed.is_ok());
    let Ok(log) = parsed else { return };

    assert_eq!(log["version"], "2.1.0");
    let run = &log["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "seethru");
    let empty = Vec::new();
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap_or(&empty);
    let results = run["results"].as_array().unwrap_or(&empty);
    assert_eq!(results.len(), report.findings.len() - 1);
    assert!(rules.iter().all(|rule| rule["id"] != "external"));
    for rule in rules {
        for key in ["shortDescription", "fullDescription", "help"] {
            assert!(
                rule[key]["text"].as_str().is_some_and(|t| !t.is_empty()),
                "{rule}"
            );
        }
    }
    for result in results {
        let index = result["ruleIndex"]
            .as_u64()
            .and_then(|i| usize::try_from(i).ok());
        assert_eq!(
            index.and_then(|i| rules.get(i)).map(|rule| &rule["id"]),
            Some(&result["ruleId"])
        );
        assert!(
            result["message"]["text"]
                .as_str()
                .is_some_and(|t| !t.is_empty())
        );
        assert!(
            result["partialFingerprints"]["seethruFindingId/v1"]
                .as_str()
                .is_some()
        );
        let place = &result["locations"][0]["physicalLocation"];
        assert_eq!(place["artifactLocation"]["uriBaseId"], "%SRCROOT%");
        assert!(
            place["artifactLocation"]["uri"]
                .as_str()
                .is_some_and(|uri| !uri.starts_with('/') && !uri.contains(' '))
        );
        assert!(
            place["region"]["startLine"]
                .as_u64()
                .is_some_and(|n| n >= 1)
        );
    }
    assert_eq!(results[0]["suppressions"][0]["status"], "accepted");
    assert_eq!(
        results[0]["suppressions"][0]["justification"],
        "Known and planned"
    );
    let unguarded = results
        .iter()
        .find(|result| result["ruleId"] == "supabase-service-role-unguarded");
    assert!(
        unguarded.is_some_and(|result| {
            result["level"] == "error"
                && result["codeFlows"][0]["threadFlows"][0]["locations"]
                    .as_array()
                    .is_some_and(|steps| steps.len() >= 2)
        }),
        "{unguarded:?}"
    );
    let critical = rules
        .iter()
        .find(|rule| rule["id"] == "supabase-service-role-in-browser");
    assert!(
        critical.is_some_and(|rule| {
            rule["properties"]["security-severity"] == "9.5"
                && rule["properties"]["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.contains(&Value::from("external/cwe/cwe-798")))
        }),
        "{critical:?}"
    );
}
