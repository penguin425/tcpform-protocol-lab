//! Multi-implementation interoperability and observable-behavior reports.

use crate::TraceEvent;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InteroperabilityConfig {
    pub implementations: Vec<ImplementationTarget>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImplementationTarget {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct ImplementationRun {
    pub name: String,
    pub address: String,
    pub trace: Vec<TraceEvent>,
    pub failure_kind: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InteroperabilityReport {
    pub schema_version: &'static str,
    pub protocol: String,
    pub role: String,
    pub status: String,
    pub implementations: Vec<ImplementationResult>,
    pub comparisons: Vec<PairComparison>,
    pub compatibility_matrix: Vec<CompatibilityRow>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImplementationResult {
    pub name: String,
    pub address: String,
    pub status: String,
    pub events: usize,
    pub failure_kind: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PairComparison {
    pub left: String,
    pub right: String,
    pub compatible: bool,
    pub differences: Vec<EventDifference>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EventDifference {
    pub index: usize,
    pub left: Option<serde_json::Value>,
    pub right: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompatibilityRow {
    pub implementation: String,
    pub compatible: BTreeMap<String, bool>,
}

pub fn validate_config(config: &InteroperabilityConfig) -> Result<(), String> {
    if config.implementations.len() < 2 {
        return Err("interoperability requires at least two implementations".into());
    }
    let mut names = std::collections::HashSet::new();
    for implementation in &config.implementations {
        if implementation.name.trim().is_empty() {
            return Err("implementation name must not be empty".into());
        }
        if implementation.address.trim().is_empty() {
            return Err(format!(
                "implementation `{}` address must not be empty",
                implementation.name
            ));
        }
        if !names.insert(&implementation.name) {
            return Err(format!(
                "duplicate implementation name `{}`",
                implementation.name
            ));
        }
    }
    Ok(())
}

pub fn build_report(
    protocol: &str,
    role: &str,
    runs: &[ImplementationRun],
) -> InteroperabilityReport {
    let implementations = runs
        .iter()
        .map(|run| ImplementationResult {
            name: run.name.clone(),
            address: run.address.clone(),
            status: if run.error.is_none() {
                "passed"
            } else {
                "failed"
            }
            .into(),
            events: run.trace.len(),
            failure_kind: run.failure_kind.clone(),
            error: run.error.clone(),
        })
        .collect::<Vec<_>>();
    let mut comparisons = Vec::new();
    for left_index in 0..runs.len() {
        for right_index in left_index + 1..runs.len() {
            let left = &runs[left_index];
            let right = &runs[right_index];
            let left_events = normalized(&left.trace);
            let right_events = normalized(&right.trace);
            let differences = (0..left_events.len().max(right_events.len()))
                .filter_map(|index| {
                    let left = left_events.get(index);
                    let right = right_events.get(index);
                    (left != right).then(|| EventDifference {
                        index,
                        left: left.cloned(),
                        right: right.cloned(),
                    })
                })
                .collect::<Vec<_>>();
            comparisons.push(PairComparison {
                left: left.name.clone(),
                right: right.name.clone(),
                compatible: left.error.is_none() && right.error.is_none() && differences.is_empty(),
                differences,
            });
        }
    }
    let compatibility_matrix = runs
        .iter()
        .map(|left| CompatibilityRow {
            implementation: left.name.clone(),
            compatible: runs
                .iter()
                .map(|right| {
                    let compatible = if left.name == right.name {
                        left.error.is_none()
                    } else {
                        comparisons
                            .iter()
                            .find(|comparison| {
                                (comparison.left == left.name && comparison.right == right.name)
                                    || (comparison.left == right.name
                                        && comparison.right == left.name)
                            })
                            .is_some_and(|comparison| comparison.compatible)
                    };
                    (right.name.clone(), compatible)
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    let interoperable = implementations
        .iter()
        .all(|implementation| implementation.status == "passed")
        && comparisons.iter().all(|comparison| comparison.compatible)
        && !comparisons.is_empty();
    InteroperabilityReport {
        schema_version: "1.0",
        protocol: protocol.into(),
        role: role.into(),
        status: if interoperable {
            "interoperable"
        } else {
            "not_interoperable"
        }
        .into(),
        implementations,
        comparisons,
        compatibility_matrix,
    }
}

fn normalized(trace: &[TraceEvent]) -> Vec<serde_json::Value> {
    trace
        .iter()
        .map(|event| {
            json!({
                "role": event.role,
                "step": event.step,
                "action": event.action.as_str(),
                "ok": event.ok,
                "flags": event.flags,
                "seq": event.seq_num,
                "ack": event.ack_num,
                "peer": event.peer,
                "wire_hex": crate::bytes_to_hex(&event.wire_data),
                "network": format!("{:?}", event.network).to_lowercase(),
            })
        })
        .collect()
}

pub fn markdown(report: &InteroperabilityReport) -> String {
    let names = report
        .implementations
        .iter()
        .map(|implementation| implementation.name.as_str())
        .collect::<Vec<_>>();
    let mut output = format!(
        "# tcpform interoperability report\n\n- Protocol: `{}`\n- Role: `{}`\n- Status: **{}**\n\n| Implementation | Address | Status | Events |\n| --- | --- | --- | ---: |\n",
        report.protocol, report.role, report.status
    );
    for implementation in &report.implementations {
        output.push_str(&format!(
            "| {} | `{}` | {} | {} |\n",
            implementation.name.replace('|', "\\|"),
            implementation.address.replace('|', "\\|"),
            implementation.status,
            implementation.events
        ));
    }
    output.push_str("\n## Compatibility matrix\n\n| | ");
    output.push_str(&names.join(" | "));
    output.push_str(" |\n| --- |");
    output.push_str(&" --- |".repeat(names.len()));
    output.push('\n');
    for row in &report.compatibility_matrix {
        output.push_str(&format!("| {} |", row.implementation));
        for name in &names {
            output.push_str(if row.compatible.get(*name).copied().unwrap_or(false) {
                " ✓ |"
            } else {
                " ✗ |"
            });
        }
        output.push('\n');
    }
    output
}

pub fn junit(report: &InteroperabilityReport) -> String {
    let mut cases = String::new();
    for comparison in &report.comparisons {
        let failure = if comparison.compatible {
            String::new()
        } else {
            format!(
                "<failure message=\"{} observable differences\"/>",
                comparison.differences.len()
            )
        };
        cases.push_str(&format!(
            "  <testcase classname=\"tcpform.interoperability.{}\" name=\"{} vs {}\">{failure}</testcase>\n",
            xml(&report.protocol),
            xml(&comparison.left),
            xml(&comparison.right)
        ));
    }
    let failures = report
        .comparisons
        .iter()
        .filter(|comparison| !comparison.compatible)
        .count();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"tcpform interoperability\" tests=\"{}\" failures=\"{failures}\">\n{cases}</testsuite>\n",
        report.comparisons.len()
    )
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_targets_and_builds_a_pairwise_matrix() {
        let protocol = crate::model::interpret(
            &crate::parse_file(
                r#"protocol "ping" {
                  step "send" { role="client" action="send" to="server" segment { payload="ping" } }
                  step "recv" { role="server" action="recv" expect { payload="ping" } }
                }"#,
            )
            .unwrap(),
        )
        .unwrap()
        .remove(0);
        let trace = crate::Engine::new(protocol).unwrap().run().unwrap();
        let mut different = trace.clone();
        different[0].wire_data[0] ^= 1;
        let report = build_report(
            "ping",
            "client",
            &[
                ImplementationRun {
                    name: "a".into(),
                    address: "a:1".into(),
                    trace: trace.clone(),
                    failure_kind: None,
                    error: None,
                },
                ImplementationRun {
                    name: "b".into(),
                    address: "b:1".into(),
                    trace,
                    failure_kind: None,
                    error: None,
                },
                ImplementationRun {
                    name: "c".into(),
                    address: "c:1".into(),
                    trace: different,
                    failure_kind: None,
                    error: None,
                },
            ],
        );
        assert_eq!(report.status, "not_interoperable");
        assert_eq!(report.comparisons.len(), 3);
        assert!(report.comparisons[0].compatible);
        assert!(!report.comparisons[1].compatible);
        assert!(markdown(&report).contains("Compatibility matrix"));
        assert!(junit(&report).contains("failures=\"2\""));
    }
}
