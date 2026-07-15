//! CI snapshots and human/machine-readable regression comparisons.

use crate::model::{Cases, Protocol};
use crate::{bytes_to_hex, Engine, TraceEvent};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const CI_SNAPSHOT_VERSION: &str = "1.0";

pub fn create_snapshot(
    protocols: &[Protocol],
    suites: &[Cases],
    filter: Option<&str>,
) -> Result<Value, String> {
    let selected = protocols
        .iter()
        .filter(|protocol| filter.is_none_or(|name| protocol.name == name))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Err(filter.map_or_else(
            || "no protocols found".into(),
            |name| format!("unknown protocol `{name}`"),
        ));
    }
    let mut runs = Vec::new();
    let mut case_values = Vec::new();
    let mut packets = Vec::new();
    let mut states = Vec::new();
    for protocol in selected {
        let manifest: Value = serde_json::from_str(&crate::output::visualization_manifest(
            protocol,
            suites,
            &[],
        ))
        .map_err(|error| error.to_string())?;
        let headers = manifest
            .get("steps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|step| {
                Some((
                    step.get("name")?.as_str()?.to_string(),
                    step.get("headers").cloned().unwrap_or(Value::Null),
                ))
            })
            .collect::<BTreeMap<_, _>>();
        if let Some(steps) = manifest.get("steps").and_then(Value::as_array) {
            for step in steps {
                states.push(json!({
                    "protocol": protocol.name,
                    "step": step.get("name"),
                    "from_state": step.get("from_state"),
                    "to_state": step.get("to_state"),
                    "depends_on": step.get("depends_on")
                }));
            }
        }
        let matching_suites = suites
            .iter()
            .filter(|suite| suite.protocol == protocol.name)
            .collect::<Vec<_>>();
        if matching_suites.is_empty() {
            match Engine::new(protocol.clone())
                .map_err(|error| error.to_string())?
                .run()
            {
                Ok(trace) => {
                    add_run(&mut runs, &protocol.name, "default", true, &trace);
                    add_packets(&mut packets, &protocol.name, &trace, &headers);
                }
                Err(error) => {
                    let trace = match &error {
                        crate::EngineError::Runtime { trace, .. } => trace.as_slice(),
                        crate::EngineError::Plan(_) => &[],
                    };
                    add_run(&mut runs, &protocol.name, "default", false, trace);
                    add_packets(&mut packets, &protocol.name, trace, &headers);
                }
            }
        } else {
            let engine = Engine::new(protocol.clone()).map_err(|error| error.to_string())?;
            for suite in matching_suites {
                for result in engine.run_cases(&suite.cases) {
                    add_run(
                        &mut runs,
                        &protocol.name,
                        &result.name,
                        result.passed,
                        &result.trace,
                    );
                    add_packets(&mut packets, &protocol.name, &result.trace, &headers);
                    case_values.push(json!({"protocol":protocol.name,"name":result.name,"status":if result.passed{"pass"}else{"fail"},"actual":result.actual.as_str(),"expected":result.expected.as_str(),"failure_kind":result.failure_kind.map(|kind|kind.as_str()),"error":result.error}));
                }
            }
        }
    }
    let total = runs.len();
    let passed = runs
        .iter()
        .filter(|run| run.get("passed").and_then(Value::as_bool) == Some(true))
        .count();
    let mut durations = runs
        .iter()
        .filter_map(|run| run.get("duration_us").and_then(Value::as_u64))
        .collect::<Vec<_>>();
    durations.sort_unstable();
    let p95 = durations
        .get(
            durations
                .len()
                .saturating_mul(95)
                .div_ceil(100)
                .saturating_sub(1),
        )
        .copied()
        .unwrap_or(0);
    Ok(json!({
        "schema_version": CI_SNAPSHOT_VERSION,
        "metrics":{"runs":total,"success_rate":if total==0{0.0}else{passed as f64/total as f64},"p95_us":p95},
        "runs":runs,"cases":case_values,"packets":packets,"state_machine":states
    }))
}

fn add_run(runs: &mut Vec<Value>, protocol: &str, name: &str, passed: bool, trace: &[TraceEvent]) {
    let duration = trace
        .iter()
        .map(|event| event.timestamp_us)
        .max()
        .unwrap_or(0);
    runs.push(json!({"protocol":protocol,"name":name,"passed":passed,"duration_us":duration}));
}

fn add_packets(
    packets: &mut Vec<Value>,
    protocol: &str,
    trace: &[TraceEvent],
    headers: &BTreeMap<String, Value>,
) {
    for event in trace
        .iter()
        .filter(|event| !event.wire_data.is_empty() || event.action.as_str().contains("send"))
    {
        packets.push(json!({"protocol":protocol,"step":event.step,"role":event.role,"flags":event.flags,"seq":event.seq_num,"ack":event.ack_num,"wire_hex":bytes_to_hex(&event.wire_data),"headers":headers.get(&event.step).cloned().unwrap_or(Value::Null)}));
    }
}

pub fn compare_snapshots(baseline: &Value, current: &Value) -> Value {
    let metric = |document: &Value, name: &str| {
        document
            .pointer(&format!("/metrics/{name}"))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let baseline_success = metric(baseline, "success_rate").as_f64().unwrap_or(0.0);
    let current_success = metric(current, "success_rate").as_f64().unwrap_or(0.0);
    let baseline_p95 = metric(baseline, "p95_us").as_u64().unwrap_or(0);
    let current_p95 = metric(current, "p95_us").as_u64().unwrap_or(0);
    let baseline_failures = failing_cases(baseline);
    let current_failures = failing_cases(current);
    let new_failures = current_failures
        .difference(&baseline_failures)
        .cloned()
        .collect::<Vec<_>>();
    let resolved_failures = baseline_failures
        .difference(&current_failures)
        .cloned()
        .collect::<Vec<_>>();
    let packet_differences = indexed_differences(baseline.get("packets"), current.get("packets"));
    let header_differences = header_differences(baseline, current);
    let state_differences =
        indexed_differences(baseline.get("state_machine"), current.get("state_machine"));
    json!({
        "schema_version":"1.0",
        "regression": !new_failures.is_empty() || current_success < baseline_success,
        "metrics":{
            "success_rate":{"baseline":baseline_success,"current":current_success,"delta":current_success-baseline_success},
            "p95_us":{"baseline":baseline_p95,"current":current_p95,"delta":current_p95 as i128-baseline_p95 as i128}
        },
        "packet_differences":packet_differences,
        "header_differences":header_differences,
        "state_machine_differences":state_differences,
        "new_failing_cases":new_failures,
        "resolved_failing_cases":resolved_failures
    })
}

fn failing_cases(document: &Value) -> BTreeSet<String> {
    document
        .get("cases")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|case| case.get("status").and_then(Value::as_str) == Some("fail"))
        .filter_map(|case| {
            Some(format!(
                "{}::{}",
                case.get("protocol")?.as_str()?,
                case.get("name")?.as_str()?
            ))
        })
        .collect()
}

fn indexed_differences(baseline: Option<&Value>, current: Option<&Value>) -> Vec<Value> {
    let left = baseline
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let right = current
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    (0..left.len().max(right.len()))
        .filter_map(|index| {
            let baseline = left.get(index);
            let current = right.get(index);
            (baseline != current)
                .then(|| json!({"index":index,"baseline":baseline,"current":current}))
        })
        .collect()
}

fn header_differences(baseline: &Value, current: &Value) -> Vec<Value> {
    let packets = |document: &Value| {
        document
            .get("packets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let left = packets(baseline);
    let right = packets(current);
    let mut differences = Vec::new();
    for index in 0..left.len().max(right.len()) {
        let baseline_headers = left.get(index).and_then(|packet| packet.get("headers"));
        let current_headers = right.get(index).and_then(|packet| packet.get("headers"));
        if baseline_headers != current_headers {
            differences.push(
                json!({"packet":index,"baseline":baseline_headers,"current":current_headers}),
            );
        }
    }
    differences
}

pub fn markdown_report(report: &Value) -> String {
    let metrics = &report["metrics"];
    let success = &metrics["success_rate"];
    let p95 = &metrics["p95_us"];
    let list = |name: &str| {
        report
            .get(name)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let failures = list("new_failing_cases");
    let rendered_failures = if failures.is_empty() {
        "- None".into()
    } else {
        failures
            .iter()
            .map(|value| format!("- `{}`", value.as_str().unwrap_or("unknown")))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!("<!-- tcpform-ci-report -->\n## tcpform CI difference report\n\n| Metric | Baseline | Current | Delta |\n| --- | ---: | ---: | ---: |\n| Success rate | {:.2}% | {:.2}% | {:+.2}% |\n| P95 latency | {} µs | {} µs | {:+} µs |\n\n| Difference | Count |\n| --- | ---: |\n| Packets | {} |\n| Headers | {} |\n| State machine | {} |\n\n### Newly failing cases\n\n{}\n",
        success["baseline"].as_f64().unwrap_or(0.0)*100.0, success["current"].as_f64().unwrap_or(0.0)*100.0, success["delta"].as_f64().unwrap_or(0.0)*100.0,
        p95["baseline"].as_u64().unwrap_or(0), p95["current"].as_u64().unwrap_or(0), p95["delta"].as_i64().unwrap_or(0),
        list("packet_differences").len(), list("header_differences").len(), list("state_machine_differences").len(), rendered_failures)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn comparisons_report_metrics_packets_states_and_new_failures() {
        let baseline = json!({"metrics":{"success_rate":1.0,"p95_us":10},"cases":[],"packets":[{"headers":{"tcp":{"flags":"SYN"}}}],"state_machine":["open"]});
        let current = json!({"metrics":{"success_rate":0.5,"p95_us":20},"cases":[{"protocol":"p","name":"bad","status":"fail"}],"packets":[{"headers":{"tcp":{"flags":"RST"}}}],"state_machine":["closed"]});
        let report = compare_snapshots(&baseline, &current);
        assert_eq!(report["new_failing_cases"][0], "p::bad");
        assert_eq!(report["header_differences"].as_array().unwrap().len(), 1);
        assert!(markdown_report(&report).contains("P95 latency"));
    }
}
