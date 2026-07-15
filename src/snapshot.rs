//! Git-friendly local snapshots for protocol regression testing.

use crate::model::{Cases, Protocol};
use serde_json::{json, Value};

pub const SNAPSHOT_VERSION: &str = "1.0";

/// Run the selected protocols and include all data needed by the visualizer.
pub fn create(
    protocols: &[Protocol],
    suites: &[Cases],
    filter: Option<&str>,
) -> Result<Value, String> {
    let mut snapshot = crate::ci_report::create_snapshot(protocols, suites, filter)?;
    let visualizer = protocols
        .iter()
        .filter(|protocol| filter.is_none_or(|name| protocol.name == name))
        .map(|protocol| {
            serde_json::from_str::<Value>(&crate::output::visualization_manifest(
                protocol,
                suites,
                &[],
            ))
            .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    snapshot["snapshot_version"] = json!(SNAPSHOT_VERSION);
    snapshot["visualizer"] = json!(visualizer);
    Ok(snapshot)
}

/// Compare deterministic behavior exactly and latency within a caller-defined tolerance.
pub fn check(baseline: &Value, current: &Value, latency_tolerance_us: u64) -> Result<(), String> {
    if baseline.get("snapshot_version").and_then(Value::as_str) != Some(SNAPSHOT_VERSION) {
        return Err("unsupported snapshot version; run `tcpform snapshot --update`".into());
    }
    let baseline_latency = baseline
        .pointer("/metrics/p95_us")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let current_latency = current
        .pointer("/metrics/p95_us")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let latency_delta = baseline_latency.abs_diff(current_latency);
    let mut expected = baseline.clone();
    let mut actual = current.clone();
    normalize_latency(&mut expected);
    normalize_latency(&mut actual);
    if expected != actual || latency_delta > latency_tolerance_us {
        let report = crate::ci_report::compare_snapshots(baseline, current);
        let packet_changes = report["packet_differences"].as_array().map_or(0, Vec::len);
        let header_changes = report["header_differences"].as_array().map_or(0, Vec::len);
        let state_changes = report["state_machine_differences"]
            .as_array()
            .map_or(0, Vec::len);
        return Err(format!(
            "snapshot mismatch (packets: {packet_changes}, headers: {header_changes}, states: {state_changes}, latency delta: {latency_delta} µs; tolerance: {latency_tolerance_us} µs); inspect the change or run `tcpform snapshot --update`"
        ));
    }
    Ok(())
}

fn normalize_latency(document: &mut Value) {
    if let Some(metric) = document.pointer_mut("/metrics/p95_us") {
        *metric = Value::Null;
    }
    if let Some(runs) = document.get_mut("runs").and_then(Value::as_array_mut) {
        for run in runs {
            if let Some(duration) = run.get_mut("duration_us") {
                *duration = Value::Null;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_uses_tolerance_but_packet_changes_fail() {
        let baseline = json!({"snapshot_version":"1.0","metrics":{"p95_us":10},"runs":[{"duration_us":10}],"packets":[1]});
        let within = json!({"snapshot_version":"1.0","metrics":{"p95_us":12},"runs":[{"duration_us":12}],"packets":[1]});
        assert!(check(&baseline, &within, 2).is_ok());
        assert!(check(&baseline, &within, 1).is_err());
        let changed = json!({"snapshot_version":"1.0","metrics":{"p95_us":10},"runs":[{"duration_us":10}],"packets":[2]});
        assert!(check(&baseline, &changed, 2).is_err());
    }
}
