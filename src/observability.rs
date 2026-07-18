//! Convert tcpform traces and optional kernel/eBPF JSONL events to OTLP JSON.

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
struct TraceDocument {
    events: Vec<TraceInput>,
}

#[derive(Debug, Deserialize)]
struct TraceInput {
    index: u64,
    timestamp_ns: Value,
    role: String,
    step: String,
    action: String,
    ok: bool,
    detail: String,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    wire_hex: String,
    #[serde(default)]
    requirements: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct KernelEvent {
    timestamp_ns: Value,
    event: String,
    #[serde(default)]
    duration_ns: u64,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    tid: Option<u32>,
    #[serde(default)]
    socket_cookie: Option<u64>,
    #[serde(default)]
    bytes: Option<u64>,
    #[serde(default)]
    attributes: BTreeMap<String, Value>,
}

pub fn to_otlp_json(
    trace_json: &str,
    ebpf_jsonl: Option<&str>,
    service_name: &str,
    start_unix_ns: u128,
    correlation_window_ns: u128,
) -> Result<Value, String> {
    if service_name.trim().is_empty() {
        return Err("service name must not be empty".into());
    }
    let trace: TraceDocument = serde_json::from_str(trace_json)
        .map_err(|error| format!("invalid tcpform trace: {error}"))?;
    let kernel = parse_kernel_events(ebpf_jsonl.unwrap_or(""))?;
    let trace_id = hex_prefix(
        &Sha256::digest(format!("{service_name}:{start_unix_ns}").as_bytes()),
        16,
    );
    let mut correlated: Vec<Vec<(KernelEvent, u128, u128)>> =
        (0..trace.events.len()).map(|_| Vec::new()).collect();
    let mut unmatched = Vec::new();
    for event in kernel {
        let timestamp = json_u128(&event.timestamp_ns, "eBPF timestamp_ns")?;
        let nearest = trace
            .events
            .iter()
            .enumerate()
            .filter_map(|(index, trace)| {
                let trace_timestamp = json_u128(&trace.timestamp_ns, "trace timestamp_ns").ok()?;
                Some((index, trace_timestamp.abs_diff(timestamp)))
            })
            .min_by_key(|(_, difference)| *difference);
        if let Some((index, difference)) =
            nearest.filter(|(_, difference)| *difference <= correlation_window_ns)
        {
            correlated[index].push((event, timestamp, difference));
        } else {
            unmatched.push((event, timestamp));
        }
    }
    let mut spans = Vec::new();
    for (position, event) in trace.events.iter().enumerate() {
        let timestamp = json_u128(&event.timestamp_ns, "trace timestamp_ns")?;
        let end = start_unix_ns.saturating_add(timestamp);
        let next = trace
            .events
            .get(position + 1)
            .map(|next| json_u128(&next.timestamp_ns, "trace timestamp_ns"))
            .transpose()?
            .unwrap_or(timestamp.saturating_add(1));
        let span_id = span_id(&trace_id, event.index, &event.step);
        let attributes = vec![
            kv("tcpform.role", json!(event.role)),
            kv("tcpform.step", json!(event.step)),
            kv("tcpform.action", json!(event.action)),
            kv("tcpform.detail", json!(event.detail)),
            kv(
                "tcpform.network",
                json!(event.network.as_deref().unwrap_or("unknown")),
            ),
            kv("tcpform.wire_bytes", json!(event.wire_hex.len() / 2)),
            kv("tcpform.requirements", json!(event.requirements.join(","))),
        ];
        let span_events: Vec<_> = correlated[position].iter().map(|(kernel, kernel_timestamp, difference)| {
            json!({"timeUnixNano":start_unix_ns.saturating_add(*kernel_timestamp).to_string(),"name":format!("ebpf.{}",kernel.event),
                "attributes":kernel_attributes(kernel, *difference)})
        }).collect();
        spans.push(json!({
            "traceId":trace_id,"spanId":span_id,"name":format!("tcpform.{}.{}",event.role,event.step),"kind":1,
            "startTimeUnixNano":end.to_string(),"endTimeUnixNano":start_unix_ns.saturating_add(next.max(timestamp.saturating_add(1))).to_string(),
            "attributes":attributes,"events":span_events,
            "status":{"code":if event.ok {1} else {2},"message":if event.ok {""} else {"tcpform step failed"}}
        }));
    }
    let unmatched_events: Vec<_> = unmatched.iter().map(|(event, timestamp)| json!({
        "timeUnixNano":start_unix_ns.saturating_add(*timestamp).to_string(),"name":format!("ebpf.{}",event.event),"attributes":kernel_attributes(event, u128::MAX)
    })).collect();
    let correlated_count = correlated.iter().map(Vec::len).sum::<usize>();
    if !unmatched_events.is_empty() {
        let first = unmatched
            .iter()
            .map(|(_, timestamp)| *timestamp)
            .min()
            .unwrap_or(0);
        let last = unmatched
            .iter()
            .map(|(_, timestamp)| *timestamp)
            .max()
            .unwrap_or(first);
        spans.push(json!({"traceId":trace_id,"spanId":span_id(&trace_id,u64::MAX,"ebpf.unmatched"),
            "name":"tcpform.ebpf.unmatched","kind":1,"startTimeUnixNano":start_unix_ns.saturating_add(first).to_string(),
            "endTimeUnixNano":start_unix_ns.saturating_add(last.saturating_add(1)).to_string(),
            "attributes":[kv("ebpf.unmatched_count",json!(unmatched_events.len()))],"events":unmatched_events,"status":{"code":0}}));
    }
    Ok(json!({
      "resourceSpans":[{"resource":{"attributes":[kv("service.name",json!(service_name)),kv("telemetry.sdk.name",json!("tcpform")),kv("telemetry.sdk.language",json!("rust")),
        kv("tcpform.trace_event_count",json!(trace.events.len())),kv("tcpform.ebpf_event_count",json!(correlated_count+unmatched.len())),
        kv("tcpform.correlated_ebpf_event_count",json!(correlated_count)),kv("tcpform.unmatched_ebpf_event_count",json!(unmatched.len()))]},
        "scopeSpans":[{"scope":{"name":"tcpform.observability","version":env!("CARGO_PKG_VERSION")},"spans":spans}]}]
    }))
}

fn parse_kernel_events(input: &str) -> Result<Vec<KernelEvent>, String> {
    input
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line)
                .map_err(|error| format!("invalid eBPF JSONL line {}: {error}", index + 1))
        })
        .collect()
}

fn kernel_attributes(event: &KernelEvent, difference: u128) -> Vec<Value> {
    let mut values = vec![
        kv("ebpf.event", json!(event.event)),
        kv("ebpf.duration_ns", json!(event.duration_ns)),
    ];
    for (key, value) in [
        ("process.pid", event.pid.map(Value::from)),
        ("thread.id", event.tid.map(Value::from)),
        (
            "network.socket.cookie",
            event.socket_cookie.map(Value::from),
        ),
        ("network.io.bytes", event.bytes.map(Value::from)),
    ] {
        if let Some(value) = value {
            values.push(kv(key, value));
        }
    }
    if difference != u128::MAX {
        values.push(kv(
            "tcpform.correlation_delta_ns",
            json!(difference.to_string()),
        ));
    }
    values.extend(
        event
            .attributes
            .iter()
            .map(|(key, value)| kv(&format!("ebpf.{key}"), value.clone())),
    );
    values
}

fn kv(key: &str, value: Value) -> Value {
    let any = match value {
        Value::Bool(value) => json!({"boolValue":value}),
        Value::Number(value) => json!({"intValue":value.to_string()}),
        Value::String(value) => json!({"stringValue":value}),
        other => json!({"stringValue":other.to_string()}),
    };
    json!({"key":key,"value":any})
}

fn json_u128(value: &Value, field: &str) -> Result<u128, String> {
    match value {
        Value::String(value) => value
            .parse()
            .map_err(|_| format!("{field} must be an unsigned integer")),
        Value::Number(value) => value
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| format!("{field} must be an unsigned integer")),
        _ => Err(format!("{field} must be a string or integer")),
    }
}

fn span_id(trace_id: &str, index: u64, step: &str) -> String {
    hex_prefix(
        &Sha256::digest(format!("{trace_id}:{index}:{step}").as_bytes()),
        8,
    )
}

fn hex_prefix(bytes: &[u8], length: usize) -> String {
    bytes
        .iter()
        .take(length)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn correlates_kernel_events_and_emits_otlp_spans() {
        let trace = r#"{"events":[{"index":0,"timestamp_ns":"100","role":"client","step":"send","action":"send","ok":true,"detail":"sent","network":"tcp","wire_hex":"aabb","requirements":[]}]}"#;
        let ebpf = r#"{"timestamp_ns":110,"event":"tcp_sendmsg","pid":7,"bytes":2,"attributes":{"comm":"demo"}}"#;
        let output = to_otlp_json(trace, Some(ebpf), "demo", 1_000, 20).unwrap();
        let span = &output["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["traceId"].as_str().unwrap().len(), 32);
        assert_eq!(span["events"][0]["name"], "ebpf.tcp_sendmsg");
        assert_eq!(output.as_object().unwrap().len(), 1);
        assert!(output["resourceSpans"][0]["resource"]["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |attribute| attribute["key"] == "tcpform.correlated_ebpf_event_count"
                    && attribute["value"]["intValue"] == "1"
            ));
    }
}
