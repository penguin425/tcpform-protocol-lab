//! Machine-readable and visualization output formatters.

use crate::model::{Cases, FieldMatch, Protocol};
use crate::{CaseResult, TraceEvent, Value};
use serde::Serialize;
use serde_json::{json, Map};

/// Semantic version of tcpform's machine-readable JSON document shape.
pub const OUTPUT_SCHEMA_VERSION: &str = "1.0";
pub const VISUALIZATION_SCHEMA_VERSION: &str = "1.0";

/// Compare two executions while excluding timestamps and global event indexes.
pub fn differential_trace_json(left: &[TraceEvent], right: &[TraceEvent]) -> (String, bool) {
    let event = |value: &TraceEvent| {
        json!({
            "role":value.role,"step":value.step,"action":value.action.as_str(),"ok":value.ok,
            "flags":value.flags,"seq":value.seq_num,"ack":value.ack_num,"peer":value.peer,
            "wire_hex":crate::value::bytes_to_hex(&value.wire_data),"network":format!("{:?}",value.network).to_lowercase()
        })
    };
    let left_values = left.iter().map(event).collect::<Vec<_>>();
    let right_values = right.iter().map(event).collect::<Vec<_>>();
    let differences = (0..left_values.len().max(right_values.len()))
        .filter_map(|index| {
            let left = left_values.get(index);
            let right = right_values.get(index);
            (left != right).then(|| json!({"index":index,"left":left,"right":right}))
        })
        .collect::<Vec<_>>();
    let equal = differences.is_empty();
    (
        serde_json::to_string_pretty(&json!({
            "schema_version":OUTPUT_SCHEMA_VERSION,"equal":equal,
            "left_events":left_values.len(),"right_events":right_values.len(),
            "differences":differences
        }))
        .unwrap(),
        equal,
    )
}

/// Describe the complete declarative protocol, independently of a particular
/// run. The dashboard joins this plan with one or more trace documents.
pub fn visualization_manifest(
    protocol: &Protocol,
    suites: &[Cases],
    trace_files: &[String],
) -> String {
    visualization_manifest_with_case_traces(protocol, suites, trace_files, &[])
}

pub fn visualization_manifest_with_case_traces(
    protocol: &Protocol,
    suites: &[Cases],
    trace_files: &[String],
    case_trace_files: &[String],
) -> String {
    let resolved =
        crate::graph::plan(protocol).expect("manifest is generated only for a valid plan");
    let resolved_deps = resolved
        .order
        .iter()
        .map(|planned| (planned.step.name.as_str(), planned.deps.as_slice()))
        .collect::<std::collections::HashMap<_, _>>();
    let mut roles = Vec::<String>::new();
    for step in &protocol.steps {
        if !roles.contains(&step.role) {
            roles.push(step.role.clone());
        }
        if let Some(peer) = &step.to {
            if !roles.contains(peer) {
                roles.push(peer.clone());
            }
        }
    }
    let steps = protocol.steps.iter().enumerate().map(|(index, step)| {
        let headers = step.raw_packet.as_ref().map(|raw| json!({
            "ethernet": raw.ethernet.as_ref().map(value_map_json),
            "ipv4": raw.ipv4.as_ref().map(value_map_json),
            "ipv6": raw.ipv6.as_ref().map(value_map_json),
            "tcp": raw.tcp.as_ref().map(value_map_json),
            "udp": raw.udp.as_ref().map(value_map_json),
            "mtu": raw.mtu,
            "fragment_id": raw.fragment_id,
        }));
        json!({
            "index": index,
            "name": step.name,
            "role": step.role,
            "action": step.action.as_str(),
            "to": step.to,
            "depends_on": resolved_deps.get(step.name.as_str()).copied().unwrap_or(&[]),
            "explicit_depends_on": step.depends_on,
            "from_state": step.from_state,
            "to_state": step.to_state,
            "description": step.description,
            "when": step.when.as_ref().map(value_json),
            "retry": step.retry,
            "loop": step.loop_count,
            "retransmit": step.retransmit,
            "retry_policy": {
                "on_timeout": step.on_timeout,
                "retry_on": step.retry_policy.retry_on,
                "initial_delay_ms": step.retry_policy.initial_delay_ms,
                "max_delay_ms": step.retry_policy.max_delay_ms,
                "backoff": step.retry_policy.backoff,
                "jitter": step.retry_policy.jitter,
            },
            "timer": step.timer.as_ref().map(|timer| json!({"timeout_ms":timer.timeout_ms,"retransmit":timer.retransmit})),
            "plugin": step.plugin.as_ref().map(|plugin| json!({"manifest":plugin.manifest,"kind":plugin.kind,"name":plugin.name,"input":value_json(&plugin.input)})),
            "segment": step.segment.as_ref().map(|segment| json!({
                "flags": segment.flags, "seq":segment.seq, "ack":segment.ack,
                "payload":segment.payload, "hex":segment.hex, "payload_len":segment.payload_len,
                "window":segment.window, "stream":segment.stream,
                "fields":value_map_json(&segment.fields), "delay_ms":segment.delay_ms,
                "flip_bit":segment.flip_bit,
            })),
            "expect": step.expect.as_ref().map(|expect| json!({
                "flags":expect.flags, "payload":expect.payload,
                "hex":expect.hex.as_ref().map(|v| crate::value::bytes_to_hex(v)),
                "hex_contains":expect.hex_contains.as_ref().map(|v| crate::value::bytes_to_hex(v)),
                "from":expect.from, "window":expect.window, "stream":expect.stream,
                "fields":expect.fields.iter().map(|(key,value)|(key.clone(),field_match_json(value))).collect::<Map<_,_>>(),
                "capture":expect.capture,
            })),
            "headers": headers,
            "source": step.source,
            "line": step.line,
        })
    }).collect::<Vec<_>>();
    let cases = suites
        .iter()
        .filter(|suite| suite.protocol == protocol.name)
        .flat_map(|suite| &suite.cases)
        .enumerate()
        .map(|(index, case)| {
            json!({
                "name":case.name, "tags":case.tags, "vars":value_map_json(&case.vars),
                "expected":case.expect.outcome.as_str(),
                "trace_file":case_trace_files.get(index),
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&json!({
        "schema_version":VISUALIZATION_SCHEMA_VERSION,
        "protocol":{"name":protocol.name,"description":protocol.description},
        "roles":roles,
        "steps":steps,
        "cases":cases,
        "trace_files":trace_files,
        "transport":protocol.transport.as_ref().map(|t|json!({"loss_rate":t.loss_rate,"delay_ms":t.delay_ms,"reorder":t.reorder,"seed":t.seed,"disconnect_nth":t.disconnect_nth,"delay_spike_nth":t.delay_spike_nth,"delay_spike_ms":t.delay_spike_ms,"mtu":t.mtu,"mtu_blackhole":t.mtu_blackhole,"port_capacity":t.port_capacity,"nat_source_ip":t.nat_source_ip,"nat_source_port":t.nat_source_port})),
        "header_schemas":protocol.header_schemas.iter().map(|schema| json!({
            "name":schema.name,"offset":schema.offset,"endian":schema.endian,
            "fields":schema.fields.iter().map(header_field_json).collect::<Vec<_>>()
        })).collect::<Vec<_>>(),
    })).expect("visualization manifest is serializable")
}

fn header_field_json(field: &crate::model::HeaderFieldSpec) -> serde_json::Value {
    json!({
        "name":field.name,
        "order":(field.order != usize::MAX).then_some(field.order),
        "offset":field.offset,
        "offset_explicit":field.offset_explicit,
        "length":field.length,
        "length_from":field.length_from,
        "length_adjust":field.length_adjust,
        "repeat":field.repeat,
        "repeat_from":field.repeat_from,
        "terminator":field.terminator.as_ref().map(|bytes|crate::value::bytes_to_hex(bytes)),
        "when":field.when,
        "bit_offset":field.bit_offset,
        "bits":field.bits,
        "format":field.format,
        "enum":field.enum_values.iter().map(|(key,value)|(key.clone(),value_json(value))).collect::<Map<_,_>>(),
        "fields":field.fields.iter().map(header_field_json).collect::<Vec<_>>(),
        "switch_on":field.switch_on,
        "cases":field.cases.iter().map(|(key,fields)|(key.clone(),serde_json::Value::Array(fields.iter().map(header_field_json).collect()))).collect::<Map<_,_>>(),
        "transform":field.transform,
        "key_from":field.key_from,
        "nonce_from":field.nonce_from,
        "checksum":field.checksum,
        "checksum_range":field.checksum_range,
    })
}

fn value_map_json(
    values: &std::collections::HashMap<String, Value>,
) -> Map<String, serde_json::Value> {
    values
        .iter()
        .map(|(key, value)| (key.clone(), value_json(value)))
        .collect()
}

fn field_match_json(value: &FieldMatch) -> serde_json::Value {
    match value {
        FieldMatch::Equal(v) => json!({"equal":value_json(v)}),
        FieldMatch::NotEqual(v) => json!({"not_equal":value_json(v)}),
        FieldMatch::Contains(v) => json!({"contains":v}),
        FieldMatch::Prefix(v) => json!({"prefix":v}),
        FieldMatch::Suffix(v) => json!({"suffix":v}),
        FieldMatch::Regex { pattern, .. } => json!({"regex":pattern}),
        FieldMatch::BytesContains(v) => json!({"hex_contains":crate::value::bytes_to_hex(v)}),
        FieldMatch::Min(v) => json!({"min":v}),
        FieldMatch::Max(v) => json!({"max":v}),
        FieldMatch::Range { min, max } => json!({"min":min,"max":max}),
    }
}

pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('"');
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if c < '\u{20}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn trace_json(status: &str, error: Option<&str>, trace: &[TraceEvent]) -> String {
    trace_json_with_failure(status, None, error, trace)
}

pub fn trace_json_with_failure(
    status: &str,
    failure_kind: Option<&str>,
    error: Option<&str>,
    trace: &[TraceEvent],
) -> String {
    #[derive(Serialize)]
    struct TraceDocument<'a> {
        status: &'a str,
        schema_version: &'static str,
        failure_kind: Option<&'a str>,
        error: Option<&'a str>,
        events: Vec<serde_json::Value>,
    }
    serde_json::to_string(&TraceDocument {
        status,
        schema_version: OUTPUT_SCHEMA_VERSION,
        failure_kind,
        error,
        events: trace_values(trace),
    })
    .expect("JSON values are serializable")
}

pub fn case_results_json(results: &[(&str, &CaseResult)]) -> String {
    let passed = results.iter().filter(|(_, result)| result.passed).count();
    let items = results
        .iter()
        .map(|(protocol, result)| {
            json!({
                "protocol": protocol,
                "case": result.name,
                "tags": result.tags,
                "expected": result.expected.as_str(),
                "actual": result.actual.as_str(),
                "passed": result.passed,
                "failure_kind": result.failure_kind.map(|kind| kind.as_str()),
                "error": result.error,
                "assertion_failures": result.assertion_failures.iter().map(|failure| json!({
                    "role": failure.role,
                    "key": failure.key,
                    "expected": value_json(&failure.expected),
                    "actual": failure.actual.as_ref().map(value_json),
                })).collect::<Vec<_>>(),
                "trace": trace_values(&result.trace),
            })
        })
        .collect::<Vec<_>>();
    #[derive(Serialize)]
    struct CaseDocument {
        passed: usize,
        failed: usize,
        schema_version: &'static str,
        results: Vec<serde_json::Value>,
    }
    serde_json::to_string(&CaseDocument {
        passed,
        failed: results.len() - passed,
        schema_version: OUTPUT_SCHEMA_VERSION,
        results: items,
    })
    .expect("JSON values are serializable")
}

/// Render case results as JUnit XML for CI systems. Declaration order is
/// retained, and failed cases include typed errors, assertion diagnostics,
/// and their trace as escaped text.
pub fn case_results_junit(results: &[(&str, &CaseResult)]) -> String {
    let failures = results.iter().filter(|(_, result)| !result.passed).count();
    let total_us: u64 = results
        .iter()
        .map(|(_, result)| {
            result
                .trace
                .iter()
                .map(|event| event.timestamp_us)
                .max()
                .unwrap_or(0)
        })
        .sum();
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"tcpform\" tests=\"{}\" failures=\"{}\" errors=\"0\" time=\"{:.6}\">\n",
        results.len(),
        failures,
        total_us as f64 / 1_000_000.0
    );
    for (protocol, result) in results {
        let duration_us = result
            .trace
            .iter()
            .map(|event| event.timestamp_us)
            .max()
            .unwrap_or(0);
        xml.push_str(&format!(
            "  <testcase classname=\"{}\" name=\"{}\" time=\"{:.6}\">\n",
            xml_escape(protocol),
            xml_escape(&result.name),
            duration_us as f64 / 1_000_000.0
        ));
        if !result.tags.is_empty() {
            xml.push_str("    <properties>\n");
            for tag in &result.tags {
                xml.push_str(&format!(
                    "      <property name=\"tcpform.tag\" value=\"{}\"/>\n",
                    xml_escape(tag)
                ));
            }
            xml.push_str("    </properties>\n");
        }
        if !result.passed {
            let kind = result
                .failure_kind
                .map_or("expectation", |kind| kind.as_str());
            let mut detail = format!(
                "expected {} but got {}",
                result.expected.as_str(),
                result.actual.as_str()
            );
            if let Some(error) = &result.error {
                detail.push_str(&format!("\n{error}"));
            }
            for failure in &result.assertion_failures {
                detail.push_str(&format!(
                    "\nrole {} assertion {}: expected {}, actual {}",
                    failure.role,
                    failure.key,
                    failure.expected.to_display(),
                    failure
                        .actual
                        .as_ref()
                        .map_or_else(|| "<missing>".to_string(), Value::to_display)
                ));
            }
            xml.push_str(&format!(
                "    <failure type=\"{}\" message=\"{}\">{}</failure>\n",
                xml_escape(kind),
                xml_escape(detail.lines().next().unwrap_or("case failed")),
                xml_escape(&detail)
            ));
        }
        if !result.trace.is_empty() {
            let trace = result
                .trace
                .iter()
                .map(|event| {
                    format!(
                        "{}us {} {} {} {}",
                        event.timestamp_us,
                        event.role,
                        event.step,
                        event.action.as_str(),
                        event.detail
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            xml.push_str(&format!(
                "    <system-out>{}</system-out>\n",
                xml_escape(&trace)
            ));
        }
        xml.push_str("  </testcase>\n");
    }
    xml.push_str("</testsuite>\n");
    xml
}

fn xml_escape(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\t' => escaped.push_str("&#9;"),
            '\n' => escaped.push_str("&#10;"),
            '\r' => escaped.push_str("&#13;"),
            character
                if character < '\u{20}' || character == '\u{fffe}' || character == '\u{ffff}' =>
            {
                escaped.push('\u{fffd}');
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn trace_values(trace: &[TraceEvent]) -> Vec<serde_json::Value> {
    let mut frame = 0u64;
    trace
        .iter()
        .map(|event| {
            let pcap_frame = if is_outbound(event.action) && event.peer.is_some() {
                frame += 1;
                Some(frame)
            } else {
                None
            };
            trace_value(event, pcap_frame)
        })
        .collect()
}

fn trace_value(event: &TraceEvent, pcap_frame: Option<u64>) -> serde_json::Value {
    json!({
        "index": event.seq,
        "timestamp_us": event.timestamp_us,
        "timestamp_ns": event.timestamp_ns.to_string(),
        "role": event.role,
        "step": event.step,
        "action": event.action.as_str(),
        "ok": event.ok,
        "detail": event.detail,
        "flags": event.flags,
        "seq": event.seq_num,
        "ack": event.ack_num,
        "peer": event.peer,
        "pcap_frame": pcap_frame,
        "wire_hex": crate::value::bytes_to_hex(&event.wire_data),
        "network": match event.network {
            crate::NetworkProtocol::Tcp => "tcp",
            crate::NetworkProtocol::Udp => "udp",
            crate::NetworkProtocol::Tls => "tls",
            crate::NetworkProtocol::Raw => "raw",
            crate::NetworkProtocol::WebSocket => "websocket",
            crate::NetworkProtocol::Quic => "quic",
        },
    })
}

fn value_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(value) => json!(value),
        Value::Number(value) => json!(value),
        Value::String(value) => json!(value),
        Value::Bytes(value) => json!({"hex": crate::value::bytes_to_hex(value)}),
        Value::Array(values) => serde_json::Value::Array(values.iter().map(value_json).collect()),
        Value::Object(values) => {
            let object: Map<String, serde_json::Value> = values
                .iter()
                .map(|(key, value)| (key.clone(), value_json(value)))
                .collect();
            serde_json::Value::Object(object)
        }
    }
}

/// Render a Mermaid-compatible text sequence diagram.
pub fn sequence_diagram(trace: &[TraceEvent]) -> String {
    let mut roles = Vec::<&str>::new();
    for event in trace {
        if !roles.contains(&event.role.as_str()) {
            roles.push(&event.role);
        }
        if let Some(peer) = &event.peer {
            if !roles.contains(&peer.as_str()) {
                roles.push(peer);
            }
        }
    }
    let mut out = String::from("sequenceDiagram\n");
    for role in roles {
        out.push_str(&format!("    participant {}\n", mermaid_text(role)));
    }
    for event in trace {
        let label = mermaid_text(&format!(
            "{} {}: {}",
            event.action.as_str(),
            event.step,
            event.detail
        ));
        if let Some(peer) = &event.peer {
            let (from, to) = if matches!(
                event.action,
                crate::Action::Recv | crate::Action::RecvRaw | crate::Action::Drop
            ) {
                (peer.as_str(), event.role.as_str())
            } else {
                (event.role.as_str(), peer.as_str())
            };
            out.push_str(&format!(
                "    {}->>{}: {}\n",
                mermaid_text(from),
                mermaid_text(to),
                label
            ));
        } else {
            out.push_str(&format!(
                "    Note over {}: {}\n",
                mermaid_text(&event.role),
                label
            ));
        }
    }
    out
}

fn mermaid_text(input: &str) -> String {
    input
        .replace(['\r', '\n'], " ")
        .replace(';', "&#59;")
        .replace(':', "&#58;")
}

/// Encode outbound wire events as Ethernet/IPv4/TCP packets in a standard
/// little-endian PCAP stream. Addresses and ports are stable synthetic values
/// derived from role names; sequence, acknowledgement, TCP flags and
/// application payload come from the trace.
pub fn trace_pcap(trace: &[TraceEvent]) -> Vec<u8> {
    let mut out = Vec::new();
    let link_type = capture_link_type(trace);
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&link_type.to_le_bytes());

    for event in trace.iter().filter(|event| is_outbound(event.action)) {
        let Some(peer) = event.peer.as_deref() else {
            continue;
        };
        let packet = capture_packet(event, peer, link_type);
        let length = packet.len() as u32;
        out.extend_from_slice(&((event.timestamp_us / 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&((event.timestamp_us % 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&packet);
    }
    out
}

/// Encode the same packets as PCAP Next Generation with microsecond
/// timestamps and one Ethernet interface.
pub fn trace_pcapng(trace: &[TraceEvent]) -> Vec<u8> {
    let mut out = Vec::new();
    let link_type = capture_link_type(trace);
    // Section Header Block.
    out.extend_from_slice(&0x0a0d0d0au32.to_le_bytes());
    out.extend_from_slice(&28u32.to_le_bytes());
    out.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
    out.extend_from_slice(&(link_type as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&u64::MAX.to_le_bytes());
    out.extend_from_slice(&28u32.to_le_bytes());
    // Interface Description Block (Ethernet, snaplen 65535).
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&20u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&65_535u32.to_le_bytes());
    out.extend_from_slice(&20u32.to_le_bytes());

    for event in trace.iter().filter(|event| is_outbound(event.action)) {
        let Some(peer) = event.peer.as_deref() else {
            continue;
        };
        let packet = capture_packet(event, peer, link_type);
        let padded = (packet.len() + 3) & !3;
        let block_len = 32 + padded;
        out.extend_from_slice(&6u32.to_le_bytes());
        out.extend_from_slice(&(block_len as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&((event.timestamp_us >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&(event.timestamp_us as u32).to_le_bytes());
        out.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        out.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        out.extend_from_slice(&packet);
        out.resize(out.len() + (padded - packet.len()), 0);
        out.extend_from_slice(&(block_len as u32).to_le_bytes());
    }
    out
}

const DLT_EN10MB: u32 = 1;
const DLT_RAW: u32 = 101;

fn capture_link_type(trace: &[TraceEvent]) -> u32 {
    let outbound: Vec<_> = trace
        .iter()
        .filter(|event| is_outbound(event.action) && event.peer.is_some())
        .collect();
    if !outbound.is_empty()
        && outbound.iter().all(|event| {
            event.network == crate::NetworkProtocol::Raw
                && event
                    .wire_data
                    .first()
                    .is_some_and(|byte| matches!(byte >> 4, 4 | 6))
        })
    {
        DLT_RAW
    } else {
        DLT_EN10MB
    }
}

fn capture_packet(event: &TraceEvent, peer: &str, link_type: u32) -> Vec<u8> {
    match event.network {
        crate::NetworkProtocol::Udp => udp_packet(event, peer),
        crate::NetworkProtocol::Tcp
        | crate::NetworkProtocol::Tls
        | crate::NetworkProtocol::WebSocket
        | crate::NetworkProtocol::Quic => tcp_packet(event, peer),
        crate::NetworkProtocol::Raw if link_type == DLT_EN10MB => {
            let version = event.wire_data.first().map(|byte| byte >> 4);
            if matches!(version, Some(4 | 6)) {
                let source = role_id(&event.role);
                let destination = role_id(peer);
                let mut frame = Vec::with_capacity(14 + event.wire_data.len());
                frame.extend_from_slice(&[0x02, 0, 0, destination[0], destination[1], 2]);
                frame.extend_from_slice(&[0x02, 0, 0, source[0], source[1], 1]);
                frame.extend_from_slice(
                    &if version == Some(6) {
                        0x86ddu16
                    } else {
                        0x0800u16
                    }
                    .to_be_bytes(),
                );
                frame.extend_from_slice(&event.wire_data);
                frame
            } else {
                event.wire_data.clone()
            }
        }
        crate::NetworkProtocol::Raw => event.wire_data.clone(),
    }
}

fn is_outbound(action: crate::Action) -> bool {
    matches!(
        action,
        crate::Action::Send
            | crate::Action::SendRaw
            | crate::Action::Ack
            | crate::Action::Nack
            | crate::Action::Reset
            | crate::Action::Duplicate
            | crate::Action::Corrupt
    )
}

fn tcp_packet(event: &TraceEvent, peer: &str) -> Vec<u8> {
    let payload_len = event.wire_data.len().min(65_535 - 40);
    let payload = &event.wire_data[..payload_len];
    let source_id = role_id(&event.role);
    let destination_id = role_id(peer);
    let source_ip = [10, 0, source_id[0], source_id[1]];
    let destination_ip = [10, 0, destination_id[0], destination_id[1]];
    let source_port = 10_000 + u16::from_be_bytes(source_id) % 50_000;
    let destination_port = 10_000 + u16::from_be_bytes(destination_id) % 50_000;

    let mut packet = Vec::with_capacity(14 + 20 + 20 + payload.len());
    packet.extend_from_slice(&[0x02, 0, 0, destination_id[0], destination_id[1], 2]);
    packet.extend_from_slice(&[0x02, 0, 0, source_id[0], source_id[1], 1]);
    packet.extend_from_slice(&0x0800u16.to_be_bytes());

    let ip_start = packet.len();
    packet.extend_from_slice(&[0x45, 0]);
    packet.extend_from_slice(&((20 + 20 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&(event.seq as u16).to_be_bytes());
    packet.extend_from_slice(&0x4000u16.to_be_bytes());
    packet.extend_from_slice(&[64, 6]);
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&source_ip);
    packet.extend_from_slice(&destination_ip);
    let ip_checksum = checksum(&packet[ip_start..ip_start + 20]);
    packet[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

    let tcp_start = packet.len();
    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&destination_port.to_be_bytes());
    packet.extend_from_slice(&(event.seq_num.unwrap_or(0) as u32).to_be_bytes());
    packet.extend_from_slice(&(event.ack_num.unwrap_or(0) as u32).to_be_bytes());
    packet.push(5 << 4);
    packet.push(tcp_flags(&event.flags));
    packet.extend_from_slice(&65_535u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(payload);

    let tcp_len = (20 + payload.len()) as u16;
    let mut pseudo = Vec::with_capacity(12 + usize::from(tcp_len) + 1);
    pseudo.extend_from_slice(&source_ip);
    pseudo.extend_from_slice(&destination_ip);
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&tcp_len.to_be_bytes());
    pseudo.extend_from_slice(&packet[tcp_start..]);
    let tcp_checksum = checksum(&pseudo);
    packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    packet
}

fn udp_packet(event: &TraceEvent, peer: &str) -> Vec<u8> {
    let payload_len = event.wire_data.len().min(65_535 - 28);
    let payload = &event.wire_data[..payload_len];
    let source_id = role_id(&event.role);
    let destination_id = role_id(peer);
    let source_ip = [10, 0, source_id[0], source_id[1]];
    let destination_ip = [10, 0, destination_id[0], destination_id[1]];
    let source_port = 10_000 + u16::from_be_bytes(source_id) % 50_000;
    let destination_port = 10_000 + u16::from_be_bytes(destination_id) % 50_000;
    let mut packet = Vec::with_capacity(14 + 20 + 8 + payload.len());
    packet.extend_from_slice(&[0x02, 0, 0, destination_id[0], destination_id[1], 2]);
    packet.extend_from_slice(&[0x02, 0, 0, source_id[0], source_id[1], 1]);
    packet.extend_from_slice(&0x0800u16.to_be_bytes());
    let ip_start = packet.len();
    packet.extend_from_slice(&[0x45, 0]);
    packet.extend_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&(event.seq as u16).to_be_bytes());
    packet.extend_from_slice(&0x4000u16.to_be_bytes());
    packet.extend_from_slice(&[64, 17]);
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&source_ip);
    packet.extend_from_slice(&destination_ip);
    let ip_checksum = checksum(&packet[ip_start..ip_start + 20]);
    packet[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());
    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&destination_port.to_be_bytes());
    packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn tcp_flags(flags: &[String]) -> u8 {
    let mut bits = 0;
    for flag in flags {
        bits |= match flag.as_str() {
            "FIN" => 0x01,
            "SYN" => 0x02,
            "RST" => 0x04,
            "PSH" => 0x08,
            "ACK" => 0x10,
            "URG" => 0x20,
            "ECE" => 0x40,
            "CWR" => 0x80,
            _ => 0,
        };
    }
    bits
}

fn role_id(role: &str) -> [u8; 2] {
    let hash = role.bytes().fold(0x811c_u32, |hash, byte| {
        hash.wrapping_mul(16777619) ^ u32::from(byte)
    });
    let mut id = (hash as u16).to_be_bytes();
    if id == [0, 0] {
        id[1] = 1;
    }
    id
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        let word = if pair.len() == 2 {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from(pair[0]) << 8
        };
        sum += u32::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
