//! Team/CI platform primitives kept independent from the HTTP frontend.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResult {
    pub worker: String,
    pub shard: u32,
    pub case: String,
    pub status: String,
    pub document: Value,
}

/// Deterministically aggregate distributed shards and suppress duplicate results.
pub fn aggregate_worker_results(results: Vec<WorkerResult>) -> Value {
    let mut unique = BTreeMap::new();
    for result in results {
        unique
            .entry((result.shard, result.case.clone()))
            .or_insert(result);
    }
    let failed = unique
        .values()
        .filter(|result| result.status != "ok")
        .count();
    json!({"schema_version":"1.0","total":unique.len(),"failed":failed,"results":unique.into_values().collect::<Vec<_>>()})
}

pub fn kubernetes_job(name: &str, image: &str, shards: u32, source: &str, protocol: &str) -> Value {
    json!({"apiVersion":"batch/v1","kind":"Job","metadata":{"name":name},"spec":{"completionMode":"Indexed","completions":shards.max(1),"parallelism":shards.max(1),"template":{"spec":{"restartPolicy":"Never","containers":[{"name":"tcpform","image":image,"args":["test","--shard","$(JOB_COMPLETION_INDEX)/".to_string()+&shards.max(1).to_string(),source,protocol],"env":[{"name":"JOB_COMPLETION_INDEX","valueFrom":{"fieldRef":{"fieldPath":"metadata.annotations['batch.kubernetes.io/job-completion-index']"}}}]}]}}}})
}

static METRICS: OnceLock<Mutex<HashMap<String, (u64, u128)>>> = OnceLock::new();

pub struct Span {
    name: String,
    started: Instant,
}
impl Span {
    pub fn start(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            started: Instant::now(),
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        let mut values = METRICS.get_or_init(Default::default).lock().unwrap();
        let entry = values.entry(self.name.clone()).or_default();
        entry.0 += 1;
        entry.1 += self.started.elapsed().as_nanos();
    }
}
pub fn prometheus_metrics() -> String {
    let values = METRICS.get_or_init(Default::default).lock().unwrap();
    let mut names = values.keys().collect::<Vec<_>>();
    names.sort();
    names.into_iter().map(|name| { let (count,nanos)=values[name]; format!("tcpform_operation_total{{operation=\"{name}\"}} {count}\ntcpform_operation_nanoseconds_total{{operation=\"{name}\"}} {nanos}\n") }).collect()
}
pub fn structured_log(level: &str, event: &str, fields: Value) -> String {
    json!({"timestamp_ns":unix_time_ns(),"level":level,"event":event,"fields":fields}).to_string()
}

#[derive(Debug, Clone)]
pub struct Debugger {
    events: Vec<crate::TraceEvent>,
    cursor: usize,
    breakpoints: Vec<Breakpoint>,
    watches: Vec<String>,
    snapshots: Vec<usize>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Breakpoint {
    pub step: Option<String>,
    pub role: Option<String>,
    pub only_failures: bool,
}
impl Debugger {
    pub fn new(events: Vec<crate::TraceEvent>) -> Self {
        Self {
            events,
            cursor: 0,
            breakpoints: vec![],
            watches: vec![],
            snapshots: vec![0],
        }
    }
    pub fn add_breakpoint(&mut self, breakpoint: Breakpoint) {
        self.breakpoints.push(breakpoint);
    }
    pub fn watch(&mut self, field: impl Into<String>) {
        self.watches.push(field.into());
    }
    pub fn step(&mut self) -> Option<Value> {
        let event = self.events.get(self.cursor)?;
        self.cursor += 1;
        self.snapshots.push(self.cursor);
        Some(self.inspect(event))
    }
    pub fn resume(&mut self) -> Option<Value> {
        while self.cursor < self.events.len() {
            let index = self.cursor;
            let event = &self.events[index];
            self.cursor += 1;
            self.snapshots.push(self.cursor);
            if self.breakpoints.iter().any(|b| b.matches(event)) {
                return Some(self.inspect(event));
            }
        }
        None
    }
    pub fn rewind(&mut self) -> Option<Value> {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
        self.events
            .get(self.cursor)
            .map(|event| self.inspect(event))
    }
    pub fn cursor(&self) -> usize {
        self.cursor
    }
    fn inspect(&self, event: &crate::TraceEvent) -> Value {
        let full = json!({"index":event.seq,"timestamp_ns":event.timestamp_ns.to_string(),"role":event.role,"step":event.step,"action":event.action.as_str(),"ok":event.ok,"flags":event.flags,"seq":event.seq_num,"ack":event.ack_num,"peer":event.peer,"wire_hex":crate::bytes_to_hex(&event.wire_data)});
        let watched = self
            .watches
            .iter()
            .map(|key| (key.clone(), full.get(key).cloned().unwrap_or(Value::Null)))
            .collect::<serde_json::Map<_, _>>();
        json!({"cursor":self.cursor,"event":full,"watches":watched})
    }
}
impl Breakpoint {
    fn matches(&self, event: &crate::TraceEvent) -> bool {
        self.step.as_ref().is_none_or(|v| v == &event.step)
            && self.role.as_ref().is_none_or(|v| v == &event.role)
            && (!self.only_failures || !event.ok)
    }
}

/// Generate a conservative tcpform request/response skeleton from OpenAPI 3 JSON.
pub fn openapi_to_tcpform(document: &Value) -> Result<String, String> {
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or("OpenAPI paths object is required")?;
    let mut out = String::from("protocol \"openapi_generated\" {\n");
    for (path, methods) in paths {
        for (method, _) in methods
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(m, _)| matches!(m.as_str(), "get" | "post" | "put" | "patch" | "delete"))
        {
            let name = format!(
                "{}_{}",
                method,
                path.trim_matches('/')
                    .replace('/', "_")
                    .replace(['{', '}'], "")
            );
            out.push_str(&format!("  step \"{name}\" {{ role = \"client\" action = \"send\" segment {{ fields = {{ method = \"{}\" path = \"{}\" }} }} }}\n",method.to_uppercase(),path));
        }
    }
    out.push_str("}\n");
    Ok(out)
}

pub fn protobuf_to_tcpform(source: &str) -> Result<String, String> {
    let message = regex_lite::Regex::new(r"(?m)^\s*message\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
        .unwrap()
        .captures(source)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str())
        .ok_or("no protobuf message found")?;
    Ok(format!("protocol \"{}\" {{\n  step \"send\" {{ role = \"client\" action = \"send\" segment {{ fields = {{ message_type = \"{}\" }} }} }}\n}}\n",message.to_ascii_lowercase(),message))
}

pub fn tcpform_to_proto(protocol: &crate::Protocol) -> String {
    let mut fields = HashSet::new();
    for step in &protocol.steps {
        if let Some(segment) = &step.segment {
            fields.extend(segment.fields.keys().cloned());
        }
    }
    let mut fields = fields.into_iter().collect::<Vec<_>>();
    fields.sort();
    let declarations = fields
        .iter()
        .enumerate()
        .map(|(index, name)| format!("  string {} = {};", name.replace('-', "_"), index + 1))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "syntax = \"proto3\";\nmessage {} {{\n{}\n}}\n",
        protocol.name.replace('-', "_"),
        declarations
    )
}

pub fn wireshark_lua(protocol: &crate::Protocol, tcp_port: u16) -> String {
    let safe = code_identifier(&protocol.name);
    let mut declarations = String::new();
    let mut registrations = Vec::new();
    let mut decoders = String::new();
    for schema in &protocol.header_schemas {
        for field in &schema.fields {
            let key = format!(
                "{}_{}",
                code_identifier(&schema.name),
                code_identifier(&field.name)
            );
            let lua_type = match (field.format.as_str(), field.length) {
                ("uint", 1) => "uint8",
                ("uint", 2) => "uint16",
                ("uint", 4) => "uint32",
                ("uint", 8) => "uint64",
                ("ascii", _) => "string",
                ("ipv4", 4) => "ipv4",
                _ => "bytes",
            };
            declarations.push_str(&format!(
                "local f_{key} = ProtoField.{lua_type}(\"{safe}.{}.{}\", \"{}\")\n",
                code_identifier(&schema.name),
                code_identifier(&field.name),
                field.name
            ));
            registrations.push(format!("f_{key}"));
            let offset = schema.offset + field.offset;
            let add = if schema.endian == "little" && lua_type.starts_with("uint") {
                "add_le"
            } else {
                "add"
            };
            decoders.push_str(&format!(
                "  if buffer:len() >= {} then subtree:{add}(f_{key}, buffer({offset}, {})) end\n",
                offset + field.length,
                field.length
            ));
        }
    }
    let fields = if registrations.is_empty() {
        String::new()
    } else {
        format!("p.fields = {{{}}}\n", registrations.join(", "))
    };
    format!("-- Generated by tcpform. Install in a Wireshark plugin directory.\nlocal p = Proto(\"{safe}\", \"{}\")\n{declarations}{fields}function p.dissector(buffer,pinfo,tree)\n  pinfo.cols.protocol = \"{safe}\"\n  local subtree = tree:add(p, buffer(), \"{} payload (\" .. buffer:len() .. \" bytes)\")\n{decoders}end\nDissectorTable.get(\"tcp.port\"):add({tcp_port}, p)\n",protocol.name,protocol.name)
}

pub fn scapy_python(protocol: &crate::Protocol, tcp_port: u16) -> String {
    let base = python_class_name(&protocol.name);
    let mut classes = String::new();
    let mut class_names = Vec::new();
    if protocol.header_schemas.is_empty() {
        classes.push_str(&format!(
            "class {base}(Packet):\n    name = {:?}\n    fields_desc = [StrField(\"payload\", b\"\")]\n\n",
            protocol.name
        ));
        class_names.push(base.clone());
    } else {
        for schema in &protocol.header_schemas {
            let class = format!("{}{}", base, python_class_name(&schema.name));
            class_names.push(class.clone());
            classes.push_str(&format!(
                "class {class}(Packet):\n    name = {:?}\n    fields_desc = [\n",
                format!("{} {}", protocol.name, schema.name)
            ));
            let mut fields = schema.fields.iter().collect::<Vec<_>>();
            fields.sort_by_key(|field| (field.offset, std::cmp::Reverse(field.bit_offset)));
            let mut cursor = 0usize;
            let mut padding = 0usize;
            let mut bit_region = None::<(usize, usize)>;
            for field in fields {
                let offset = schema.offset + field.offset;
                let is_bit_field = usize::from(field.bits) < field.length * 8;
                if offset < cursor && !(is_bit_field && bit_region == Some((offset, field.length)))
                {
                    classes.push_str(&format!(
                        "        # skipped overlapping bit/byte view: {}\n",
                        field.name
                    ));
                    continue;
                }
                if offset > cursor {
                    padding += 1;
                    classes.push_str(&format!(
                        "        XStrFixedLenField(\"_padding_{padding}\", b\"\\x00\" * {}, length={}),\n",
                        offset - cursor,
                        offset - cursor
                    ));
                }
                classes.push_str(&format!(
                    "        {},\n",
                    scapy_field(field, &schema.endian)
                ));
                cursor = offset + field.length;
                bit_region = is_bit_field.then_some((offset, field.length));
            }
            classes.push_str("    ]\n\n");
        }
    }
    let binding = class_names.first().cloned().unwrap_or(base);
    format!(
        "# Generated by tcpform. Requires: pip install scapy\nfrom scapy.all import (Packet, TCP, BitField, ByteField, ShortField, LEShortField, IntField, LEIntField, LongField, LELongField, IPField, StrField, StrFixedLenField, XStrFixedLenField, bind_layers)\n\n{classes}bind_layers(TCP, {binding}, dport={tcp_port})\nbind_layers(TCP, {binding}, sport={tcp_port})\n"
    )
}

fn scapy_field(field: &crate::model::HeaderFieldSpec, endian: &str) -> String {
    let name = code_identifier(&field.name);
    if usize::from(field.bits) < field.length * 8 {
        return format!("BitField(\"{name}\", 0, size={})", field.bits);
    }
    match (field.format.as_str(), field.length, endian) {
        ("uint", 1, _) => format!("ByteField(\"{name}\", 0)"),
        ("uint", 2, "little") => format!("LEShortField(\"{name}\", 0)"),
        ("uint", 2, _) => format!("ShortField(\"{name}\", 0)"),
        ("uint", 4, "little") => format!("LEIntField(\"{name}\", 0)"),
        ("uint", 4, _) => format!("IntField(\"{name}\", 0)"),
        ("uint", 8, "little") => format!("LELongField(\"{name}\", 0)"),
        ("uint", 8, _) => format!("LongField(\"{name}\", 0)"),
        ("ascii", length, _) => {
            format!("StrFixedLenField(\"{name}\", b\"\", length={length})")
        }
        ("ipv4", 4, _) => format!("IPField(\"{name}\", \"0.0.0.0\")"),
        (_, length, _) => {
            format!("XStrFixedLenField(\"{name}\", b\"\\x00\" * {length}, length={length})")
        }
    }
}

fn code_identifier(value: &str) -> String {
    let mut value = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if value.is_empty() || value.starts_with(|character: char| character.is_ascii_digit()) {
        value.insert_str(0, "field_");
    }
    value
}

fn python_class_name(value: &str) -> String {
    let mut output = String::new();
    for part in value.split(|character: char| !character.is_ascii_alphanumeric()) {
        let mut characters = part.chars();
        if let Some(first) = characters.next() {
            output.push(first.to_ascii_uppercase());
            output.extend(characters);
        }
    }
    if output.is_empty() || output.starts_with(|character: char| character.is_ascii_digit()) {
        output.insert_str(0, "Tcpform");
    }
    output
}
pub fn json_schema_compatible(old: &Value, new: &Value) -> Result<(), Vec<String>> {
    let old_required = old
        .get("required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let new_required = new
        .get("required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let old_set = old_required
        .into_iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect::<HashSet<_>>();
    let added = new_required
        .into_iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .filter(|v| !old_set.contains(v))
        .collect::<Vec<_>>();
    if added.is_empty() {
        Ok(())
    } else {
        Err(added
            .into_iter()
            .map(|v| format!("new required property `{v}`"))
            .collect())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginLock {
    pub id: String,
    pub version: String,
    pub sha256: String,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub signature_hex: String,
    #[serde(default)]
    pub public_key_hex: String,
}
pub fn verify_plugin(
    bytes: &[u8],
    lock: &PluginLock,
    allowed: &HashSet<String>,
    requested: &str,
) -> Result<(), String> {
    if !allowed.contains(&lock.id) {
        return Err("plugin is not allowlisted".into());
    }
    if !lock.capabilities.iter().any(|v| v == requested) {
        return Err("plugin capability denied".into());
    }
    let actual = crate::bytes_to_hex(&Sha256::digest(bytes));
    if actual != lock.sha256 {
        return Err("plugin hash does not match lock file".into());
    }
    if !lock.signature_hex.is_empty() || !lock.public_key_hex.is_empty() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let key = crate::parse_hex(&lock.public_key_hex)
            .map_err(|e| format!("invalid plugin public key: {e}"))?;
        let signature = crate::parse_hex(&lock.signature_hex)
            .map_err(|e| format!("invalid plugin signature: {e}"))?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| "plugin public key must be 32 bytes")?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| "plugin signature must be 64 bytes")?;
        VerifyingKey::from_bytes(&key)
            .map_err(|_| "invalid plugin public key")?
            .verify(bytes, &Signature::from_bytes(&signature))
            .map_err(|_| "plugin signature verification failed")?;
    }
    Ok(())
}

pub fn resolve_plugin<'a>(
    id: &str,
    requirement: &str,
    available: &'a [PluginLock],
) -> Result<&'a PluginLock, String> {
    let major = requirement
        .trim_start_matches('^')
        .split('.')
        .next()
        .ok_or("invalid version requirement")?;
    let mut candidates = available
        .iter()
        .filter(|plugin| plugin.id == id && plugin.version.split('.').next() == Some(major))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|plugin| {
        plugin
            .version
            .split('.')
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    });
    candidates
        .pop()
        .ok_or_else(|| format!("no compatible plugin `{id}` for `{requirement}`"))
}

static MONOTONIC_EPOCH: OnceLock<Instant> = OnceLock::new();
pub fn monotonic_time_ns() -> u128 {
    MONOTONIC_EPOCH
        .get_or_init(Instant::now)
        .elapsed()
        .as_nanos()
}
pub fn unix_time_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
pub fn clock_calibration(samples: usize) -> Value {
    let samples = samples.clamp(1, 10_000);
    let mut deltas = Vec::with_capacity(samples);
    for _ in 0..samples {
        let before = monotonic_time_ns();
        let after = monotonic_time_ns();
        deltas.push(after.saturating_sub(before));
    }
    deltas.sort();
    json!({"clock":"monotonic","samples":samples,"resolution_ns_p50":deltas[samples/2].to_string(),"resolution_ns_max":deltas[samples-1].to_string()})
}
pub fn netem_commands(
    interface: &str,
    delay_ms: u64,
    loss_rate: f64,
    reorder: bool,
) -> Result<(Vec<String>, Vec<String>), String> {
    if !interface
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err("invalid network interface".into());
    }
    if !(0.0..=1.0).contains(&loss_rate) {
        return Err("loss_rate must be between 0 and 1".into());
    }
    let mut args = vec![
        "qdisc".into(),
        "replace".into(),
        "dev".into(),
        interface.into(),
        "root".into(),
        "netem".into(),
        "delay".into(),
        format!("{delay_ms}ms"),
        "loss".into(),
        format!("{}%", loss_rate * 100.0),
    ];
    if reorder {
        args.extend(["reorder".into(), "25%".into()]);
    }
    let cleanup = vec![
        "qdisc".into(),
        "del".into(),
        "dev".into(),
        interface.into(),
        "root".into(),
    ];
    Ok((args, cleanup))
}

pub fn single_html_report(
    source: &str,
    trace: &Value,
    diagram: &str,
    pcap: Option<&[u8]>,
) -> String {
    let payload = json!({"source":source,"trace":trace,"diagram":diagram,"pcap_hex":pcap.map(|v|v.iter().map(|b|format!("{b:02x}")).collect::<String>())});
    let safe = payload.to_string().replace('<', "\\u003c");
    format!("<!doctype html><meta charset=utf-8><title>tcpform report</title><h1>tcpform report</h1><pre id=report></pre><script type=application/json id=data>{safe}</script><script>report.textContent=JSON.stringify(JSON.parse(data.textContent),null,2)</script>")
}
pub fn sarif_report(failures: &[(String, String, usize)]) -> Value {
    json!({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"tcpform"}},"results":failures.iter().map(|(message,file,line)|json!({"level":"error","message":{"text":message},"locations":[{"physicalLocation":{"artifactLocation":{"uri":file},"region":{"startLine":line}}}]})).collect::<Vec<_>>()}]})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schema_detects_breaking_change() {
        assert!(
            json_schema_compatible(&json!({"required":["a"]}), &json!({"required":["a","b"]}))
                .is_err()
        )
    }
    #[test]
    fn plugin_pin_is_enforced() {
        let bytes = b"plugin";
        let lock = PluginLock {
            id: "p".into(),
            version: "1".into(),
            sha256: crate::bytes_to_hex(&Sha256::digest(bytes)),
            capabilities: vec!["decode".into()],
            signature_hex: String::new(),
            public_key_hex: String::new(),
        };
        assert!(verify_plugin(bytes, &lock, &HashSet::from(["p".into()]), "decode").is_ok())
    }
    #[test]
    fn plugin_signature_is_verified() {
        use ed25519_dalek::{Signer, SigningKey};
        let bytes = b"signed plugin";
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let signature = signing.sign(bytes);
        let lock = PluginLock {
            id: "p".into(),
            version: "1".into(),
            sha256: crate::bytes_to_hex(&Sha256::digest(bytes)),
            capabilities: vec!["decode".into()],
            signature_hex: crate::bytes_to_hex(&signature.to_bytes()),
            public_key_hex: crate::bytes_to_hex(&signing.verifying_key().to_bytes()),
        };
        assert!(verify_plugin(bytes, &lock, &HashSet::from(["p".into()]), "decode").is_ok());
        assert!(verify_plugin(b"tampered", &lock, &HashSet::from(["p".into()]), "decode").is_err());
    }
    #[test]
    fn schema_generators_emit_valid_dsl_and_dissector() {
        let source = openapi_to_tcpform(&json!({"paths":{"/pets":{"get":{}}}})).unwrap();
        assert!(crate::parse_file(&source).is_ok());
        assert!(protobuf_to_tcpform("message Pet { string name = 1; }")
            .unwrap()
            .contains("protocol \"pet\""));
        let blocks =
            crate::parse_file(include_str!("../examples/custom_header_schema.tcpf")).unwrap();
        let protocol = crate::model::interpret(&blocks).unwrap().remove(0);
        let lua = wireshark_lua(&protocol, 9000);
        assert!(lua.contains("ProtoField.uint8"));
        assert!(lua.contains("ProtoField.string"));
        assert!(lua.contains("buffer(0, 1)"));
        assert!(lua.contains("tcp.port\"):add(9000"));
        let scapy = scapy_python(&protocol, 9000);
        assert!(scapy.contains("class CustomHeaderDemoAcme(Packet):"));
        assert!(scapy.contains("BitField(\"version\""));
        assert!(scapy.contains("BitField(\"kind\""));
        assert!(scapy.contains("StrFixedLenField(\"label\""));
        assert!(scapy.contains("dport=9000"));
    }
    #[test]
    fn aggregation_deduplicates() {
        let r = WorkerResult {
            worker: "a".into(),
            shard: 0,
            case: "x".into(),
            status: "ok".into(),
            document: json!({}),
        };
        assert_eq!(aggregate_worker_results(vec![r.clone(), r])["total"], 1)
    }
}
