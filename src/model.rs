//! Interpret the generic AST (`protocol` blocks) into typed protocol models.

use crate::ast::Block;
use crate::value::Value;
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Error raised while interpreting the AST into a [`Protocol`].
#[derive(Debug, Clone)]
pub struct ModelError {
    pub message: String,
    pub source: Option<String>,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let (Some(source), Some(line), Some(column)) = (&self.source, self.line, self.column) {
            write!(f, "{source}:{line}:{column}: model error: {}", self.message)
        } else {
            write!(f, "model error: {}", self.message)
        }
    }
}

impl std::error::Error for ModelError {}

fn err(msg: impl Into<String>) -> ModelError {
    ModelError {
        message: msg.into(),
        source: None,
        line: None,
        column: None,
    }
}

fn at_block(mut error: ModelError, block: &Block) -> ModelError {
    if error.source.is_none() {
        error.source = block.source.clone();
        error.line = Some(block.line);
        error.column = Some(block.column);
    }
    error
}

/// A protocol definition: a named collection of ordered, composable steps.
#[derive(Debug, Clone)]
pub struct Protocol {
    pub name: String,
    pub description: Option<String>,
    pub steps: Vec<Step>,
    /// Optional simulated-transport configuration (loss, delay, reorder).
    pub transport: Option<TransportConfig>,
    pub limits: ResourceLimits,
    pub clock: ClockMode,
    /// Validate raw TCP handshake/teardown transitions when enabled.
    pub raw_tcp_stateful: bool,
    /// Declarative byte/bit layouts used by the visualizer for proprietary headers.
    pub header_schemas: Vec<HeaderSchema>,
}

#[derive(Debug, Clone)]
pub struct HeaderSchema {
    pub name: String,
    pub offset: usize,
    pub endian: String,
    pub fields: Vec<HeaderFieldSpec>,
}

#[derive(Debug, Clone)]
pub struct HeaderFieldSpec {
    pub name: String,
    /// Stable declaration order for sequential dynamic layouts. Fixed-offset
    /// legacy layouts continue to be ordered by offset.
    pub order: usize,
    pub offset: usize,
    /// Whether `offset` was explicitly supplied. Dynamic fields without an
    /// explicit offset start immediately after the preceding field.
    pub offset_explicit: bool,
    pub length: usize,
    /// Resolve the byte length from an earlier decoded field.
    pub length_from: Option<String>,
    pub length_adjust: i64,
    /// Decode the field repeatedly, either a fixed number of times or from an
    /// earlier decoded field.
    pub repeat: usize,
    pub repeat_from: Option<String>,
    /// Optional terminator byte sequence (hex) for variable strings/bytes.
    pub terminator: Option<Vec<u8>>,
    /// A small, deterministic predicate over previously decoded fields.
    pub when: Option<String>,
    pub bit_offset: u8,
    pub bits: u8,
    pub format: String,
    pub enum_values: HashMap<String, Value>,
    /// Nested fields are decoded within this field's byte range.
    pub fields: Vec<HeaderFieldSpec>,
    /// Tagged-union alternatives selected by `switch_on`.
    pub switch_on: Option<String>,
    pub cases: HashMap<String, Vec<HeaderFieldSpec>>,
    /// Optional reversible content transformation (`zlib` or `plugin:<name>`).
    pub transform: Option<String>,
    pub key_from: Option<String>,
    pub nonce_from: Option<String>,
    /// Optional checksum algorithm covering `checksum_range`.
    pub checksum: Option<String>,
    pub checksum_range: Option<String>,
}

/// One composable unit of a protocol.
#[derive(Debug, Clone)]
pub struct Step {
    pub name: String,
    pub role: String,
    pub action: Action,
    pub depends_on: Vec<String>,
    /// Optional explicit per-role state required before this step executes.
    pub from_state: Option<String>,
    /// Optional explicit per-role state entered after this step succeeds.
    pub to_state: Option<String>,
    pub description: Option<String>,
    pub to: Option<String>,
    /// `open` mode: `"active"` (connect) or `"passive"` (listen).
    pub mode: Option<String>,
    /// Free-text note emitted by `log` steps.
    pub message: Option<String>,
    pub segment: Option<Segment>,
    pub expect: Option<Expect>,
    pub timer: Option<Timer>,
    pub assert: Option<Assert>,
    pub set: Option<Set>,
    pub plugin: Option<PluginSpec>,
    pub raw_packet: Option<RawPacketSpec>,
    pub retransmit: u32,
    /// Optional boolean/value expression controlling whether this step runs.
    pub when: Option<Value>,
    /// Number of retries after a step execution failure.
    pub retry: u32,
    /// If true, retry only timeout failures.
    pub on_timeout: bool,
    /// Number of successful executions (defaults to one; zero skips).
    pub loop_count: u32,
    pub retry_policy: RetryPolicy,
    pub source: Option<String>,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClockMode {
    #[default]
    Real,
    Virtual,
}

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff: f64,
    pub jitter: f64,
    pub retry_on: Vec<String>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_delay_ms: 0,
            max_delay_ms: 60_000,
            backoff: 1.0,
            jitter: 0.0,
            retry_on: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_inbox: usize,
    pub max_trace: usize,
    pub max_payload: usize,
    pub max_loop: u32,
    pub max_retry: u32,
    pub connect_timeout_ms: u64,
    /// Maximum real or virtual runtime for one execution.
    pub max_runtime_ms: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_inbox: 10_000,
            max_trace: 100_000,
            max_payload: 16 * 1024 * 1024,
            max_loop: 10_000,
            max_retry: 1_000,
            connect_timeout_ms: 10_000,
            max_runtime_ms: 300_000,
        }
    }
}

/// The primitive actions a step can perform.
///
/// - **Lifecycle**: `open` (active/passive connect), `close` (graceful),
///   `reset` (abortive, RST).
/// - **Data**: `send`, `recv`, `ack` (positive), `nack` (negative).
/// - **Reliability injection**: `drop` (lose a matching inbound segment),
///   `duplicate` (send the segment twice).
/// - **Verification/state**: `assert` (check a condition), `set` (write a
///   local variable), `log` (emit a trace marker).
/// - **Timing**: `wait`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Send,
    SendRaw,
    Recv,
    RecvRaw,
    Ack,
    Nack,
    Wait,
    Close,
    Open,
    Reset,
    Drop,
    Duplicate,
    Corrupt,
    Assert,
    Set,
    Log,
    Plugin,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Send => "send",
            Action::SendRaw => "send_raw",
            Action::Recv => "recv",
            Action::RecvRaw => "recv_raw",
            Action::Ack => "ack",
            Action::Nack => "nack",
            Action::Wait => "wait",
            Action::Close => "close",
            Action::Open => "open",
            Action::Reset => "reset",
            Action::Drop => "drop",
            Action::Duplicate => "duplicate",
            Action::Corrupt => "corrupt",
            Action::Assert => "assert",
            Action::Set => "set",
            Action::Log => "log",
            Action::Plugin => "plugin",
        }
    }
}

/// Deferred raw-header attributes. Values may contain `${var}` and are
/// validated again after interpolation immediately before packet encoding.
#[derive(Debug, Clone, Default)]
pub struct RawPacketSpec {
    pub ethernet: Option<HashMap<String, Value>>,
    pub ipv4: Option<HashMap<String, Value>>,
    pub ipv6: Option<HashMap<String, Value>>,
    pub tcp: Option<HashMap<String, Value>>,
    pub udp: Option<HashMap<String, Value>>,
    pub mtu: Option<usize>,
    pub fragment_id: Option<u32>,
}

/// An outbound segment (the "send" payload + metadata).
#[derive(Debug, Clone, Default)]
pub struct Segment {
    pub flags: Vec<String>,
    pub seq: Option<i64>,
    pub ack: Option<i64>,
    pub payload: Option<String>,
    /// Raw hex payload string (from `hex = "..."`). May contain `${var}`
    /// tokens; parsed into bytes at send time after interpolation. When set,
    /// takes precedence over `payload`.
    pub hex: Option<String>,
    pub payload_len: Option<i64>,
    /// Flow-control advertisement (TCP window). Defaults to 0 when unset.
    pub window: Option<i64>,
    /// Multiplexing identifier (QUIC/HTTP2 stream id). `None` = default stream.
    pub stream: Option<i64>,
    /// Structured message fields (key→value). String values may contain
    /// `${var}` tokens interpolated from the role's variable map at send time.
    pub fields: HashMap<String, Value>,
    /// Per-segment delivery delay in milliseconds (latency injection).
    /// 0 = no extra delay. Overlays the transport-level `delay_ms`.
    pub delay_ms: u64,
    /// Zero-based bit index to flip for the `corrupt` action (MSB first).
    pub flip_bit: Option<u64>,
}

/// An inbound expectation (the "recv" matcher).
#[derive(Debug, Clone, Default)]
pub struct Expect {
    pub flags: Vec<String>,
    pub payload: Option<String>,
    /// Raw binary payload to match exactly (from `hex = "..."`).
    pub hex: Option<Vec<u8>>,
    /// Raw binary substring to find in the received payload
    /// (from `hex_contains = "..."`).
    pub hex_contains: Option<Vec<u8>>,
    pub from: Option<String>,
    /// If set, the message window must equal this.
    pub window: Option<i64>,
    /// If set, the message stream id must equal this.
    pub stream: Option<i64>,
    /// Per-field matchers: only the named fields are checked (partial match).
    pub fields: HashMap<String, FieldMatch>,
    /// Field capture: `field_name -> variable_name`. On a successful match,
    /// the engine stores `msg.fields[field_name]` into the role variable map
    /// under `variable_name`, making it usable by later `send` (`${var}`) and
    /// `assert` steps.
    pub capture: HashMap<String, String>,
}

impl Expect {
    /// Interpolate `${var}` tokens in the field matchers' `Equal` values,
    /// using the role's variable map. Other matchers (Contains, Min, etc.)
    /// are left as-is since they don't carry `${var}` in their operands.
    pub fn interpolate(&mut self, vars: &HashMap<String, Value>) {
        for matcher in self.fields.values_mut() {
            match matcher {
                FieldMatch::Equal(v) | FieldMatch::NotEqual(v) => {
                    *v = crate::engine::interpolate_value_pub(v, vars);
                }
                FieldMatch::Contains(s) | FieldMatch::Prefix(s) | FieldMatch::Suffix(s) => {
                    *s = crate::engine::interpolate_str_pub(s, vars);
                }
                FieldMatch::Regex { pattern, compiled } => {
                    *pattern = crate::engine::interpolate_str_pub(pattern, vars);
                    *compiled = regex_lite::Regex::new(pattern).ok();
                }
                _ => {}
            }
        }
    }
}

/// A matcher for a single structured field. Parsed from a `fields` value:
/// a scalar becomes `Equal`; an object like `{ contains = "OK" }` or
/// `{ min = 1 max = 10 }` becomes the corresponding operator.
#[derive(Debug, Clone)]
pub enum FieldMatch {
    Equal(Value),
    NotEqual(Value),
    Contains(String),
    Prefix(String),
    Suffix(String),
    Regex {
        pattern: String,
        compiled: Option<regex_lite::Regex>,
    },
    /// Raw byte substring search (from `hex_contains = "..."`).
    BytesContains(Vec<u8>),
    Min(i64),
    Max(i64),
    Range {
        min: Option<i64>,
        max: Option<i64>,
    },
}

impl FieldMatch {
    /// True if `actual` satisfies this matcher.
    pub fn matches(&self, actual: &Value) -> bool {
        match self {
            FieldMatch::Equal(expected) => expected == actual,
            FieldMatch::NotEqual(expected) => expected != actual,
            FieldMatch::Contains(needle) => match actual {
                Value::String(s) => s.contains(needle.as_str()),
                _ => false,
            },
            FieldMatch::Prefix(prefix) => match actual {
                Value::String(s) => s.starts_with(prefix),
                _ => false,
            },
            FieldMatch::Suffix(suffix) => match actual {
                Value::String(s) => s.ends_with(suffix),
                _ => false,
            },
            FieldMatch::Regex { compiled, .. } => match actual {
                Value::String(s) => compiled.as_ref().is_some_and(|regex| regex.is_match(s)),
                _ => false,
            },
            FieldMatch::BytesContains(needle) => match actual {
                Value::Bytes(b) if !needle.is_empty() => {
                    b.windows(needle.len()).any(|w| w == needle.as_slice())
                }
                _ => false,
            },
            FieldMatch::Min(lo) => match actual {
                Value::Number(n) => *n >= *lo as f64,
                _ => false,
            },
            FieldMatch::Max(hi) => match actual {
                Value::Number(n) => *n <= *hi as f64,
                _ => false,
            },
            FieldMatch::Range { min, max } => match actual {
                Value::Number(n) => {
                    let lo_ok = min.is_none_or(|lo| *n >= lo as f64);
                    let hi_ok = max.is_none_or(|hi| *n <= hi as f64);
                    lo_ok && hi_ok
                }
                _ => false,
            },
        }
    }
}

/// Interpret a `fields` object value into per-field matchers.
pub fn interpret_field_matches(
    obj: &HashMap<String, Value>,
) -> Result<HashMap<String, FieldMatch>, ModelError> {
    let mut out = HashMap::new();
    for (k, v) in obj {
        out.insert(k.clone(), interpret_field_match(v)?);
    }
    Ok(out)
}

fn interpret_field_match(v: &Value) -> Result<FieldMatch, ModelError> {
    match v {
        Value::Object(o) => {
            validate_map_keys(
                o,
                &[
                    "hex",
                    "hex_contains",
                    "contains",
                    "not_equal",
                    "prefix",
                    "suffix",
                    "regex",
                    "min",
                    "max",
                ],
                "field matcher",
            )?;
            let operator_count = o.keys().count();
            let is_range = operator_count == 2 && o.contains_key("min") && o.contains_key("max");
            if operator_count != 1 && !is_range {
                return Err(err(
                    "field matcher must define exactly one operator, except min+max range",
                ));
            }
            if let Some(hs) = o.get("hex").and_then(|x| x.as_str()) {
                let bytes =
                    crate::value::parse_hex(hs).map_err(|e| err(format!("field `hex`: {e}")))?;
                return Ok(FieldMatch::Equal(Value::Bytes(bytes)));
            }
            if let Some(hs) = o.get("hex_contains").and_then(|x| x.as_str()) {
                let bytes = crate::value::parse_hex(hs)
                    .map_err(|e| err(format!("field `hex_contains`: {e}")))?;
                if bytes.is_empty() {
                    return Err(err("field `hex_contains` must not be empty"));
                }
                return Ok(FieldMatch::BytesContains(bytes));
            }
            if let Some(needle) = o.get("contains").and_then(|x| x.as_str()) {
                return Ok(FieldMatch::Contains(needle.to_string()));
            }
            if let Some(expected) = o.get("not_equal") {
                return Ok(FieldMatch::NotEqual(expected.clone()));
            }
            if let Some(prefix) = o.get("prefix").and_then(|x| x.as_str()) {
                return Ok(FieldMatch::Prefix(prefix.to_string()));
            }
            if let Some(suffix) = o.get("suffix").and_then(|x| x.as_str()) {
                return Ok(FieldMatch::Suffix(suffix.to_string()));
            }
            if let Some(pattern) = o.get("regex").and_then(|x| x.as_str()) {
                let compiled = regex_lite::Regex::new(pattern)
                    .map_err(|e| err(format!("field `regex`: {e}")))?;
                return Ok(FieldMatch::Regex {
                    pattern: pattern.to_string(),
                    compiled: Some(compiled),
                });
            }
            let min = o.get("min").and_then(|x| x.as_i64());
            let max = o.get("max").and_then(|x| x.as_i64());
            if min.is_some() || max.is_some() {
                if min.is_some() && max.is_some() {
                    return Ok(FieldMatch::Range { min, max });
                }
                if let Some(lo) = min {
                    return Ok(FieldMatch::Min(lo));
                }
                if let Some(hi) = max {
                    return Ok(FieldMatch::Max(hi));
                }
            }
            Err(err(
                "field matcher object must have `hex`, `hex_contains`, `contains`, `not_equal`, `prefix`, `suffix`, `regex`, `min`, or `max`",
            ))
        }
        scalar => Ok(FieldMatch::Equal(scalar.clone())),
    }
}

/// Timing / reliability knobs for a step.
#[derive(Debug, Clone)]
pub struct Timer {
    pub timeout_ms: u64,
    pub retransmit: u32,
}

/// Simulated transport configuration: probabilistic loss, per-message delay,
/// and reordering. Applied to every segment sent over the transport.
#[derive(Debug, Clone, Default)]
pub struct TransportConfig {
    /// Probability of dropping a segment (0.0–1.0). 0 = no loss.
    pub loss_rate: f64,
    /// Fixed delay added to every segment delivery, in milliseconds.
    pub delay_ms: u64,
    /// If true, segments may be delivered out of order (shuffled per batch).
    pub reorder: bool,
    /// Seed for deterministic loss/reorder (0 = non-deterministic).
    pub seed: u64,
    /// Symmetric random variation added to delay, in milliseconds.
    pub jitter_ms: u64,
    /// Simulated link bandwidth in bits per second. Zero means unlimited.
    pub bandwidth_bps: u64,
    /// Eligible send ordinal after which `bandwidth_after_bps` applies.
    pub bandwidth_after_nth: u64,
    /// Dynamic bandwidth used from `bandwidth_after_nth` onward.
    pub bandwidth_after_bps: u64,
    /// Maximum application payload accepted by this transport. Zero means no
    /// transport-specific MTU (the global resource limit still applies).
    pub mtu: usize,
    /// Number of consecutive drops triggered by a probabilistic loss event.
    pub burst_loss: u32,
    /// Probability of delivering a second copy of an eligible message.
    pub duplicate_rate: f64,
    /// Probability of flipping the first payload bit of an eligible message.
    pub corrupt_rate: f64,
    /// Drop exactly this eligible send ordinal (zero disables it).
    pub drop_nth: u64,
    /// Fail the selected eligible send as a simulated link disconnect.
    pub disconnect_nth: u64,
    /// Eligible send ordinal that receives an additional deterministic delay.
    pub delay_spike_nth: u64,
    /// Additional delay applied by `delay_spike_nth`.
    pub delay_spike_ms: u64,
    /// Silently discard payloads above `mtu`, emulating PMTUD black holes.
    pub mtu_blackhole: bool,
    /// Fail eligible sends after this ordinal to emulate ephemeral-port exhaustion.
    pub port_capacity: u64,
    /// Optional source address exposed to receivers after simulated NAT.
    pub nat_source_ip: Option<String>,
    /// Optional source port exposed to receivers after simulated NAT.
    pub nat_source_port: Option<u32>,
    /// Deterministic connection setup failure (`dns`, `refused`, `tls_handshake`).
    pub connect_failure: Option<String>,
    /// Optional step-name allowlist for transport faults.
    pub fault_steps: Vec<String>,
    /// Optional message flag required for transport faults.
    pub fault_flag: Option<String>,
    /// Optional structured/raw decoded field equality predicate.
    pub fault_when: Option<FaultPredicate>,
}

#[derive(Debug, Clone)]
pub struct FaultPredicate {
    pub field: String,
    pub equals: Value,
}

/// A verification block (`assert { ... }`): each attribute is checked against
/// the role's state. Built-in keys (`send_count`, `recv_count`, `next_seq`,
/// `last_recv_seq`, `last_recv_ack`, `last_recv_from`, `last_recv_window`,
/// `last_sent_seq`, `last_sent_ack`, `last_sent_to`, `aborted`) use equality;
/// `recv_flags` / `sent_flags` use subset matching (every expected flag
/// present); any other key is read from the user variable map set via `set`.
#[derive(Debug, Clone, Default)]
pub struct Assert {
    pub attrs: HashMap<String, Value>,
}

/// A local-state write (`set { ... }`): each attribute is stored in the role's
/// variable map, readable later by `assert`.
#[derive(Debug, Clone, Default)]
pub struct Set {
    pub vars: HashMap<String, Value>,
}

/// Process-isolated extension invocation attached to a `plugin` action.
#[derive(Debug, Clone)]
pub struct PluginSpec {
    pub manifest: String,
    pub kind: String,
    pub name: String,
    pub input: Value,
}

/// A data-driven test suite for a protocol. Each [`Case`] runs the protocol
/// with its own set of initial variables (`${var}` interpolation), then checks
/// the outcome and per-role state assertions.
#[derive(Debug, Clone)]
pub struct Cases {
    /// The protocol name these cases target.
    pub protocol: String,
    pub cases: Vec<Case>,
}

/// A single data-driven test case.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    /// User-defined labels used by CI/test selection (for example `smoke`).
    pub tags: Vec<String>,
    /// Initial variables injected into every role's variable map before the
    /// run starts. Referenced via `${var}` in `segment`/`assert`/etc.
    pub vars: HashMap<String, Value>,
    pub expect: CaseExpect,
}

/// What a case expects from the run.
#[derive(Debug, Clone)]
pub struct CaseExpect {
    /// Whether the run should succeed (`Pass`) or fail (`Fail`).
    pub outcome: CaseOutcome,
    /// Per-role post-run assertions: `role -> assert attrs`. Checked against
    /// the role's final state using the same logic as `assert` steps.
    pub asserts: HashMap<String, HashMap<String, Value>>,
}

/// The expected outcome of a case run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseOutcome {
    /// The run should complete without error.
    Pass,
    /// The run should fail (error or timeout).
    Fail,
}

impl CaseOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            CaseOutcome::Pass => "pass",
            CaseOutcome::Fail => "fail",
        }
    }
}

/// Interpret a file's top-level blocks into protocols and case suites.
pub fn interpret(blocks: &[Block]) -> Result<Vec<Protocol>, ModelError> {
    validate_top_level(blocks)?;
    let mut out = Vec::new();
    let mut names = HashSet::new();
    for b in expand_modules(blocks)? {
        if b.name == "protocol" {
            let protocol = interpret_protocol(&b).map_err(|error| at_block(error, &b))?;
            if !names.insert(protocol.name.clone()) {
                return Err(err(format!(
                    "duplicate protocol definition `{}`",
                    protocol.name
                )));
            }
            out.push(protocol);
        }
    }
    Ok(out)
}

/// Interpret a file's top-level blocks into case suites (`cases` blocks).
pub fn interpret_cases(blocks: &[Block]) -> Result<Vec<Cases>, ModelError> {
    validate_top_level(blocks)?;
    let mut out = Vec::new();
    for b in expand_modules(blocks)? {
        if b.name == "cases" {
            out.push(interpret_cases_block(&b).map_err(|error| at_block(error, &b))?);
        }
    }
    Ok(out)
}

fn expand_modules(blocks: &[Block]) -> Result<Vec<Block>, ModelError> {
    fn visit(blocks: &[Block], prefix: &str, out: &mut Vec<Block>) -> Result<(), ModelError> {
        for block in blocks {
            if block.name == "module" {
                validate_attributes(block, &[])?;
                if block.labels.len() != 1 {
                    return Err(err("module block requires exactly one name label"));
                }
                let label = block
                    .labels
                    .first()
                    .ok_or_else(|| err("module block needs a name label"))?;
                let nested = if prefix.is_empty() {
                    label.clone()
                } else {
                    format!("{prefix}.{label}")
                };
                visit(&block.blocks, &nested, out)?;
                continue;
            }
            let mut block = block.clone();
            if !prefix.is_empty() && matches!(block.name.as_str(), "protocol" | "cases") {
                if let Some(label) = block.labels.first_mut() {
                    *label = format!("{prefix}.{label}");
                }
            }
            out.push(block);
        }
        Ok(())
    }

    let mut out = Vec::new();
    visit(blocks, "", &mut out)?;
    Ok(out)
}

fn interpret_cases_block(b: &Block) -> Result<Cases, ModelError> {
    if b.labels.len() != 1 {
        return Err(err("cases block requires exactly one protocol label"));
    }
    validate_attributes(b, &[])?;
    validate_children(b, |name| name == "case", "cases")?;
    let protocol = b
        .labels
        .first()
        .cloned()
        .ok_or_else(|| err("cases block needs a protocol name label"))?;
    let mut cases = Vec::new();
    for case_block in b.children("case") {
        cases.push(interpret_case(case_block)?);
    }
    if cases.is_empty() {
        return Err(err(format!(
            "cases block for `{protocol}` has no `case` blocks"
        )));
    }
    Ok(Cases { protocol, cases })
}

fn interpret_case(b: &Block) -> Result<Case, ModelError> {
    let name = b
        .labels
        .first()
        .cloned()
        .ok_or_else(|| err("case block needs a name label"))?;
    if b.labels.len() != 1 {
        return Err(err("case block requires exactly one name label"));
    }
    validate_attributes(b, &["vars", "expect", "tags"])?;
    validate_children(
        b,
        |child| child == "vars" || child.starts_with("assert_"),
        &format!("case `{name}`"),
    )?;
    // vars: either a `vars` nested block or a `vars` object attribute
    if b.child("vars").is_some() && b.attr("vars").is_some() {
        return Err(err(format!(
            "case `{name}` defines vars as both block and attribute"
        )));
    }
    ensure_single_child(b, "vars", &format!("case `{name}`"))?;
    let vars = match b.child("vars") {
        Some(child) => {
            validate_children(child, |_| false, "vars")?;
            resolve_hex_values(&child.attributes)
        }
        None => match b.attr("vars") {
            Some(Value::Object(o)) => resolve_hex_values(o),
            Some(value) => {
                return Err(type_error(
                    &format!("case `{name}`"),
                    "vars",
                    "an object",
                    value,
                ))
            }
            None => HashMap::new(),
        },
    };
    // expect: "pass" (default) or "fail"
    let outcome = match b.attr("expect") {
        None => CaseOutcome::Pass,
        Some(Value::String(value)) if value == "pass" => CaseOutcome::Pass,
        Some(Value::String(value)) if value == "fail" => CaseOutcome::Fail,
        Some(value) => {
            return Err(err(format!(
                "case `{name}` expect must be \"pass\" or \"fail\", got {}",
                value.to_display()
            )))
        }
    };
    let tags = optional_string_array(&b.attributes, &format!("case `{name}`"), "tags")?;
    let mut unique_tags = HashSet::new();
    for tag in &tags {
        if tag.is_empty() {
            return Err(err(format!(
                "case `{name}` tags must not contain an empty tag"
            )));
        }
        if !unique_tags.insert(tag) {
            return Err(err(format!("case `{name}` contains duplicate tag `{tag}`")));
        }
    }
    // Per-role asserts: `assert_role` nested blocks, e.g. `assert_client { ... }`
    let mut asserts: HashMap<String, HashMap<String, Value>> = HashMap::new();
    for child in &b.blocks {
        if let Some(role) = child.name.strip_prefix("assert_") {
            if !role.is_empty() {
                asserts.insert(role.to_string(), resolve_hex_values(&child.attributes));
            }
        }
    }
    Ok(Case {
        name,
        tags,
        vars,
        expect: CaseExpect { outcome, asserts },
    })
}

fn interpret_protocol(b: &Block) -> Result<Protocol, ModelError> {
    let name = b
        .labels
        .first()
        .cloned()
        .ok_or_else(|| err("protocol block needs a name label"))?;
    if b.labels.len() != 1 {
        return Err(err("protocol block requires exactly one name label"));
    }
    validate_attributes(b, &["description", "clock", "raw_tcp_stateful"])?;
    validate_children(
        b,
        |child| matches!(child, "step" | "transport" | "limits" | "header_schema"),
        &format!("protocol `{name}`"),
    )?;
    ensure_single_child(b, "transport", &format!("protocol `{name}`"))?;
    ensure_single_child(b, "limits", &format!("protocol `{name}`"))?;
    let limits = b
        .child("limits")
        .map(interpret_limits)
        .transpose()?
        .unwrap_or_default();
    let clock = match b.attr("clock") {
        None => ClockMode::Real,
        Some(Value::String(value)) if value == "real" => ClockMode::Real,
        Some(Value::String(value)) if value == "virtual" => ClockMode::Virtual,
        Some(value) => {
            return Err(err(format!(
                "protocol `{name}` clock must be \"real\" or \"virtual\", got {}",
                value.to_display()
            )))
        }
    };
    let description = optional_string(&b.attributes, &format!("protocol `{name}`"), "description")?;
    let raw_tcp_stateful = optional_bool(
        &b.attributes,
        &format!("protocol `{name}`"),
        "raw_tcp_stateful",
        false,
    )?;
    let mut steps = Vec::new();
    for step_block in b.children("step") {
        let step = interpret_step(step_block).map_err(|error| at_block(error, step_block))?;
        if step.loop_count > limits.max_loop {
            return Err(err(format!(
                "step `{}` loop={} exceeds limits.max_loop={}",
                step.name, step.loop_count, limits.max_loop
            )));
        }
        if step.retry > limits.max_retry || step.retransmit > limits.max_retry {
            return Err(err(format!(
                "step `{}` retry/retransmit exceeds limits.max_retry={}",
                step.name, limits.max_retry
            )));
        }
        steps.push(step);
    }
    if steps.is_empty() {
        return Err(err(format!(
            "protocol `{name}` has no steps; add at least one `step` block"
        )));
    }
    // Optional `transport { ... }` block for lossy/delayed/reordering transport
    let transport = b
        .child("transport")
        .map(interpret_transport_config)
        .transpose()
        .map_err(|error| at_block(error, b.child("transport").unwrap_or(b)))?;
    let mut header_schemas = Vec::new();
    let mut schema_names = HashSet::new();
    for schema in b.children("header_schema") {
        let parsed = interpret_header_schema(schema).map_err(|error| at_block(error, schema))?;
        if !schema_names.insert(parsed.name.clone()) {
            return Err(err(format!("duplicate header_schema `{}`", parsed.name)));
        }
        header_schemas.push(parsed);
    }
    Ok(Protocol {
        name,
        description,
        steps,
        transport,
        limits,
        clock,
        raw_tcp_stateful,
        header_schemas,
    })
}

fn interpret_header_schema(b: &Block) -> Result<HeaderSchema, ModelError> {
    let name = b
        .labels
        .first()
        .cloned()
        .ok_or_else(|| err("header_schema needs a name label"))?;
    if b.labels.len() != 1 {
        return Err(err("header_schema requires exactly one name label"));
    }
    validate_attributes(b, &["offset", "endian", "fields"])?;
    validate_children(b, |_| false, &format!("header_schema `{name}`"))?;
    let offset = usize::try_from(optional_u64(
        &b.attributes,
        &format!("header_schema `{name}`"),
        "offset",
        0,
    )?)
    .map_err(|_| err(format!("header_schema `{name}` offset is too large")))?;
    let endian = optional_string(&b.attributes, &format!("header_schema `{name}`"), "endian")?
        .unwrap_or_else(|| "big".into());
    if !matches!(endian.as_str(), "big" | "little") {
        return Err(err(format!(
            "header_schema `{name}` endian must be big or little"
        )));
    }
    let values = match b.attr("fields") {
        Some(Value::Object(values)) => values,
        Some(value) => {
            return Err(type_error(
                &format!("header_schema `{name}`"),
                "fields",
                "an object",
                value,
            ))
        }
        None => return Err(err(format!("header_schema `{name}` requires fields"))),
    };
    let mut fields = parse_header_fields(values, &format!("header_schema `{name}`"))?;
    sort_header_fields(&mut fields);
    if fields.is_empty() {
        return Err(err(format!(
            "header_schema `{name}` requires at least one field"
        )));
    }
    Ok(HeaderSchema {
        name,
        offset,
        endian,
        fields,
    })
}

fn parse_header_fields(
    values: &HashMap<String, Value>,
    parent: &str,
) -> Result<Vec<HeaderFieldSpec>, ModelError> {
    let mut fields = Vec::new();
    for (field_name, value) in values {
        let object = match value {
            Value::Object(object) => object,
            _ => {
                return Err(err(format!(
                    "{parent} field `{field_name}` must be an object"
                )))
            }
        };
        for key in object.keys() {
            if !matches!(
                key.as_str(),
                "offset"
                    | "order"
                    | "length"
                    | "length_from"
                    | "length_adjust"
                    | "repeat"
                    | "repeat_from"
                    | "terminator"
                    | "when"
                    | "bit_offset"
                    | "bits"
                    | "format"
                    | "enum"
                    | "fields"
                    | "switch_on"
                    | "cases"
                    | "transform"
                    | "key_from"
                    | "nonce_from"
                    | "checksum"
                    | "checksum_range"
            ) {
                return Err(err(format!(
                    "{parent} field `{field_name}` has unknown attribute `{key}`"
                )));
            }
        }
        let context = format!("{parent} field `{field_name}`");
        let order = optional_usize(object, &context, "order", usize::MAX)?;
        let offset_explicit = object.contains_key("offset");
        let field_offset = usize::try_from(optional_u64(object, &context, "offset", 0)?)
            .map_err(|_| err(format!("{context} offset is too large")))?;
        let length = optional_usize(object, &context, "length", 1)?;
        if length == 0 {
            return Err(err(format!("{context} length must be positive")));
        }
        let length_from = optional_string(object, &context, "length_from")?;
        let length_adjust = object
            .get("length_adjust")
            .map(|value| {
                value
                    .as_i64()
                    .ok_or_else(|| err(format!("{context} length_adjust must be an integer")))
            })
            .transpose()?
            .unwrap_or(0);
        let repeat = optional_usize(object, &context, "repeat", 1)?;
        if repeat == 0 {
            return Err(err(format!("{context} repeat must be positive")));
        }
        let repeat_from = optional_string(object, &context, "repeat_from")?;
        if repeat_from.is_some() && object.contains_key("repeat") {
            return Err(err(format!(
                "{context} cannot use repeat and repeat_from together"
            )));
        }
        let terminator = optional_string(object, &context, "terminator")?
            .map(|value| {
                crate::value::parse_hex(&value)
                    .map_err(|error| err(format!("{context} terminator: {error}")))
            })
            .transpose()?;
        if terminator.as_ref().is_some_and(Vec::is_empty) {
            return Err(err(format!("{context} terminator cannot be empty")));
        }
        let when = optional_string(object, &context, "when")?;
        let bit_offset = optional_u64(object, &context, "bit_offset", 0)?;
        let bits = optional_u64(object, &context, "bits", (length * 8).min(64) as u64)?;
        if bit_offset > 7 || bits == 0 || bits > 64 || bit_offset + bits > (length * 8) as u64 {
            return Err(err(format!("{context} bit range exceeds its byte length")));
        }
        let format = optional_string(object, &context, "format")?.unwrap_or_else(|| {
            if object.contains_key("fields")
                || object.contains_key("cases")
                || object.contains_key("transform")
                || length > 8
            {
                "bytes".into()
            } else {
                "uint".into()
            }
        });
        if !matches!(
            format.as_str(),
            "uint" | "int" | "hex" | "bytes" | "ascii" | "utf8" | "ipv4" | "bool"
        ) {
            return Err(err(format!("{context} has unsupported format `{format}`")));
        }
        if matches!(format.as_str(), "uint" | "int" | "bool" | "ipv4") && length > 8 {
            return Err(err(format!("{context} numeric length must be 1..=8")));
        }
        let enum_values = match object.get("enum") {
            Some(Value::Object(values)) => values.clone(),
            Some(value) => return Err(type_error(&context, "enum", "an object", value)),
            None => HashMap::new(),
        };
        let nested = match object.get("fields") {
            Some(Value::Object(values)) => parse_header_fields(values, &context)?,
            Some(value) => return Err(type_error(&context, "fields", "an object", value)),
            None => Vec::new(),
        };
        let switch_on = optional_string(object, &context, "switch_on")?;
        let mut cases = HashMap::new();
        match object.get("cases") {
            Some(Value::Object(values)) => {
                for (selector, case) in values {
                    let case_fields = match case {
                        Value::Object(case) => match case.get("fields") {
                            Some(Value::Object(fields)) => fields,
                            _ => case,
                        },
                        value => return Err(type_error(&context, "cases", "an object", value)),
                    };
                    cases.insert(
                        selector.clone(),
                        parse_header_fields(case_fields, &format!("{context} case `{selector}`"))?,
                    );
                }
            }
            Some(value) => return Err(type_error(&context, "cases", "an object", value)),
            None => {}
        }
        if switch_on.is_some() != !cases.is_empty() {
            return Err(err(format!(
                "{context} switch_on and cases must be supplied together"
            )));
        }
        let transform = optional_string(object, &context, "transform")?;
        if transform.as_ref().is_some_and(|value| {
            value != "zlib" && value != "aes-gcm" && !value.starts_with("plugin:")
        }) {
            return Err(err(format!(
                "{context} transform must be zlib, aes-gcm, or plugin:<name>"
            )));
        }
        let key_from = optional_string(object, &context, "key_from")?;
        let nonce_from = optional_string(object, &context, "nonce_from")?;
        if transform.as_deref() == Some("aes-gcm") && (key_from.is_none() || nonce_from.is_none()) {
            return Err(err(format!(
                "{context} aes-gcm requires key_from and nonce_from"
            )));
        }
        let checksum = optional_string(object, &context, "checksum")?;
        if checksum
            .as_ref()
            .is_some_and(|value| !matches!(value.as_str(), "crc16" | "crc32" | "internet"))
        {
            return Err(err(format!(
                "{context} checksum must be crc16, crc32, or internet"
            )));
        }
        let checksum_range = optional_string(object, &context, "checksum_range")?;
        fields.push(HeaderFieldSpec {
            name: field_name.clone(),
            order,
            offset: field_offset,
            offset_explicit,
            length,
            length_from,
            length_adjust,
            repeat,
            repeat_from,
            terminator,
            when,
            bit_offset: bit_offset as u8,
            bits: bits as u8,
            format,
            enum_values,
            fields: nested,
            switch_on,
            cases,
            transform,
            key_from,
            nonce_from,
            checksum,
            checksum_range,
        });
    }
    sort_header_fields(&mut fields);
    Ok(fields)
}

fn sort_header_fields(fields: &mut [HeaderFieldSpec]) {
    fields.sort_by_key(|field| {
        if field.order != usize::MAX {
            (0, field.order, field.bit_offset as usize)
        } else {
            (1, field.offset, field.bit_offset as usize)
        }
    });
}

fn interpret_transport_config(b: &Block) -> Result<TransportConfig, ModelError> {
    validate_attributes(
        b,
        &[
            "loss_rate",
            "delay",
            "jitter",
            "bandwidth_bps",
            "bandwidth_after_nth",
            "bandwidth_after_bps",
            "mtu",
            "burst_loss",
            "duplicate_rate",
            "corrupt_rate",
            "drop_nth",
            "disconnect_nth",
            "delay_spike_nth",
            "delay_spike",
            "mtu_blackhole",
            "port_capacity",
            "nat_source_ip",
            "nat_source_port",
            "connect_failure",
            "fault_steps",
            "fault_flag",
            "reorder",
            "seed",
        ],
    )?;
    validate_children(b, |name| name == "fault_when", "transport")?;
    if b.children("fault_when").count() > 1 {
        return Err(err("transport allows at most one fault_when block"));
    }
    let loss_rate = match b.attr("loss_rate") {
        None => 0.0,
        Some(Value::Number(value)) if value.is_finite() => *value,
        Some(value) => return Err(type_error("transport", "loss_rate", "number", value)),
    };
    if !(0.0..=1.0).contains(&loss_rate) {
        return Err(err(format!(
            "transport `loss_rate` must be 0.0–1.0, got {loss_rate}"
        )));
    }
    let delay_ms = optional_duration(&b.attributes, "transport", "delay", 0)?;
    let reorder = optional_bool(&b.attributes, "transport", "reorder", false)?;
    let seed = optional_u64(&b.attributes, "transport", "seed", 0)?;
    let jitter_ms = optional_duration(&b.attributes, "transport", "jitter", 0)?;
    let bandwidth_bps = optional_u64(&b.attributes, "transport", "bandwidth_bps", 0)?;
    let bandwidth_after_nth = optional_u64(&b.attributes, "transport", "bandwidth_after_nth", 0)?;
    let bandwidth_after_bps = optional_u64(&b.attributes, "transport", "bandwidth_after_bps", 0)?;
    if (bandwidth_after_nth == 0) != (bandwidth_after_bps == 0) {
        return Err(err(
            "transport `bandwidth_after_nth` and `bandwidth_after_bps` must be configured together",
        ));
    }
    let mtu = optional_usize(&b.attributes, "transport", "mtu", 0)?;
    let burst_loss = optional_u32(&b.attributes, "transport", "burst_loss", 1)?;
    let duplicate_rate = optional_probability(&b.attributes, "transport", "duplicate_rate")?;
    let corrupt_rate = optional_probability(&b.attributes, "transport", "corrupt_rate")?;
    let drop_nth = optional_u64(&b.attributes, "transport", "drop_nth", 0)?;
    let disconnect_nth = optional_u64(&b.attributes, "transport", "disconnect_nth", 0)?;
    let delay_spike_nth = optional_u64(&b.attributes, "transport", "delay_spike_nth", 0)?;
    let delay_spike_ms = optional_duration(&b.attributes, "transport", "delay_spike", 0)?;
    if (delay_spike_nth == 0) != (delay_spike_ms == 0) {
        return Err(err(
            "transport `delay_spike_nth` and non-zero `delay_spike` must be configured together",
        ));
    }
    let mtu_blackhole = optional_bool(&b.attributes, "transport", "mtu_blackhole", false)?;
    if mtu_blackhole && mtu == 0 {
        return Err(err("transport `mtu_blackhole` requires a non-zero `mtu`"));
    }
    let port_capacity = optional_u64(&b.attributes, "transport", "port_capacity", 0)?;
    let nat_source_ip = optional_string(&b.attributes, "transport", "nat_source_ip")?;
    let nat_source_port = b
        .attr("nat_source_port")
        .map(|value| match value {
            Value::Number(number)
                if number.is_finite()
                    && number.fract() == 0.0
                    && (1.0..=65535.0).contains(number) =>
            {
                Ok(*number as u32)
            }
            _ => Err(type_error(
                "transport",
                "nat_source_port",
                "port number 1–65535",
                value,
            )),
        })
        .transpose()?;
    let connect_failure = optional_string(&b.attributes, "transport", "connect_failure")?;
    if connect_failure
        .as_ref()
        .is_some_and(|failure| !matches!(failure.as_str(), "dns" | "refused" | "tls_handshake"))
    {
        return Err(err(
            "transport `connect_failure` must be dns, refused or tls_handshake",
        ));
    }
    let fault_steps = optional_string_array(&b.attributes, "transport", "fault_steps")?;
    let fault_flag = optional_string(&b.attributes, "transport", "fault_flag")?;
    let fault_when = b
        .children("fault_when")
        .next()
        .map(interpret_fault_predicate)
        .transpose()?;
    Ok(TransportConfig {
        loss_rate,
        delay_ms,
        reorder,
        seed,
        jitter_ms,
        bandwidth_bps,
        bandwidth_after_nth,
        bandwidth_after_bps,
        mtu,
        burst_loss,
        duplicate_rate,
        corrupt_rate,
        drop_nth,
        disconnect_nth,
        delay_spike_nth,
        delay_spike_ms,
        mtu_blackhole,
        port_capacity,
        nat_source_ip,
        nat_source_port,
        connect_failure,
        fault_steps,
        fault_flag,
        fault_when,
    })
}

fn interpret_fault_predicate(block: &Block) -> Result<FaultPredicate, ModelError> {
    validate_attributes(block, &["field", "equals"])?;
    validate_children(block, |_| false, "fault_when")?;
    let field = optional_string(&block.attributes, "fault_when", "field")?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| err("fault_when requires non-empty `field`"))?;
    let equals = block
        .attr("equals")
        .cloned()
        .ok_or_else(|| err("fault_when requires `equals`"))?;
    Ok(FaultPredicate { field, equals })
}

fn optional_probability(
    attributes: &HashMap<String, Value>,
    context: &str,
    key: &str,
) -> Result<f64, ModelError> {
    let value = match attributes.get(key) {
        None => 0.0,
        Some(Value::Number(value)) if value.is_finite() => *value,
        Some(value) => return Err(type_error(context, key, "number", value)),
    };
    if !(0.0..=1.0).contains(&value) {
        return Err(err(format!(
            "{context} `{key}` must be 0.0–1.0, got {value}"
        )));
    }
    Ok(value)
}
fn interpret_step(b: &Block) -> Result<Step, ModelError> {
    let name = b
        .labels
        .first()
        .cloned()
        .ok_or_else(|| err("step block needs a name label"))?;
    if b.labels.len() != 1 {
        return Err(err("step block requires exactly one name label"));
    }
    validate_attributes(
        b,
        &[
            "role",
            "action",
            "depends_on",
            "from_state",
            "to_state",
            "description",
            "to",
            "mode",
            "message",
            "retransmit",
            "when",
            "retry",
            "on_timeout",
            "loop",
            "retry_delay",
            "retry_max_delay",
            "retry_backoff",
            "retry_jitter",
            "retry_on",
            "segment",
            "expect",
            "timer",
            "assert",
            "set",
            "mtu",
            "fragment_id",
        ],
    )?;
    validate_children(
        b,
        |child| {
            matches!(
                child,
                "segment"
                    | "expect"
                    | "timer"
                    | "assert"
                    | "set"
                    | "plugin"
                    | "ethernet"
                    | "ipv4"
                    | "ipv6"
                    | "tcp"
                    | "udp"
            )
        },
        &format!("step `{name}`"),
    )?;
    for section in ["segment", "expect", "timer", "assert", "set", "plugin"] {
        ensure_single_child(b, section, &format!("step `{name}`"))?;
        if b.child(section).is_some() && b.attr(section).is_some() {
            return Err(err(format!(
                "step `{name}` defines `{section}` as both block and attribute"
            )));
        }
    }
    for section in ["ethernet", "ipv4", "ipv6", "tcp", "udp"] {
        ensure_single_child(b, section, &format!("step `{name}`"))?;
    }
    for child in &b.blocks {
        validate_children(
            child,
            |nested| child.name == "expect" && nested == "capture",
            &format!("{} section of step `{name}`", child.name),
        )?;
        if child.name == "expect" {
            ensure_single_child(
                child,
                "capture",
                &format!("expect section of step `{name}`"),
            )?;
        }
    }
    let role = b
        .attr_str("role")
        .ok_or_else(|| err(format!("step `{name}` is missing `role`")))?
        .to_string();
    let action_str = b
        .attr_str("action")
        .ok_or_else(|| err(format!("step `{name}` is missing `action`")))?;
    let action = parse_action(action_str)
        .ok_or_else(|| err(format!("step `{name}` has unknown action `{action_str}`")))?;
    let depends_on = match b.attr("depends_on") {
        None => Vec::new(),
        Some(value) => value.as_string_array().ok_or_else(|| {
            type_error(
                &format!("step `{name}`"),
                "depends_on",
                "array of strings",
                value,
            )
        })?,
    };
    let from_state = optional_string(&b.attributes, &context_for_step(&name), "from_state")?;
    let to_state = optional_string(&b.attributes, &context_for_step(&name), "to_state")?;
    for (key, value) in [("from_state", &from_state), ("to_state", &to_state)] {
        if value.as_ref().is_some_and(|value| value.trim().is_empty()) {
            return Err(err(format!("step `{name}` `{key}` must not be empty")));
        }
    }
    let description = optional_string(&b.attributes, &context_for_step(&name), "description")?;
    let to = optional_string(&b.attributes, &context_for_step(&name), "to")?;
    // `open`/`connect` default to active; `listen` defaults to passive.
    // An explicit `mode` attribute overrides either.
    let mode =
        optional_string(&b.attributes, &context_for_step(&name), "mode")?.unwrap_or_else(|| {
            (if action_str == "listen" {
                "passive"
            } else {
                "active"
            })
            .to_string()
        });
    if !matches!(mode.as_str(), "active" | "passive") {
        return Err(err(format!("step `{name}` mode must be active or passive")));
    }
    let message = optional_string(&b.attributes, &context_for_step(&name), "message")?;
    let context = format!("step `{name}`");
    let retransmit = optional_u32(&b.attributes, &context, "retransmit", 0)?;
    let when = b.attr("when").cloned();
    let retry = optional_u32(&b.attributes, &context, "retry", 0)?;
    let on_timeout = optional_bool(&b.attributes, &context, "on_timeout", false)?;
    let loop_count = optional_u32(&b.attributes, &context, "loop", 1)?;
    let retry_policy = interpret_retry_policy(&b.attributes, &context)?;
    let segment = section_attrs(b, "segment")?
        .map(interpret_segment)
        .transpose()?;
    let mut expect = section_attrs(b, "expect")?
        .map(interpret_expect)
        .transpose()?;
    if let Some(ref mut ex) = expect {
        ex.capture = extract_capture(b)?;
    }
    let timer = section_attrs(b, "timer")?
        .map(interpret_timer)
        .transpose()?;
    let assert = section_attrs(b, "assert")?.map(|a| Assert {
        attrs: resolve_hex_values(a),
    });
    let set = section_attrs(b, "set")?.map(|a| Set { vars: a.clone() });
    let plugin = b.child("plugin").map(interpret_plugin_spec).transpose()?;
    let raw_packet = interpret_raw_packet_spec(b, &name)?;

    validate_action_sections(
        &name,
        action,
        segment.is_some(),
        expect.is_some(),
        timer.is_some(),
        assert.is_some(),
        set.is_some(),
        raw_packet.is_some(),
        plugin.is_some(),
    )?;

    Ok(Step {
        name,
        role,
        action,
        depends_on,
        from_state,
        to_state,
        description,
        to,
        mode: Some(mode),
        message,
        segment,
        expect,
        timer,
        assert,
        set,
        plugin,
        raw_packet,
        retransmit,
        when,
        retry,
        on_timeout,
        loop_count,
        retry_policy,
        source: b.source.clone(),
        line: b.line,
        column: b.column,
    })
}

fn parse_action(s: &str) -> Option<Action> {
    match s {
        "send" => Some(Action::Send),
        "send_raw" => Some(Action::SendRaw),
        "recv" => Some(Action::Recv),
        "recv_raw" => Some(Action::RecvRaw),
        "ack" => Some(Action::Ack),
        "nack" => Some(Action::Nack),
        "wait" => Some(Action::Wait),
        "close" => Some(Action::Close),
        "open" | "connect" | "listen" => Some(Action::Open),
        "reset" | "abort" => Some(Action::Reset),
        "drop" => Some(Action::Drop),
        "duplicate" | "dup" => Some(Action::Duplicate),
        "corrupt" => Some(Action::Corrupt),
        "assert" | "check" => Some(Action::Assert),
        "set" => Some(Action::Set),
        "log" | "mark" => Some(Action::Log),
        "plugin" => Some(Action::Plugin),
        _ => None,
    }
}

fn interpret_plugin_spec(block: &Block) -> Result<PluginSpec, ModelError> {
    validate_attributes(block, &["manifest", "kind", "name", "input"])?;
    validate_children(block, |_| false, "plugin")?;
    let required = |key: &str| {
        optional_string(&block.attributes, "plugin", key)?
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| err(format!("plugin requires non-empty `{key}`")))
    };
    let manifest = required("manifest")?;
    let kind = required("kind")?;
    if !matches!(kind.as_str(), "action" | "matcher" | "decoder" | "report") {
        return Err(err(
            "plugin kind must be action, matcher, decoder or report",
        ));
    }
    let name = required("name")?;
    let input = block
        .attr("input")
        .cloned()
        .unwrap_or_else(|| Value::Object(HashMap::new()));
    Ok(PluginSpec {
        manifest,
        kind,
        name,
        input,
    })
}

/// Get a "section" (segment/expect/timer) as an attribute map, accepting both
/// the nested-block form (`segment { ... }`) and the object-attribute form
/// (`segment = { ... }`).
fn section_attrs<'a>(
    b: &'a Block,
    name: &str,
) -> Result<Option<&'a HashMap<String, Value>>, ModelError> {
    if let Some(c) = b.child(name) {
        return Ok(Some(&c.attributes));
    }
    match b.attr(name) {
        None => Ok(None),
        Some(Value::Object(object)) => Ok(Some(object)),
        Some(value) => Err(type_error("step section", name, "an object", value)),
    }
}

/// Extract the `capture` map from an `expect` section. Accepts both the
/// block form (`expect { capture { id = "txn_id" } }`) and the object form
/// (`expect = { capture = { id = "txn_id" } }`). Keys are message field
/// names; values are variable names to store under.
fn extract_capture(b: &Block) -> Result<HashMap<String, String>, ModelError> {
    let mut out = HashMap::new();
    // block form: look for expect -> capture child block
    if let Some(exp_block) = b.child("expect") {
        if let Some(cap_block) = exp_block.child("capture") {
            for (k, v) in &cap_block.attributes {
                let var_name = v
                    .as_str()
                    .ok_or_else(|| type_error("expect capture", k, "a string", v))?;
                out.insert(k.clone(), var_name.to_string());
            }
        }
    }
    // object form: look for expect attribute -> capture key
    if out.is_empty() {
        if let Some(Value::Object(exp_obj)) = b.attr("expect") {
            if let Some(Value::Object(cap_obj)) = exp_obj.get("capture") {
                for (k, v) in cap_obj {
                    let var_name = v
                        .as_str()
                        .ok_or_else(|| type_error("expect capture", k, "a string", v))?;
                    out.insert(k.clone(), var_name.to_string());
                }
            }
        }
    }
    Ok(out)
}

fn interpret_raw_packet_spec(
    block: &Block,
    step_name: &str,
) -> Result<Option<RawPacketSpec>, ModelError> {
    let section = |name: &str| block.child(name).map(|child| child.attributes.clone());
    let ethernet = section("ethernet");
    let ipv4 = section("ipv4");
    let ipv6 = section("ipv6");
    let tcp = section("tcp");
    let udp = section("udp");
    let present =
        ethernet.is_some() || ipv4.is_some() || ipv6.is_some() || tcp.is_some() || udp.is_some();
    if !present {
        if block.attr("mtu").is_some() || block.attr("fragment_id").is_some() {
            return Err(err(format!(
                "step `{step_name}` mtu/fragment_id require raw header blocks"
            )));
        }
        return Ok(None);
    }
    for (name, attributes, allowed) in [
        (
            "ethernet",
            ethernet.as_ref(),
            &[
                "source",
                "destination",
                "ether_type",
                "vlan_id",
                "vlan_priority",
                "vlan_drop_eligible",
            ][..],
        ),
        (
            "ipv4",
            ipv4.as_ref(),
            &[
                "source",
                "destination",
                "dscp",
                "ecn",
                "id",
                "dont_fragment",
                "more_fragments",
                "fragment_offset",
                "ttl",
                "protocol",
                "options",
                "ihl",
                "total_length",
                "checksum",
            ][..],
        ),
        (
            "ipv6",
            ipv6.as_ref(),
            &[
                "source",
                "destination",
                "traffic_class",
                "flow_label",
                "payload_length",
                "next_header",
                "hop_limit",
                "fragment_offset",
                "more_fragments",
                "fragment_id",
            ][..],
        ),
        (
            "tcp",
            tcp.as_ref(),
            &[
                "source_port",
                "destination_port",
                "seq",
                "ack",
                "flags",
                "window",
                "urgent_pointer",
                "options",
                "data_offset",
                "checksum",
            ][..],
        ),
        (
            "udp",
            udp.as_ref(),
            &["source_port", "destination_port", "length", "checksum"][..],
        ),
    ] {
        if let Some(attributes) = attributes {
            validate_map_keys(attributes, allowed, &format!("{name} header"))?;
        }
    }
    if ipv4.is_some() == ipv6.is_some() {
        return Err(err(format!(
            "step `{step_name}` raw packet requires exactly one of ipv4/ipv6"
        )));
    }
    if tcp.is_some() && udp.is_some() {
        return Err(err(format!(
            "step `{step_name}` raw packet cannot contain both tcp and udp"
        )));
    }
    let mtu = if block.attr("mtu").is_some() {
        Some(optional_usize(
            &block.attributes,
            &context_for_step(step_name),
            "mtu",
            0,
        )?)
    } else {
        None
    };
    if let Some(mtu) = mtu {
        let minimum = if ipv6.is_some() { 1280 } else { 68 };
        if mtu < minimum {
            return Err(err(format!(
                "step `{step_name}` MTU {mtu} is below the protocol minimum {minimum}"
            )));
        }
    }
    let fragment_id = optional_optional_u64(
        &block.attributes,
        &context_for_step(step_name),
        "fragment_id",
    )?
    .map(|value| {
        u32::try_from(value).map_err(|_| err(format!("step `{step_name}` fragment_id exceeds u32")))
    })
    .transpose()?;
    Ok(Some(RawPacketSpec {
        ethernet,
        ipv4,
        ipv6,
        tcp,
        udp,
        mtu,
        fragment_id,
    }))
}

/// Convert `{ hex = "aabb" }` objects in an attrs map to `Value::Bytes`,
/// so `assert { recv_field:id = { hex = "1234" } }` compares bytes to bytes.
fn resolve_hex_values(attrs: &HashMap<String, Value>) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    for (k, v) in attrs {
        let resolved = match v {
            Value::Object(o) if o.contains_key("hex") => {
                if let Some(hs) = o.get("hex").and_then(|x| x.as_str()) {
                    match crate::value::parse_hex(hs) {
                        Ok(bytes) => Value::Bytes(bytes),
                        Err(_) => v.clone(),
                    }
                } else {
                    v.clone()
                }
            }
            _ => v.clone(),
        };
        out.insert(k.clone(), resolved);
    }
    out
}

fn interpret_segment(attrs: &HashMap<String, Value>) -> Result<Segment, ModelError> {
    validate_map_keys(
        attrs,
        &[
            "flags",
            "seq",
            "ack",
            "payload",
            "hex",
            "payload_len",
            "window",
            "stream",
            "fields",
            "delay",
            "flip",
        ],
        "segment",
    )?;
    let hex = match attrs.get("hex") {
        Some(Value::String(s)) => {
            // Validate hex only if it has no ${var} tokens (those are parsed
            // at send time after interpolation).
            if !s.contains("${") {
                crate::value::parse_hex(s).map_err(|e| err(format!("segment `hex`: {e}")))?;
            }
            Some(s.clone())
        }
        Some(value) => return Err(type_error("segment", "hex", "a string", value)),
        None => None,
    };
    let fields = match attrs.get("fields") {
        Some(Value::Object(o)) => interpret_field_values(o)?,
        Some(value) => return Err(type_error("segment", "fields", "an object", value)),
        None => HashMap::new(),
    };
    let delay_ms = optional_duration(attrs, "segment", "delay", 0)?;
    let flip_bit = optional_optional_u64(attrs, "segment", "flip")?;
    Ok(Segment {
        flags: optional_string_array(attrs, "segment", "flags")?,
        seq: optional_optional_i64(attrs, "segment", "seq")?,
        ack: optional_optional_i64(attrs, "segment", "ack")?,
        payload: optional_string(attrs, "segment", "payload")?,
        hex,
        payload_len: optional_optional_i64(attrs, "segment", "payload_len")?,
        window: optional_optional_i64(attrs, "segment", "window")?,
        stream: optional_optional_i64(attrs, "segment", "stream")?,
        fields,
        delay_ms,
        flip_bit,
    })
}

fn interpret_expect(attrs: &HashMap<String, Value>) -> Result<Expect, ModelError> {
    validate_map_keys(
        attrs,
        &[
            "flags",
            "payload",
            "hex",
            "hex_contains",
            "from",
            "window",
            "stream",
            "fields",
            "capture",
        ],
        "expect",
    )?;
    let hex = match attrs.get("hex") {
        Some(Value::String(s)) => {
            Some(crate::value::parse_hex(s).map_err(|e| err(format!("expect `hex`: {e}")))?)
        }
        Some(value) => return Err(type_error("expect", "hex", "a string", value)),
        None => None,
    };
    let hex_contains = match attrs.get("hex_contains") {
        Some(Value::String(s)) => {
            let bytes = crate::value::parse_hex(s)
                .map_err(|e| err(format!("expect `hex_contains`: {e}")))?;
            if bytes.is_empty() {
                return Err(err("expect `hex_contains` must not be empty"));
            }
            Some(bytes)
        }
        Some(value) => return Err(type_error("expect", "hex_contains", "a string", value)),
        None => None,
    };
    let fields = match attrs.get("fields") {
        Some(Value::Object(o)) => interpret_field_matches(o)?,
        Some(value) => return Err(type_error("expect", "fields", "an object", value)),
        None => HashMap::new(),
    };
    Ok(Expect {
        flags: optional_string_array(attrs, "expect", "flags")?,
        payload: optional_string(attrs, "expect", "payload")?,
        hex,
        hex_contains,
        from: optional_string(attrs, "expect", "from")?,
        window: optional_optional_i64(attrs, "expect", "window")?,
        stream: optional_optional_i64(attrs, "expect", "stream")?,
        fields,
        capture: HashMap::new(),
    })
}

/// Interpret `fields` for an outbound segment: convert `hex = "aabb"` values
/// into `Value::Bytes`. If the hex string contains `${var}` tokens (not yet
/// resolvable at model time), store it as a deferred marker
/// `Value::String("__hex__:<hex>")` — resolved to bytes at send time by
/// [`resolve_deferred_hex`] after interpolation.
fn interpret_field_values(
    obj: &HashMap<String, Value>,
) -> Result<HashMap<String, Value>, ModelError> {
    let mut out = HashMap::new();
    for (k, v) in obj {
        let resolved = match v {
            Value::Object(o) if o.contains_key("hex") => {
                let hs = o
                    .get("hex")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| err(format!("field `{k}` hex must be a string")))?;
                if hs.contains("${") {
                    // Deferred: parse after ${var} interpolation at send time
                    Value::String(format!("__hex__:{hs}"))
                } else {
                    Value::Bytes(
                        crate::value::parse_hex(hs)
                            .map_err(|e| err(format!("field `{k}` hex: {e}")))?,
                    )
                }
            }
            other => other.clone(),
        };
        out.insert(k.clone(), resolved);
    }
    Ok(out)
}

fn interpret_timer(attrs: &HashMap<String, Value>) -> Result<Timer, ModelError> {
    validate_map_keys(attrs, &["timeout", "retransmit"], "timer")?;
    let timeout_ms = optional_duration(attrs, "timer", "timeout", 1000)?;
    let retransmit = optional_u32(attrs, "timer", "retransmit", 0)?;
    Ok(Timer {
        timeout_ms,
        retransmit,
    })
}

/// Parse a duration string like `"100ms"`, `"2s"`, `"500"` (ms implied).
pub fn parse_duration_ms(s: &str) -> Result<u64, ModelError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(err("empty duration"));
    }
    let (num_part, unit) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, ""),
    };
    let n: u64 = num_part
        .parse()
        .map_err(|_| err(format!("invalid duration number in `{s}`")))?;
    let mult: u64 = match unit.trim() {
        "" | "ms" => 1,
        "s" => 1000,
        other => {
            return Err(err(format!(
                "unknown duration unit `{other}` (use ms or s)"
            )))
        }
    };
    n.checked_mul(mult)
        .ok_or_else(|| err(format!("duration `{s}` overflows milliseconds")))
}

fn type_error(context: &str, key: &str, expected: &str, actual: &Value) -> ModelError {
    err(format!(
        "{context} `{key}` must be {expected}, got {}",
        actual.to_display()
    ))
}

fn optional_u32(
    attrs: &HashMap<String, Value>,
    context: &str,
    key: &str,
    default: u32,
) -> Result<u32, ModelError> {
    match attrs.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_u32()
            .ok_or_else(|| type_error(context, key, "a non-negative integer up to u32", value)),
    }
}

fn optional_u64(
    attrs: &HashMap<String, Value>,
    context: &str,
    key: &str,
    default: u64,
) -> Result<u64, ModelError> {
    match attrs.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| type_error(context, key, "a non-negative integer", value)),
    }
}

fn optional_optional_u64(
    attrs: &HashMap<String, Value>,
    context: &str,
    key: &str,
) -> Result<Option<u64>, ModelError> {
    attrs
        .get(key)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| type_error(context, key, "a non-negative integer", value))
        })
        .transpose()
}

fn optional_optional_i64(
    attrs: &HashMap<String, Value>,
    context: &str,
    key: &str,
) -> Result<Option<i64>, ModelError> {
    attrs
        .get(key)
        .map(|value| {
            value
                .as_i64()
                .ok_or_else(|| type_error(context, key, "an integer", value))
        })
        .transpose()
}

fn optional_string(
    attrs: &HashMap<String, Value>,
    context: &str,
    key: &str,
) -> Result<Option<String>, ModelError> {
    attrs
        .get(key)
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| type_error(context, key, "a string", value))
        })
        .transpose()
}

fn optional_string_array(
    attrs: &HashMap<String, Value>,
    context: &str,
    key: &str,
) -> Result<Vec<String>, ModelError> {
    match attrs.get(key) {
        None => Ok(Vec::new()),
        Some(value) => value
            .as_string_array()
            .ok_or_else(|| type_error(context, key, "an array of strings", value)),
    }
}

fn optional_bool(
    attrs: &HashMap<String, Value>,
    context: &str,
    key: &str,
    default: bool,
) -> Result<bool, ModelError> {
    match attrs.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| type_error(context, key, "a boolean", value)),
    }
}

fn optional_duration(
    attrs: &HashMap<String, Value>,
    context: &str,
    key: &str,
    default: u64,
) -> Result<u64, ModelError> {
    match attrs.get(key) {
        None => Ok(default),
        Some(Value::String(value)) => parse_duration_ms(value),
        Some(value) => Err(type_error(context, key, "a duration string", value)),
    }
}

fn interpret_limits(block: &Block) -> Result<ResourceLimits, ModelError> {
    validate_attributes(
        block,
        &[
            "max_inbox",
            "max_trace",
            "max_payload",
            "max_loop",
            "max_retry",
            "connect_timeout",
            "max_runtime",
        ],
    )?;
    validate_children(block, |_| false, "limits")?;
    let defaults = ResourceLimits::default();
    Ok(ResourceLimits {
        max_inbox: optional_usize(&block.attributes, "limits", "max_inbox", defaults.max_inbox)?,
        max_trace: optional_usize(&block.attributes, "limits", "max_trace", defaults.max_trace)?,
        max_payload: optional_usize(
            &block.attributes,
            "limits",
            "max_payload",
            defaults.max_payload,
        )?,
        max_loop: optional_u32(&block.attributes, "limits", "max_loop", defaults.max_loop)?,
        max_retry: optional_u32(&block.attributes, "limits", "max_retry", defaults.max_retry)?,
        connect_timeout_ms: optional_duration(
            &block.attributes,
            "limits",
            "connect_timeout",
            defaults.connect_timeout_ms,
        )?,
        max_runtime_ms: optional_duration(
            &block.attributes,
            "limits",
            "max_runtime",
            defaults.max_runtime_ms,
        )?,
    })
}

fn interpret_retry_policy(
    attrs: &HashMap<String, Value>,
    context: &str,
) -> Result<RetryPolicy, ModelError> {
    let defaults = RetryPolicy::default();
    let retry_on = match attrs.get("retry_on") {
        None => Vec::new(),
        Some(value) => value
            .as_string_array()
            .ok_or_else(|| type_error(context, "retry_on", "an array of failure names", value))?,
    };
    for kind in &retry_on {
        if !matches!(
            kind.as_str(),
            "timeout"
                | "transport"
                | "assertion"
                | "validation"
                | "resource_limit"
                | "panic"
                | "runtime"
        ) {
            return Err(err(format!(
                "{context} retry_on has unknown failure `{kind}`"
            )));
        }
    }
    let backoff = optional_f64(attrs, context, "retry_backoff", defaults.backoff)?;
    if backoff < 1.0 {
        return Err(err(format!("{context} retry_backoff must be >= 1.0")));
    }
    let jitter = optional_f64(attrs, context, "retry_jitter", defaults.jitter)?;
    if !(0.0..=1.0).contains(&jitter) {
        return Err(err(format!("{context} retry_jitter must be 0.0–1.0")));
    }
    Ok(RetryPolicy {
        initial_delay_ms: optional_duration(
            attrs,
            context,
            "retry_delay",
            defaults.initial_delay_ms,
        )?,
        max_delay_ms: optional_duration(attrs, context, "retry_max_delay", defaults.max_delay_ms)?,
        backoff,
        jitter,
        retry_on,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_action_sections(
    name: &str,
    action: Action,
    segment: bool,
    expect: bool,
    timer: bool,
    assert: bool,
    set: bool,
    raw_packet: bool,
    plugin: bool,
) -> Result<(), ModelError> {
    let allowed = match action {
        Action::Duplicate | Action::Corrupt | Action::Reset => (true, false, true, false, false),
        Action::Send | Action::Ack | Action::Nack => (true, true, true, false, false),
        Action::SendRaw => (true, false, true, false, false),
        Action::Recv | Action::RecvRaw | Action::Drop => (false, true, true, false, false),
        Action::Wait => (false, false, true, false, false),
        Action::Assert => (false, false, false, true, false),
        Action::Set => (false, false, false, false, true),
        Action::Open | Action::Close | Action::Log => (false, false, false, false, false),
        Action::Plugin => (false, false, false, false, false),
    };
    for (present, permitted, section) in [
        (segment, allowed.0, "segment"),
        (expect, allowed.1, "expect"),
        (timer, allowed.2, "timer"),
        (assert, allowed.3, "assert"),
        (set, allowed.4, "set"),
    ] {
        if present && !permitted {
            return Err(err(format!(
                "step `{name}` action `{}` does not allow `{section}`",
                action.as_str()
            )));
        }
    }
    if action == Action::Corrupt && !segment {
        return Err(err(format!("step `{name}` corrupt requires `segment`")));
    }
    if action == Action::Assert && !assert {
        return Err(err(format!(
            "step `{name}` assert requires `assert` section"
        )));
    }
    if action == Action::Set && !set {
        return Err(err(format!("step `{name}` set requires `set` section")));
    }
    if action == Action::SendRaw && !raw_packet {
        return Err(err(format!(
            "step `{name}` send_raw requires raw header blocks"
        )));
    }
    if action != Action::SendRaw && raw_packet {
        return Err(err(format!(
            "step `{name}` raw header blocks require action `send_raw`"
        )));
    }
    if action == Action::Plugin && !plugin {
        return Err(err(format!(
            "step `{name}` plugin requires `plugin` section"
        )));
    }
    if action != Action::Plugin && plugin {
        return Err(err(format!(
            "step `{name}` plugin section requires action `plugin`"
        )));
    }
    Ok(())
}

fn validate_attributes(block: &Block, allowed: &[&str]) -> Result<(), ModelError> {
    validate_map_keys(&block.attributes, allowed, &format!("{} block", block.name))
}

fn context_for_step(name: &str) -> String {
    format!("step `{name}`")
}

fn validate_top_level(blocks: &[Block]) -> Result<(), ModelError> {
    for block in blocks {
        if !matches!(
            block.name.as_str(),
            "protocol" | "cases" | "module" | "import" | "tcpform"
        ) {
            return Err(at_block(
                err(format!("unknown top-level block `{}`", block.name)),
                block,
            ));
        }
    }
    Ok(())
}

fn validate_map_keys(
    attributes: &HashMap<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), ModelError> {
    for key in attributes.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(err(format!("unknown attribute `{key}` in {context}")));
        }
    }
    Ok(())
}

fn validate_children(
    block: &Block,
    allowed: impl Fn(&str) -> bool,
    context: &str,
) -> Result<(), ModelError> {
    for child in &block.blocks {
        if !allowed(&child.name) {
            return Err(err(format!(
                "unknown child block `{}` in {context}",
                child.name
            )));
        }
    }
    Ok(())
}

fn ensure_single_child(block: &Block, name: &str, context: &str) -> Result<(), ModelError> {
    if block.children(name).count() > 1 {
        return Err(err(format!("duplicate `{name}` block in {context}")));
    }
    Ok(())
}

fn optional_usize(
    attrs: &HashMap<String, Value>,
    context: &str,
    key: &str,
    default: usize,
) -> Result<usize, ModelError> {
    match attrs.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|number| usize::try_from(number).ok())
            .filter(|number| *number > 0)
            .ok_or_else(|| type_error(context, key, "a positive platform-sized integer", value)),
    }
}

fn optional_f64(
    attrs: &HashMap<String, Value>,
    context: &str,
    key: &str,
    default: f64,
) -> Result<f64, ModelError> {
    match attrs.get(key) {
        None => Ok(default),
        Some(Value::Number(value)) if value.is_finite() => Ok(*value),
        Some(value) => Err(type_error(context, key, "a finite number", value)),
    }
}
