//! Deterministic, state-aware protocol fuzzing campaign orchestration.

use crate::model::{Action, Protocol};
use crate::{bytes_to_hex, parse_hex, TraceEvent};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};

#[derive(Debug, Clone)]
pub struct FuzzConfig {
    pub iterations: usize,
    pub seed: u64,
    pub max_input_bytes: usize,
    pub stop_on_crash: bool,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            iterations: 1_000,
            seed: 1,
            max_input_bytes: 1 << 20,
            stop_on_crash: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FuzzOutcome {
    Ok,
    Rejected,
    Hang,
    Crash,
}

#[derive(Debug, Clone)]
pub struct FuzzObservation {
    pub outcome: FuzzOutcome,
    pub trace: Vec<TraceEvent>,
    pub detail: Option<String>,
    /// Optional code-coverage identifiers supplied by an instrumented target.
    pub code_coverage: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Mutation {
    pub operator: String,
    pub step: String,
    pub offset: Option<usize>,
    pub before_hex: String,
    pub after_hex: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CorpusEntry {
    pub iteration: usize,
    pub signature: String,
    pub reason: String,
    pub mutations: Vec<Mutation>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub iteration: usize,
    pub outcome: FuzzOutcome,
    pub signature: String,
    pub detail: Option<String>,
    pub mutations: Vec<Mutation>,
    pub minimized_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FuzzReport {
    pub schema_version: &'static str,
    pub protocol: String,
    pub role: String,
    pub seed: u64,
    pub iterations: usize,
    pub executions: usize,
    pub state_coverage: usize,
    pub code_coverage: usize,
    pub corpus: Vec<CorpusEntry>,
    pub findings: Vec<Finding>,
}

pub fn run_campaign<F>(
    protocol: &Protocol,
    role: &str,
    config: &FuzzConfig,
    mut runner: F,
) -> Result<FuzzReport, String>
where
    F: FnMut(&Protocol) -> FuzzObservation,
{
    let send_indexes = fuzzable_steps(protocol, role)?;
    let mut rng = Rng(config.seed);
    let mut states = HashSet::new();
    let mut code = HashSet::new();
    let mut failures = HashSet::new();
    let mut corpus = Vec::new();
    let mut findings = Vec::new();
    let mut executions = 0;

    for iteration in 1..=config.iterations {
        let (mutant, mutations) =
            mutate_protocol(protocol, &send_indexes, &mut rng, config.max_input_bytes)?;
        let observation = runner(&mutant);
        executions += 1;
        let state_signature = observation_signature(&observation);
        let mut reasons = Vec::new();
        if states.insert(state_signature.clone()) {
            reasons.push("new_state");
        }
        let new_code = observation
            .code_coverage
            .iter()
            .filter(|item| code.insert((*item).clone()))
            .count();
        if new_code > 0 {
            reasons.push("new_code");
        }
        if !reasons.is_empty() {
            corpus.push(CorpusEntry {
                iteration,
                signature: state_signature.clone(),
                reason: reasons.join("+"),
                mutations: mutations.clone(),
            });
        }
        if matches!(observation.outcome, FuzzOutcome::Crash | FuzzOutcome::Hang) {
            let failure_signature = failure_signature(&observation);
            if failures.insert(failure_signature.clone()) {
                let minimized =
                    minimize_finding(&mutant, &send_indexes, &mut runner, &observation.outcome);
                let minimized_hex = minimized.as_ref().map(|(hex, _)| hex.clone());
                executions += minimized.as_ref().map_or(0, |(_, runs)| *runs);
                findings.push(Finding {
                    iteration,
                    outcome: observation.outcome.clone(),
                    signature: failure_signature,
                    detail: observation.detail,
                    mutations,
                    minimized_hex,
                });
            }
            if config.stop_on_crash && observation.outcome == FuzzOutcome::Crash {
                break;
            }
        }
    }
    Ok(FuzzReport {
        schema_version: "1.0",
        protocol: protocol.name.clone(),
        role: role.into(),
        seed: config.seed,
        iterations: config.iterations,
        executions,
        state_coverage: states.len(),
        code_coverage: code.len(),
        corpus,
        findings,
    })
}

fn fuzzable_steps(protocol: &Protocol, role: &str) -> Result<Vec<usize>, String> {
    if !protocol.steps.iter().any(|step| step.role == role) {
        return Err(format!("protocol `{}` has no role `{role}`", protocol.name));
    }
    let indexes = protocol
        .steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| {
            (step.role == role
                && matches!(step.action, Action::Send | Action::SendRaw)
                && step
                    .segment
                    .as_ref()
                    .is_some_and(|segment| segment.payload.is_some() || segment.hex.is_some()))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    if indexes.is_empty() {
        Err(format!(
            "protocol `{}` has no fuzzable sends for role `{role}`",
            protocol.name
        ))
    } else {
        Ok(indexes)
    }
}

fn mutate_protocol(
    protocol: &Protocol,
    indexes: &[usize],
    rng: &mut Rng,
    max_input: usize,
) -> Result<(Protocol, Vec<Mutation>), String> {
    let mut mutant = protocol.clone();
    let count = 1 + rng.usize(3.min(indexes.len().max(1)));
    let mut mutations = Vec::new();
    for _ in 0..count {
        let index = indexes[rng.usize(indexes.len())];
        let splice = if indexes.len() > 1 {
            let other = indexes[rng.usize(indexes.len())];
            Some(segment_bytes(
                mutant.steps[other].segment.as_ref().unwrap(),
                &mutant.steps[other].name,
            )?)
        } else {
            None
        };
        let step = &mut mutant.steps[index];
        let segment = step.segment.as_mut().unwrap();
        let mut bytes = segment_bytes(segment, &step.name)?;
        let before = bytes_to_hex(&bytes);
        let mut offset = None;
        let operator = match rng.usize(7) {
            0 if !bytes.is_empty() => {
                let at = rng.usize(bytes.len());
                offset = Some(at);
                bytes[at] ^= 1 << rng.usize(8);
                "flip_bit"
            }
            1 if !bytes.is_empty() => {
                let at = rng.usize(bytes.len());
                offset = Some(at);
                bytes[at] = [0, 1, 0x7f, 0x80, 0xfe, 0xff][rng.usize(6)];
                "boundary"
            }
            2 if bytes.len() < max_input => {
                let at = rng.usize(bytes.len() + 1);
                offset = Some(at);
                bytes.insert(at, rng.byte());
                "insert_byte"
            }
            3 if !bytes.is_empty() => {
                let at = rng.usize(bytes.len());
                offset = Some(at);
                bytes.remove(at);
                "delete_byte"
            }
            4 => {
                bytes.clear();
                "delete_message"
            }
            5 => {
                step.loop_count = step.loop_count.saturating_add(1).max(2);
                "duplicate_message"
            }
            _ if splice.is_some() => {
                bytes = splice.unwrap();
                "splice_message"
            }
            _ => {
                bytes.push(rng.byte());
                "append_byte"
            }
        };
        if bytes.len() > max_input {
            bytes.truncate(max_input);
        }
        set_segment_bytes(segment, bytes.clone());
        mutations.push(Mutation {
            operator: operator.into(),
            step: step.name.clone(),
            offset,
            before_hex: before,
            after_hex: bytes_to_hex(&bytes),
        });
    }
    Ok((mutant, mutations))
}

fn segment_bytes(segment: &crate::Segment, step: &str) -> Result<Vec<u8>, String> {
    if let Some(hex) = &segment.hex {
        if hex.contains("${") {
            return Err(format!("step `{step}` contains interpolated hex"));
        }
        parse_hex(hex).map_err(|error| format!("step `{step}`: {error}"))
    } else if let Some(payload) = &segment.payload {
        if payload.contains("${") {
            return Err(format!("step `{step}` contains interpolated payload"));
        }
        Ok(payload.as_bytes().to_vec())
    } else {
        Ok(Vec::new())
    }
}

fn set_segment_bytes(segment: &mut crate::Segment, bytes: Vec<u8>) {
    segment.payload = None;
    segment.hex = Some(bytes_to_hex(&bytes));
    segment.payload_len = Some(bytes.len() as i64);
}

fn observation_signature(observation: &FuzzObservation) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}", observation.outcome));
    for event in &observation.trace {
        hasher.update(event.role.as_bytes());
        hasher.update([0]);
        hasher.update(event.step.as_bytes());
        hasher.update([event.ok as u8]);
        hasher.update(&event.wire_data);
    }
    for item in &observation.code_coverage {
        hasher.update(item.as_bytes());
        hasher.update([0]);
    }
    bytes_to_hex(&hasher.finalize())
}

fn failure_signature(observation: &FuzzObservation) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}", observation.outcome));
    hasher.update(observation.detail.as_deref().unwrap_or("").as_bytes());
    bytes_to_hex(&hasher.finalize())
}

fn minimize_finding<F>(
    protocol: &Protocol,
    indexes: &[usize],
    runner: &mut F,
    expected: &FuzzOutcome,
) -> Option<(String, usize)>
where
    F: FnMut(&Protocol) -> FuzzObservation,
{
    let index = *indexes.first()?;
    let original = segment_bytes(
        protocol.steps[index].segment.as_ref()?,
        &protocol.steps[index].name,
    )
    .ok()?;
    if original.is_empty() {
        return None;
    }
    let mut runs = 0usize;
    let minimized = minimize_bytes(&original, |candidate| {
        runs += 1;
        let mut attempt = protocol.clone();
        set_segment_bytes(
            attempt.steps[index].segment.as_mut().unwrap(),
            candidate.to_vec(),
        );
        runner(&attempt).outcome == *expected
    });
    Some((bytes_to_hex(&minimized), runs))
}

/// Delta-debug a failure-inducing byte string while preserving the predicate.
pub fn minimize_bytes<F>(input: &[u8], mut preserves: F) -> Vec<u8>
where
    F: FnMut(&[u8]) -> bool,
{
    let mut current = input.to_vec();
    let mut granularity = 2;
    while current.len() >= 2 {
        let chunk = current.len().div_ceil(granularity);
        let mut reduced = false;
        for start in (0..current.len()).step_by(chunk) {
            let end = (start + chunk).min(current.len());
            let mut candidate = current[..start].to_vec();
            candidate.extend_from_slice(&current[end..]);
            if preserves(&candidate) {
                current = candidate;
                granularity = 2;
                reduced = true;
                break;
            }
        }
        if !reduced {
            if granularity >= current.len() {
                break;
            }
            granularity = (granularity * 2).min(current.len());
        }
    }
    current
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn usize(&mut self, upper: usize) -> usize {
        if upper == 0 {
            0
        } else {
            self.next() as usize % upper
        }
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protocol() -> Protocol {
        crate::model::interpret(
            &crate::parse_file(
                r#"protocol "p" {
          step "hello" { role="client" action="send" segment { payload="HELLO" } }
          step "peer" { role="server" action="recv" expect { payload="HELLO" } }
          step "again" { role="client" action="send" segment { hex="010203" } }
        }"#,
            )
            .unwrap(),
        )
        .unwrap()
        .remove(0)
    }

    #[test]
    fn campaign_is_deterministic_and_retains_novel_states_and_crashes() {
        let config = FuzzConfig {
            iterations: 20,
            seed: 42,
            max_input_bytes: 64,
            stop_on_crash: false,
        };
        let run = |candidate: &Protocol| {
            let bytes =
                segment_bytes(candidate.steps[0].segment.as_ref().unwrap(), "hello").unwrap();
            FuzzObservation {
                outcome: if bytes.contains(&0xff) {
                    FuzzOutcome::Crash
                } else {
                    FuzzOutcome::Ok
                },
                trace: Vec::new(),
                detail: (bytes.contains(&0xff)).then(|| "signal 11".into()),
                code_coverage: BTreeSet::from([format!("len:{}", bytes.len())]),
            }
        };
        let left = run_campaign(&protocol(), "client", &config, run).unwrap();
        let right = run_campaign(&protocol(), "client", &config, run).unwrap();
        assert_eq!(left.corpus, right.corpus);
        assert!(left.state_coverage > 0);
        assert!(left.code_coverage > 0);
    }

    #[test]
    fn delta_debugging_removes_irrelevant_bytes() {
        let minimized = minimize_bytes(b"prefixCRASHsuffix", |bytes| {
            bytes.windows(5).any(|part| part == b"CRASH")
        });
        assert_eq!(minimized, b"CRASH");
    }
}
