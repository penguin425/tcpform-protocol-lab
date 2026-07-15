//! The execution engine. Runs a validated [`Plan`](crate::graph::Plan) by
//! spawning one thread per role; each role executes its steps in plan order,
//! blocking on explicit `depends_on` for cross-role synchronization, and exchanging [`Message`]s
//! over the simulated [`Transport`]. Produces a timestamped [`TraceEvent`]
//! timeline.

use crate::graph;
use crate::model::{Action, Case, CaseOutcome, ClockMode, Expect, Protocol, RawPacketSpec, Step};
use crate::packet::{
    self, Checksum, EthernetHeader, Ipv4Header, Ipv6Fragment, Ipv6Header, MacAddr, NetworkHeader,
    Packet, TcpHeader, TcpOption, TransportHeader, UdpHeader, VlanTag,
};
use crate::primitives::Message;
use crate::raw_socket::RawSocketConfig;
use crate::transport::{
    Framing, Inbox, NetworkProtocol, TlsOptions, Transport, TransportErrorKind, UdpOptions,
    WebSocketOptions,
};
use crate::value::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Default wait for a `recv` when no `timer` block is present. Keeps
/// simulations from hanging forever on a mis-ordered protocol.
const DEFAULT_RECV_TIMEOUT_MS: u64 = 2000;

/// One line of the execution timeline.
#[derive(Debug, Clone)]
pub struct TraceEvent {
    /// Global monotonic counter used to sort the final timeline.
    pub seq: u64,
    pub role: String,
    pub step: String,
    pub action: Action,
    pub ok: bool,
    pub detail: String,
    pub flags: Vec<String>,
    pub seq_num: Option<i64>,
    pub ack_num: Option<i64>,
    pub peer: Option<String>,
    /// Application bytes carried by this wire event. Text payloads are UTF-8;
    /// binary segments retain their exact bytes.
    pub wire_data: Vec<u8>,
    pub timestamp_us: u64,
    /// Monotonic nanoseconds since this engine run started.
    pub timestamp_ns: u128,
    pub network: NetworkProtocol,
}

pub type TraceObserver = Arc<dyn Fn(&TraceEvent) + Send + Sync>;

#[derive(Debug)]
pub enum EngineError {
    Plan(String),
    Runtime {
        kind: FailureKind,
        message: String,
        trace: Vec<TraceEvent>,
        assertion_failures: Vec<AssertionFailure>,
    },
}

/// Stable machine-readable failure classification used by retry policies,
/// case reports and JSON output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    Timeout,
    Transport,
    Assertion,
    Validation,
    ResourceLimit,
    Panic,
    Runtime,
}

impl FailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::Assertion => "assertion",
            Self::Validation => "validation",
            Self::ResourceLimit => "resource_limit",
            Self::Panic => "panic",
            Self::Runtime => "runtime",
        }
    }
}

#[derive(Debug, Clone)]
struct StepFailure {
    kind: FailureKind,
    message: String,
    assertion_failures: Vec<AssertionFailure>,
}

impl StepFailure {
    fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            assertion_failures: Vec::new(),
        }
    }

    fn assertion(message: String, assertion_failures: Vec<AssertionFailure>) -> Self {
        Self {
            kind: FailureKind::Assertion,
            message,
            assertion_failures,
        }
    }

    fn timeout(message: impl Into<String>) -> Self {
        Self::new(FailureKind::Timeout, message)
    }
}

impl From<String> for StepFailure {
    fn from(message: String) -> Self {
        Self::new(FailureKind::Runtime, message)
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Plan(m) => write!(f, "{m}"),
            EngineError::Runtime { message, .. } => write!(f, "runtime error: {message}"),
        }
    }
}

impl std::error::Error for EngineError {}

/// A ready-to-run protocol simulator.
#[derive(Debug)]
pub struct Engine {
    protocol: Protocol,
    plan: graph::Plan,
    allow_plugins: bool,
}

impl Engine {
    /// Build an engine, validating the protocol's dependency graph up front.
    pub fn new(protocol: Protocol) -> Result<Engine, EngineError> {
        let plan = graph::plan(&protocol).map_err(|e| EngineError::Plan(e.to_string()))?;
        for step in &protocol.steps {
            if let Some(spec) = &step.raw_packet {
                if !raw_spec_contains_variable(spec) {
                    build_raw_packets(spec, &HashMap::new(), Vec::new()).map_err(|error| {
                        EngineError::Plan(format!(
                            "step `{}` has an invalid raw packet: {}",
                            step.name, error.message
                        ))
                    })?;
                }
            }
        }
        Ok(Engine {
            protocol,
            plan,
            allow_plugins: false,
        })
    }

    /// Explicitly authorize process-isolated plugin execution for this engine.
    pub fn with_plugins_enabled(mut self, enabled: bool) -> Self {
        self.allow_plugins = enabled;
        self
    }

    pub fn plan(&self) -> &graph::Plan {
        &self.plan
    }

    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    /// Execute the protocol, returning the sorted event timeline.
    pub fn run(&self) -> Result<Vec<TraceEvent>, EngineError> {
        self.run_with_vars(&HashMap::new()).map(|r| r.0)
    }

    /// Execute the in-memory protocol while reporting every event immediately
    /// after it is recorded. The observer may be called concurrently by role
    /// workers and must therefore be thread safe.
    pub fn run_with_observer(
        &self,
        observer: TraceObserver,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        let roles = self.plan.roles.clone();
        let transport_config = self.protocol.transport.clone().unwrap_or_default();
        let transport = Transport::with_options(
            &roles,
            &transport_config,
            &self.protocol.limits,
            self.protocol.clock == ClockMode::Virtual,
        );
        self.run_with_transport(
            &HashMap::new(),
            roles.clone(),
            roles,
            transport,
            Some(observer),
        )
        .map(|result| result.0)
    }

    /// Execute the protocol with initial variables injected into every role's
    /// variable map. Returns the sorted event timeline and the final
    /// per-role states.
    pub fn run_with_vars(
        &self,
        initial_vars: &HashMap<String, Value>,
    ) -> Result<(Vec<TraceEvent>, HashMap<String, RoleState>), EngineError> {
        let roles = self.plan.roles.clone();
        let transport_config = self.protocol.transport.clone().unwrap_or_default();
        let transport = Transport::with_options(
            &roles,
            &transport_config,
            &self.protocol.limits,
            self.protocol.clock == ClockMode::Virtual,
        );
        self.run_with_transport(initial_vars, roles.clone(), roles, transport, None)
    }

    /// Execute over actual loopback TCP or UDP sockets instead of the
    /// in-memory transport. Live mode requires exactly two protocol roles.
    pub fn run_live(&self, bind: &str, udp: bool) -> Result<Vec<TraceEvent>, EngineError> {
        self.run_live_with_optional_observer(bind, udp, None)
    }

    pub fn run_live_with_observer(
        &self,
        bind: &str,
        udp: bool,
        observer: TraceObserver,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        self.run_live_with_optional_observer(bind, udp, Some(observer))
    }

    fn run_live_with_optional_observer(
        &self,
        bind: &str,
        udp: bool,
        observer: Option<TraceObserver>,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        let roles = self.plan.roles.clone();
        let transport = Transport::live_with_limits(&roles, bind, udp, &self.protocol.limits)
            .map_err(|message| EngineError::Runtime {
                kind: FailureKind::Transport,
                message,
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            })?;
        self.run_with_transport(&HashMap::new(), roles.clone(), roles, transport, observer)
            .map(|result| result.0)
    }

    /// Execute only `local_role` against an external TCP endpoint. The other
    /// protocol role names the peer and its steps are treated as externally
    /// fulfilled. Segment payload/hex bytes are sent without tcpform framing.
    pub fn run_external_tcp(
        &self,
        local_role: &str,
        address: &str,
        listen: bool,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        self.run_external_tcp_framed(local_role, address, listen, Framing::Raw)
    }

    pub fn run_external_tcp_framed(
        &self,
        local_role: &str,
        address: &str,
        listen: bool,
        framing: Framing,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        let roles = self.plan.roles.clone();
        if roles.len() != 2 {
            return Err(EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!(
                    "external TCP mode requires exactly 2 protocol roles, got {}",
                    roles.len()
                ),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            });
        }
        let peer_role = roles
            .iter()
            .find(|role| role.as_str() != local_role)
            .ok_or_else(|| EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!("role `{local_role}` not found in protocol"),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            })?
            .clone();
        let transport = Transport::external_tcp_framed(
            &roles,
            local_role,
            &peer_role,
            address,
            listen,
            &self.protocol.limits,
            framing,
        )
        .map_err(|message| EngineError::Runtime {
            kind: FailureKind::Transport,
            message,
            trace: Vec::new(),
            assertion_failures: Vec::new(),
        })?;
        self.run_with_transport(
            &HashMap::new(),
            roles,
            vec![local_role.to_string()],
            transport,
            None,
        )
        .map(|result| result.0)
    }

    #[cfg(unix)]
    pub fn run_external_unix(
        &self,
        local_role: &str,
        path: &str,
        listen: bool,
        framing: Framing,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        let roles = self.plan.roles.clone();
        if roles.len() != 2 {
            return Err(EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!(
                    "external Unix socket mode requires exactly 2 protocol roles, got {}",
                    roles.len()
                ),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            });
        }
        let peer_role = roles
            .iter()
            .find(|role| role.as_str() != local_role)
            .ok_or_else(|| EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!("role `{local_role}` not found in protocol"),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            })?
            .clone();
        let transport = Transport::external_unix_framed(
            &roles,
            local_role,
            &peer_role,
            path,
            listen,
            &self.protocol.limits,
            framing,
        )
        .map_err(|message| EngineError::Runtime {
            kind: FailureKind::Transport,
            message,
            trace: Vec::new(),
            assertion_failures: Vec::new(),
        })?;
        self.run_with_transport(
            &HashMap::new(),
            roles,
            vec![local_role.to_string()],
            transport,
            None,
        )
        .map(|result| result.0)
    }

    pub fn run_external_websocket(
        &self,
        local_role: &str,
        endpoint: &str,
        listen: bool,
        options: &WebSocketOptions,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        let roles = self.plan.roles.clone();
        if roles.len() != 2 {
            return Err(EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!(
                    "external WebSocket mode requires exactly 2 protocol roles, got {}",
                    roles.len()
                ),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            });
        }
        let peer_role = roles
            .iter()
            .find(|role| role.as_str() != local_role)
            .ok_or_else(|| EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!("role `{local_role}` not found in protocol"),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            })?
            .clone();
        let transport = Transport::external_websocket(
            &roles,
            local_role,
            &peer_role,
            endpoint,
            listen,
            &self.protocol.limits,
            options,
        )
        .map_err(|message| EngineError::Runtime {
            kind: FailureKind::Transport,
            message,
            trace: Vec::new(),
            assertion_failures: Vec::new(),
        })?;
        self.run_with_transport(
            &HashMap::new(),
            roles,
            vec![local_role.into()],
            transport,
            None,
        )
        .map(|result| result.0)
    }

    pub fn run_external_quic(
        &self,
        local_role: &str,
        address: &str,
        listen: bool,
        options: &TlsOptions,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        let roles = self.plan.roles.clone();
        if roles.len() != 2 {
            return Err(EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!(
                    "external QUIC mode requires exactly 2 protocol roles, got {}",
                    roles.len()
                ),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            });
        }
        let peer = roles
            .iter()
            .find(|role| role.as_str() != local_role)
            .ok_or_else(|| EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!("role `{local_role}` not found in protocol"),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            })?
            .clone();
        let transport = Transport::external_quic(
            &roles,
            local_role,
            &peer,
            address,
            listen,
            &self.protocol.limits,
            options,
        )
        .map_err(|message| EngineError::Runtime {
            kind: FailureKind::Transport,
            message,
            trace: Vec::new(),
            assertion_failures: Vec::new(),
        })?;
        self.run_with_transport(
            &HashMap::new(),
            roles,
            vec![local_role.into()],
            transport,
            None,
        )
        .map(|result| result.0)
    }

    pub fn run_external_udp(
        &self,
        local_role: &str,
        address: &str,
        listen: bool,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        self.run_external_udp_with_options(local_role, address, listen, &UdpOptions::default())
    }

    pub fn run_external_udp_with_options(
        &self,
        local_role: &str,
        address: &str,
        listen: bool,
        options: &UdpOptions,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        let roles = self.plan.roles.clone();
        if roles.len() != 2 {
            return Err(EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!(
                    "external UDP mode requires exactly 2 protocol roles, got {}",
                    roles.len()
                ),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            });
        }
        let peer_role = roles
            .iter()
            .find(|role| role.as_str() != local_role)
            .ok_or_else(|| EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!("role `{local_role}` not found in protocol"),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            })?
            .clone();
        let transport = Transport::external_udp_with_options(
            &roles,
            local_role,
            &peer_role,
            address,
            listen,
            &self.protocol.limits,
            options,
        )
        .map_err(|message| EngineError::Runtime {
            kind: FailureKind::Transport,
            message,
            trace: Vec::new(),
            assertion_failures: Vec::new(),
        })?;
        self.run_with_transport(
            &HashMap::new(),
            roles,
            vec![local_role.to_string()],
            transport,
            None,
        )
        .map(|result| result.0)
    }

    /// Execute one role using complete Ethernet frames on an AF_PACKET socket.
    pub fn run_external_raw(
        &self,
        local_role: &str,
        config: RawSocketConfig,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        self.run_external_raw_with_optional_observer(local_role, config, None)
    }

    pub fn run_external_raw_with_observer(
        &self,
        local_role: &str,
        config: RawSocketConfig,
        observer: TraceObserver,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        self.run_external_raw_with_optional_observer(local_role, config, Some(observer))
    }

    fn run_external_raw_with_optional_observer(
        &self,
        local_role: &str,
        config: RawSocketConfig,
        observer: Option<TraceObserver>,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        let roles = self.plan.roles.clone();
        if roles.len() != 2 {
            return Err(EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!(
                    "external raw mode requires exactly 2 protocol roles, got {}",
                    roles.len()
                ),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            });
        }
        if let Some(step) = self.protocol.steps.iter().find(|step| {
            step.role == local_role
                && step.action == Action::SendRaw
                && step
                    .raw_packet
                    .as_ref()
                    .is_some_and(|spec| spec.ethernet.is_none())
        }) {
            return Err(EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!(
                    "raw interface mode requires an ethernet block on outbound step `{}`",
                    step.name
                ),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            });
        }
        if !config.allow_host_tcp {
            if let Some(step) = self.protocol.steps.iter().find(|step| {
                step.role == local_role
                    && step.action == Action::SendRaw
                    && step
                        .raw_packet
                        .as_ref()
                        .is_some_and(|spec| spec.tcp.is_some())
            }) {
                return Err(EngineError::Runtime {
                    kind: FailureKind::Validation,
                    message: format!(
                        "raw TCP step `{}` is blocked by default because the host TCP stack may emit competing RST/ACK packets; use an isolated network namespace or unassigned source address, then pass --allow-host-tcp to acknowledge the risk",
                        step.name
                    ),
                    trace: Vec::new(),
                    assertion_failures: Vec::new(),
                });
            }
        }
        let peer_role = roles
            .iter()
            .find(|role| role.as_str() != local_role)
            .ok_or_else(|| EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!("role `{local_role}` not found in protocol"),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            })?
            .clone();
        let transport = Transport::external_raw(
            &roles,
            local_role,
            &peer_role,
            config,
            &self.protocol.limits,
        )
        .map_err(|message| EngineError::Runtime {
            kind: FailureKind::Transport,
            message,
            trace: Vec::new(),
            assertion_failures: Vec::new(),
        })?;
        self.run_with_transport(
            &HashMap::new(),
            roles,
            vec![local_role.to_string()],
            transport,
            observer,
        )
        .map(|result| result.0)
    }

    pub fn run_external_tls(
        &self,
        local_role: &str,
        address: &str,
        listen: bool,
        framing: Framing,
        options: &TlsOptions,
    ) -> Result<Vec<TraceEvent>, EngineError> {
        let roles = self.plan.roles.clone();
        if roles.len() != 2 {
            return Err(EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!(
                    "external TLS mode requires exactly 2 protocol roles, got {}",
                    roles.len()
                ),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            });
        }
        let peer_role = roles
            .iter()
            .find(|role| role.as_str() != local_role)
            .ok_or_else(|| EngineError::Runtime {
                kind: FailureKind::Validation,
                message: format!("role `{local_role}` not found in protocol"),
                trace: Vec::new(),
                assertion_failures: Vec::new(),
            })?
            .clone();
        let transport = Transport::external_tls(
            &roles,
            local_role,
            &peer_role,
            address,
            listen,
            &self.protocol.limits,
            framing,
            options,
        )
        .map_err(|message| EngineError::Runtime {
            kind: FailureKind::Transport,
            message,
            trace: Vec::new(),
            assertion_failures: Vec::new(),
        })?;
        self.run_with_transport(
            &HashMap::new(),
            roles,
            vec![local_role.to_string()],
            transport,
            None,
        )
        .map(|result| result.0)
    }

    fn run_with_transport(
        &self,
        initial_vars: &HashMap<String, Value>,
        roles: Vec<String>,
        active_roles: Vec<String>,
        transport: Transport,
        observer: Option<TraceObserver>,
    ) -> Result<(Vec<TraceEvent>, HashMap<String, RoleState>), EngineError> {
        let network = transport.network_protocol();
        let sim = Arc::new(Sim {
            transport,
            completed: Arc::new((
                Mutex::new(
                    self.plan
                        .order
                        .iter()
                        .filter(|planned| !active_roles.contains(&planned.step.role))
                        .map(|planned| planned.step.name.clone())
                        .collect(),
                ),
                Condvar::new(),
            )),
            trace: Arc::new(Mutex::new(Vec::new())),
            error: Arc::new(Mutex::new(None)),
            counter: Arc::new(AtomicU64::new(0)),
            all_roles: roles.clone(),
            clock: self.protocol.clock,
            started: Instant::now(),
            virtual_ms: Arc::new(AtomicU64::new(0)),
            max_trace: self.protocol.limits.max_trace,
            max_payload: self.protocol.limits.max_payload,
            max_inbox: self.protocol.limits.max_inbox,
            max_runtime_ms: self.protocol.limits.max_runtime_ms,
            raw_tcp_stateful: self.protocol.raw_tcp_stateful,
            network,
            observer,
            allow_plugins: self.allow_plugins,
        });

        // Per-role ordered step lists (plan order restricted to the role ==
        // declaration order, since within-role steps are implicitly chained).
        let mut role_steps: HashMap<String, Vec<Step>> = HashMap::new();
        for ps in &self.plan.order {
            role_steps
                .entry(ps.step.role.clone())
                .or_default()
                .push(ps.step.clone());
        }

        let mut handles = Vec::new();
        for role in &active_roles {
            let steps = role_steps.remove(role).unwrap_or_default();
            let sim = Arc::clone(&sim);
            let role = role.clone();
            let vars = initial_vars.clone();
            handles.push(thread::spawn(move || run_role(&sim, &role, steps, vars)));
        }
        let mut final_states = HashMap::new();
        for (role, h) in active_roles.iter().zip(handles) {
            match h.join() {
                Ok(state) => {
                    final_states.insert(role.clone(), state);
                }
                Err(payload) => {
                    let detail = if let Some(message) = payload.downcast_ref::<&str>() {
                        (*message).to_string()
                    } else if let Some(message) = payload.downcast_ref::<String>() {
                        message.clone()
                    } else {
                        "unknown panic payload".to_string()
                    };
                    sim.set_failure(
                        role,
                        FailureKind::Panic,
                        format!("executor panicked: {detail}"),
                    );
                }
            }
        }
        if let Err(message) = sim.transport.finish() {
            let kind = match message.kind {
                TransportErrorKind::Transport => FailureKind::Transport,
                TransportErrorKind::ResourceLimit => FailureKind::ResourceLimit,
            };
            sim.set_failure("transport", kind, message.message);
        }

        let mut sorted = sim.trace.lock().unwrap().clone();
        sorted.sort_by_key(|e| e.seq);

        let err_opt = sim.error.lock().unwrap().clone();
        match err_opt {
            Some((role, kind, msg, assertion_failures)) => Err(EngineError::Runtime {
                kind,
                message: format!("[role {role}] {msg}"),
                trace: sorted,
                assertion_failures,
            }),
            None => Ok((sorted, final_states)),
        }
    }

    /// Run a data-driven test suite. Each case runs the protocol with its own
    /// initial variables; the outcome (pass/fail) and per-role post-run
    /// assertions are checked against the expected values. Returns one
    /// [`CaseResult`] per case.
    pub fn run_cases(&self, cases: &[Case]) -> Vec<CaseResult> {
        cases.iter().map(|case| self.run_case(case)).collect()
    }

    /// Run independent cases concurrently while preserving declaration order
    /// in the returned results. A zero worker count is treated as one.
    pub fn run_cases_parallel(&self, cases: &[Case], jobs: usize) -> Vec<CaseResult> {
        if cases.len() <= 1 || jobs <= 1 {
            return self.run_cases(cases);
        }
        let next = AtomicUsize::new(0);
        let results = Mutex::new(vec![None; cases.len()]);
        thread::scope(|scope| {
            for _ in 0..jobs.min(cases.len()) {
                scope.spawn(|| loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(case) = cases.get(index) else {
                        break;
                    };
                    results.lock().unwrap()[index] = Some(self.run_case(case));
                });
            }
        });
        results
            .into_inner()
            .unwrap()
            .into_iter()
            .map(|result| result.expect("every selected case has one worker result"))
            .collect()
    }

    fn run_case(&self, case: &Case) -> CaseResult {
        let (run_outcome, failure_kind, error, trace, assertion_failures) =
            match self.run_with_vars(&case.vars) {
                Ok((trace, final_states)) => {
                    let failures = check_case_asserts(&final_states, &case.expect.asserts);
                    let outcome = if failures.is_empty() {
                        CaseOutcome::Pass
                    } else {
                        CaseOutcome::Fail
                    };
                    let kind = (!failures.is_empty()).then_some(FailureKind::Assertion);
                    (outcome, kind, None, trace, failures)
                }
                Err(EngineError::Runtime {
                    kind,
                    message,
                    trace,
                    assertion_failures,
                }) => (
                    CaseOutcome::Fail,
                    Some(kind),
                    Some(message),
                    trace,
                    assertion_failures,
                ),
                Err(error) => (
                    CaseOutcome::Fail,
                    Some(FailureKind::Validation),
                    Some(error.to_string()),
                    Vec::new(),
                    Vec::new(),
                ),
            };
        let passed = run_outcome == case.expect.outcome;
        CaseResult {
            name: case.name.clone(),
            tags: case.tags.clone(),
            expected: case.expect.outcome,
            actual: run_outcome,
            passed,
            failure_kind,
            error,
            trace,
            assertion_failures,
        }
    }
}

/// The result of running a single data-driven test case.
#[derive(Debug, Clone)]
pub struct CaseResult {
    pub name: String,
    pub tags: Vec<String>,
    pub expected: CaseOutcome,
    pub actual: CaseOutcome,
    pub passed: bool,
    pub failure_kind: Option<FailureKind>,
    pub error: Option<String>,
    pub trace: Vec<TraceEvent>,
    pub assertion_failures: Vec<AssertionFailure>,
}

#[derive(Debug, Clone)]
pub struct AssertionFailure {
    pub role: String,
    pub key: String,
    pub expected: Value,
    pub actual: Option<Value>,
}

/// Check per-role post-run assertions against the final role states. Each
/// `(role, attrs)` pair is verified using the same logic as `assert` steps.
fn check_case_asserts(
    final_states: &HashMap<String, RoleState>,
    asserts: &HashMap<String, HashMap<String, Value>>,
) -> Vec<AssertionFailure> {
    let mut failures = Vec::new();
    for (role, attrs) in asserts {
        let Some(state) = final_states.get(role) else {
            for (key, expected) in attrs {
                failures.push(AssertionFailure {
                    role: role.clone(),
                    key: key.clone(),
                    expected: expected.clone(),
                    actual: None,
                });
            }
            continue;
        };
        for (key, expected) in attrs {
            if key == "recv_flags" || key == "sent_flags" {
                let actual = if key == "recv_flags" {
                    &state.last_recv_flags
                } else {
                    &state.last_sent_flags
                };
                let want: Vec<String> = expected
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                if !want.iter().all(|f| actual.iter().any(|g| g == f)) {
                    failures.push(AssertionFailure {
                        role: role.clone(),
                        key: key.clone(),
                        expected: expected.clone(),
                        actual: Some(Value::Array(
                            actual.iter().cloned().map(Value::String).collect(),
                        )),
                    });
                }
            } else {
                let actual = resolve_state_value(state, key);
                if actual.as_ref() != Some(expected) {
                    failures.push(AssertionFailure {
                        role: role.clone(),
                        key: key.clone(),
                        expected: expected.clone(),
                        actual,
                    });
                }
            }
        }
    }
    failures
}

/// Drive a single role: run its steps in order, blocking on `depends_on`.
/// Returns the role's final state (for `cases` post-run assertions).
fn run_role(
    sim: &Sim,
    role: &str,
    steps: Vec<Step>,
    initial_vars: HashMap<String, Value>,
) -> RoleState {
    let mut state = RoleState::new_with_vars(&initial_vars);
    let inbox = match sim.transport.inbox(role) {
        Some(i) => i,
        None => {
            let msg = format!("role `{role}` has no inbox");
            sim.record(Ev {
                role: role.to_string(),
                step: "-".to_string(),
                action: Action::Close,
                ok: false,
                detail: msg.clone(),
                flags: vec![],
                seq_num: None,
                ack_num: None,
                peer: None,
            });
            sim.set_error(role, msg);
            return state;
        }
    };

    for step in steps {
        if sim.enforce_runtime(role) {
            return state;
        }
        if !sim.wait_deps(&step.depends_on) {
            return state;
        }
        if sim.failed() {
            return state;
        }
        let enabled = match step_enabled(&step, &state.vars) {
            Ok(enabled) => enabled,
            Err(msg) => {
                record_step_failure(sim, role, &step, &msg);
                sim.set_error(role, msg);
                sim.mark_done(&step.name);
                return state;
            }
        };
        if !enabled || step.loop_count == 0 {
            sim.record(Ev {
                role: role.to_string(),
                step: step.name.clone(),
                action: step.action,
                ok: true,
                detail: if !enabled {
                    "skipped: when=false".to_string()
                } else {
                    "skipped: loop=0".to_string()
                },
                flags: vec![],
                seq_num: None,
                ack_num: None,
                peer: None,
            });
            sim.mark_done(&step.name);
            continue;
        }

        if let Some(required) = &step.from_state {
            if required != "*" && required != &state.protocol_state {
                let message = format!(
                    "state transition rejected: step `{}` requires `{required}`, role `{role}` is `{}`",
                    step.name, state.protocol_state
                );
                record_step_failure(sim, role, &step, &message);
                sim.set_failure(role, FailureKind::Validation, message);
                sim.mark_done(&step.name);
                return state;
            }
        }

        // Determine retransmit count: step-level or timer-level, whichever is set
        let retransmit = step
            .retransmit
            .max(step.timer.as_ref().map(|t| t.retransmit).unwrap_or(0));
        for _ in 0..step.loop_count {
            let mut retransmit_attempts = 0;
            let mut retry_attempts = 0;
            loop {
                match execute_step(sim, &step, &mut state, &inbox, role) {
                    Ok(()) => break,
                    Err(failure) => {
                        // On recv timeout with retransmit configured, re-send the
                        // last send step and retry the recv.
                        if retransmit > 0
                            && retransmit_attempts < retransmit
                            && matches!(step.action, Action::Recv | Action::RecvRaw)
                            && failure.kind == FailureKind::Timeout
                        {
                            if let Some(last) = state.last_transmission.clone() {
                                sim.record(Ev {
                                    role: role.to_string(),
                                    step: step.name.clone(),
                                    action: step.action,
                                    // The timeout is handled by the configured
                                    // retry policy, so it is not a terminal error.
                                    ok: true,
                                    detail: format!(
                                        "timed out, retransmitting {} (attempt {}/{})",
                                        last.step_name,
                                        retransmit_attempts + 1,
                                        retransmit
                                    ),
                                    flags: vec![],
                                    seq_num: None,
                                    ack_num: None,
                                    peer: None,
                                });
                                if let Err(rmsg) = retransmit_snapshot(sim, &mut state, &last) {
                                    sim.record(Ev {
                                        role: role.to_string(),
                                        step: last.step_name.clone(),
                                        action: last.action,
                                        ok: false,
                                        detail: rmsg.message.clone(),
                                        flags: vec![],
                                        seq_num: None,
                                        ack_num: None,
                                        peer: None,
                                    });
                                    sim.set_failure(role, rmsg.kind, rmsg.message);
                                    sim.mark_done(&step.name);
                                    return state;
                                }
                                retransmit_attempts += 1;
                                continue;
                            }
                        }
                        let timeout = failure.kind == FailureKind::Timeout;
                        let selected = if step.retry_policy.retry_on.is_empty() {
                            !step.on_timeout || timeout
                        } else {
                            step.retry_policy
                                .retry_on
                                .iter()
                                .any(|kind| kind == failure.kind.as_str())
                        };
                        if retry_attempts < step.retry && selected {
                            retry_attempts += 1;
                            let retry_delay = retry_delay_ms(
                                &step,
                                retry_attempts,
                                sim.counter.load(Ordering::SeqCst),
                            );
                            sim.sleep(retry_delay);
                            sim.record(Ev {
                                role: role.to_string(),
                                step: step.name.clone(),
                                action: step.action,
                                ok: true,
                                detail: format!(
                                    "retry after failure (attempt {}/{}) : {}",
                                    retry_attempts, step.retry, failure.message
                                ),
                                flags: vec![],
                                seq_num: None,
                                ack_num: None,
                                peer: None,
                            });
                            continue;
                        }
                        record_step_failure(sim, role, &step, &failure.message);
                        sim.set_failure_with_assertions(
                            role,
                            failure.kind,
                            failure.message,
                            failure.assertion_failures,
                        );
                        sim.mark_done(&step.name);
                        return state;
                    }
                }
            }
            if sim.enforce_runtime(role) {
                sim.mark_done(&step.name);
                return state;
            }
        }
        if let Some(next) = &step.to_state {
            state.protocol_state = next.clone();
        }
        sim.mark_done(&step.name);
    }
    state
}

fn step_enabled(step: &Step, vars: &HashMap<String, Value>) -> Result<bool, String> {
    let Some(condition) = &step.when else {
        return Ok(true);
    };
    match interpolate_value(condition, vars) {
        Value::Bool(enabled) => Ok(enabled),
        other => Err(format!(
            "step `{}` when must resolve to bool, got {}",
            step.name,
            other.to_display()
        )),
    }
}

fn record_step_failure(sim: &Sim, role: &str, step: &Step, msg: &str) {
    sim.record(Ev {
        role: role.to_string(),
        step: step.name.clone(),
        action: step.action,
        ok: false,
        detail: msg.to_string(),
        flags: vec![],
        seq_num: None,
        ack_num: None,
        peer: None,
    });
}
/// Execute a single step, mutating per-role `state` and emitting trace events.
fn execute_step(
    sim: &Sim,
    step: &Step,
    state: &mut RoleState,
    inbox: &Inbox,
    role: &str,
) -> Result<(), StepFailure> {
    match step.action {
        Action::Send | Action::Ack => {
            if step.expect.is_some() {
                if let Some(mut expect) = step.expect.clone() {
                    expect.interpolate(&state.vars);
                    let timeout_ms = step
                        .timer
                        .as_ref()
                        .map(|timer| timer.timeout_ms)
                        .unwrap_or(DEFAULT_RECV_TIMEOUT_MS);
                    let received = recv_match(sim, inbox, &expect, timeout_ms)?;
                    state.recv_count += 1;
                    state.last_recv_seq = received.seq;
                    state.last_recv_payload_len = 1.max(received.payload_len() as i64);
                    state.last_recv_ack = received.ack;
                    state.last_recv_flags = received.flags;
                    state.last_recv_from = received.from;
                    state.last_recv_window = received.window;
                    state.last_recv_stream = received.stream;
                    state.last_recv_fields = received.fields;
                    state.last_recv_raw = received.raw;
                }
            }
            let to = resolve_to(step, &sim.all_roles)?;
            let seg = step.segment.clone().unwrap_or_default();
            let seq = seg.seq.unwrap_or(state.next_seq);
            let ack = if step.action == Action::Ack {
                seg.ack
                    .unwrap_or(state.last_recv_seq + 1.max(state.last_recv_payload_len))
            } else {
                seg.ack.unwrap_or(0)
            };
            let (fields, payload, raw) = build_outbound(&seg, &state.vars)?;
            let plen = seg.payload_len.unwrap_or(if !raw.is_empty() {
                raw.len() as i64
            } else {
                payload.len() as i64
            });
            let msg = Message {
                from: role.to_string(),
                flags: seg.flags.clone(),
                seq,
                ack,
                payload,
                raw,
                window: seg.window.unwrap_or(0),
                stream: seg.stream,
                fields,
            };
            transmit(TransmitArgs {
                sim,
                step_name: &step.name,
                action: step.action,
                state,
                to: &to,
                msg,
                label: step.action.as_str(),
                delay_ms: seg.delay_ms,
            })?;
            state.next_seq = seq + 1.max(plen);
            Ok(())
        }
        Action::SendRaw => {
            let to = resolve_to(step, &sim.all_roles)?;
            let segment = step.segment.clone().unwrap_or_default();
            let (structured, payload, raw_payload) = build_outbound(&segment, &state.vars)?;
            let application = if raw_payload.is_empty() {
                payload.as_bytes().to_vec()
            } else {
                raw_payload
            };
            let spec = step.raw_packet.as_ref().ok_or_else(|| {
                StepFailure::new(
                    FailureKind::Validation,
                    format!("step `{}` has no raw packet specification", step.name),
                )
            })?;
            let packets = build_raw_packets(spec, &state.vars, application)?;
            let mut tcp_observed = false;
            let mut transmitted = Vec::new();
            for bytes in packets {
                let mut message = message_from_raw_wire(role, bytes, structured.clone())?;
                if sim.raw_tcp_stateful && !tcp_observed && !message.flags.is_empty() {
                    observe_raw_tcp_state(state, packet::TcpDirection::Outbound, &message.raw)?;
                    tcp_observed = true;
                }
                if message.payload.is_empty() {
                    message.payload = payload.clone();
                }
                transmitted.push(message.clone());
                transmit(TransmitArgs {
                    sim,
                    step_name: &step.name,
                    action: step.action,
                    state,
                    to: &to,
                    msg: message,
                    label: "send_raw",
                    delay_ms: segment.delay_ms,
                })?;
            }
            if transmitted.len() > 1 {
                state.last_transmission = Some(LastTransmission {
                    step_name: step.name.clone(),
                    action: step.action,
                    to,
                    messages: transmitted,
                    label: "send_raw".to_string(),
                    delay_ms: segment.delay_ms,
                });
            }
            Ok(())
        }
        Action::Nack => {
            if let Some(mut expect) = step.expect.clone() {
                expect.interpolate(&state.vars);
                let timeout_ms = step
                    .timer
                    .as_ref()
                    .map(|timer| timer.timeout_ms)
                    .unwrap_or(DEFAULT_RECV_TIMEOUT_MS);
                let received = recv_match(sim, inbox, &expect, timeout_ms)?;
                state.recv_count += 1;
                state.last_recv_seq = received.seq;
                state.last_recv_payload_len = 1.max(received.payload_len() as i64);
                state.last_recv_ack = received.ack;
                state.last_recv_flags = received.flags;
                state.last_recv_from = received.from;
                state.last_recv_window = received.window;
                state.last_recv_stream = received.stream;
                state.last_recv_fields = received.fields;
                state.last_recv_raw = received.raw;
            }
            let to = resolve_to(step, &sim.all_roles)?;
            let seg = step.segment.clone().unwrap_or_default();
            let seq = seg.seq.unwrap_or(state.next_seq);
            // NACK references the rejected sequence, not seq+1.
            let ack = seg.ack.unwrap_or(state.last_recv_seq);
            let flags = if seg.flags.is_empty() {
                vec!["NACK".to_string()]
            } else {
                seg.flags.clone()
            };
            let (fields, payload, raw) = build_outbound(&seg, &state.vars)?;
            let plen = seg.payload_len.unwrap_or(if !raw.is_empty() {
                raw.len() as i64
            } else {
                payload.len() as i64
            });
            let msg = Message {
                from: role.to_string(),
                flags,
                seq,
                ack,
                payload,
                raw,
                window: seg.window.unwrap_or(0),
                stream: seg.stream,
                fields,
            };
            transmit(TransmitArgs {
                sim,
                step_name: &step.name,
                action: step.action,
                state,
                to: &to,
                msg,
                label: "nack",
                delay_ms: seg.delay_ms,
            })?;
            state.next_seq = seq + 1.max(plen);
            Ok(())
        }
        Action::Reset => {
            let to = resolve_to(step, &sim.all_roles)?;
            let seg = step.segment.clone().unwrap_or_default();
            let seq = seg.seq.unwrap_or(state.next_seq);
            let flags = if seg.flags.is_empty() {
                vec!["RST".to_string()]
            } else {
                seg.flags.clone()
            };
            let (fields, payload, raw) = build_outbound(&seg, &state.vars)?;
            let msg = Message {
                from: role.to_string(),
                flags,
                seq,
                ack: seg.ack.unwrap_or(0),
                payload,
                raw,
                window: seg.window.unwrap_or(0),
                stream: seg.stream,
                fields,
            };
            transmit(TransmitArgs {
                sim,
                step_name: &step.name,
                action: step.action,
                state,
                to: &to,
                msg,
                label: "reset",
                delay_ms: seg.delay_ms,
            })?;
            state.aborted = true;
            Ok(())
        }
        Action::Duplicate => {
            let to = resolve_to(step, &sim.all_roles)?;
            let seg = step.segment.clone().unwrap_or_default();
            let seq = seg.seq.unwrap_or(state.next_seq);
            let ack = seg.ack.unwrap_or(0);
            let (fields, payload, raw) = build_outbound(&seg, &state.vars)?;
            let plen = seg.payload_len.unwrap_or(if !raw.is_empty() {
                raw.len() as i64
            } else {
                payload.len() as i64
            });
            let win = seg.window.unwrap_or(0);
            let stream = seg.stream;
            let flags = seg.flags.clone();
            let msg1 = Message {
                from: role.to_string(),
                flags: flags.clone(),
                seq,
                ack,
                payload: payload.clone(),
                raw: raw.clone(),
                window: win,
                stream,
                fields: fields.clone(),
            };
            transmit(TransmitArgs {
                sim,
                step_name: &step.name,
                action: step.action,
                state,
                to: &to,
                msg: msg1,
                label: "send",
                delay_ms: seg.delay_ms,
            })?;
            let msg2 = Message {
                from: role.to_string(),
                flags,
                seq,
                ack,
                payload,
                raw,
                window: win,
                stream,
                fields,
            };
            transmit(TransmitArgs {
                sim,
                step_name: &step.name,
                action: step.action,
                state,
                to: &to,
                msg: msg2,
                label: "send (dup)",
                delay_ms: seg.delay_ms,
            })?;
            state.next_seq = seq + 1.max(plen);
            Ok(())
        }
        Action::Corrupt => {
            let to = resolve_to(step, &sim.all_roles)?;
            let seg = step.segment.clone().unwrap_or_default();
            let seq = seg.seq.unwrap_or(state.next_seq);
            let ack = seg.ack.unwrap_or(0);
            let (fields, payload, mut raw) = build_outbound(&seg, &state.vars)?;
            if raw.is_empty() {
                return Err(StepFailure::new(
                    FailureKind::Validation,
                    "corrupt requires `segment.hex` with at least one byte",
                ));
            }
            let flip = seg
                .flip_bit
                .ok_or_else(|| "corrupt requires `segment.flip`".to_string())?;
            let bit_len = (raw.len() as u64) * 8;
            if flip >= bit_len {
                return Err(StepFailure::new(
                    FailureKind::Validation,
                    format!("corrupt flip bit {flip} is outside payload ({bit_len} bits)"),
                ));
            }
            let byte = (flip / 8) as usize;
            let bit_in_byte = (flip % 8) as u8;
            raw[byte] ^= 1 << (7 - bit_in_byte);
            let plen = seg.payload_len.unwrap_or(raw.len() as i64);
            let msg = Message {
                from: role.to_string(),
                flags: seg.flags.clone(),
                seq,
                ack,
                payload,
                raw,
                window: seg.window.unwrap_or(0),
                stream: seg.stream,
                fields,
            };
            transmit(TransmitArgs {
                sim,
                step_name: &step.name,
                action: step.action,
                state,
                to: &to,
                msg,
                label: "corrupt",
                delay_ms: seg.delay_ms,
            })?;
            state.next_seq = seq + 1.max(plen);
            Ok(())
        }
        Action::Recv | Action::RecvRaw => {
            let mut expect = step.expect.clone().unwrap_or_default();
            // Interpolate ${var} in expect field matchers before matching
            expect.interpolate(&state.vars);
            let timeout_ms = step
                .timer
                .as_ref()
                .map(|t| t.timeout_ms)
                .unwrap_or(DEFAULT_RECV_TIMEOUT_MS);
            let msg = if step.action == Action::RecvRaw {
                recv_raw_match(sim, inbox, &expect, timeout_ms)?
            } else {
                recv_match(sim, inbox, &expect, timeout_ms)?
            };
            if step.action == Action::RecvRaw && sim.raw_tcp_stateful && !msg.flags.is_empty() {
                observe_raw_tcp_state(state, packet::TcpDirection::Inbound, &msg.raw)?;
            }
            state.recv_count += 1;
            state.last_recv_seq = msg.seq;
            state.last_recv_ack = msg.ack;
            state.last_recv_flags = msg.flags.clone();
            state.last_recv_from = msg.from.clone();
            state.last_recv_window = msg.window;
            state.last_recv_stream = msg.stream;
            state.last_recv_fields = msg.fields.clone();
            state.last_recv_raw = msg.raw.clone();
            state.last_recv_payload_len = 1.max(msg.payload_len() as i64);
            // Capture: store named message fields into the role's variable map
            // so later `send` (`${var}`) and `assert` steps can use them.
            for (field_name, var_name) in &expect.capture {
                if let Some(v) = msg.fields.get(field_name) {
                    state.vars.insert(var_name.clone(), v.clone());
                }
            }
            let wire_data = if msg.raw.is_empty() {
                msg.payload.clone().into_bytes()
            } else {
                msg.raw.clone()
            };
            let event = Ev {
                role: role.to_string(),
                step: step.name.clone(),
                action: step.action,
                ok: true,
                detail: {
                    let hex_part = if !msg.raw.is_empty() {
                        let h = crate::value::bytes_to_hex(&msg.raw);
                        let truncated = if h.len() > 32 {
                            format!("{}…({} bytes)", &h[..32], msg.raw.len())
                        } else {
                            h
                        };
                        format!(" hex={truncated}")
                    } else {
                        String::new()
                    };
                    format!(
                        "recv <- {} flags={} seq={} ack={} win={}{}",
                        msg.from,
                        msg.flags_str(),
                        msg.seq,
                        msg.ack,
                        msg.window,
                        hex_part
                    )
                },
                flags: msg.flags.clone(),
                seq_num: Some(msg.seq),
                ack_num: Some(msg.ack),
                peer: Some(msg.from),
            };
            if step.action == Action::RecvRaw {
                sim.record_with_network(event, wire_data, NetworkProtocol::Raw);
            } else {
                sim.record_with_wire(event, wire_data);
            }
            Ok(())
        }
        Action::Drop => {
            let mut expect = step.expect.clone().unwrap_or_default();
            expect.interpolate(&state.vars);
            let timeout_ms = step.timer.as_ref().map(|t| t.timeout_ms).unwrap_or(1000);
            match recv_match(sim, inbox, &expect, timeout_ms) {
                Ok(msg) => {
                    // Discarded: do NOT update last_recv state (segment was lost).
                    sim.record(Ev {
                        role: role.to_string(),
                        step: step.name.clone(),
                        action: step.action,
                        ok: true,
                        detail: format!(
                            "dropped <- {} flags={} seq={}",
                            msg.from,
                            msg.flags_str(),
                            msg.seq
                        ),
                        flags: msg.flags.clone(),
                        seq_num: Some(msg.seq),
                        ack_num: Some(msg.ack),
                        peer: Some(msg.from),
                    });
                    Ok(())
                }
                Err(_) => {
                    // Nothing matching to drop — benign; never fails the run.
                    sim.record(Ev {
                        role: role.to_string(),
                        step: step.name.clone(),
                        action: step.action,
                        ok: true,
                        detail: "drop: no matching segment (timeout)".to_string(),
                        flags: vec![],
                        seq_num: None,
                        ack_num: None,
                        peer: None,
                    });
                    Ok(())
                }
            }
        }
        Action::Open => {
            if let Some(failure) = sim.transport.configured_connect_failure() {
                let detail = match failure {
                    "dns" => "simulated DNS resolution failure",
                    "refused" => "simulated connection refused",
                    "tls_handshake" => "simulated TLS handshake failure",
                    _ => "simulated connection failure",
                };
                return Err(StepFailure::new(FailureKind::Transport, detail));
            }
            let mode = step.mode.as_deref().unwrap_or("active");
            sim.record(Ev {
                role: role.to_string(),
                step: step.name.clone(),
                action: step.action,
                ok: true,
                detail: format!("open mode={mode}"),
                flags: vec![],
                seq_num: None,
                ack_num: None,
                peer: None,
            });
            Ok(())
        }
        Action::Log => {
            let note = step.message.clone().unwrap_or_default();
            sim.record(Ev {
                role: role.to_string(),
                step: step.name.clone(),
                action: step.action,
                ok: true,
                detail: format!("log: {note}"),
                flags: vec![],
                seq_num: None,
                ack_num: None,
                peer: None,
            });
            Ok(())
        }
        Action::Plugin => {
            if !sim.allow_plugins {
                return Err(StepFailure::new(
                    FailureKind::Validation,
                    "plugin execution is disabled; use an explicitly plugin-enabled engine",
                ));
            }
            let plugin = step.plugin.as_ref().ok_or_else(|| {
                StepFailure::new(
                    FailureKind::Validation,
                    "plugin action has no plugin section",
                )
            })?;
            let manifest_path = {
                let configured = std::path::Path::new(&plugin.manifest);
                if configured.is_absolute() {
                    configured.to_path_buf()
                } else {
                    step.source
                        .as_deref()
                        .and_then(|source| std::path::Path::new(source).parent())
                        .unwrap_or_else(|| std::path::Path::new("."))
                        .join(configured)
                }
            };
            let manifest_text = std::fs::read_to_string(&manifest_path).map_err(|error| {
                StepFailure::new(
                    FailureKind::Validation,
                    format!(
                        "cannot read plugin manifest {}: {error}",
                        manifest_path.display()
                    ),
                )
            })?;
            let manifest: crate::plugin::PluginManifest = serde_json::from_str(&manifest_text)
                .map_err(|error| {
                    StepFailure::new(
                        FailureKind::Validation,
                        format!(
                            "invalid plugin manifest {}: {error}",
                            manifest_path.display()
                        ),
                    )
                })?;
            let resolved = interpolate_value(&plugin.input, &state.vars);
            let mut input = crate::plugin::dsl_value_to_json(&resolved);
            if let Some(object) = input.as_object_mut() {
                object.insert(
                    "_tcpform".into(),
                    serde_json::json!({
                        "role":role,"step":step.name,"protocol_state":state.protocol_state,
                        "vars":crate::plugin::dsl_value_to_json(&Value::Object(state.vars.clone())),
                        "last_recv_fields":crate::plugin::dsl_value_to_json(&Value::Object(state.last_recv_fields.clone()))
                    }),
                );
            }
            let result = crate::plugin::invoke_plugin(&manifest, &plugin.kind, &plugin.name, input)
                .map_err(|message| StepFailure::new(FailureKind::Runtime, message))?;
            if plugin.kind == "matcher"
                && result.get("matched").and_then(|value| value.as_bool()) != Some(true)
            {
                return Err(StepFailure::assertion(
                    format!("plugin matcher `{}` did not match", plugin.name),
                    Vec::new(),
                ));
            }
            if let Some(vars) = result.get("vars").and_then(|value| value.as_object()) {
                for (key, value) in vars {
                    state
                        .vars
                        .insert(key.clone(), crate::plugin::json_to_dsl_value(value));
                }
            }
            if plugin.kind == "decoder" {
                if let Some(fields) = result.get("fields").and_then(|value| value.as_object()) {
                    for (key, value) in fields {
                        state
                            .last_recv_fields
                            .insert(key.clone(), crate::plugin::json_to_dsl_value(value));
                    }
                }
            }
            state.vars.insert(
                format!("plugin.{}", step.name),
                crate::plugin::json_to_dsl_value(&result),
            );
            let detail = result
                .get("detail")
                .and_then(|value| value.as_str())
                .unwrap_or("ok");
            sim.record(Ev {
                role: role.to_string(),
                step: step.name.clone(),
                action: step.action,
                ok: true,
                detail: format!("plugin {}:{} {detail}", plugin.kind, plugin.name),
                flags: vec![],
                seq_num: None,
                ack_num: None,
                peer: None,
            });
            Ok(())
        }
        Action::Set => {
            let set = step.set.clone().unwrap_or_default();
            let mut parts = Vec::new();
            for (k, v) in &set.vars {
                state.vars.insert(k.clone(), v.clone());
                parts.push(format!("{k}={}", v.to_display()));
            }
            sim.record(Ev {
                role: role.to_string(),
                step: step.name.clone(),
                action: step.action,
                ok: true,
                detail: format!("set {}", parts.join(", ")),
                flags: vec![],
                seq_num: None,
                ack_num: None,
                peer: None,
            });
            Ok(())
        }
        Action::Assert => {
            let assert = step.assert.clone().unwrap_or_default();
            let mut failures = Vec::new();
            let mut assertion_failures = Vec::new();
            for (key, expected) in &assert.attrs {
                let expected = interpolate_value(expected, &state.vars);
                if key == "recv_flags" || key == "sent_flags" {
                    let actual = if key == "recv_flags" {
                        &state.last_recv_flags
                    } else {
                        &state.last_sent_flags
                    };
                    let want: Vec<String> = expected
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    if !want.iter().all(|f| actual.iter().any(|g| g == f)) {
                        failures.push(format!("{key}: expected {:?}, got {:?}", want, actual));
                        assertion_failures.push(AssertionFailure {
                            role: role.to_string(),
                            key: key.clone(),
                            expected: expected.clone(),
                            actual: Some(Value::Array(
                                actual.iter().cloned().map(Value::String).collect(),
                            )),
                        });
                    }
                } else {
                    match resolve_state_value(state, key) {
                        Some(actual) => {
                            if actual != expected {
                                failures.push(format!(
                                    "{key}: expected {}, got {}",
                                    expected.to_display(),
                                    actual.to_display()
                                ));
                                assertion_failures.push(AssertionFailure {
                                    role: role.to_string(),
                                    key: key.clone(),
                                    expected: expected.clone(),
                                    actual: Some(actual),
                                });
                            }
                        }
                        None => {
                            failures.push(format!("{key}: unknown state key"));
                            assertion_failures.push(AssertionFailure {
                                role: role.to_string(),
                                key: key.clone(),
                                expected: expected.clone(),
                                actual: None,
                            });
                        }
                    }
                }
            }
            if failures.is_empty() {
                sim.record(Ev {
                    role: role.to_string(),
                    step: step.name.clone(),
                    action: step.action,
                    ok: true,
                    detail: "assert ok".to_string(),
                    flags: vec![],
                    seq_num: None,
                    ack_num: None,
                    peer: None,
                });
                Ok(())
            } else {
                Err(StepFailure::assertion(
                    format!("assert failed: {}", failures.join("; ")),
                    assertion_failures,
                ))
            }
        }
        Action::Wait => {
            let ms = step.timer.as_ref().map(|t| t.timeout_ms).unwrap_or(0);
            if ms > 0 {
                sim.sleep(ms);
            }
            sim.record(Ev {
                role: role.to_string(),
                step: step.name.clone(),
                action: step.action,
                ok: true,
                detail: format!("wait {ms}ms"),
                flags: vec![],
                seq_num: None,
                ack_num: None,
                peer: None,
            });
            Ok(())
        }
        Action::Close => {
            sim.transport
                .half_close(role)
                .map_err(|message| StepFailure::new(FailureKind::Transport, message))?;
            sim.record(Ev {
                role: role.to_string(),
                step: step.name.clone(),
                action: step.action,
                ok: true,
                detail: "close (write half)".to_string(),
                flags: vec![],
                seq_num: None,
                ack_num: None,
                peer: None,
            });
            Ok(())
        }
    }
}

fn build_raw_packets(
    spec: &RawPacketSpec,
    vars: &HashMap<String, Value>,
    payload: Vec<u8>,
) -> Result<Vec<Vec<u8>>, StepFailure> {
    let transport = if let Some(attributes) = &spec.tcp {
        Some(TransportHeader::Tcp(build_tcp_header(attributes, vars)?))
    } else if let Some(attributes) = &spec.udp {
        Some(TransportHeader::Udp(build_udp_header(attributes, vars)?))
    } else {
        None
    };
    let inferred_protocol = match transport {
        Some(TransportHeader::Tcp(_)) => Some(packet::IP_PROTOCOL_TCP),
        Some(TransportHeader::Udp(_)) => Some(packet::IP_PROTOCOL_UDP),
        None => None,
    };
    let network = if let Some(attributes) = &spec.ipv4 {
        NetworkHeader::Ipv4(build_ipv4_header(attributes, vars)?)
    } else if let Some(attributes) = &spec.ipv6 {
        NetworkHeader::Ipv6(build_ipv6_header(attributes, vars, inferred_protocol)?)
    } else {
        return Err(raw_validation("raw packet requires ipv4 or ipv6"));
    };
    let ethernet = spec
        .ethernet
        .as_ref()
        .map(|attributes| build_ethernet_header(attributes, vars))
        .transpose()?;
    let packet = Packet {
        ethernet,
        network,
        transport,
        payload,
    };
    match (&packet.network, spec.mtu) {
        (_, None) => packet
            .encode()
            .map(|packet| vec![packet])
            .map_err(|error| raw_validation(error.to_string())),
        (NetworkHeader::Ipv4(_), Some(mtu)) => {
            packet::fragment_ipv4(&packet, mtu).map_err(|error| raw_validation(error.to_string()))
        }
        (NetworkHeader::Ipv6(_), Some(mtu)) => {
            packet::fragment_ipv6(&packet, mtu, spec.fragment_id.unwrap_or(0))
                .map_err(|error| raw_validation(error.to_string()))
        }
    }
}

fn raw_spec_contains_variable(spec: &RawPacketSpec) -> bool {
    [
        spec.ethernet.as_ref(),
        spec.ipv4.as_ref(),
        spec.ipv6.as_ref(),
        spec.tcp.as_ref(),
        spec.udp.as_ref(),
    ]
    .into_iter()
    .flatten()
    .flat_map(|attributes| attributes.values())
    .any(value_contains_variable)
}

fn value_contains_variable(value: &Value) -> bool {
    match value {
        Value::String(value) => value.contains("${"),
        Value::Array(values) => values.iter().any(value_contains_variable),
        Value::Object(values) => values.values().any(value_contains_variable),
        _ => false,
    }
}

fn build_ethernet_header(
    attributes: &HashMap<String, Value>,
    vars: &HashMap<String, Value>,
) -> Result<EthernetHeader, StepFailure> {
    let source = raw_required_string(attributes, "source", vars)?
        .parse::<MacAddr>()
        .map_err(|error| raw_validation(error.to_string()))?;
    let destination = raw_required_string(attributes, "destination", vars)?
        .parse::<MacAddr>()
        .map_err(|error| raw_validation(error.to_string()))?;
    let vlan_id = raw_optional_u16(attributes, "vlan_id", vars)?;
    let vlan_priority = raw_u8(attributes, "vlan_priority", vars, 0)?;
    let vlan_drop_eligible = raw_bool(attributes, "vlan_drop_eligible", vars, false)?;
    if vlan_id.is_none() && (vlan_priority != 0 || vlan_drop_eligible) {
        return Err(raw_validation(
            "ethernet vlan_priority/vlan_drop_eligible require vlan_id",
        ));
    }
    Ok(EthernetHeader {
        source,
        destination,
        vlan: vlan_id.map(|id| VlanTag {
            priority: vlan_priority,
            drop_eligible: vlan_drop_eligible,
            id,
        }),
        ether_type: raw_optional_u16(attributes, "ether_type", vars)?,
    })
}

fn build_ipv4_header(
    attributes: &HashMap<String, Value>,
    vars: &HashMap<String, Value>,
) -> Result<Ipv4Header, StepFailure> {
    Ok(Ipv4Header {
        source: raw_required_string(attributes, "source", vars)?
            .parse()
            .map_err(|error| raw_validation(format!("invalid IPv4 source: {error}")))?,
        destination: raw_required_string(attributes, "destination", vars)?
            .parse()
            .map_err(|error| raw_validation(format!("invalid IPv4 destination: {error}")))?,
        dscp: raw_u8(attributes, "dscp", vars, 0)?,
        ecn: raw_u8(attributes, "ecn", vars, 0)?,
        identification: raw_u16(attributes, "id", vars, 0)?,
        dont_fragment: raw_bool(attributes, "dont_fragment", vars, false)?,
        more_fragments: raw_bool(attributes, "more_fragments", vars, false)?,
        fragment_offset: raw_u16(attributes, "fragment_offset", vars, 0)?,
        ttl: raw_u8(attributes, "ttl", vars, 64)?,
        protocol: raw_optional_u8(attributes, "protocol", vars)?,
        options: raw_hex(attributes, "options", vars)?.unwrap_or_default(),
        ihl: raw_optional_u8(attributes, "ihl", vars)?,
        total_length: raw_optional_u16(attributes, "total_length", vars)?,
        checksum: raw_checksum(attributes, "checksum", vars)?,
    })
}

fn build_ipv6_header(
    attributes: &HashMap<String, Value>,
    vars: &HashMap<String, Value>,
    inferred_protocol: Option<u8>,
) -> Result<Ipv6Header, StepFailure> {
    let configured_next = raw_optional_u8(attributes, "next_header", vars)?;
    let fragment_offset = raw_optional_u16(attributes, "fragment_offset", vars)?;
    let more_fragments = raw_bool(attributes, "more_fragments", vars, false)?;
    let fragment_id = raw_optional_u32(attributes, "fragment_id", vars)?;
    let fragment = if fragment_offset.is_some() || more_fragments || fragment_id.is_some() {
        Some(Ipv6Fragment {
            next_header: configured_next.or(inferred_protocol).ok_or_else(|| {
                raw_validation("IPv6 fragment requires next_header or tcp/udp header")
            })?,
            offset: fragment_offset.unwrap_or(0),
            more_fragments,
            identification: fragment_id.unwrap_or(0),
        })
    } else {
        None
    };
    Ok(Ipv6Header {
        traffic_class: raw_u8(attributes, "traffic_class", vars, 0)?,
        flow_label: raw_u32(attributes, "flow_label", vars, 0)?,
        payload_length: raw_optional_u16(attributes, "payload_length", vars)?,
        next_header: configured_next,
        hop_limit: raw_u8(attributes, "hop_limit", vars, 64)?,
        source: raw_required_string(attributes, "source", vars)?
            .parse()
            .map_err(|error| raw_validation(format!("invalid IPv6 source: {error}")))?,
        destination: raw_required_string(attributes, "destination", vars)?
            .parse()
            .map_err(|error| raw_validation(format!("invalid IPv6 destination: {error}")))?,
        fragment,
    })
}

fn build_tcp_header(
    attributes: &HashMap<String, Value>,
    vars: &HashMap<String, Value>,
) -> Result<TcpHeader, StepFailure> {
    Ok(TcpHeader {
        source_port: raw_u16(attributes, "source_port", vars, 0)?,
        destination_port: raw_u16(attributes, "destination_port", vars, 0)?,
        sequence: raw_u32(attributes, "seq", vars, 0)?,
        acknowledgment: raw_u32(attributes, "ack", vars, 0)?,
        flags: raw_tcp_flags(attributes, vars)?,
        window: raw_u16(attributes, "window", vars, 65_535)?,
        urgent_pointer: raw_u16(attributes, "urgent_pointer", vars, 0)?,
        options: raw_tcp_options(attributes, vars)?,
        data_offset: raw_optional_u8(attributes, "data_offset", vars)?,
        checksum: raw_checksum(attributes, "checksum", vars)?,
    })
}

fn build_udp_header(
    attributes: &HashMap<String, Value>,
    vars: &HashMap<String, Value>,
) -> Result<UdpHeader, StepFailure> {
    Ok(UdpHeader {
        source_port: raw_u16(attributes, "source_port", vars, 0)?,
        destination_port: raw_u16(attributes, "destination_port", vars, 0)?,
        length: raw_optional_u16(attributes, "length", vars)?,
        checksum: raw_checksum(attributes, "checksum", vars)?,
    })
}

fn raw_tcp_flags(
    attributes: &HashMap<String, Value>,
    vars: &HashMap<String, Value>,
) -> Result<u16, StepFailure> {
    let Some(value) = raw_value(attributes, "flags", vars) else {
        return Ok(0);
    };
    if let Some(bits) = value.as_u64() {
        return u16::try_from(bits).map_err(|_| raw_validation("tcp flags exceed u16"));
    }
    let values = value
        .as_array()
        .ok_or_else(|| raw_validation("tcp flags must be a number or array of strings"))?;
    let mut flags = 0;
    for value in values {
        let name = value
            .as_str()
            .ok_or_else(|| raw_validation("tcp flags must contain strings"))?;
        flags |= match name.to_ascii_uppercase().as_str() {
            "FIN" => packet::tcp_flag::FIN,
            "SYN" => packet::tcp_flag::SYN,
            "RST" => packet::tcp_flag::RST,
            "PSH" => packet::tcp_flag::PSH,
            "ACK" => packet::tcp_flag::ACK,
            "URG" => packet::tcp_flag::URG,
            "ECE" => packet::tcp_flag::ECE,
            "CWR" => packet::tcp_flag::CWR,
            "NS" => packet::tcp_flag::NS,
            _ => return Err(raw_validation(format!("unknown TCP flag `{name}`"))),
        };
    }
    Ok(flags)
}

fn raw_tcp_options(
    attributes: &HashMap<String, Value>,
    vars: &HashMap<String, Value>,
) -> Result<Vec<TcpOption>, StepFailure> {
    let Some(value) = raw_value(attributes, "options", vars) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| raw_validation("tcp options must be an array"))?;
    let mut options = Vec::new();
    for value in values {
        if let Some(name) = value.as_str() {
            options.push(match name {
                "end" => TcpOption::End,
                "nop" => TcpOption::Nop,
                "sack_permitted" => TcpOption::SackPermitted,
                _ => return Err(raw_validation(format!("unknown TCP option `{name}`"))),
            });
            continue;
        }
        let object = value
            .as_object()
            .ok_or_else(|| raw_validation("tcp option must be a string or object"))?;
        if let Some(value) = object.get("mss") {
            options.push(TcpOption::MaximumSegmentSize(value_to_u16(
                value,
                "tcp option mss",
            )?));
        } else if let Some(value) = object.get("window_scale") {
            options.push(TcpOption::WindowScale(value_to_u8(
                value,
                "tcp option window_scale",
            )?));
        } else if let Some(Value::Object(timestamp)) = object.get("timestamp") {
            options.push(TcpOption::Timestamp {
                value: map_required_u32(timestamp, "value", "tcp timestamp")?,
                echo: map_required_u32(timestamp, "echo", "tcp timestamp")?,
            });
        } else if let Some(Value::Array(blocks)) = object.get("sack") {
            let mut parsed = Vec::new();
            for block in blocks {
                let values = block
                    .as_array()
                    .ok_or_else(|| raw_validation("tcp sack block must be [left,right]"))?;
                if values.len() != 2 {
                    return Err(raw_validation("tcp sack block must have two values"));
                }
                parsed.push((
                    value_to_u32(&values[0], "tcp sack left")?,
                    value_to_u32(&values[1], "tcp sack right")?,
                ));
            }
            options.push(TcpOption::Sack(parsed));
        } else if let Some(Value::Object(unknown)) = object.get("unknown") {
            let kind = map_required_u8(unknown, "kind", "unknown tcp option")?;
            let data = unknown
                .get("hex")
                .and_then(Value::as_str)
                .ok_or_else(|| raw_validation("unknown tcp option requires hex"))?;
            options.push(TcpOption::Unknown {
                kind,
                data: crate::value::parse_hex(data).map_err(raw_validation)?,
            });
        } else {
            return Err(raw_validation("unknown TCP option object"));
        }
    }
    Ok(options)
}

fn raw_checksum(
    attributes: &HashMap<String, Value>,
    key: &str,
    vars: &HashMap<String, Value>,
) -> Result<Checksum, StepFailure> {
    let Some(value) = raw_value(attributes, key, vars) else {
        return Ok(Checksum::Auto);
    };
    if let Some(number) = value.as_u64() {
        return u16::try_from(number)
            .map(Checksum::Value)
            .map_err(|_| raw_validation(format!("{key} checksum exceeds u16")));
    }
    match value.as_str() {
        Some("auto") => Ok(Checksum::Auto),
        Some("invalid") => Ok(Checksum::Invalid),
        Some("zero") => Ok(Checksum::Value(0)),
        _ => Err(raw_validation(format!(
            "{key} checksum must be auto, invalid, zero, or a u16"
        ))),
    }
}

fn raw_hex(
    attributes: &HashMap<String, Value>,
    key: &str,
    vars: &HashMap<String, Value>,
) -> Result<Option<Vec<u8>>, StepFailure> {
    raw_value(attributes, key, vars)
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| raw_validation(format!("{key} must be a hex string")))?;
            crate::value::parse_hex(value).map_err(raw_validation)
        })
        .transpose()
}

fn raw_required_string(
    attributes: &HashMap<String, Value>,
    key: &str,
    vars: &HashMap<String, Value>,
) -> Result<String, StepFailure> {
    raw_value(attributes, key, vars)
        .and_then(|value| value.as_str().map(str::to_string))
        .ok_or_else(|| raw_validation(format!("raw header `{key}` requires a string")))
}

fn raw_value(
    attributes: &HashMap<String, Value>,
    key: &str,
    vars: &HashMap<String, Value>,
) -> Option<Value> {
    attributes
        .get(key)
        .map(|value| interpolate_value(value, vars))
}

fn raw_bool(
    attributes: &HashMap<String, Value>,
    key: &str,
    vars: &HashMap<String, Value>,
    default: bool,
) -> Result<bool, StepFailure> {
    match raw_value(attributes, key, vars) {
        None => Ok(default),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| raw_validation(format!("raw header `{key}` must be boolean"))),
    }
}

macro_rules! raw_integer {
    ($name:ident, $optional:ident, $type:ty) => {
        fn $name(
            attributes: &HashMap<String, Value>,
            key: &str,
            vars: &HashMap<String, Value>,
            default: $type,
        ) -> Result<$type, StepFailure> {
            $optional(attributes, key, vars).map(|value| value.unwrap_or(default))
        }

        fn $optional(
            attributes: &HashMap<String, Value>,
            key: &str,
            vars: &HashMap<String, Value>,
        ) -> Result<Option<$type>, StepFailure> {
            raw_value(attributes, key, vars)
                .map(|value| {
                    let value = value.as_u64().ok_or_else(|| {
                        raw_validation(format!("raw header `{key}` must be a non-negative integer"))
                    })?;
                    <$type>::try_from(value)
                        .map_err(|_| raw_validation(format!("raw header `{key}` is out of range")))
                })
                .transpose()
        }
    };
}

raw_integer!(raw_u8, raw_optional_u8, u8);
raw_integer!(raw_u16, raw_optional_u16, u16);
raw_integer!(raw_u32, raw_optional_u32, u32);

fn value_to_u8(value: &Value, context: &str) -> Result<u8, StepFailure> {
    value
        .as_u64()
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| raw_validation(format!("{context} must be a u8")))
}

fn value_to_u16(value: &Value, context: &str) -> Result<u16, StepFailure> {
    value
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| raw_validation(format!("{context} must be a u16")))
}

fn value_to_u32(value: &Value, context: &str) -> Result<u32, StepFailure> {
    value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| raw_validation(format!("{context} must be a u32")))
}

fn map_required_u8(
    values: &HashMap<String, Value>,
    key: &str,
    context: &str,
) -> Result<u8, StepFailure> {
    values
        .get(key)
        .ok_or_else(|| raw_validation(format!("{context} requires `{key}`")))
        .and_then(|value| value_to_u8(value, context))
}

fn map_required_u32(
    values: &HashMap<String, Value>,
    key: &str,
    context: &str,
) -> Result<u32, StepFailure> {
    values
        .get(key)
        .ok_or_else(|| raw_validation(format!("{context} requires `{key}`")))
        .and_then(|value| value_to_u32(value, context))
}

fn raw_validation(message: impl Into<String>) -> StepFailure {
    StepFailure::new(FailureKind::Validation, message)
}

fn message_from_raw_wire(
    from: &str,
    bytes: Vec<u8>,
    mut fields: HashMap<String, Value>,
) -> Result<Message, StepFailure> {
    let decoded = decode_raw_wire(&bytes).map_err(|error| raw_validation(error.to_string()))?;
    fields.extend(raw_packet_fields(&decoded));
    let (flags, seq, ack, window) = match &decoded.packet.transport {
        Some(TransportHeader::Tcp(header)) => (
            tcp_flag_names(header.flags),
            i64::from(header.sequence),
            i64::from(header.acknowledgment),
            i64::from(header.window),
        ),
        _ => (Vec::new(), 0, 0, 0),
    };
    Ok(Message {
        from: from.to_string(),
        flags,
        seq,
        ack,
        payload: String::from_utf8_lossy(&decoded.packet.payload).into_owned(),
        raw: bytes,
        window,
        stream: None,
        fields,
    })
}

fn decode_raw_wire(bytes: &[u8]) -> Result<packet::DecodedPacket, packet::PacketError> {
    if bytes.len() >= 14 {
        let ether_type = u16::from_be_bytes([bytes[12], bytes[13]]);
        if matches!(
            ether_type,
            packet::ETHERTYPE_IPV4 | packet::ETHERTYPE_IPV6 | packet::ETHERTYPE_VLAN
        ) {
            return packet::decode_ethernet(bytes);
        }
    }
    packet::decode_ip(bytes)
}

fn observe_raw_tcp_state(
    state: &mut RoleState,
    direction: packet::TcpDirection,
    bytes: &[u8],
) -> Result<(), StepFailure> {
    let decoded = decode_raw_wire(bytes).map_err(|error| raw_validation(error.to_string()))?;
    let Some(TransportHeader::Tcp(header)) = decoded.packet.transport else {
        return Ok(());
    };
    state.raw_tcp_state = state
        .raw_tcp_tracker
        .observe(direction, header.flags)
        .map_err(|error| raw_validation(error.to_string()))?;
    Ok(())
}

fn raw_packet_fields(decoded: &packet::DecodedPacket) -> HashMap<String, Value> {
    // Start from the codec's canonical field set. The assignments below are
    // retained for backward-compatible names and values.
    let mut fields = packet::decoded_fields(decoded);
    fields.insert(
        "packet.length".to_string(),
        Value::Number(decoded.network_payload.len() as f64),
    );
    if let Some(ethernet) = &decoded.packet.ethernet {
        fields.insert(
            "ethernet.source".to_string(),
            Value::String(ethernet.source.to_string()),
        );
        fields.insert(
            "ethernet.destination".to_string(),
            Value::String(ethernet.destination.to_string()),
        );
        fields.insert(
            "ethernet.ether_type".to_string(),
            Value::Number(ethernet.ether_type.unwrap_or(0) as f64),
        );
        if let Some(vlan) = ethernet.vlan {
            fields.insert(
                "ethernet.vlan_id".to_string(),
                Value::Number(vlan.id as f64),
            );
            fields.insert(
                "ethernet.vlan_priority".to_string(),
                Value::Number(vlan.priority as f64),
            );
        }
    }
    match &decoded.packet.network {
        NetworkHeader::Ipv4(header) => {
            fields.insert("ip.version".to_string(), Value::Number(4.0));
            fields.insert(
                "ipv4.source".to_string(),
                Value::String(header.source.to_string()),
            );
            fields.insert(
                "ipv4.destination".to_string(),
                Value::String(header.destination.to_string()),
            );
            fields.insert("ipv4.ttl".to_string(), Value::Number(header.ttl as f64));
            fields.insert(
                "ipv4.id".to_string(),
                Value::Number(header.identification as f64),
            );
            fields.insert(
                "ipv4.fragment_offset".to_string(),
                Value::Number(header.fragment_offset as f64),
            );
            fields.insert(
                "ipv4.more_fragments".to_string(),
                Value::Bool(header.more_fragments),
            );
            if let Some(valid) = decoded.ipv4_checksum_valid {
                fields.insert("ipv4.checksum_valid".to_string(), Value::Bool(valid));
            }
        }
        NetworkHeader::Ipv6(header) => {
            fields.insert("ip.version".to_string(), Value::Number(6.0));
            fields.insert(
                "ipv6.source".to_string(),
                Value::String(header.source.to_string()),
            );
            fields.insert(
                "ipv6.destination".to_string(),
                Value::String(header.destination.to_string()),
            );
            fields.insert(
                "ipv6.hop_limit".to_string(),
                Value::Number(header.hop_limit as f64),
            );
            fields.insert(
                "ipv6.flow_label".to_string(),
                Value::Number(header.flow_label as f64),
            );
            if let Some(fragment) = header.fragment {
                fields.insert(
                    "ipv6.fragment_offset".to_string(),
                    Value::Number(fragment.offset as f64),
                );
                fields.insert(
                    "ipv6.more_fragments".to_string(),
                    Value::Bool(fragment.more_fragments),
                );
                fields.insert(
                    "ipv6.fragment_id".to_string(),
                    Value::Number(fragment.identification as f64),
                );
            }
        }
    }
    match &decoded.packet.transport {
        Some(TransportHeader::Tcp(header)) => {
            fields.insert(
                "tcp.source_port".to_string(),
                Value::Number(header.source_port as f64),
            );
            fields.insert(
                "tcp.destination_port".to_string(),
                Value::Number(header.destination_port as f64),
            );
            fields.insert("tcp.seq".to_string(), Value::Number(header.sequence as f64));
            fields.insert(
                "tcp.ack".to_string(),
                Value::Number(header.acknowledgment as f64),
            );
            fields.insert(
                "tcp.window".to_string(),
                Value::Number(header.window as f64),
            );
            fields.insert(
                "tcp.flags".to_string(),
                Value::Array(
                    tcp_flag_names(header.flags)
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
        Some(TransportHeader::Udp(header)) => {
            fields.insert(
                "udp.source_port".to_string(),
                Value::Number(header.source_port as f64),
            );
            fields.insert(
                "udp.destination_port".to_string(),
                Value::Number(header.destination_port as f64),
            );
            fields.insert(
                "udp.length".to_string(),
                Value::Number(header.length.unwrap_or(0) as f64),
            );
        }
        None => {}
    }
    if let Some(valid) = decoded.transport_checksum_valid {
        fields.insert("transport.checksum_valid".to_string(), Value::Bool(valid));
    }
    fields.insert(
        "raw.payload".to_string(),
        Value::Bytes(decoded.packet.payload.clone()),
    );
    fields
}

fn tcp_flag_names(flags: u16) -> Vec<String> {
    [
        (packet::tcp_flag::FIN, "FIN"),
        (packet::tcp_flag::SYN, "SYN"),
        (packet::tcp_flag::RST, "RST"),
        (packet::tcp_flag::PSH, "PSH"),
        (packet::tcp_flag::ACK, "ACK"),
        (packet::tcp_flag::URG, "URG"),
        (packet::tcp_flag::ECE, "ECE"),
        (packet::tcp_flag::CWR, "CWR"),
        (packet::tcp_flag::NS, "NS"),
    ]
    .into_iter()
    .filter(|(bit, _)| flags & bit != 0)
    .map(|(_, name)| name.to_string())
    .collect()
}

fn recv_raw_match(
    sim: &Sim,
    inbox: &Inbox,
    expect: &Expect,
    timeout_ms: u64,
) -> Result<Message, StepFailure> {
    let effective_timeout = if sim.clock == ClockMode::Virtual {
        timeout_ms.min(10)
    } else {
        timeout_ms
    };
    let deadline = Instant::now() + Duration::from_millis(effective_timeout);
    let mut reassembler = packet::FragmentReassembler::new(packet::ReassemblyConfig {
        max_datagrams: sim.max_inbox.clamp(1, 4096),
        max_buffered_bytes: sim.max_payload,
        timeout: Duration::from_millis(timeout_ms.max(1)),
    });
    let mut deferred = Vec::new();
    loop {
        let message = {
            let (lock, cv) = &**inbox;
            let mut queue = lock.lock().unwrap();
            loop {
                let position = queue.iter().position(|message| {
                    expect
                        .from
                        .as_ref()
                        .is_none_or(|from| from == &message.from)
                });
                if let Some(position) = position {
                    break queue.remove(position).unwrap();
                }
                let now = Instant::now();
                if now >= deadline {
                    restore_deferred(queue, deferred);
                    sim.advance(timeout_ms);
                    return Err(StepFailure::timeout(recv_timeout_msg(expect, timeout_ms)));
                }
                let result = cv.wait_timeout(queue, deadline - now).unwrap();
                queue = result.0;
                if result.1.timed_out() {
                    restore_deferred(queue, deferred);
                    sim.advance(timeout_ms);
                    return Err(StepFailure::timeout(recv_timeout_msg(expect, timeout_ms)));
                }
            }
        };

        // This permits exact-hex matching of intentionally malformed frames,
        // which may not be decodable as an IP packet.
        if expect.matches(&message) {
            restore_deferred(inbox.0.lock().unwrap(), deferred);
            return Ok(message);
        }
        let decoded = match decode_raw_wire(&message.raw) {
            Ok(decoded) => decoded,
            Err(_) => {
                deferred.push(message);
                continue;
            }
        };
        let original_fragmented = match &decoded.packet.network {
            NetworkHeader::Ipv4(header) => header.fragment_offset != 0 || header.more_fragments,
            NetworkHeader::Ipv6(header) => header.fragment.is_some(),
        };
        let Some(packet) = reassembler
            .push(&decoded)
            .map_err(|error| StepFailure::new(FailureKind::Validation, error.to_string()))?
        else {
            continue;
        };
        let wire = if original_fragmented {
            packet
                .encode()
                .map_err(|error| StepFailure::new(FailureKind::Validation, error.to_string()))?
        } else {
            message.raw.clone()
        };
        let normalized = message_from_raw_wire(&message.from, wire, HashMap::new())?;
        if expect.matches(&normalized) {
            restore_deferred(inbox.0.lock().unwrap(), deferred);
            return Ok(normalized);
        }
        deferred.push(message);
    }
}

fn restore_deferred(
    mut queue: std::sync::MutexGuard<'_, VecDeque<Message>>,
    deferred: Vec<Message>,
) {
    for message in deferred.into_iter().rev() {
        queue.push_front(message);
    }
    drop(queue);
}

/// Wait for (and consume) the first inbox message matching `expect`, scanning
/// the deque so unrelated/out-of-order segments are left for later recvs.
fn recv_match(
    sim: &Sim,
    inbox: &Inbox,
    expect: &Expect,
    timeout_ms: u64,
) -> Result<Message, StepFailure> {
    let (lock, cv) = &**inbox;
    let effective_timeout = if sim.clock == ClockMode::Virtual {
        timeout_ms.min(10)
    } else {
        timeout_ms
    };
    let deadline = Instant::now() + Duration::from_millis(effective_timeout);
    let mut q = lock.lock().unwrap();
    loop {
        if let Some(pos) = q.iter().position(|m| expect.matches(m)) {
            return Ok(q.remove(pos).unwrap());
        }
        let now = Instant::now();
        if now >= deadline {
            sim.advance(timeout_ms);
            return Err(StepFailure::timeout(recv_timeout_msg(expect, timeout_ms)));
        }
        let r = cv.wait_timeout(q, deadline - now).unwrap();
        q = r.0;
        if r.1.timed_out() {
            if let Some(pos) = q.iter().position(|m| expect.matches(m)) {
                return Ok(q.remove(pos).unwrap());
            }
            sim.advance(timeout_ms);
            return Err(StepFailure::timeout(recv_timeout_msg(expect, timeout_ms)));
        }
    }
}

fn recv_timeout_msg(expect: &Expect, timeout_ms: u64) -> String {
    let from = expect
        .from
        .as_ref()
        .map(|f| format!(" from={f}"))
        .unwrap_or_default();
    format!(
        "timed out after {}ms waiting for segment flags={:?}{}",
        timeout_ms, expect.flags, from
    )
}

/// Per-role mutable state: auto-numbered seq/ack plus observability fields
/// (counters, last sent/recv segment metadata) and a user variable map for
/// `set`/`assert`. Public so that `run_cases` can inspect final state.
pub struct RoleState {
    /// Explicit DSL state, starting at `initial` and changed by `to_state`.
    pub protocol_state: String,
    pub next_seq: i64,
    pub last_recv_seq: i64,
    pub last_recv_payload_len: i64,
    pub last_recv_ack: i64,
    pub last_recv_flags: Vec<String>,
    pub last_recv_from: String,
    pub last_recv_window: i64,
    pub last_recv_stream: Option<i64>,
    pub last_recv_fields: HashMap<String, Value>,
    pub last_recv_raw: Vec<u8>,
    pub raw_tcp_state: packet::TcpState,
    pub last_sent_seq: i64,
    pub last_sent_ack: i64,
    pub last_sent_flags: Vec<String>,
    pub last_sent_to: String,
    pub last_sent_window: i64,
    pub last_sent_stream: Option<i64>,
    pub send_count: u64,
    pub recv_count: u64,
    pub aborted: bool,
    pub vars: HashMap<String, Value>,
    last_transmission: Option<LastTransmission>,
    raw_tcp_tracker: packet::TcpStateTracker,
}

#[derive(Clone)]
struct LastTransmission {
    step_name: String,
    action: Action,
    to: String,
    messages: Vec<Message>,
    label: String,
    delay_ms: u64,
}

impl RoleState {
    #[allow(dead_code)]
    fn new() -> Self {
        Self::new_with_vars(&HashMap::new())
    }

    /// Create a role state with initial variables pre-loaded (for `cases`).
    fn new_with_vars(vars: &HashMap<String, Value>) -> Self {
        RoleState {
            protocol_state: "initial".to_string(),
            next_seq: 1000,
            last_recv_seq: 0,
            last_recv_payload_len: 0,
            last_recv_ack: 0,
            last_recv_flags: Vec::new(),
            last_recv_from: String::new(),
            last_recv_window: 0,
            last_recv_stream: None,
            last_recv_fields: HashMap::new(),
            last_recv_raw: Vec::new(),
            raw_tcp_state: packet::TcpState::Closed,
            last_sent_seq: 0,
            last_sent_ack: 0,
            last_sent_flags: Vec::new(),
            last_sent_to: String::new(),
            last_sent_window: 0,
            last_sent_stream: None,
            send_count: 0,
            recv_count: 0,
            aborted: false,
            vars: vars.clone(),
            last_transmission: None,
            raw_tcp_tracker: packet::TcpStateTracker::default(),
        }
    }
}

/// Shared simulation context, shared across role threads via `Arc`.
struct Sim {
    transport: Transport,
    completed: Arc<(Mutex<HashSet<String>>, Condvar)>,
    trace: Arc<Mutex<Vec<TraceEvent>>>,
    error: Arc<Mutex<Option<SimFailure>>>,
    counter: Arc<AtomicU64>,
    all_roles: Vec<String>,
    clock: ClockMode,
    started: Instant,
    virtual_ms: Arc<AtomicU64>,
    max_trace: usize,
    max_payload: usize,
    max_inbox: usize,
    max_runtime_ms: u64,
    raw_tcp_stateful: bool,
    network: NetworkProtocol,
    observer: Option<TraceObserver>,
    allow_plugins: bool,
}

type SimFailure = (String, FailureKind, String, Vec<AssertionFailure>);

/// A trace event under construction (the global counter is stamped on record).
struct Ev {
    role: String,
    step: String,
    action: Action,
    ok: bool,
    detail: String,
    flags: Vec<String>,
    seq_num: Option<i64>,
    ack_num: Option<i64>,
    peer: Option<String>,
}

impl Sim {
    fn elapsed_ms(&self) -> u64 {
        if self.clock == ClockMode::Virtual {
            self.virtual_ms.load(Ordering::SeqCst)
        } else {
            self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
        }
    }

    /// Returns true after recording a resource-limit failure.
    fn enforce_runtime(&self, role: &str) -> bool {
        let elapsed = self.elapsed_ms();
        if elapsed <= self.max_runtime_ms {
            return false;
        }
        self.set_failure(
            role,
            FailureKind::ResourceLimit,
            format!(
                "runtime reached limits.max_runtime={}ms (elapsed {elapsed}ms)",
                self.max_runtime_ms
            ),
        );
        let (_, cv) = &*self.completed;
        cv.notify_all();
        true
    }
    fn record(&self, ev: Ev) {
        self.record_with_wire(ev, Vec::new());
    }

    fn record_with_wire(&self, ev: Ev, wire_data: Vec<u8>) {
        self.record_with_network(ev, wire_data, self.network);
    }

    fn record_with_network(&self, ev: Ev, wire_data: Vec<u8>, network: NetworkProtocol) {
        let seq = self.counter.fetch_add(1, Ordering::SeqCst);
        if seq as usize >= self.max_trace {
            self.set_failure(
                &ev.role,
                FailureKind::ResourceLimit,
                format!("trace reached max_trace {}", self.max_trace),
            );
            return;
        }
        let timestamp_ns = if self.clock == ClockMode::Virtual {
            u128::from(self.virtual_ms.load(Ordering::SeqCst)).saturating_mul(1_000_000)
        } else {
            self.started.elapsed().as_nanos()
        };
        let timestamp_us = (timestamp_ns / 1000).min(u128::from(u64::MAX)) as u64;
        let event = TraceEvent {
            seq,
            role: ev.role,
            step: ev.step,
            action: ev.action,
            ok: ev.ok,
            detail: ev.detail,
            flags: ev.flags,
            seq_num: ev.seq_num,
            ack_num: ev.ack_num,
            peer: ev.peer,
            wire_data,
            timestamp_us,
            timestamp_ns,
            network,
        };
        if let Some(observer) = &self.observer {
            observer(&event);
        }
        self.trace.lock().unwrap().push(event);
    }

    fn failed(&self) -> bool {
        self.error.lock().unwrap().is_some()
    }

    fn set_error(&self, role: &str, msg: String) {
        self.set_failure(role, FailureKind::Runtime, msg);
    }

    fn set_failure(&self, role: &str, kind: FailureKind, msg: String) {
        self.set_failure_with_assertions(role, kind, msg, Vec::new());
    }

    fn set_failure_with_assertions(
        &self,
        role: &str,
        kind: FailureKind,
        msg: String,
        assertion_failures: Vec<AssertionFailure>,
    ) {
        let mut e = self.error.lock().unwrap();
        if e.is_none() {
            *e = Some((role.to_string(), kind, msg, assertion_failures));
        }
    }

    fn advance(&self, milliseconds: u64) {
        if self.clock == ClockMode::Virtual {
            self.virtual_ms.fetch_add(milliseconds, Ordering::SeqCst);
        }
    }

    fn sleep(&self, milliseconds: u64) {
        if self.clock == ClockMode::Virtual {
            self.advance(milliseconds);
        } else if milliseconds > 0 {
            thread::sleep(Duration::from_millis(milliseconds));
        }
    }

    fn mark_done(&self, step: &str) {
        let (lock, cv) = &*self.completed;
        lock.lock().unwrap().insert(step.to_string());
        cv.notify_all();
    }

    /// Block until all `deps` are complete. Returns false if another role
    /// errored while we were waiting (so the caller should abort).
    fn wait_deps(&self, deps: &[String]) -> bool {
        loop {
            let ready = {
                let (lock, cv) = &*self.completed;
                let mut done = lock.lock().unwrap();
                while !deps.iter().all(|d| done.contains(d)) {
                    let r = cv.wait_timeout(done, Duration::from_millis(50)).unwrap();
                    done = r.0;
                    if r.1.timed_out() {
                        break;
                    }
                }
                deps.iter().all(|d| done.contains(d))
            };
            if ready {
                return true;
            }
            if self.failed() {
                return false;
            }
            if self.enforce_runtime("scheduler") {
                return false;
            }
        }
    }
}

fn join_flags(flags: &[String]) -> String {
    if flags.is_empty() {
        "-".into()
    } else {
        flags.join(",")
    }
}

fn retry_delay_ms(step: &Step, attempt: u32, entropy: u64) -> u64 {
    let policy = &step.retry_policy;
    let multiplier = policy.backoff.powi(attempt.saturating_sub(1) as i32);
    let base = ((policy.initial_delay_ms as f64) * multiplier)
        .min(policy.max_delay_ms as f64)
        .max(0.0);
    if policy.jitter == 0.0 || base == 0.0 {
        return base as u64;
    }
    let unit = ((entropy.wrapping_mul(0x9e3779b97f4a7c15) >> 11) as f64) / ((1u64 << 53) as f64);
    let factor = 1.0 + (unit * 2.0 - 1.0) * policy.jitter;
    (base * factor).clamp(0.0, policy.max_delay_ms as f64) as u64
}

/// Replace `${var}` tokens in a string with values from the role's variable
/// map. Unknown tokens are left as-is.
fn interpolate_str(s: &str, vars: &HashMap<String, Value>) -> String {
    let mut result = s.to_string();
    for (k, v) in vars {
        let token = format!("${{{k}}}");
        if result.contains(&token) {
            let replacement = match v {
                Value::String(vs) => vs.clone(),
                Value::Bytes(b) => crate::value::bytes_to_hex(b),
                Value::Number(n) => {
                    if n.fract() == 0.0 {
                        format!("{}", *n as i64)
                    } else {
                        format!("{n}")
                    }
                }
                Value::Bool(b) => b.to_string(),
                _ => v.to_display(),
            };
            result = result.replace(&token, &replacement);
        }
    }
    result
}

pub(crate) fn interpolate_str_pub(s: &str, vars: &HashMap<String, Value>) -> String {
    interpolate_str(s, vars)
}

/// Recursively interpolate `${var}` tokens in any [`Value`] (strings inside
/// arrays/objects are interpolated too). If a string is *exactly* `${var}`,
/// the variable's [`Value`] is substituted directly (preserving type); mixed
/// strings like `"id=${var}"` are stringified.
fn interpolate_value(v: &Value, vars: &HashMap<String, Value>) -> Value {
    interpolate_value_pub(v, vars)
}

/// Public-within-crate version of [`interpolate_value`], used by
/// `model::Expect::interpolate`.
pub(crate) fn interpolate_value_pub(v: &Value, vars: &HashMap<String, Value>) -> Value {
    match v {
        Value::String(s) => {
            if let Some(name) = exact_var_ref(s) {
                if let Some(val) = vars.get(name) {
                    return val.clone();
                }
            }
            Value::String(interpolate_str(s, vars))
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| interpolate_value(x, vars)).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), interpolate_value(v, vars)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// If `s` is exactly `${name}` (a single variable reference), return `name`.
fn exact_var_ref(s: &str) -> Option<&str> {
    let inner = s.strip_prefix("${")?;
    let name = inner.strip_suffix('}')?;
    if name.is_empty() || name.contains("${") || name.contains('}') {
        return None;
    }
    Some(name)
}

/// The interpolated outbound content of a segment: structured fields, text
/// payload, and raw binary bytes (from `hex`).
type Outbound = (HashMap<String, Value>, String, Vec<u8>);

/// Build the interpolated `fields` map, `payload` string, and `raw` bytes for
/// an outbound segment, applying `${var}` substitution from the role's
/// variable map. The `hex` string is interpolated first, then parsed to bytes.
fn build_outbound(
    seg: &crate::model::Segment,
    vars: &HashMap<String, Value>,
) -> Result<Outbound, String> {
    let fields: HashMap<String, Value> = seg
        .fields
        .iter()
        .map(|(k, v)| {
            let interpolated = interpolate_value(v, vars);
            (k.clone(), resolve_deferred_hex(interpolated))
        })
        .collect();
    let payload = interpolate_str(&seg.payload.clone().unwrap_or_default(), vars);
    let raw = match &seg.hex {
        Some(hex_str) => {
            let interpolated = interpolate_str(hex_str, vars);
            crate::value::parse_hex(&interpolated).map_err(|e| format!("segment `hex`: {e}"))?
        }
        None => Vec::new(),
    };
    Ok((fields, payload, raw))
}

/// After interpolation, resolve deferred hex field values: a `Value::String`
/// starting with `__hex__:` is parsed into `Value::Bytes`. This handles
/// `fields = { id = { hex = "${txn_id}" } }` where the `${var}` was
/// substituted at interpolation time (producing e.g. `"__hex__:1234"`).
fn resolve_deferred_hex(v: Value) -> Value {
    match &v {
        Value::String(s) if s.starts_with("__hex__:") => {
            let hex_part = &s["__hex__:".len()..];
            match crate::value::parse_hex(hex_part) {
                Ok(bytes) => Value::Bytes(bytes),
                Err(_) => v, // leave as string if parse fails (shouldn't happen)
            }
        }
        _ => v,
    }
}

/// Arguments for [`transmit`], grouped to keep the argument count manageable.
struct TransmitArgs<'a> {
    sim: &'a Sim,
    step_name: &'a str,
    action: Action,
    state: &'a mut RoleState,
    to: &'a str,
    msg: Message,
    label: &'a str,
    delay_ms: u64,
}

/// Build, send and trace one outbound segment, updating the role's send-side
/// state (`send_count`, `last_sent_*`). The caller advances `next_seq`.
/// `delay_ms` is the per-segment delay from `segment.delay`.
fn transmit(args: TransmitArgs) -> Result<(), StepFailure> {
    let TransmitArgs {
        sim,
        step_name,
        action,
        state,
        to,
        msg,
        label,
        delay_ms,
    } = args;
    let flags = msg.flags.clone();
    let wire_data = if msg.raw.is_empty() {
        msg.payload.as_bytes().to_vec()
    } else {
        msg.raw.clone()
    };
    let seq = msg.seq;
    let ack = msg.ack;
    let from = msg.from.clone();
    let has_raw = !msg.raw.is_empty();
    let hex_preview = if has_raw {
        let h = crate::value::bytes_to_hex(&msg.raw);
        let truncated = if h.len() > 32 {
            format!("{}…({} bytes)", &h[..32], msg.raw.len())
        } else {
            h
        };
        format!(" hex={truncated}")
    } else {
        String::new()
    };
    let delay_note = if delay_ms > 0 {
        format!(" delay={delay_ms}ms")
    } else {
        String::new()
    };
    let sent_window = msg.window;
    let sent_stream = msg.stream;
    let snapshot = LastTransmission {
        step_name: step_name.to_string(),
        action,
        to: to.to_string(),
        messages: vec![msg.clone()],
        label: label.to_string(),
        delay_ms,
    };
    let delivery = sim
        .transport
        .send_scoped(to, msg, delay_ms, Some(step_name))
        .map_err(|error| {
            let kind = match error.kind {
                TransportErrorKind::Transport => FailureKind::Transport,
                TransportErrorKind::ResourceLimit => FailureKind::ResourceLimit,
            };
            StepFailure::new(kind, error.message)
        })?;
    sim.advance(delivery.delay_ms);
    state.send_count += 1;
    state.last_sent_seq = seq;
    state.last_sent_ack = ack;
    state.last_sent_flags = flags.clone();
    state.last_sent_to = to.to_string();
    state.last_sent_window = sent_window;
    state.last_sent_stream = sent_stream;
    state.last_transmission = Some(snapshot);
    let mut fault_notes = Vec::new();
    if delivery.dropped {
        fault_notes.push("dropped");
    }
    if delivery.reordered {
        fault_notes.push("reordered");
    }
    if delivery.duplicated {
        fault_notes.push("duplicated");
    }
    if delivery.corrupted {
        fault_notes.push("corrupted");
    }
    let fault_note = if fault_notes.is_empty() {
        String::new()
    } else {
        format!(" transport={}", fault_notes.join(","))
    };
    let event = Ev {
        role: from,
        step: step_name.to_string(),
        action,
        ok: true,
        detail: format!(
            "{label} -> {to} flags={} seq={seq} ack={ack}{hex_preview}{delay_note}{fault_note}",
            join_flags(&flags)
        ),
        flags,
        seq_num: Some(seq),
        ack_num: Some(ack),
        peer: Some(to.to_string()),
    };
    if action == Action::SendRaw {
        sim.record_with_network(event, wire_data, NetworkProtocol::Raw);
    } else {
        sim.record_with_wire(event, wire_data);
    }
    Ok(())
}

fn retransmit_snapshot(
    sim: &Sim,
    state: &mut RoleState,
    snapshot: &LastTransmission,
) -> Result<(), StepFailure> {
    for message in &snapshot.messages {
        transmit(TransmitArgs {
            sim,
            step_name: &snapshot.step_name,
            action: snapshot.action,
            state,
            to: &snapshot.to,
            msg: message.clone(),
            label: &snapshot.label,
            delay_ms: snapshot.delay_ms,
        })?;
    }
    state.last_transmission = Some(snapshot.clone());
    Ok(())
}

/// Resolve an `assert` key to a [`Value`]: built-in counters / last-segment
/// fields, a received structured field (`recv_field:<name>`), or a user
/// variable previously written by `set` or `capture`.
fn resolve_state_value(state: &RoleState, key: &str) -> Option<Value> {
    match key {
        "send_count" => Some(Value::Number(state.send_count as f64)),
        "recv_count" => Some(Value::Number(state.recv_count as f64)),
        "next_seq" => Some(Value::Number(state.next_seq as f64)),
        "last_recv_seq" => Some(Value::Number(state.last_recv_seq as f64)),
        "last_recv_ack" => Some(Value::Number(state.last_recv_ack as f64)),
        "last_recv_from" => Some(Value::String(state.last_recv_from.clone())),
        "last_recv_window" => Some(Value::Number(state.last_recv_window as f64)),
        "last_sent_seq" => Some(Value::Number(state.last_sent_seq as f64)),
        "last_sent_ack" => Some(Value::Number(state.last_sent_ack as f64)),
        "last_sent_to" => Some(Value::String(state.last_sent_to.clone())),
        "last_sent_window" => Some(Value::Number(state.last_sent_window as f64)),
        "aborted" => Some(Value::Bool(state.aborted)),
        "last_recv_hex" => {
            if state.last_recv_raw.is_empty() {
                Some(Value::String(String::new()))
            } else {
                Some(Value::Bytes(state.last_recv_raw.clone()))
            }
        }
        _ => {
            // `recv_field:<name>` — access a structured field from the last recv
            if let Some(name) = key.strip_prefix("recv_field:") {
                return state.last_recv_fields.get(name).cloned();
            }
            state.vars.get(key).cloned()
        }
    }
}

/// Resolve the destination role for a send/ack step.
fn resolve_to(step: &Step, all_roles: &[String]) -> Result<String, String> {
    if let Some(to) = &step.to {
        return Ok(to.clone());
    }
    let others: Vec<&String> = all_roles.iter().filter(|r| *r != &step.role).collect();
    match others.len() {
        1 => Ok(others[0].clone()),
        0 => Err(format!("step `{}` has no peer role to send to", step.name)),
        _ => Err(format!(
            "step `{}` send is ambiguous (multiple peer roles); set `to = ...`",
            step.name
        )),
    }
}
