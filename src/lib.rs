//! tcpform — declaratively compose protocol primitives
//! (send/recv/send_raw/recv_raw/ack/nack/open/close/reset/wait/drop/duplicate/assert/set/log)
//! into new protocols using a declarative protocol DSL, then simulate them.
//!
//! ```text
//! // A .tcpf file describes a protocol as ordered, composable steps.
//! protocol "tcp_handshake" {
//!   step "syn" {
//!     role   = "client"
//!     action = "send"
//!     segment { flags = ["SYN"] seq = 1000 }
//!   }
//!   step "syn_ack" {
//!     role       = "server"
//!     action     = "send"
//!     depends_on = ["recv_syn"]
//!     segment    { flags = ["SYN", "ACK"] seq = 5000 ack = 1001 }
//!   }
//!   step "recv_syn" {
//!     role   = "server"
//!     action = "recv"
//!     expect { flags = ["SYN"] }
//!   }
//!   step "ack" {
//!     role       = "client"
//!     action     = "send"
//!     depends_on = ["syn", "recv_syn_ack"]
//!     segment    { flags = ["ACK"] ack = 5001 }
//!   }
//!   step "recv_syn_ack" {
//!     role       = "client"
//!     action     = "recv"
//!     depends_on = ["syn"]
//!     expect     { flags = ["SYN", "ACK"] }
//!   }
//! }
//! ```

pub mod ast;
pub mod ci_report;
pub mod compat;
pub mod completion;
pub mod doctor;
pub mod engine;
pub mod fuzz_export;
pub mod graph;
pub mod kaitai;
pub mod loader;
pub mod model;
pub mod output;
pub mod packet;
pub mod packetdrill;
pub mod parser;
pub mod pcap_import;
pub mod platform;
pub mod plugin;
pub mod primitives;
pub mod raw_socket;
pub mod snapshot;
pub mod storage;
pub mod template_registry;
pub mod templates;
pub mod tls_audit;
pub mod tooling;
pub mod transport;
pub mod value;

pub use ast::Block;
pub use engine::{AssertionFailure, CaseResult, Engine, EngineError, FailureKind, TraceEvent};
pub use loader::{load_blocks, load_blocks_from_sources};
pub use model::{
    Action, Assert, Case, CaseExpect, CaseOutcome, Cases, ClockMode, Expect, FieldMatch,
    PluginSpec, Protocol, RawPacketSpec, ResourceLimits, RetryPolicy, Segment, Set, Step, Timer,
    TransportConfig,
};
pub use parser::{parse_file, parse_file_named};
pub use plugin::{invoke_plugin, PluginCapabilities, PluginManifest, PLUGIN_PROTOCOL_VERSION};
pub use raw_socket::{RawPacketSocket, RawSocketConfig, RawSocketError, RawSocketErrorKind};
pub use storage::{Job, Store};
pub use tls_audit::{audit_certificate_file, audit_tls_endpoint, CertificateAudit, TlsAudit};
pub use transport::{
    Framing, NetworkProtocol, TlsOptions, TransportError, TransportErrorKind, UdpOptions,
    WebSocketOptions,
};
pub use value::{bytes_to_hex, parse_hex, Value};
