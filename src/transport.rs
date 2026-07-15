//! Simulated in-memory transport. Each role gets a deque-backed inbox shared
//! via an `Arc<(Mutex<VecDeque<Message>>, Condvar)>`; a `send` pushes a
//! [`Message`] into the destination role's inbox and notifies it.
//!
//! When a [`TransportConfig`] is set, the transport applies probabilistic
//! loss, fixed delay, and optional reordering to every segment.

use crate::model::{ResourceLimits, TransportConfig};
use crate::packet::{self, TransportHeader};
use crate::primitives::Message;
use crate::raw_socket::{RawPacketSocket, RawSocketConfig};
use crate::value::Value;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::BufReader;
use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message as WebSocketMessage, WebSocket};

/// A role's inbox: a shared, condition-variable-guarded deque of messages.
pub type Inbox = Arc<(Mutex<VecDeque<Message>>, Condvar)>;

pub struct Transport {
    inboxes: HashMap<String, Inbox>,
    config: TransportConfig,
    random_counter: AtomicU64,
    send_counter: AtomicU64,
    burst_remaining: AtomicU64,
    live_senders: Option<HashMap<String, LiveSocket>>,
    live_alive: Option<Arc<AtomicBool>>,
    workers: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    worker_errors: Arc<Mutex<Vec<TransportError>>>,
    limits: ResourceLimits,
    virtual_time: bool,
    network: NetworkProtocol,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_external_framing_round_trips_fragmented_input() {
        for framing in [
            Framing::Raw,
            Framing::LengthPrefix,
            Framing::Delimiter(b"\r\n".to_vec()),
            Framing::Fixed(4),
        ] {
            let encoded = frame_outbound(b"ping", &framing).unwrap();
            let mut pending = Vec::new();
            let mut frames = Vec::new();
            if framing == Framing::Raw {
                pending.extend(encoded);
                frames.extend(drain_frames(&mut pending, &framing, 1024).unwrap());
            } else {
                for byte in encoded {
                    pending.push(byte);
                    frames.extend(drain_frames(&mut pending, &framing, 1024).unwrap());
                }
            }
            assert_eq!(frames, vec![b"ping".to_vec()], "{framing:?}");
        }
    }

    #[test]
    fn fixed_framing_rejects_wrong_size() {
        assert!(frame_outbound(b"short", &Framing::Fixed(4)).is_err());
    }

    #[test]
    fn oversized_length_prefixed_frame_is_rejected() {
        let mut pending = vec![0, 0, 4, 0];
        assert!(drain_frames(&mut pending, &Framing::LengthPrefix, 100).is_err());
    }

    #[test]
    fn udp_live_options_validate_multicast_and_support_broadcast_reuse() {
        let roles = vec!["client".to_string(), "server".to_string()];
        let limits = ResourceLimits::default();
        let invalid = UdpOptions {
            multicast_group: Some("127.0.0.1".into()),
            ..UdpOptions::default()
        };
        let error = match Transport::external_udp_with_options(
            &roles,
            "client",
            "server",
            "127.0.0.1:9",
            false,
            &limits,
            &invalid,
        ) {
            Ok(_) => panic!("non-multicast group accepted"),
            Err(error) => error,
        };
        assert!(error.contains("not multicast"));
        let configured = UdpOptions {
            broadcast: true,
            reuse_address: true,
            ..UdpOptions::default()
        };
        let transport = Transport::external_udp_with_options(
            &roles,
            "client",
            "server",
            "127.0.0.1:9",
            false,
            &limits,
            &configured,
        )
        .unwrap();
        assert_eq!(transport.network_protocol(), NetworkProtocol::Udp);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Tls,
    Raw,
    WebSocket,
    Quic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryReport {
    pub dropped: bool,
    pub delay_ms: u64,
    pub reordered: bool,
    pub duplicated: bool,
    pub corrupted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportErrorKind {
    Transport,
    ResourceLimit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError {
    pub kind: TransportErrorKind,
    pub message: String,
}

impl TransportError {
    fn transport(message: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::Transport,
            message: message.into(),
        }
    }

    fn resource_limit(message: impl Into<String>) -> Self {
        Self {
            kind: TransportErrorKind::ResourceLimit,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TransportError {}

impl From<String> for TransportError {
    fn from(message: String) -> Self {
        Self::transport(message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Framing {
    #[default]
    Raw,
    LengthPrefix,
    Delimiter(Vec<u8>),
    Fixed(usize),
}

#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    pub server_name: Option<String>,
    pub ca_file: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub alpn_protocols: Vec<String>,
    pub require_client_auth: bool,
}

#[derive(Debug, Clone, Default)]
pub struct UdpOptions {
    pub broadcast: bool,
    pub reuse_address: bool,
    pub multicast_group: Option<String>,
    pub multicast_interface: Option<String>,
    pub multicast_ttl: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct WebSocketOptions {
    pub text: bool,
    pub subprotocols: Vec<String>,
    pub origin: Option<String>,
}

#[derive(Clone)]
enum LiveSocket {
    Tcp(Arc<Mutex<TcpStream>>),
    TcpRaw {
        stream: Arc<Mutex<TcpStream>>,
        framing: Framing,
    },
    #[cfg(unix)]
    UnixRaw {
        stream: Arc<Mutex<UnixStream>>,
        framing: Framing,
    },
    Udp(Arc<UdpSocket>),
    UdpRaw {
        socket: Arc<UdpSocket>,
        peer: Arc<Mutex<Option<SocketAddr>>>,
    },
    TlsClient {
        stream: Arc<Mutex<StreamOwned<ClientConnection, TcpStream>>>,
        framing: Framing,
    },
    TlsServer {
        stream: Arc<Mutex<StreamOwned<ServerConnection, TcpStream>>>,
        framing: Framing,
    },
    Raw(Arc<RawPacketSocket>),
    WebSocket {
        sender: mpsc::Sender<WebSocketCommand>,
        text: bool,
    },
    Quic {
        sender: mpsc::Sender<QuicCommand>,
    },
}

#[derive(Debug)]
enum WebSocketCommand {
    Data(Vec<u8>, bool, mpsc::SyncSender<Result<(), String>>),
    Close,
}
#[derive(Debug)]
enum QuicCommand {
    Data(Vec<u8>, mpsc::SyncSender<Result<(), String>>),
    Close,
}

struct ExternalReader {
    inbox: Inbox,
    peer_role: String,
    alive: Arc<AtomicBool>,
    max_payload: usize,
    max_inbox: usize,
    framing: Framing,
    worker_errors: Arc<Mutex<Vec<TransportError>>>,
}

impl Transport {
    pub fn configured_connect_failure(&self) -> Option<&str> {
        self.config.connect_failure.as_deref()
    }

    /// Create a perfect (no loss, no delay) transport with one inbox per role.
    pub fn new(roles: &[String]) -> Transport {
        Transport::with_config(roles, &TransportConfig::default())
    }

    /// Create a transport with the given lossy/delay/reorder configuration.
    pub fn with_config(roles: &[String], config: &TransportConfig) -> Transport {
        Self::with_options(roles, config, &ResourceLimits::default(), false)
    }

    pub fn with_options(
        roles: &[String],
        config: &TransportConfig,
        limits: &ResourceLimits,
        virtual_time: bool,
    ) -> Transport {
        let mut inboxes = HashMap::new();
        for r in roles {
            inboxes.insert(
                r.clone(),
                Arc::new((Mutex::new(VecDeque::new()), Condvar::new())),
            );
        }
        let random_seed = if config.seed == 0 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(1)
        } else {
            config.seed
        };
        Transport {
            inboxes,
            config: config.clone(),
            random_counter: AtomicU64::new(random_seed),
            send_counter: AtomicU64::new(0),
            burst_remaining: AtomicU64::new(0),
            live_senders: None,
            live_alive: None,
            workers: Arc::new(Mutex::new(Vec::new())),
            worker_errors: Arc::new(Mutex::new(Vec::new())),
            limits: limits.clone(),
            virtual_time,
            network: NetworkProtocol::Tcp,
        }
    }

    /// Create a two-role transport backed by actual TCP or UDP loopback
    /// sockets. `bind` is the listener/server address and may use port zero.
    pub fn live(roles: &[String], bind: &str, udp: bool) -> Result<Transport, String> {
        Self::live_with_limits(roles, bind, udp, &ResourceLimits::default())
    }

    pub fn live_with_limits(
        roles: &[String],
        bind: &str,
        udp: bool,
        limits: &ResourceLimits,
    ) -> Result<Transport, String> {
        if roles.len() != 2 {
            return Err(format!(
                "live transport requires exactly 2 roles, got {}",
                roles.len()
            ));
        }
        let mut transport =
            Transport::with_options(roles, &TransportConfig::default(), limits, false);
        let alive = Arc::new(AtomicBool::new(true));
        let sockets = if udp {
            setup_udp(
                roles,
                bind,
                &transport.inboxes,
                &alive,
                &transport.workers,
                &transport.worker_errors,
                limits,
            )?
        } else {
            setup_tcp(
                roles,
                bind,
                &transport.inboxes,
                &alive,
                &transport.workers,
                &transport.worker_errors,
                limits,
            )?
        };
        transport.live_senders = Some(sockets);
        transport.live_alive = Some(alive);
        transport.network = if udp {
            NetworkProtocol::Udp
        } else {
            NetworkProtocol::Tcp
        };
        Ok(transport)
    }

    /// Connect one local protocol role to an external TCP peer. Unlike
    /// `live`, this carries only segment payload bytes and does not use the
    /// tcpform-internal message envelope.
    pub fn external_tcp(
        roles: &[String],
        local_role: &str,
        peer_role: &str,
        address: &str,
        listen: bool,
        limits: &ResourceLimits,
    ) -> Result<Transport, String> {
        Self::external_tcp_framed(
            roles,
            local_role,
            peer_role,
            address,
            listen,
            limits,
            Framing::Raw,
        )
    }

    pub fn external_tcp_framed(
        roles: &[String],
        local_role: &str,
        peer_role: &str,
        address: &str,
        listen: bool,
        limits: &ResourceLimits,
        framing: Framing,
    ) -> Result<Transport, String> {
        if !roles.iter().any(|role| role == local_role)
            || !roles.iter().any(|role| role == peer_role)
        {
            return Err("external transport roles are not present in the protocol".to_string());
        }
        let mut transport =
            Transport::with_options(roles, &TransportConfig::default(), limits, false);
        let alive = Arc::new(AtomicBool::new(true));
        let stream = if listen {
            let listener = TcpListener::bind(address)
                .map_err(|e| format!("cannot bind external TCP {address}: {e}"))?;
            accept_with_timeout(&listener, limits.connect_timeout_ms, "TCP")?
        } else {
            let mut addresses = address
                .to_socket_addrs()
                .map_err(|e| format!("cannot resolve external TCP {address}: {e}"))?;
            let address_value = addresses
                .next()
                .ok_or_else(|| format!("external TCP {address} resolved to no addresses"))?;
            TcpStream::connect_timeout(
                &address_value,
                Duration::from_millis(limits.connect_timeout_ms),
            )
            .map_err(|e| format!("cannot connect external TCP {address}: {e}"))?
        };
        stream.set_nodelay(true).ok();
        let reader = stream
            .try_clone()
            .map_err(|e| format!("cannot clone external TCP socket: {e}"))?;
        reader
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| format!("cannot configure external TCP socket: {e}"))?;
        let worker = spawn_stream_raw_reader(
            reader,
            ExternalReader {
                inbox: transport.inboxes.get(local_role).unwrap().clone(),
                peer_role: peer_role.to_string(),
                alive: Arc::clone(&alive),
                max_payload: limits.max_payload,
                max_inbox: limits.max_inbox,
                framing: framing.clone(),
                worker_errors: Arc::clone(&transport.worker_errors),
            },
        );
        transport.workers.lock().unwrap().push(worker);
        transport.live_senders = Some(HashMap::from([(
            local_role.to_string(),
            LiveSocket::TcpRaw {
                stream: Arc::new(Mutex::new(stream)),
                framing,
            },
        )]));
        transport.live_alive = Some(alive);
        transport.network = NetworkProtocol::Tcp;
        Ok(transport)
    }

    #[allow(clippy::result_large_err)]
    pub fn external_websocket(
        roles: &[String],
        local_role: &str,
        peer_role: &str,
        endpoint: &str,
        listen: bool,
        limits: &ResourceLimits,
        options: &WebSocketOptions,
    ) -> Result<Transport, String> {
        use tungstenite::client::IntoClientRequest;
        if !roles.iter().any(|role| role == local_role)
            || !roles.iter().any(|role| role == peer_role)
        {
            return Err("external transport roles are not present in the protocol".into());
        }
        let mut transport =
            Transport::with_options(roles, &TransportConfig::default(), limits, false);
        let alive = Arc::new(AtomicBool::new(true));
        let reader = ExternalReader {
            inbox: transport.inboxes.get(local_role).unwrap().clone(),
            peer_role: peer_role.into(),
            alive: Arc::clone(&alive),
            max_payload: limits.max_payload,
            max_inbox: limits.max_inbox,
            framing: Framing::Raw,
            worker_errors: Arc::clone(&transport.worker_errors),
        };
        let live = if listen {
            let address = endpoint
                .strip_prefix("ws://")
                .unwrap_or(endpoint)
                .split('/')
                .next()
                .unwrap_or(endpoint);
            let listener = TcpListener::bind(address)
                .map_err(|e| format!("cannot bind WebSocket {address}: {e}"))?;
            let stream = accept_with_timeout(&listener, limits.connect_timeout_ms, "WebSocket")?;
            let supported = options.subprotocols.clone();
            let socket = tungstenite::accept_hdr(
                stream,
                move |request: &tungstenite::handshake::server::Request,
                      mut response: tungstenite::handshake::server::Response| {
                    if let Some(requested) = request
                        .headers()
                        .get("Sec-WebSocket-Protocol")
                        .and_then(|v| v.to_str().ok())
                    {
                        if let Some(selected) = requested
                            .split(',')
                            .map(str::trim)
                            .find(|value| supported.iter().any(|item| item == value))
                        {
                            if let Ok(value) = selected.parse() {
                                response
                                    .headers_mut()
                                    .insert("Sec-WebSocket-Protocol", value);
                            }
                        }
                    }
                    Ok(response)
                },
            )
            .map_err(|e| format!("WebSocket server handshake failed: {e}"))?;
            socket
                .get_ref()
                .set_nonblocking(true)
                .map_err(|e| e.to_string())?;
            let (sender, receiver) = mpsc::channel();
            transport
                .workers
                .lock()
                .unwrap()
                .push(spawn_websocket_loop(socket, receiver, reader));
            LiveSocket::WebSocket {
                sender,
                text: options.text,
            }
        } else {
            let mut request = endpoint
                .into_client_request()
                .map_err(|e| format!("invalid WebSocket endpoint: {e}"))?;
            if !options.subprotocols.is_empty() {
                request.headers_mut().insert(
                    "Sec-WebSocket-Protocol",
                    options
                        .subprotocols
                        .join(", ")
                        .parse()
                        .map_err(|_| "invalid WebSocket subprotocol")?,
                );
            }
            if let Some(origin) = &options.origin {
                request.headers_mut().insert(
                    "Origin",
                    origin.parse().map_err(|_| "invalid WebSocket origin")?,
                );
            }
            let (mut socket, _) = tungstenite::connect(request)
                .map_err(|e| format!("WebSocket client handshake failed: {e}"))?;
            if let MaybeTlsStream::Plain(stream) = socket.get_mut() {
                stream.set_nonblocking(true).map_err(|e| e.to_string())?;
            }
            let (sender, receiver) = mpsc::channel();
            transport
                .workers
                .lock()
                .unwrap()
                .push(spawn_websocket_loop(socket, receiver, reader));
            LiveSocket::WebSocket {
                sender,
                text: options.text,
            }
        };
        transport.live_senders = Some(HashMap::from([(local_role.into(), live)]));
        transport.live_alive = Some(alive);
        transport.network = NetworkProtocol::WebSocket;
        Ok(transport)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn external_quic(
        roles: &[String],
        local_role: &str,
        peer_role: &str,
        address: &str,
        listen: bool,
        limits: &ResourceLimits,
        options: &TlsOptions,
    ) -> Result<Transport, String> {
        if !roles.iter().any(|role| role == local_role)
            || !roles.iter().any(|role| role == peer_role)
        {
            return Err("external transport roles are not present in the protocol".into());
        }
        let address_value = address
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve QUIC {address}: {e}"))?
            .next()
            .ok_or("QUIC endpoint resolved to no addresses")?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let guard = runtime.enter();
        let setup = if listen {
            let cert_file = options
                .cert_file
                .as_deref()
                .ok_or("QUIC listen mode requires --tls-cert")?;
            let key_file = options
                .key_file
                .as_deref()
                .ok_or("QUIC listen mode requires --tls-key")?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let builder = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?;
            let builder = if options.require_client_auth {
                let ca = options
                    .ca_file
                    .as_deref()
                    .ok_or("QUIC mTLS server requires --ca")?;
                let mut roots = rustls::RootCertStore::empty();
                for cert in load_certificates(ca)? {
                    roots.add(cert).map_err(|e| e.to_string())?
                }
                let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .map_err(|e| e.to_string())?;
                builder.with_client_cert_verifier(verifier)
            } else {
                builder.with_no_client_auth()
            };
            let mut crypto = builder
                .with_single_cert(load_certificates(cert_file)?, load_private_key(key_file)?)
                .map_err(|e| e.to_string())?;
            crypto.alpn_protocols = options
                .alpn_protocols
                .iter()
                .map(|v| v.as_bytes().to_vec())
                .collect();
            let quic = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                .map_err(|e| e.to_string())?;
            let endpoint = quinn::Endpoint::server(
                quinn::ServerConfig::with_crypto(Arc::new(quic)),
                address_value,
            )
            .map_err(|e| format!("cannot bind QUIC {address}: {e}"))?;
            let connection = runtime.block_on(async {
                let incoming = tokio::time::timeout(
                    Duration::from_millis(limits.connect_timeout_ms),
                    endpoint.accept(),
                )
                .await
                .map_err(|_| "QUIC accept timed out".to_string())?
                .ok_or("QUIC endpoint closed")?;
                incoming.await.map_err(|e| e.to_string())
            })?;
            let (send, recv) = runtime.block_on(async {
                tokio::time::timeout(
                    Duration::from_millis(limits.connect_timeout_ms),
                    connection.accept_bi(),
                )
                .await
                .map_err(|_| "QUIC stream accept timed out".to_string())?
                .map_err(|e| e.to_string())
            })?;
            (endpoint, connection, send, recv)
        } else {
            let bind = if address_value.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            }
            .parse()
            .unwrap();
            let mut endpoint = quinn::Endpoint::client(bind).map_err(|e| e.to_string())?;
            let mut roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(ca) = options.ca_file.as_deref() {
                for cert in load_certificates(ca)? {
                    roots.add(cert).map_err(|e| e.to_string())?
                }
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let builder = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_root_certificates(roots);
            let mut crypto = match (options.cert_file.as_deref(), options.key_file.as_deref()) {
                (Some(cert), Some(key)) => builder
                    .with_client_auth_cert(load_certificates(cert)?, load_private_key(key)?)
                    .map_err(|e| e.to_string())?,
                (None, None) => builder.with_no_client_auth(),
                _ => {
                    return Err("QUIC client certificate and key must be specified together".into())
                }
            };
            crypto.alpn_protocols = options
                .alpn_protocols
                .iter()
                .map(|v| v.as_bytes().to_vec())
                .collect();
            let quic = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| e.to_string())?;
            endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
            let server_name = options
                .server_name
                .as_deref()
                .ok_or("QUIC client requires --server-name")?;
            let connection = runtime.block_on(async {
                tokio::time::timeout(
                    Duration::from_millis(limits.connect_timeout_ms),
                    endpoint
                        .connect(address_value, server_name)
                        .map_err(|e| e.to_string())?,
                )
                .await
                .map_err(|_| "QUIC connect timed out".to_string())?
                .map_err(|e| e.to_string())
            })?;
            let (send, recv) = runtime
                .block_on(connection.open_bi())
                .map_err(|e| e.to_string())?;
            (endpoint, connection, send, recv)
        };
        drop(guard);
        let (endpoint, connection, send, recv) = setup;
        let mut transport =
            Transport::with_options(roles, &TransportConfig::default(), limits, false);
        let alive = Arc::new(AtomicBool::new(true));
        let reader = ExternalReader {
            inbox: transport.inboxes.get(local_role).unwrap().clone(),
            peer_role: peer_role.into(),
            alive: Arc::clone(&alive),
            max_payload: limits.max_payload,
            max_inbox: limits.max_inbox,
            framing: Framing::Raw,
            worker_errors: Arc::clone(&transport.worker_errors),
        };
        let (sender, commands) = mpsc::channel();
        transport.workers.lock().unwrap().push(spawn_quic_worker(
            runtime, endpoint, connection, send, recv, commands, reader,
        ));
        transport.live_senders = Some(HashMap::from([(
            local_role.into(),
            LiveSocket::Quic { sender },
        )]));
        transport.live_alive = Some(alive);
        transport.network = NetworkProtocol::Quic;
        Ok(transport)
    }

    #[cfg(unix)]
    pub fn external_unix_framed(
        roles: &[String],
        local_role: &str,
        peer_role: &str,
        path: &str,
        listen: bool,
        limits: &ResourceLimits,
        framing: Framing,
    ) -> Result<Transport, String> {
        if !roles.iter().any(|role| role == local_role)
            || !roles.iter().any(|role| role == peer_role)
        {
            return Err("external transport roles are not present in the protocol".into());
        }
        let mut transport =
            Transport::with_options(roles, &TransportConfig::default(), limits, false);
        let alive = Arc::new(AtomicBool::new(true));
        let stream = if listen {
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path)
                .map_err(|e| format!("cannot bind Unix socket {path}: {e}"))?;
            listener.set_nonblocking(true).map_err(|e| e.to_string())?;
            let deadline = Instant::now() + Duration::from_millis(limits.connect_timeout_ms);
            loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        return Err(format!(
                            "Unix socket accept timed out after {}ms",
                            limits.connect_timeout_ms
                        ))
                    }
                    Err(e) => return Err(format!("cannot accept Unix socket {path}: {e}")),
                }
            }
        } else {
            UnixStream::connect(path)
                .map_err(|e| format!("cannot connect Unix socket {path}: {e}"))?
        };
        let reader = stream
            .try_clone()
            .map_err(|e| format!("cannot clone Unix socket: {e}"))?;
        reader
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| format!("cannot configure Unix socket: {e}"))?;
        let worker = spawn_stream_raw_reader(
            reader,
            ExternalReader {
                inbox: transport.inboxes.get(local_role).unwrap().clone(),
                peer_role: peer_role.into(),
                alive: Arc::clone(&alive),
                max_payload: limits.max_payload,
                max_inbox: limits.max_inbox,
                framing: framing.clone(),
                worker_errors: Arc::clone(&transport.worker_errors),
            },
        );
        transport.workers.lock().unwrap().push(worker);
        transport.live_senders = Some(HashMap::from([(
            local_role.into(),
            LiveSocket::UnixRaw {
                stream: Arc::new(Mutex::new(stream)),
                framing,
            },
        )]));
        transport.live_alive = Some(alive);
        transport.network = NetworkProtocol::Tcp;
        Ok(transport)
    }

    pub fn external_udp(
        roles: &[String],
        local_role: &str,
        peer_role: &str,
        address: &str,
        listen: bool,
        limits: &ResourceLimits,
    ) -> Result<Transport, String> {
        Self::external_udp_with_options(
            roles,
            local_role,
            peer_role,
            address,
            listen,
            limits,
            &UdpOptions::default(),
        )
    }

    pub fn external_udp_with_options(
        roles: &[String],
        local_role: &str,
        peer_role: &str,
        address: &str,
        listen: bool,
        limits: &ResourceLimits,
        options: &UdpOptions,
    ) -> Result<Transport, String> {
        if !roles.iter().any(|role| role == local_role)
            || !roles.iter().any(|role| role == peer_role)
        {
            return Err("external transport roles are not present in the protocol".to_string());
        }
        let mut transport =
            Transport::with_options(roles, &TransportConfig::default(), limits, false);
        let alive = Arc::new(AtomicBool::new(true));
        let peer = Arc::new(Mutex::new(None));
        let socket = if listen {
            UdpSocket::bind(address)
                .map_err(|e| format!("cannot bind external UDP {address}: {e}"))?
        } else {
            let address_value = address
                .to_socket_addrs()
                .map_err(|e| format!("cannot resolve external UDP {address}: {e}"))?
                .next()
                .ok_or_else(|| format!("external UDP {address} resolved to no addresses"))?;
            let bind = if address_value.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let socket = UdpSocket::bind(bind)
                .map_err(|e| format!("cannot bind external UDP client: {e}"))?;
            *peer.lock().unwrap() = Some(address_value);
            socket
        };
        socket
            .set_broadcast(options.broadcast)
            .map_err(|e| format!("cannot configure UDP broadcast: {e}"))?;
        if options.reuse_address {
            set_socket_reuse_address(&socket)?;
        }
        if let Some(group) = options.multicast_group.as_deref() {
            let address: std::net::IpAddr = group
                .parse()
                .map_err(|_| format!("invalid multicast group `{group}`"))?;
            if !address.is_multicast() {
                return Err(format!("address `{group}` is not multicast"));
            }
            match address {
                std::net::IpAddr::V4(group) => {
                    let interface = options
                        .multicast_interface
                        .as_deref()
                        .unwrap_or("0.0.0.0")
                        .parse()
                        .map_err(|_| "IPv4 multicast interface must be an IPv4 address")?;
                    socket
                        .join_multicast_v4(&group, &interface)
                        .map_err(|e| format!("cannot join IPv4 multicast group {group}: {e}"))?;
                    if let Some(ttl) = options.multicast_ttl {
                        socket
                            .set_multicast_ttl_v4(ttl)
                            .map_err(|e| e.to_string())?;
                    }
                }
                std::net::IpAddr::V6(group) => {
                    let interface = options
                        .multicast_interface
                        .as_deref()
                        .unwrap_or("0")
                        .parse::<u32>()
                        .map_err(|_| "IPv6 multicast interface must be an interface index")?;
                    socket
                        .join_multicast_v6(&group, interface)
                        .map_err(|e| format!("cannot join IPv6 multicast group {group}: {e}"))?;
                }
            }
        }
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| format!("cannot configure external UDP socket: {e}"))?;
        let reader = socket
            .try_clone()
            .map_err(|e| format!("cannot clone external UDP socket: {e}"))?;
        transport.workers.lock().unwrap().push(spawn_udp_raw_reader(
            reader,
            Arc::clone(&peer),
            ExternalReader {
                inbox: transport.inboxes.get(local_role).unwrap().clone(),
                peer_role: peer_role.to_string(),
                alive: Arc::clone(&alive),
                max_payload: limits.max_payload.min(65_507),
                max_inbox: limits.max_inbox,
                framing: Framing::Raw,
                worker_errors: Arc::clone(&transport.worker_errors),
            },
        ));
        transport.live_senders = Some(HashMap::from([(
            local_role.to_string(),
            LiveSocket::UdpRaw {
                socket: Arc::new(socket),
                peer,
            },
        )]));
        transport.live_alive = Some(alive);
        transport.network = NetworkProtocol::Udp;
        Ok(transport)
    }

    /// Open a Linux AF_PACKET endpoint for complete Ethernet frames.
    ///
    /// No promiscuous mode is enabled unless it is explicitly requested in
    /// `config`. Opening the socket may require root or `CAP_NET_RAW`.
    pub fn external_raw(
        roles: &[String],
        local_role: &str,
        peer_role: &str,
        config: RawSocketConfig,
        limits: &ResourceLimits,
    ) -> Result<Transport, String> {
        if !roles.iter().any(|role| role == local_role)
            || !roles.iter().any(|role| role == peer_role)
        {
            return Err("external transport roles are not present in the protocol".to_string());
        }
        let mut transport =
            Transport::with_options(roles, &TransportConfig::default(), limits, false);
        let alive = Arc::new(AtomicBool::new(true));
        let socket = Arc::new(RawPacketSocket::open(config).map_err(|error| error.to_string())?);
        transport.workers.lock().unwrap().push(spawn_raw_reader(
            Arc::clone(&socket),
            ExternalReader {
                inbox: transport.inboxes.get(local_role).unwrap().clone(),
                peer_role: peer_role.to_string(),
                alive: Arc::clone(&alive),
                max_payload: limits.max_payload,
                max_inbox: limits.max_inbox,
                framing: Framing::Raw,
                worker_errors: Arc::clone(&transport.worker_errors),
            },
        ));
        transport.live_senders = Some(HashMap::from([(
            local_role.to_string(),
            LiveSocket::Raw(socket),
        )]));
        transport.live_alive = Some(alive);
        transport.network = NetworkProtocol::Raw;
        Ok(transport)
    }

    // The explicit endpoint arguments keep this public API parallel with the
    // TCP/UDP constructors; TLS adds framing and credential options.
    #[allow(clippy::too_many_arguments)]
    pub fn external_tls(
        roles: &[String],
        local_role: &str,
        peer_role: &str,
        address: &str,
        listen: bool,
        limits: &ResourceLimits,
        framing: Framing,
        options: &TlsOptions,
    ) -> Result<Transport, String> {
        if !roles.iter().any(|role| role == local_role)
            || !roles.iter().any(|role| role == peer_role)
        {
            return Err("external transport roles are not present in the protocol".to_string());
        }
        let mut transport =
            Transport::with_options(roles, &TransportConfig::default(), limits, false);
        let alive = Arc::new(AtomicBool::new(true));
        let socket = if listen {
            let listener = TcpListener::bind(address)
                .map_err(|e| format!("cannot bind external TLS {address}: {e}"))?;
            accept_with_timeout(&listener, limits.connect_timeout_ms, "TLS")?
        } else {
            let address_value = address
                .to_socket_addrs()
                .map_err(|e| format!("cannot resolve external TLS {address}: {e}"))?
                .next()
                .ok_or_else(|| format!("external TLS {address} resolved to no addresses"))?;
            TcpStream::connect_timeout(
                &address_value,
                Duration::from_millis(limits.connect_timeout_ms),
            )
            .map_err(|e| format!("cannot connect external TLS {address}: {e}"))?
        };
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("cannot configure external TLS socket: {e}"))?;

        let inbox = transport.inboxes.get(local_role).unwrap().clone();
        let peer_name = peer_role.to_string();
        let live_socket = if listen {
            let cert_file = options.cert_file.as_deref().ok_or_else(|| {
                "TLS listen mode requires --tls-cert <certificate.pem>".to_string()
            })?;
            let key_file = options.key_file.as_deref().ok_or_else(|| {
                "TLS listen mode requires --tls-key <private-key.pem>".to_string()
            })?;
            let certs = load_certificates(cert_file)?;
            let key = load_private_key(key_file)?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let builder = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| format!("cannot configure TLS versions: {e}"))?;
            let builder = if options.require_client_auth {
                let ca_file = options
                    .ca_file
                    .as_deref()
                    .ok_or("mTLS server requires --ca <client-ca.pem>")?;
                let mut roots = rustls::RootCertStore::empty();
                for certificate in load_certificates(ca_file)? {
                    roots
                        .add(certificate)
                        .map_err(|e| format!("cannot add client CA certificate: {e}"))?;
                }
                let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .map_err(|e| format!("cannot configure mTLS client verification: {e}"))?;
                builder.with_client_cert_verifier(verifier)
            } else {
                builder.with_no_client_auth()
            };
            let mut config = builder
                .with_single_cert(certs, key)
                .map_err(|e| format!("cannot configure TLS certificate: {e}"))?;
            config.alpn_protocols = options
                .alpn_protocols
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect();
            let connection = ServerConnection::new(Arc::new(config))
                .map_err(|e| format!("cannot create TLS server: {e}"))?;
            let stream = Arc::new(Mutex::new(StreamOwned::new(connection, socket)));
            transport
                .workers
                .lock()
                .unwrap()
                .push(spawn_tls_server_reader(
                    Arc::clone(&stream),
                    ExternalReader {
                        inbox,
                        peer_role: peer_name,
                        alive: Arc::clone(&alive),
                        max_payload: limits.max_payload,
                        max_inbox: limits.max_inbox,
                        framing: framing.clone(),
                        worker_errors: Arc::clone(&transport.worker_errors),
                    },
                ));
            LiveSocket::TlsServer { stream, framing }
        } else {
            let mut roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(path) = options.ca_file.as_deref() {
                for certificate in load_certificates(path)? {
                    roots
                        .add(certificate)
                        .map_err(|e| format!("cannot add CA certificate: {e}"))?;
                }
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let builder = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| format!("cannot configure TLS versions: {e}"))?
                .with_root_certificates(roots);
            let mut config = match (options.cert_file.as_deref(), options.key_file.as_deref()) {
                (Some(cert), Some(key)) => builder
                    .with_client_auth_cert(load_certificates(cert)?, load_private_key(key)?)
                    .map_err(|e| format!("cannot configure TLS client certificate: {e}"))?,
                (None, None) => builder.with_no_client_auth(),
                _ => return Err("TLS client certificate and key must be specified together".into()),
            };
            config.alpn_protocols = options
                .alpn_protocols
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect();
            let server_name = options
                .server_name
                .clone()
                .or_else(|| address.rsplit_once(':').map(|(host, _)| host.to_string()))
                .ok_or_else(|| "TLS client requires --server-name".to_string())?;
            let server_name = ServerName::try_from(server_name)
                .map_err(|e| format!("invalid TLS server name: {e}"))?;
            let connection = ClientConnection::new(Arc::new(config), server_name)
                .map_err(|e| format!("cannot create TLS client: {e}"))?;
            let stream = Arc::new(Mutex::new(StreamOwned::new(connection, socket)));
            transport
                .workers
                .lock()
                .unwrap()
                .push(spawn_tls_client_reader(
                    Arc::clone(&stream),
                    ExternalReader {
                        inbox,
                        peer_role: peer_name,
                        alive: Arc::clone(&alive),
                        max_payload: limits.max_payload,
                        max_inbox: limits.max_inbox,
                        framing: framing.clone(),
                        worker_errors: Arc::clone(&transport.worker_errors),
                    },
                ));
            LiveSocket::TlsClient { stream, framing }
        };
        transport.live_senders = Some(HashMap::from([(local_role.to_string(), live_socket)]));
        transport.live_alive = Some(alive);
        transport.network = NetworkProtocol::Tls;
        Ok(transport)
    }

    pub fn network_protocol(&self) -> NetworkProtocol {
        self.network
    }

    /// Half-close the outbound side of a live stream while keeping its reader alive.
    pub fn half_close(&self, role: &str) -> Result<(), String> {
        let Some(socket) = self
            .live_senders
            .as_ref()
            .and_then(|sockets| sockets.get(role))
        else {
            return Ok(());
        };
        match socket {
            LiveSocket::Tcp(stream) => stream
                .lock()
                .map_err(|_| "TCP socket lock poisoned")?
                .shutdown(Shutdown::Write)
                .map_err(|e| e.to_string()),
            LiveSocket::TcpRaw { stream, .. } => stream
                .lock()
                .map_err(|_| "TCP socket lock poisoned")?
                .shutdown(Shutdown::Write)
                .map_err(|e| e.to_string()),
            #[cfg(unix)]
            LiveSocket::UnixRaw { stream, .. } => stream
                .lock()
                .map_err(|_| "Unix socket lock poisoned")?
                .shutdown(Shutdown::Write)
                .map_err(|e| e.to_string()),
            LiveSocket::WebSocket { sender, .. } => sender
                .send(WebSocketCommand::Close)
                .map_err(|_| "WebSocket worker stopped".into()),
            LiveSocket::Quic { sender } => sender
                .send(QuicCommand::Close)
                .map_err(|_| "QUIC worker stopped".into()),
            LiveSocket::TlsClient { stream, .. } => {
                let mut stream = stream.lock().map_err(|_| "TLS socket lock poisoned")?;
                stream.conn.send_close_notify();
                stream.flush().map_err(|e| e.to_string())
            }
            LiveSocket::TlsServer { stream, .. } => {
                let mut stream = stream.lock().map_err(|_| "TLS socket lock poisoned")?;
                stream.conn.send_close_notify();
                stream.flush().map_err(|e| e.to_string())
            }
            LiveSocket::Udp(_) | LiveSocket::UdpRaw { .. } | LiveSocket::Raw(_) => Ok(()),
        }
    }

    /// Get the inbox handle for a role (used by that role's executor to recv).
    pub fn inbox(&self, role: &str) -> Option<Inbox> {
        self.inboxes.get(role).cloned()
    }
    /// Send `msg` to role `to`, applying loss/delay/reorder from the config.
    /// `extra_delay_ms` overlays the transport-level delay (from `segment.delay`).
    pub fn send(
        &self,
        to: &str,
        msg: Message,
        extra_delay_ms: u64,
    ) -> Result<DeliveryReport, TransportError> {
        self.send_scoped(to, msg, extra_delay_ms, None)
    }

    /// Send with the originating DSL step, allowing transport fault scopes.
    pub fn send_scoped(
        &self,
        to: &str,
        mut msg: Message,
        extra_delay_ms: u64,
        step: Option<&str>,
    ) -> Result<DeliveryReport, TransportError> {
        let inbox = self
            .inboxes
            .get(to)
            .ok_or_else(|| TransportError::transport(format!("unknown destination role `{to}`")))?;

        let eligible = (self.config.fault_steps.is_empty()
            || step.is_some_and(|name| self.config.fault_steps.iter().any(|item| item == name)))
            && self
                .config
                .fault_flag
                .as_ref()
                .is_none_or(|flag| msg.flags.iter().any(|item| item == flag))
            && self
                .config
                .fault_when
                .as_ref()
                .is_none_or(|predicate| fault_predicate_matches(&msg, predicate));
        let ordinal = if eligible {
            self.send_counter.fetch_add(1, Ordering::SeqCst) + 1
        } else {
            0
        };
        if eligible && self.config.port_capacity > 0 && ordinal > self.config.port_capacity {
            return Err(TransportError::resource_limit(format!(
                "simulated ephemeral port capacity {} exhausted on eligible send {ordinal}",
                self.config.port_capacity
            )));
        }
        let continuing_burst = eligible
            && self
                .burst_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    (remaining > 0).then(|| remaining - 1)
                })
                .is_ok();
        let random_drop =
            eligible && self.config.loss_rate > 0.0 && self.next_random() < self.config.loss_rate;
        let nth_drop = eligible && self.config.drop_nth > 0 && ordinal == self.config.drop_nth;
        if eligible && self.config.disconnect_nth > 0 && ordinal == self.config.disconnect_nth {
            return Err(TransportError::transport(format!(
                "simulated link disconnect on eligible send {ordinal}"
            )));
        }
        if random_drop && self.config.burst_loss > 1 {
            self.burst_remaining
                .store((self.config.burst_loss - 1) as u64, Ordering::SeqCst);
        }
        // Probabilistic, ordinal, or burst loss: drop the segment silently.
        if continuing_burst || random_drop || nth_drop {
            return Ok(DeliveryReport {
                dropped: true,
                delay_ms: self.config.delay_ms.saturating_add(extra_delay_ms),
                reordered: false,
                duplicated: false,
                corrupted: false,
            });
        }

        if let Some(address) = &self.config.nat_source_ip {
            for key in ["ip.source", "ipv4.source", "ipv6.source"] {
                if msg.fields.contains_key(key) {
                    msg.fields.insert(
                        key.to_string(),
                        crate::value::Value::String(address.clone()),
                    );
                }
            }
            msg.fields.insert(
                "nat.original_role".to_string(),
                crate::value::Value::String(msg.from.clone()),
            );
        }
        if let Some(port) = self.config.nat_source_port {
            for key in ["tcp.source_port", "udp.source_port"] {
                if msg.fields.contains_key(key) {
                    msg.fields
                        .insert(key.to_string(), crate::value::Value::Number(port as f64));
                }
            }
        }

        let corrupted = eligible
            && self.config.corrupt_rate > 0.0
            && self.next_random() < self.config.corrupt_rate;
        if corrupted {
            if let Some(first) = msg.raw.first_mut() {
                *first ^= 0x80;
            } else if !msg.payload.is_empty() {
                let end = msg.payload.chars().next().map(char::len_utf8).unwrap_or(0);
                msg.payload.replace_range(..end, "�");
            }
        }
        let duplicated = eligible
            && self.config.duplicate_rate > 0.0
            && self.next_random() < self.config.duplicate_rate;

        let jitter = if self.config.jitter_ms == 0 {
            0i128
        } else {
            let span = self.config.jitter_ms.saturating_mul(2).saturating_add(1);
            (self.next_random_u64() % span) as i128 - self.config.jitter_ms as i128
        };
        let spike_delay = if eligible
            && self.config.delay_spike_nth > 0
            && ordinal == self.config.delay_spike_nth
        {
            self.config.delay_spike_ms
        } else {
            0
        };
        let base_delay = self
            .config
            .delay_ms
            .saturating_add(extra_delay_ms)
            .saturating_add(spike_delay);
        let effective_bandwidth =
            if self.config.bandwidth_after_nth > 0 && ordinal >= self.config.bandwidth_after_nth {
                self.config.bandwidth_after_bps
            } else {
                self.config.bandwidth_bps
            };
        let serialization_delay = if effective_bandwidth == 0 {
            0
        } else {
            (msg.payload_len() as u64)
                .saturating_mul(8)
                .saturating_mul(1_000)
                .div_ceil(effective_bandwidth)
        };
        let total_delay = ((base_delay as i128 + jitter).max(0).min(u64::MAX as i128) as u64)
            .saturating_add(serialization_delay);
        // Pick the insertion value in send order, before a delayed-delivery
        // thread is spawned. This keeps reorder deterministic when `seed` is
        // set, even if delivery itself happens asynchronously.
        let reorder_value = self.config.reorder.then(|| self.next_random_u64());
        let live_socket = match &self.live_senders {
            Some(senders) => Some(senders.get(&msg.from).cloned().ok_or_else(|| {
                TransportError::transport(format!(
                    "live transport has no socket for role `{}`",
                    msg.from
                ))
            })?),
            None => None,
        };

        if msg.payload_len() > self.limits.max_payload {
            return Err(TransportError::resource_limit(format!(
                "payload size {} exceeds max_payload {}",
                msg.payload_len(),
                self.limits.max_payload
            )));
        }
        if self.config.mtu > 0 && msg.payload_len() > self.config.mtu && self.config.mtu_blackhole {
            return Ok(DeliveryReport {
                dropped: true,
                delay_ms: total_delay,
                reordered: false,
                duplicated: false,
                corrupted,
            });
        }
        if self.config.mtu > 0 && msg.payload_len() > self.config.mtu {
            return Err(TransportError::resource_limit(format!(
                "payload size {} exceeds transport mtu {}",
                msg.payload_len(),
                self.config.mtu
            )));
        }
        if live_socket.is_none() {
            let queued = inbox
                .0
                .lock()
                .map_err(|_| TransportError::transport("inbox lock poisoned"))?
                .len();
            if queued >= self.limits.max_inbox {
                return Err(TransportError::resource_limit(format!(
                    "destination inbox `{to}` reached max_inbox {}",
                    self.limits.max_inbox
                )));
            }
        }

        if total_delay > 0 && self.virtual_time {
            deliver_copies(
                inbox,
                msg,
                reorder_value,
                live_socket,
                self.limits.max_inbox,
                duplicated,
            )?;
        } else if total_delay > 0 && live_socket.is_some() {
            // A live socket can fail while delivering. Keep this path
            // synchronous so the executor observes that failure instead of
            // reporting a successful send from a detached thread.
            thread::sleep(Duration::from_millis(total_delay));
            deliver_copies(
                inbox,
                msg,
                reorder_value,
                live_socket,
                self.limits.max_inbox,
                duplicated,
            )?;
        } else if total_delay > 0 {
            // Delayed delivery: spawn a thread that sleeps then pushes
            let inbox = Arc::clone(inbox);
            let errors = Arc::clone(&self.worker_errors);
            let max_inbox = self.limits.max_inbox;
            let worker = thread::spawn(move || {
                thread::sleep(Duration::from_millis(total_delay));
                if let Err(error) = deliver_copies(
                    &inbox,
                    msg,
                    reorder_value,
                    live_socket,
                    max_inbox,
                    duplicated,
                ) {
                    errors.lock().unwrap().push(error);
                }
            });
            self.workers.lock().unwrap().push(worker);
        } else {
            deliver_copies(
                inbox,
                msg,
                reorder_value,
                live_socket,
                self.limits.max_inbox,
                duplicated,
            )?;
        }
        Ok(DeliveryReport {
            dropped: false,
            delay_ms: total_delay,
            reordered: reorder_value.is_some(),
            duplicated,
            corrupted,
        })
    }

    /// Deterministic pseudo-random float in [0, 1). `with_config` chooses a
    /// time-based initial state when `seed` is zero.
    fn next_random(&self) -> f64 {
        (self.next_random_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// SplitMix64 output derived from an atomically advancing counter.
    fn next_random_u64(&self) -> u64 {
        let mut z = self
            .random_counter
            .fetch_add(0x9e3779b97f4a7c15, Ordering::SeqCst)
            .wrapping_add(0x9e3779b97f4a7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    /// Stop background readers/deliveries, join every worker and return any
    /// asynchronous failures. Safe to call more than once.
    pub fn finish(&self) -> Result<(), TransportError> {
        if let Some(alive) = &self.live_alive {
            alive.store(false, Ordering::SeqCst);
        }
        let workers = std::mem::take(&mut *self.workers.lock().unwrap());
        for worker in workers {
            if worker.join().is_err() {
                self.worker_errors
                    .lock()
                    .unwrap()
                    .push(TransportError::transport("transport worker panicked"));
            }
        }
        let errors = std::mem::take(&mut *self.worker_errors.lock().unwrap());
        if errors.is_empty() {
            Ok(())
        } else {
            let kind = if errors
                .iter()
                .any(|error| error.kind == TransportErrorKind::ResourceLimit)
            {
                TransportErrorKind::ResourceLimit
            } else {
                TransportErrorKind::Transport
            };
            Err(TransportError {
                kind,
                message: errors
                    .into_iter()
                    .map(|error| error.message)
                    .collect::<Vec<_>>()
                    .join("; "),
            })
        }
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        if let Some(alive) = &self.live_alive {
            alive.store(false, Ordering::SeqCst);
        }
        let _ = self.finish();
    }
}

fn fault_predicate_matches(msg: &Message, predicate: &crate::model::FaultPredicate) -> bool {
    let actual = match predicate.field.as_str() {
        "seq" => Some(Value::Number(msg.seq as f64)),
        "ack" => Some(Value::Number(msg.ack as f64)),
        "window" => Some(Value::Number(msg.window as f64)),
        "stream" => msg.stream.map(|value| Value::Number(value as f64)),
        "from" => Some(Value::String(msg.from.clone())),
        "payload" => Some(Value::String(msg.payload.clone())),
        field if field.starts_with("fields.") => msg.fields.get(&field[7..]).cloned(),
        field => packet::decode_ethernet(&msg.raw)
            .or_else(|_| packet::decode_ip(&msg.raw))
            .ok()
            .and_then(|decoded| packet::decoded_fields(&decoded).remove(field)),
    };
    actual.as_ref() == Some(&predicate.equals)
}

fn deliver_copies(
    inbox: &Inbox,
    msg: Message,
    reorder_value: Option<u64>,
    live_socket: Option<LiveSocket>,
    max_inbox: usize,
    duplicated: bool,
) -> Result<(), TransportError> {
    if duplicated {
        deliver(
            inbox,
            msg.clone(),
            reorder_value,
            live_socket.clone(),
            max_inbox,
        )?;
    }
    deliver(inbox, msg, reorder_value, live_socket, max_inbox)
}

fn deliver(
    inbox: &Inbox,
    msg: Message,
    reorder_value: Option<u64>,
    live_socket: Option<LiveSocket>,
    max_inbox: usize,
) -> Result<(), TransportError> {
    if let Some(socket) = live_socket {
        socket.send_message(&msg).map_err(TransportError::transport)
    } else {
        push_message_limited(inbox, msg, reorder_value, max_inbox)
    }
}

fn accept_with_timeout(
    listener: &TcpListener,
    timeout_ms: u64,
    protocol: &str,
) -> Result<TcpStream, String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("cannot configure external {protocol} listener: {e}"))?;
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "external {protocol} accept timed out after {timeout_ms}ms"
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("cannot accept external {protocol}: {error}")),
        }
    }
}

/// Push a message into an inbox, optionally at a random position for reordering.
fn push_message_limited(
    inbox: &Inbox,
    msg: Message,
    reorder_value: Option<u64>,
    max_inbox: usize,
) -> Result<(), TransportError> {
    let (lock, cv) = &**inbox;
    {
        let mut q = lock.lock().unwrap();
        if q.len() >= max_inbox {
            return Err(TransportError::resource_limit(format!(
                "inbox reached max_inbox {max_inbox}"
            )));
        }
        if let Some(random) = reorder_value.filter(|_| !q.is_empty()) {
            let pos = random as usize % (q.len() + 1);
            if pos == q.len() {
                q.push_back(msg);
            } else {
                q.insert(pos, msg);
            }
        } else {
            q.push_back(msg);
        }
    }
    cv.notify_one();
    Ok(())
}

fn record_worker_error<E: Into<TransportError>>(
    errors: &Mutex<Vec<TransportError>>,
    alive: &AtomicBool,
    error: E,
) {
    if alive.load(Ordering::SeqCst) {
        errors.lock().unwrap().push(error.into());
    }
}

#[cfg(unix)]
fn set_socket_reuse_address(socket: &UdpSocket) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "cannot configure UDP SO_REUSEADDR: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(not(unix))]
fn set_socket_reuse_address(_socket: &UdpSocket) -> Result<(), String> {
    Err("UDP address reuse is not supported on this platform".into())
}

impl LiveSocket {
    fn send_message(&self, message: &Message) -> Result<(), String> {
        let payload = encode_message(message)?;
        match self {
            LiveSocket::Tcp(stream) => {
                let mut stream = stream.lock().map_err(|_| "TCP socket lock poisoned")?;
                let length = u32::try_from(payload.len())
                    .map_err(|_| "live message exceeds 4 GiB".to_string())?;
                stream
                    .write_all(&length.to_be_bytes())
                    .and_then(|_| stream.write_all(&payload))
                    .map_err(|e| format!("TCP send failed: {e}"))
            }
            LiveSocket::TcpRaw { stream, framing } => {
                let bytes = if message.raw.is_empty() {
                    message.payload.as_bytes()
                } else {
                    &message.raw
                };
                let framed = frame_outbound(bytes, framing)?;
                stream
                    .lock()
                    .map_err(|_| "TCP socket lock poisoned".to_string())?
                    .write_all(&framed)
                    .map_err(|e| format!("external TCP send failed: {e}"))
            }
            #[cfg(unix)]
            LiveSocket::UnixRaw { stream, framing } => {
                let bytes = if message.raw.is_empty() {
                    message.payload.as_bytes()
                } else {
                    &message.raw
                };
                let framed = frame_outbound(bytes, framing)?;
                stream
                    .lock()
                    .map_err(|_| "Unix socket lock poisoned".to_string())?
                    .write_all(&framed)
                    .map_err(|e| format!("external Unix socket send failed: {e}"))
            }
            LiveSocket::Udp(socket) => {
                if payload.len() > 65_507 {
                    return Err("UDP live message exceeds 65507 bytes".to_string());
                }
                socket
                    .send(&payload)
                    .map_err(|e| format!("UDP send failed: {e}"))?;
                Ok(())
            }
            LiveSocket::UdpRaw { socket, peer } => {
                let bytes = if message.raw.is_empty() {
                    message.payload.as_bytes()
                } else {
                    &message.raw
                };
                if bytes.len() > 65_507 {
                    return Err("external UDP payload exceeds 65507 bytes".to_string());
                }
                let destination = peer
                    .lock()
                    .map_err(|_| "external UDP peer lock poisoned".to_string())?
                    .ok_or_else(|| {
                        "external UDP listener has not received a peer datagram".to_string()
                    })?;
                socket
                    .send_to(bytes, destination)
                    .map_err(|e| format!("external UDP send failed: {e}"))?;
                Ok(())
            }
            LiveSocket::TlsClient { stream, framing } => send_tls(stream, framing, message),
            LiveSocket::TlsServer { stream, framing } => send_tls(stream, framing, message),
            LiveSocket::Raw(socket) => {
                if message.raw.is_empty() {
                    return Err("raw transport requires an encoded Ethernet frame".to_string());
                }
                let written = socket
                    .send(&message.raw)
                    .map_err(|error| format!("raw send failed: {error}"))?;
                if written != message.raw.len() {
                    return Err(format!(
                        "raw send was truncated: wrote {written} of {} bytes",
                        message.raw.len()
                    ));
                }
                Ok(())
            }
            LiveSocket::WebSocket { sender, text } => send_websocket(sender, *text, message),
            LiveSocket::Quic { sender } => {
                let bytes = if message.raw.is_empty() {
                    message.payload.as_bytes()
                } else {
                    &message.raw
                };
                let (ack_tx, ack_rx) = mpsc::sync_channel(0);
                sender
                    .send(QuicCommand::Data(bytes.to_vec(), ack_tx))
                    .map_err(|_| "QUIC worker stopped".to_string())?;
                ack_rx
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|_| "QUIC send acknowledgement timed out".to_string())?
            }
        }
    }
}

fn send_websocket(
    sender: &mpsc::Sender<WebSocketCommand>,
    text: bool,
    message: &Message,
) -> Result<(), String> {
    let bytes = if message.raw.is_empty() {
        message.payload.as_bytes()
    } else {
        &message.raw
    };
    if text {
        String::from_utf8(bytes.to_vec()).map_err(|_| "WebSocket text payload is not UTF-8")?;
    }
    let (ack_tx, ack_rx) = mpsc::sync_channel(0);
    sender
        .send(WebSocketCommand::Data(bytes.to_vec(), text, ack_tx))
        .map_err(|_| "WebSocket worker stopped".to_string())?;
    ack_rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "WebSocket send acknowledgement timed out".to_string())?
}

fn send_tls<S>(stream: &Arc<Mutex<S>>, framing: &Framing, message: &Message) -> Result<(), String>
where
    S: Write,
{
    let bytes = if message.raw.is_empty() {
        message.payload.as_bytes()
    } else {
        &message.raw
    };
    let framed = frame_outbound(bytes, framing)?;
    let mut offset = 0;
    while offset < framed.len() {
        let result = stream
            .lock()
            .map_err(|_| "TLS stream lock poisoned".to_string())?
            .write(&framed[offset..]);
        match result {
            Ok(0) => return Err("external TLS send made no progress".to_string()),
            Ok(written) => offset += written,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(format!("external TLS send failed: {error}")),
        }
    }
    loop {
        match stream
            .lock()
            .map_err(|_| "TLS stream lock poisoned".to_string())?
            .flush()
        {
            Ok(()) => return Ok(()),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(format!("external TLS flush failed: {error}")),
        }
    }
}

fn load_certificates(
    path: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let file = File::open(path).map_err(|e| format!("cannot open certificate {path}: {e}"))?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse certificate {path}: {e}"))
}

fn load_private_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    let file = File::open(path).map_err(|e| format!("cannot open private key {path}: {e}"))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .map_err(|e| format!("cannot parse private key {path}: {e}"))?
        .ok_or_else(|| format!("no private key found in {path}"))
}

fn frame_outbound(bytes: &[u8], framing: &Framing) -> Result<Vec<u8>, String> {
    match framing {
        Framing::Raw => Ok(bytes.to_vec()),
        Framing::LengthPrefix => {
            let length = u32::try_from(bytes.len())
                .map_err(|_| "external frame exceeds 4 GiB".to_string())?;
            let mut framed = length.to_be_bytes().to_vec();
            framed.extend_from_slice(bytes);
            Ok(framed)
        }
        Framing::Delimiter(delimiter) => {
            if delimiter.is_empty() {
                return Err("external delimiter must not be empty".to_string());
            }
            let mut framed = bytes.to_vec();
            framed.extend_from_slice(delimiter);
            Ok(framed)
        }
        Framing::Fixed(size) => {
            if bytes.len() != *size {
                return Err(format!(
                    "external fixed frame requires {size} bytes, got {}",
                    bytes.len()
                ));
            }
            Ok(bytes.to_vec())
        }
    }
}

fn setup_tcp(
    roles: &[String],
    bind: &str,
    inboxes: &HashMap<String, Inbox>,
    alive: &Arc<AtomicBool>,
    workers: &Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    worker_errors: &Arc<Mutex<Vec<TransportError>>>,
    limits: &ResourceLimits,
) -> Result<HashMap<String, LiveSocket>, String> {
    let listener = TcpListener::bind(bind).map_err(|e| format!("cannot bind TCP {bind}: {e}"))?;
    let address = listener
        .local_addr()
        .map_err(|e| format!("cannot read TCP bind address: {e}"))?;
    let client = TcpStream::connect(address)
        .map_err(|e| format!("cannot connect TCP loopback {address}: {e}"))?;
    let (server, _) = listener
        .accept()
        .map_err(|e| format!("cannot accept TCP connection: {e}"))?;
    client.set_nodelay(true).ok();
    server.set_nodelay(true).ok();

    let mut sockets = HashMap::new();
    for (role, stream) in [(&roles[0], client), (&roles[1], server)] {
        let reader = stream
            .try_clone()
            .map_err(|e| format!("cannot clone TCP socket: {e}"))?;
        reader
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| format!("cannot configure TCP socket: {e}"))?;
        workers.lock().unwrap().push(spawn_tcp_reader(
            reader,
            inboxes.get(role).unwrap().clone(),
            Arc::clone(alive),
            limits.max_payload,
            limits.max_inbox,
            Arc::clone(worker_errors),
        ));
        sockets.insert(role.clone(), LiveSocket::Tcp(Arc::new(Mutex::new(stream))));
    }
    Ok(sockets)
}

fn spawn_tcp_reader(
    mut stream: TcpStream,
    inbox: Inbox,
    alive: Arc<AtomicBool>,
    max_payload: usize,
    max_inbox: usize,
    worker_errors: Arc<Mutex<Vec<TransportError>>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while alive.load(Ordering::SeqCst) {
            let mut length = [0u8; 4];
            match read_exact_live(&mut stream, &mut length, &alive) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    record_worker_error(
                        &worker_errors,
                        &alive,
                        format!("TCP read failed: {error}"),
                    );
                    break;
                }
            }
            let length = u32::from_be_bytes(length) as usize;
            if length > max_payload {
                record_worker_error(
                    &worker_errors,
                    &alive,
                    format!("live TCP frame size {length} exceeds max_payload {max_payload}"),
                );
                break;
            }
            let mut payload = vec![0u8; length];
            match read_exact_live(&mut stream, &mut payload, &alive) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    record_worker_error(
                        &worker_errors,
                        &alive,
                        format!("TCP read failed: {error}"),
                    );
                    break;
                }
            }
            match decode_message(&payload) {
                Ok(message) => {
                    if let Err(error) = push_message_limited(&inbox, message, None, max_inbox) {
                        record_worker_error(&worker_errors, &alive, error);
                        break;
                    }
                }
                Err(error) => {
                    record_worker_error(
                        &worker_errors,
                        &alive,
                        format!("invalid live TCP frame: {error}"),
                    );
                    break;
                }
            }
        }
    })
}

fn spawn_websocket_loop<S: Read + Write + Send + 'static>(
    mut socket: WebSocket<S>,
    commands: mpsc::Receiver<WebSocketCommand>,
    reader: ExternalReader,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while reader.alive.load(Ordering::SeqCst) {
            while let Ok(command) = commands.try_recv() {
                let (result, ack) = match command {
                    WebSocketCommand::Data(bytes, true, ack) => (
                        socket.send(WebSocketMessage::Text(
                            String::from_utf8(bytes).expect("validated UTF-8").into(),
                        )),
                        Some(ack),
                    ),
                    WebSocketCommand::Data(bytes, false, ack) => (
                        socket.send(WebSocketMessage::Binary(bytes.into())),
                        Some(ack),
                    ),
                    WebSocketCommand::Close => {
                        let result = socket.close(None);
                        reader.alive.store(false, Ordering::SeqCst);
                        (result, None)
                    }
                };
                if let Some(ack) = ack {
                    let _ = ack.send(
                        result
                            .as_ref()
                            .map(|_| ())
                            .map_err(|error| error.to_string()),
                    );
                }
                if let Err(error) = result {
                    record_worker_error(
                        &reader.worker_errors,
                        &reader.alive,
                        format!("WebSocket send failed: {error}"),
                    );
                    return;
                }
            }
            let frame = socket.read();
            match frame {
                Ok(WebSocketMessage::Binary(bytes)) => {
                    if bytes.len() > reader.max_payload {
                        record_worker_error(
                            &reader.worker_errors,
                            &reader.alive,
                            TransportError::resource_limit(format!(
                                "WebSocket frame exceeds max_payload {}",
                                reader.max_payload
                            )),
                        );
                        break;
                    }
                    if let Err(error) = push_raw_message(
                        &reader.inbox,
                        &reader.peer_role,
                        bytes.to_vec(),
                        reader.max_inbox,
                    ) {
                        record_worker_error(&reader.worker_errors, &reader.alive, error);
                        break;
                    }
                }
                Ok(WebSocketMessage::Text(text)) => {
                    let bytes = text.as_bytes();
                    if bytes.len() > reader.max_payload {
                        record_worker_error(
                            &reader.worker_errors,
                            &reader.alive,
                            TransportError::resource_limit(format!(
                                "WebSocket frame exceeds max_payload {}",
                                reader.max_payload
                            )),
                        );
                        break;
                    }
                    if let Err(error) = push_raw_message(
                        &reader.inbox,
                        &reader.peer_role,
                        bytes.to_vec(),
                        reader.max_inbox,
                    ) {
                        record_worker_error(&reader.worker_errors, &reader.alive, error);
                        break;
                    }
                }
                Ok(WebSocketMessage::Ping(bytes)) => {
                    let _ = socket.send(WebSocketMessage::Pong(bytes));
                }
                Ok(WebSocketMessage::Pong(_) | WebSocketMessage::Frame(_)) => {}
                Ok(WebSocketMessage::Close(_)) => break,
                Err(tungstenite::Error::Io(error)) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                    break
                }
                Err(error) => {
                    record_worker_error(
                        &reader.worker_errors,
                        &reader.alive,
                        format!("WebSocket receive failed: {error}"),
                    );
                    break;
                }
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_quic_worker(
    runtime: tokio::runtime::Runtime,
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    commands: mpsc::Receiver<QuicCommand>,
    reader: ExternalReader,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        runtime.block_on(async move {
            let mut pending = Vec::new();
            while reader.alive.load(Ordering::SeqCst) {
                while let Ok(command) = commands.try_recv() {
                    match command {
                        QuicCommand::Data(bytes, ack) => {
                            if bytes.len() > reader.max_payload {
                                let message = format!(
                                    "QUIC message exceeds max_payload {}",
                                    reader.max_payload
                                );
                                let _ = ack.send(Err(message.clone()));
                                record_worker_error(
                                    &reader.worker_errors,
                                    &reader.alive,
                                    TransportError::resource_limit(format!(
                                        "QUIC message exceeds max_payload {}",
                                        reader.max_payload
                                    )),
                                );
                                return;
                            }
                            let length = match u32::try_from(bytes.len()) {
                                Ok(value) => value,
                                Err(_) => {
                                    let _ = ack.send(Err("QUIC message exceeds 4 GiB".into()));
                                    record_worker_error(
                                        &reader.worker_errors,
                                        &reader.alive,
                                        "QUIC message exceeds 4 GiB".to_string(),
                                    );
                                    return;
                                }
                            };
                            let result = send.write_all(&length.to_be_bytes()).await;
                            let result = match result {
                                Ok(()) => send.write_all(&bytes).await,
                                Err(error) => Err(error),
                            };
                            if let Err(error) = result {
                                let _ = ack.send(Err(error.to_string()));
                                record_worker_error(
                                    &reader.worker_errors,
                                    &reader.alive,
                                    format!("QUIC send failed: {error}"),
                                );
                                return;
                            }
                            let _ = ack.send(Ok(()));
                        }
                        QuicCommand::Close => {
                            let _ = send.finish();
                            connection.close(0u32.into(), b"tcpform close");
                            reader.alive.store(false, Ordering::SeqCst);
                            return;
                        }
                    }
                }
                match tokio::time::timeout(
                    Duration::from_millis(5),
                    recv.read_chunk(reader.max_payload.clamp(1, 65_535), true),
                )
                .await
                {
                    Ok(Ok(Some(chunk))) => {
                        pending.extend_from_slice(&chunk.bytes);
                        loop {
                            if pending.len() < 4 {
                                break;
                            }
                            let length =
                                u32::from_be_bytes(pending[..4].try_into().unwrap()) as usize;
                            if length > reader.max_payload {
                                record_worker_error(
                                    &reader.worker_errors,
                                    &reader.alive,
                                    TransportError::resource_limit(format!(
                                        "QUIC message exceeds max_payload {}",
                                        reader.max_payload
                                    )),
                                );
                                return;
                            }
                            if pending.len() < 4 + length {
                                break;
                            }
                            let bytes = pending[4..4 + length].to_vec();
                            pending.drain(..4 + length);
                            if let Err(error) = push_raw_message(
                                &reader.inbox,
                                &reader.peer_role,
                                bytes,
                                reader.max_inbox,
                            ) {
                                record_worker_error(&reader.worker_errors, &reader.alive, error);
                                return;
                            }
                        }
                    }
                    Ok(Ok(None)) => return,
                    Ok(Err(error)) => {
                        record_worker_error(
                            &reader.worker_errors,
                            &reader.alive,
                            format!("QUIC receive failed: {error}"),
                        );
                        return;
                    }
                    Err(_) => {}
                }
            }
        })
    })
}

fn spawn_stream_raw_reader<R: Read + Send + 'static>(
    mut stream: R,
    reader: ExternalReader,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let ExternalReader {
            inbox,
            peer_role,
            alive,
            max_payload,
            max_inbox,
            framing,
            worker_errors,
        } = reader;
        let mut buffer = vec![0u8; max_payload.clamp(1, 65_535)];
        let mut pending = Vec::new();
        while alive.load(Ordering::SeqCst) {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    pending.extend_from_slice(&buffer[..length]);
                    match drain_frames(&mut pending, &framing, max_payload) {
                        Ok(frames) => {
                            for raw in frames {
                                if let Err(error) =
                                    push_raw_message(&inbox, &peer_role, raw, max_inbox)
                                {
                                    record_worker_error(&worker_errors, &alive, error);
                                    return;
                                }
                            }
                        }
                        Err(error) => {
                            record_worker_error(&worker_errors, &alive, error);
                            return;
                        }
                    }
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => break,
            }
        }
        if framing == Framing::Raw && !pending.is_empty() {
            if let Err(error) = push_raw_message(&inbox, &peer_role, pending, max_inbox) {
                record_worker_error(&worker_errors, &alive, error);
            }
        }
    })
}

fn drain_frames(
    pending: &mut Vec<u8>,
    framing: &Framing,
    max_payload: usize,
) -> Result<Vec<Vec<u8>>, TransportError> {
    let mut frames = Vec::new();
    loop {
        let frame = match framing {
            Framing::Raw => {
                if pending.is_empty() {
                    None
                } else {
                    Some(std::mem::take(pending))
                }
            }
            Framing::LengthPrefix => {
                if pending.len() < 4 {
                    None
                } else {
                    let length = u32::from_be_bytes(pending[..4].try_into().unwrap()) as usize;
                    if length > max_payload {
                        return Err(TransportError::resource_limit(format!(
                            "external frame size {length} exceeds max_payload {max_payload}"
                        )));
                    }
                    if pending.len() < length + 4 {
                        None
                    } else {
                        let frame = pending[4..4 + length].to_vec();
                        pending.drain(..4 + length);
                        Some(frame)
                    }
                }
            }
            Framing::Delimiter(delimiter) => {
                let found = pending
                    .windows(delimiter.len())
                    .position(|window| window == delimiter)
                    .map(|position| {
                        let frame = pending[..position].to_vec();
                        pending.drain(..position + delimiter.len());
                        frame
                    });
                if found.is_none() && pending.len() > max_payload.saturating_add(delimiter.len()) {
                    return Err(TransportError::resource_limit(format!(
                        "external delimited frame exceeds max_payload {max_payload}"
                    )));
                }
                found
            }
            Framing::Fixed(size) if *size > 0 && pending.len() >= *size => {
                Some(pending.drain(..*size).collect())
            }
            Framing::Fixed(_) => None,
        };
        match frame {
            Some(frame) => frames.push(frame),
            None => break,
        }
    }
    Ok(frames)
}

fn push_raw_message(
    inbox: &Inbox,
    peer_role: &str,
    raw: Vec<u8>,
    max_inbox: usize,
) -> Result<(), TransportError> {
    push_message_limited(
        inbox,
        Message {
            from: peer_role.to_string(),
            flags: Vec::new(),
            seq: 0,
            ack: 0,
            payload: String::from_utf8_lossy(&raw).into_owned(),
            raw,
            window: 0,
            stream: None,
            fields: HashMap::new(),
        },
        None,
        max_inbox,
    )
}

fn spawn_raw_reader(
    socket: Arc<RawPacketSocket>,
    reader: ExternalReader,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let ExternalReader {
            inbox,
            peer_role,
            alive,
            max_payload,
            max_inbox,
            worker_errors,
            ..
        } = reader;
        while alive.load(Ordering::SeqCst) {
            match socket.receive(Duration::from_millis(100)) {
                Ok(Some(raw)) => {
                    if raw.len() > max_payload {
                        record_worker_error(
                            &worker_errors,
                            &alive,
                            TransportError::resource_limit(format!(
                                "raw frame size {} exceeds max_payload {max_payload}",
                                raw.len()
                            )),
                        );
                        break;
                    }
                    let message = raw_frame_message(&peer_role, raw);
                    if let Err(error) = push_message_limited(&inbox, message, None, max_inbox) {
                        record_worker_error(&worker_errors, &alive, error);
                        break;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    record_worker_error(
                        &worker_errors,
                        &alive,
                        format!("raw receive failed on {}: {error}", socket.interface()),
                    );
                    break;
                }
            }
        }
    })
}

fn raw_frame_message(peer_role: &str, raw: Vec<u8>) -> Message {
    let mut message = Message {
        from: peer_role.to_string(),
        flags: Vec::new(),
        seq: 0,
        ack: 0,
        payload: String::new(),
        raw,
        window: 0,
        stream: None,
        fields: HashMap::new(),
    };
    match packet::decode_ethernet(&message.raw) {
        Ok(decoded) => {
            message.fields = packet::decoded_fields(&decoded);
            message.payload = String::from_utf8_lossy(&decoded.packet.payload).into_owned();
            if let Some(TransportHeader::Tcp(tcp)) = decoded.packet.transport.as_ref() {
                message.flags = packet::tcp_flag_names(tcp.flags);
                message.seq = i64::from(tcp.sequence);
                message.ack = i64::from(tcp.acknowledgment);
                message.window = i64::from(tcp.window);
            }
        }
        Err(error) => {
            // Malformed frames are data in a packet-fuzzing tool. Keep them
            // matchable by hex instead of terminating the receive worker.
            message.fields.insert(
                "raw.decode_error".to_string(),
                Value::String(error.to_string()),
            );
        }
    }
    message
}

fn spawn_udp_raw_reader(
    socket: UdpSocket,
    peer: Arc<Mutex<Option<SocketAddr>>>,
    reader: ExternalReader,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let ExternalReader {
            inbox,
            peer_role,
            alive,
            max_payload,
            max_inbox,
            worker_errors,
            ..
        } = reader;
        let mut payload = vec![0u8; max_payload.max(1)];
        while alive.load(Ordering::SeqCst) {
            match socket.recv_from(&mut payload) {
                Ok((length, source)) => {
                    *peer.lock().unwrap() = Some(source);
                    if let Err(error) =
                        push_raw_message(&inbox, &peer_role, payload[..length].to_vec(), max_inbox)
                    {
                        record_worker_error(&worker_errors, &alive, error);
                        break;
                    }
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => break,
            }
        }
    })
}

fn spawn_tls_client_reader(
    stream: Arc<Mutex<StreamOwned<ClientConnection, TcpStream>>>,
    reader: ExternalReader,
) -> thread::JoinHandle<()> {
    spawn_tls_reader(stream, reader)
}

fn spawn_tls_server_reader(
    stream: Arc<Mutex<StreamOwned<ServerConnection, TcpStream>>>,
    reader: ExternalReader,
) -> thread::JoinHandle<()> {
    spawn_tls_reader(stream, reader)
}

fn spawn_tls_reader<S>(stream: Arc<Mutex<S>>, reader: ExternalReader) -> thread::JoinHandle<()>
where
    S: Read + Send + 'static,
{
    thread::spawn(move || {
        let ExternalReader {
            inbox,
            peer_role,
            alive,
            max_payload,
            max_inbox,
            framing,
            worker_errors,
        } = reader;
        let mut buffer = vec![0u8; max_payload.clamp(1, 65_535)];
        let mut pending = Vec::new();
        while alive.load(Ordering::SeqCst) {
            let result = stream
                .lock()
                .map_err(|_| ErrorKind::Other)
                .and_then(|mut stream| stream.read(&mut buffer).map_err(|error| error.kind()));
            match result {
                Ok(0) => break,
                Ok(length) => {
                    pending.extend_from_slice(&buffer[..length]);
                    match drain_frames(&mut pending, &framing, max_payload) {
                        Ok(frames) => {
                            for raw in frames {
                                if let Err(error) =
                                    push_raw_message(&inbox, &peer_role, raw, max_inbox)
                                {
                                    record_worker_error(&worker_errors, &alive, error);
                                    return;
                                }
                            }
                        }
                        Err(error) => {
                            record_worker_error(&worker_errors, &alive, error);
                            return;
                        }
                    }
                }
                Err(ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(_) => break,
            }
        }
    })
}

/// Read one framed component without discarding bytes already received when a
/// socket timeout occurs. `Read::read_exact` cannot be restarted safely after
/// a timeout because it does not expose how many bytes it consumed.
fn read_exact_live(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    alive: &AtomicBool,
) -> std::io::Result<bool> {
    let mut offset = 0;
    while offset < buffer.len() && alive.load(Ordering::SeqCst) {
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => return Ok(false),
            Ok(read) => offset += read,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(offset == buffer.len())
}

fn setup_udp(
    roles: &[String],
    bind: &str,
    inboxes: &HashMap<String, Inbox>,
    alive: &Arc<AtomicBool>,
    workers: &Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    worker_errors: &Arc<Mutex<Vec<TransportError>>>,
    limits: &ResourceLimits,
) -> Result<HashMap<String, LiveSocket>, String> {
    let server = UdpSocket::bind(bind).map_err(|e| format!("cannot bind UDP {bind}: {e}"))?;
    let server_address = server
        .local_addr()
        .map_err(|e| format!("cannot read UDP bind address: {e}"))?;
    let client_bind = if server_address.is_ipv6() {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    };
    let client = UdpSocket::bind(client_bind)
        .map_err(|e| format!("cannot bind UDP client {client_bind}: {e}"))?;
    let client_address = client
        .local_addr()
        .map_err(|e| format!("cannot read UDP client address: {e}"))?;
    client
        .connect(server_address)
        .map_err(|e| format!("cannot connect UDP client: {e}"))?;
    server
        .connect(client_address)
        .map_err(|e| format!("cannot connect UDP server: {e}"))?;

    let mut sockets = HashMap::new();
    for (role, socket) in [(&roles[0], client), (&roles[1], server)] {
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| format!("cannot configure UDP socket: {e}"))?;
        let reader = socket
            .try_clone()
            .map_err(|e| format!("cannot clone UDP socket: {e}"))?;
        workers.lock().unwrap().push(spawn_udp_reader(
            reader,
            inboxes.get(role).unwrap().clone(),
            Arc::clone(alive),
            limits.max_payload,
            limits.max_inbox,
            Arc::clone(worker_errors),
        ));
        sockets.insert(role.clone(), LiveSocket::Udp(Arc::new(socket)));
    }
    Ok(sockets)
}

fn spawn_udp_reader(
    socket: UdpSocket,
    inbox: Inbox,
    alive: Arc<AtomicBool>,
    max_payload: usize,
    max_inbox: usize,
    worker_errors: Arc<Mutex<Vec<TransportError>>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut payload = vec![0u8; max_payload.min(65_507).saturating_add(1).max(1)];
        while alive.load(Ordering::SeqCst) {
            match socket.recv(&mut payload) {
                Ok(length) => {
                    if length > max_payload {
                        record_worker_error(
                            &worker_errors,
                            &alive,
                            format!("live UDP datagram exceeds max_payload {max_payload}"),
                        );
                        break;
                    }
                    match decode_message(&payload[..length]) {
                        Ok(message) => {
                            if let Err(error) =
                                push_message_limited(&inbox, message, None, max_inbox)
                            {
                                record_worker_error(&worker_errors, &alive, error);
                                break;
                            }
                        }
                        Err(error) => {
                            record_worker_error(
                                &worker_errors,
                                &alive,
                                format!("invalid live UDP datagram: {error}"),
                            );
                            break;
                        }
                    }
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => break,
            }
        }
    })
}

fn encode_message(message: &Message) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    put_string(&mut out, &message.from)?;
    put_u32(&mut out, message.flags.len())?;
    for flag in &message.flags {
        put_string(&mut out, flag)?;
    }
    out.extend_from_slice(&message.seq.to_be_bytes());
    out.extend_from_slice(&message.ack.to_be_bytes());
    put_string(&mut out, &message.payload)?;
    put_bytes(&mut out, &message.raw)?;
    out.extend_from_slice(&message.window.to_be_bytes());
    match message.stream {
        Some(stream) => {
            out.push(1);
            out.extend_from_slice(&stream.to_be_bytes());
        }
        None => out.push(0),
    }
    let mut fields: Vec<_> = message.fields.iter().collect();
    fields.sort_by_key(|(key, _)| *key);
    put_u32(&mut out, fields.len())?;
    for (key, value) in fields {
        put_string(&mut out, key)?;
        encode_value(&mut out, value)?;
    }
    Ok(out)
}

fn decode_message(payload: &[u8]) -> Result<Message, String> {
    let mut cursor = Cursor::new(payload);
    let from = cursor.string()?;
    let flags_len = cursor.u32()? as usize;
    let mut flags = Vec::with_capacity(flags_len);
    for _ in 0..flags_len {
        flags.push(cursor.string()?);
    }
    let seq = cursor.i64()?;
    let ack = cursor.i64()?;
    let text = cursor.string()?;
    let raw = cursor.bytes()?;
    let window = cursor.i64()?;
    let stream = match cursor.byte()? {
        0 => None,
        1 => Some(cursor.i64()?),
        tag => return Err(format!("invalid stream tag {tag}")),
    };
    let fields_len = cursor.u32()? as usize;
    let mut fields = HashMap::with_capacity(fields_len);
    for _ in 0..fields_len {
        fields.insert(cursor.string()?, cursor.value()?);
    }
    if !cursor.is_empty() {
        return Err("trailing bytes in live message".to_string());
    }
    Ok(Message {
        from,
        flags,
        seq,
        ack,
        payload: text,
        raw,
        window,
        stream,
        fields,
    })
}

fn put_u32(out: &mut Vec<u8>, value: usize) -> Result<(), String> {
    let value = u32::try_from(value).map_err(|_| "live value is too large".to_string())?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    put_u32(out, value.len())?;
    out.extend_from_slice(value);
    Ok(())
}

fn put_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    put_bytes(out, value.as_bytes())
}

fn encode_value(out: &mut Vec<u8>, value: &Value) -> Result<(), String> {
    match value {
        Value::Null => out.push(0),
        Value::Bool(value) => {
            out.push(1);
            out.push(u8::from(*value));
        }
        Value::Number(value) => {
            out.push(2);
            out.extend_from_slice(&value.to_bits().to_be_bytes());
        }
        Value::String(value) => {
            out.push(3);
            put_string(out, value)?;
        }
        Value::Bytes(value) => {
            out.push(4);
            put_bytes(out, value)?;
        }
        Value::Array(values) => {
            out.push(5);
            put_u32(out, values.len())?;
            for value in values {
                encode_value(out, value)?;
            }
        }
        Value::Object(values) => {
            out.push(6);
            let mut values: Vec<_> = values.iter().collect();
            values.sort_by_key(|(key, _)| *key);
            put_u32(out, values.len())?;
            for (key, value) in values {
                put_string(out, key)?;
                encode_value(out, value)?;
            }
        }
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| "live message length overflow".to_string())?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| "truncated live message".to_string())?;
        self.position = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn i64(&mut self) -> Result<i64, String> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let length = self.u32()? as usize;
        Ok(self.take(length)?.to_vec())
    }

    fn string(&mut self) -> Result<String, String> {
        String::from_utf8(self.bytes()?).map_err(|e| format!("invalid UTF-8 in live message: {e}"))
    }

    fn value(&mut self) -> Result<Value, String> {
        match self.byte()? {
            0 => Ok(Value::Null),
            1 => Ok(Value::Bool(match self.byte()? {
                0 => false,
                1 => true,
                tag => return Err(format!("invalid bool tag {tag}")),
            })),
            2 => Ok(Value::Number(f64::from_bits(u64::from_be_bytes(
                self.take(8)?.try_into().unwrap(),
            )))),
            3 => Ok(Value::String(self.string()?)),
            4 => Ok(Value::Bytes(self.bytes()?)),
            5 => {
                let length = self.u32()? as usize;
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    values.push(self.value()?);
                }
                Ok(Value::Array(values))
            }
            6 => {
                let length = self.u32()? as usize;
                let mut values = HashMap::with_capacity(length);
                for _ in 0..length {
                    values.insert(self.string()?, self.value()?);
                }
                Ok(Value::Object(values))
            }
            tag => Err(format!("invalid live value tag {tag}")),
        }
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}
