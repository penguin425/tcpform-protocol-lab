//! Safe packet construction and parsing for raw Ethernet/IP transports.
//!
//! The codec never performs I/O and is therefore usable without privileges.
//! Length and checksum fields can be automatic, explicitly overridden, or
//! deliberately corrupted for negative protocol tests.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use crate::value::Value;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const IP_PROTOCOL_TCP: u8 = 6;
pub const IP_PROTOCOL_UDP: u8 = 17;
pub const IP_PROTOCOL_FRAGMENT: u8 = 44;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketError(pub String);

impl fmt::Display for PacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PacketError {}

fn error(message: impl Into<String>) -> PacketError {
    PacketError(message.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = PacketError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = value.split(':').collect();
        if parts.len() != 6 {
            return Err(error(format!("invalid MAC address `{value}`")));
        }
        let mut bytes = [0; 6];
        for (index, part) in parts.into_iter().enumerate() {
            if part.len() != 2 {
                return Err(error(format!("invalid MAC address `{value}`")));
            }
            bytes[index] = u8::from_str_radix(part, 16)
                .map_err(|_| error(format!("invalid MAC address `{value}`")))?;
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Checksum {
    #[default]
    Auto,
    Value(u16),
    Invalid,
}

impl Checksum {
    fn resolve(self, calculated: u16) -> u16 {
        match self {
            Self::Auto => calculated,
            Self::Value(value) => value,
            Self::Invalid => calculated ^ 0xffff,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetHeader {
    pub destination: MacAddr,
    pub source: MacAddr,
    pub vlan: Option<VlanTag>,
    pub ether_type: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanTag {
    pub priority: u8,
    pub drop_eligible: bool,
    pub id: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkHeader {
    Ipv4(Ipv4Header),
    Ipv6(Ipv6Header),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub dscp: u8,
    pub ecn: u8,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// Offset in eight-byte units.
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: Option<u8>,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub options: Vec<u8>,
    pub ihl: Option<u8>,
    pub total_length: Option<u16>,
    pub checksum: Checksum,
}

impl Default for Ipv4Header {
    fn default() -> Self {
        Self {
            dscp: 0,
            ecn: 0,
            identification: 0,
            dont_fragment: false,
            more_fragments: false,
            fragment_offset: 0,
            ttl: 64,
            protocol: None,
            source: Ipv4Addr::UNSPECIFIED,
            destination: Ipv4Addr::UNSPECIFIED,
            options: Vec::new(),
            ihl: None,
            total_length: None,
            checksum: Checksum::Auto,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: Option<u16>,
    pub next_header: Option<u8>,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub fragment: Option<Ipv6Fragment>,
}

impl Default for Ipv6Header {
    fn default() -> Self {
        Self {
            traffic_class: 0,
            flow_label: 0,
            payload_length: None,
            next_header: None,
            hop_limit: 64,
            source: Ipv6Addr::UNSPECIFIED,
            destination: Ipv6Addr::UNSPECIFIED,
            fragment: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Fragment {
    /// Header following the fragment extension.
    pub next_header: u8,
    /// Offset in eight-byte units.
    pub offset: u16,
    pub more_fragments: bool,
    pub identification: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportHeader {
    Tcp(TcpHeader),
    Udp(UdpHeader),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u16,
    pub window: u16,
    pub urgent_pointer: u16,
    pub options: Vec<TcpOption>,
    pub data_offset: Option<u8>,
    pub checksum: Checksum,
}

impl Default for TcpHeader {
    fn default() -> Self {
        Self {
            source_port: 0,
            destination_port: 0,
            sequence: 0,
            acknowledgment: 0,
            flags: 0,
            window: 65_535,
            urgent_pointer: 0,
            options: Vec::new(),
            data_offset: None,
            checksum: Checksum::Auto,
        }
    }
}

pub mod tcp_flag {
    pub const FIN: u16 = 0x001;
    pub const SYN: u16 = 0x002;
    pub const RST: u16 = 0x004;
    pub const PSH: u16 = 0x008;
    pub const ACK: u16 = 0x010;
    pub const URG: u16 = 0x020;
    pub const ECE: u16 = 0x040;
    pub const CWR: u16 = 0x080;
    pub const NS: u16 = 0x100;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOption {
    End,
    Nop,
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(Vec<(u32, u32)>),
    Timestamp { value: u32, echo: u32 },
    Unknown { kind: u8, data: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: Option<u16>,
    pub checksum: Checksum,
}

impl Default for UdpHeader {
    fn default() -> Self {
        Self {
            source_port: 0,
            destination_port: 0,
            length: None,
            checksum: Checksum::Auto,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub ethernet: Option<EthernetHeader>,
    pub network: NetworkHeader,
    pub transport: Option<TransportHeader>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPacket {
    pub packet: Packet,
    /// Bytes following the IP header (including any transport header).
    pub network_payload: Vec<u8>,
    pub ipv4_checksum_valid: Option<bool>,
    pub transport_checksum_valid: Option<bool>,
    pub trailing: Vec<u8>,
}

impl Packet {
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        let protocol = self.protocol()?;
        let transport = encode_transport(&self.network, self.transport.as_ref(), &self.payload)?;
        let mut network_payload = transport;
        network_payload.extend_from_slice(&self.payload);
        let ip = match &self.network {
            NetworkHeader::Ipv4(header) => encode_ipv4(header, protocol, &network_payload)?,
            NetworkHeader::Ipv6(header) => encode_ipv6(header, protocol, &network_payload)?,
        };
        if let Some(ethernet) = &self.ethernet {
            encode_ethernet(ethernet, &self.network, &ip)
        } else {
            Ok(ip)
        }
    }

    fn protocol(&self) -> Result<u8, PacketError> {
        let inferred = match self.transport {
            Some(TransportHeader::Tcp(_)) => Some(IP_PROTOCOL_TCP),
            Some(TransportHeader::Udp(_)) => Some(IP_PROTOCOL_UDP),
            None => None,
        };
        let configured = match &self.network {
            NetworkHeader::Ipv4(header) => header.protocol,
            NetworkHeader::Ipv6(header) => header
                .fragment
                .map(|fragment| fragment.next_header)
                .or(header.next_header),
        };
        configured
            .or(inferred)
            .ok_or_else(|| error("raw IP payload requires an explicit protocol/next_header"))
    }
}

pub fn decode_ethernet(bytes: &[u8]) -> Result<DecodedPacket, PacketError> {
    if bytes.len() < 14 {
        return Err(error("truncated Ethernet header"));
    }
    let destination = MacAddr(bytes[0..6].try_into().unwrap());
    let source = MacAddr(bytes[6..12].try_into().unwrap());
    let mut ether_type = u16::from_be_bytes(bytes[12..14].try_into().unwrap());
    let mut offset = 14;
    let vlan = if ether_type == ETHERTYPE_VLAN {
        if bytes.len() < 18 {
            return Err(error("truncated VLAN header"));
        }
        let control = u16::from_be_bytes(bytes[14..16].try_into().unwrap());
        ether_type = u16::from_be_bytes(bytes[16..18].try_into().unwrap());
        offset = 18;
        Some(VlanTag {
            priority: (control >> 13) as u8,
            drop_eligible: control & 0x1000 != 0,
            id: control & 0x0fff,
        })
    } else {
        None
    };
    let ethernet = EthernetHeader {
        destination,
        source,
        vlan,
        ether_type: Some(ether_type),
    };
    decode_ip_inner(&bytes[offset..], Some(ethernet))
}

pub fn decode_ip(bytes: &[u8]) -> Result<DecodedPacket, PacketError> {
    decode_ip_inner(bytes, None)
}

/// Canonical TCP flag names in wire-bit order.
pub fn tcp_flag_names(flags: u16) -> Vec<String> {
    [
        (tcp_flag::FIN, "FIN"),
        (tcp_flag::SYN, "SYN"),
        (tcp_flag::RST, "RST"),
        (tcp_flag::PSH, "PSH"),
        (tcp_flag::ACK, "ACK"),
        (tcp_flag::URG, "URG"),
        (tcp_flag::ECE, "ECE"),
        (tcp_flag::CWR, "CWR"),
        (tcp_flag::NS, "NS"),
    ]
    .into_iter()
    .filter(|(bit, _)| flags & bit != 0)
    .map(|(_, name)| name.to_string())
    .collect()
}

/// Endpoint-side TCP lifecycle used by optional strict raw-flow validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TcpState {
    #[default]
    Closed,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpDirection {
    Outbound,
    Inbound,
}

/// Minimal, deterministic TCP handshake/teardown validator. It deliberately
/// tracks lifecycle rather than retransmission/congestion behavior; malformed
/// TCP tests can leave it disabled with `raw_tcp_stateful = false`.
#[derive(Debug, Clone, Default)]
pub struct TcpStateTracker {
    state: TcpState,
}

impl TcpStateTracker {
    pub fn state(&self) -> TcpState {
        self.state
    }

    pub fn observe(
        &mut self,
        direction: TcpDirection,
        flags: u16,
    ) -> Result<TcpState, PacketError> {
        let syn = flags & tcp_flag::SYN != 0;
        let ack = flags & tcp_flag::ACK != 0;
        let fin = flags & tcp_flag::FIN != 0;
        if flags & tcp_flag::RST != 0 {
            self.state = TcpState::Reset;
            return Ok(self.state);
        }
        use TcpDirection::{Inbound, Outbound};
        use TcpState::*;
        self.state = match (self.state, direction, syn, ack, fin) {
            (Closed, Outbound, true, false, false) => SynSent,
            (Closed, Inbound, true, false, false) => SynReceived,
            (SynSent, Inbound, true, true, false) => Established,
            (SynReceived, Outbound, true, true, false) => SynReceived,
            (SynReceived, Inbound, false, true, false) => Established,
            (Established, Outbound, _, _, true) => FinWait1,
            (Established, Inbound, _, _, true) => CloseWait,
            (FinWait1, Inbound, _, true, false) => FinWait2,
            (FinWait1, Inbound, _, _, true) => TimeWait,
            (FinWait2, Inbound, _, _, true) => TimeWait,
            (CloseWait, Outbound, _, _, true) => LastAck,
            (LastAck, Inbound, _, true, false) => Closed,
            (
                state @ (SynSent | SynReceived | Established | FinWait1 | FinWait2 | CloseWait),
                _,
                false,
                _,
                false,
            ) => state,
            (TimeWait, _, false, true, false) => TimeWait,
            (state, _, _, _, _) => {
                return Err(error(format!(
                    "invalid TCP {:?} transition in {state:?} with flags {:?}",
                    direction,
                    tcp_flag_names(flags)
                )))
            }
        };
        Ok(self.state)
    }
}

/// Flatten decoded headers into stable dotted field names used by raw
/// `recv_raw` matchers and captures.
pub fn decoded_fields(decoded: &DecodedPacket) -> HashMap<String, Value> {
    let mut fields = HashMap::new();
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
            fields.insert(
                "ethernet.vlan_drop_eligible".to_string(),
                Value::Bool(vlan.drop_eligible),
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
            fields.insert("ipv4.dscp".to_string(), Value::Number(header.dscp as f64));
            fields.insert("ipv4.ecn".to_string(), Value::Number(header.ecn as f64));
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
            fields.insert(
                "ipv4.dont_fragment".to_string(),
                Value::Bool(header.dont_fragment),
            );
            fields.insert(
                "ipv4.protocol".to_string(),
                Value::Number(header.protocol.unwrap_or(0) as f64),
            );
            fields.insert(
                "ipv4.ihl".to_string(),
                Value::Number(header.ihl.unwrap_or(0) as f64),
            );
            fields.insert(
                "ipv4.total_length".to_string(),
                Value::Number(header.total_length.unwrap_or(0) as f64),
            );
            fields.insert(
                "ipv4.options".to_string(),
                Value::Bytes(header.options.clone()),
            );
            fields.insert(
                "ipv4.checksum".to_string(),
                Value::Number(checksum_number(header.checksum) as f64),
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
            fields.insert(
                "ipv6.traffic_class".to_string(),
                Value::Number(header.traffic_class as f64),
            );
            fields.insert(
                "ipv6.payload_length".to_string(),
                Value::Number(header.payload_length.unwrap_or(0) as f64),
            );
            fields.insert(
                "ipv6.next_header".to_string(),
                Value::Number(header.next_header.unwrap_or(0) as f64),
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
                fields.insert(
                    "ipv6.fragment_next_header".to_string(),
                    Value::Number(fragment.next_header as f64),
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
                "tcp.urgent_pointer".to_string(),
                Value::Number(header.urgent_pointer as f64),
            );
            fields.insert(
                "tcp.data_offset".to_string(),
                Value::Number(header.data_offset.unwrap_or(0) as f64),
            );
            fields.insert(
                "tcp.checksum".to_string(),
                Value::Number(checksum_number(header.checksum) as f64),
            );
            fields.insert(
                "tcp.options_count".to_string(),
                Value::Number(header.options.len() as f64),
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
            for (name, bit) in [
                ("fin", tcp_flag::FIN),
                ("syn", tcp_flag::SYN),
                ("rst", tcp_flag::RST),
                ("psh", tcp_flag::PSH),
                ("ack_flag", tcp_flag::ACK),
                ("urg", tcp_flag::URG),
                ("ece", tcp_flag::ECE),
                ("cwr", tcp_flag::CWR),
                ("ns", tcp_flag::NS),
            ] {
                fields.insert(format!("tcp.{name}"), Value::Bool(header.flags & bit != 0));
            }
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
            fields.insert(
                "udp.checksum".to_string(),
                Value::Number(checksum_number(header.checksum) as f64),
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

fn checksum_number(checksum: Checksum) -> u16 {
    match checksum {
        Checksum::Value(value) => value,
        Checksum::Auto | Checksum::Invalid => 0,
    }
}

fn decode_ip_inner(
    bytes: &[u8],
    ethernet: Option<EthernetHeader>,
) -> Result<DecodedPacket, PacketError> {
    let version = bytes
        .first()
        .map(|byte| byte >> 4)
        .ok_or_else(|| error("empty IP packet"))?;
    match version {
        4 => decode_ipv4(bytes, ethernet),
        6 => decode_ipv6(bytes, ethernet),
        _ => Err(error(format!("unsupported IP version {version}"))),
    }
}

fn encode_ethernet(
    header: &EthernetHeader,
    network: &NetworkHeader,
    payload: &[u8],
) -> Result<Vec<u8>, PacketError> {
    let inferred = match network {
        NetworkHeader::Ipv4(_) => ETHERTYPE_IPV4,
        NetworkHeader::Ipv6(_) => ETHERTYPE_IPV6,
    };
    let ether_type = header.ether_type.unwrap_or(inferred);
    let mut bytes = Vec::with_capacity(18 + payload.len());
    bytes.extend_from_slice(&header.destination.0);
    bytes.extend_from_slice(&header.source.0);
    if let Some(vlan) = header.vlan {
        if vlan.priority > 7 || vlan.id > 4095 {
            return Err(error("VLAN priority/id is out of range"));
        }
        bytes.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        let control =
            ((vlan.priority as u16) << 13) | ((vlan.drop_eligible as u16) << 12) | vlan.id;
        bytes.extend_from_slice(&control.to_be_bytes());
    }
    bytes.extend_from_slice(&ether_type.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn encode_ipv4(header: &Ipv4Header, protocol: u8, payload: &[u8]) -> Result<Vec<u8>, PacketError> {
    if header.dscp > 63 || header.ecn > 3 || header.fragment_offset > 8191 {
        return Err(error("IPv4 DSCP/ECN/fragment offset is out of range"));
    }
    let mut options = header.options.clone();
    if options.len() > 40 {
        return Err(error("IPv4 options exceed 40 bytes"));
    }
    options.resize((options.len() + 3) & !3, 0);
    let actual_ihl = 5 + options.len() / 4;
    let encoded_ihl = header.ihl.unwrap_or(actual_ihl as u8);
    if encoded_ihl > 15 {
        return Err(error("IPv4 IHL exceeds 15"));
    }
    let actual_length = 20usize
        .checked_add(options.len())
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or_else(|| error("IPv4 packet length overflow"))?;
    let actual_length =
        u16::try_from(actual_length).map_err(|_| error("IPv4 packet exceeds 65535 bytes"))?;
    let total_length = header.total_length.unwrap_or(actual_length);
    let mut bytes = vec![0; 20 + options.len()];
    bytes[0] = 0x40 | encoded_ihl;
    bytes[1] = (header.dscp << 2) | header.ecn;
    bytes[2..4].copy_from_slice(&total_length.to_be_bytes());
    bytes[4..6].copy_from_slice(&header.identification.to_be_bytes());
    let fragment = ((header.dont_fragment as u16) << 14)
        | ((header.more_fragments as u16) << 13)
        | header.fragment_offset;
    bytes[6..8].copy_from_slice(&fragment.to_be_bytes());
    bytes[8] = header.ttl;
    bytes[9] = header.protocol.unwrap_or(protocol);
    bytes[12..16].copy_from_slice(&header.source.octets());
    bytes[16..20].copy_from_slice(&header.destination.octets());
    bytes[20..].copy_from_slice(&options);
    let calculated = internet_checksum(&bytes);
    bytes[10..12].copy_from_slice(&header.checksum.resolve(calculated).to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn encode_ipv6(header: &Ipv6Header, protocol: u8, payload: &[u8]) -> Result<Vec<u8>, PacketError> {
    if header.flow_label > 0x000f_ffff {
        return Err(error("IPv6 flow_label exceeds 20 bits"));
    }
    let extension_len = if header.fragment.is_some() { 8 } else { 0 };
    let actual_length = extension_len + payload.len();
    let actual_length = u16::try_from(actual_length)
        .map_err(|_| error("IPv6 payload exceeds 65535 bytes (jumbograms unsupported)"))?;
    let payload_length = header.payload_length.unwrap_or(actual_length);
    let mut bytes = vec![0; 40];
    let first =
        (6u32 << 28) | ((header.traffic_class as u32) << 20) | (header.flow_label & 0x000f_ffff);
    bytes[0..4].copy_from_slice(&first.to_be_bytes());
    bytes[4..6].copy_from_slice(&payload_length.to_be_bytes());
    bytes[6] = if header.fragment.is_some() {
        IP_PROTOCOL_FRAGMENT
    } else {
        header.next_header.unwrap_or(protocol)
    };
    bytes[7] = header.hop_limit;
    bytes[8..24].copy_from_slice(&header.source.octets());
    bytes[24..40].copy_from_slice(&header.destination.octets());
    if let Some(fragment) = header.fragment {
        if fragment.offset > 8191 {
            return Err(error("IPv6 fragment offset exceeds 13 bits"));
        }
        bytes.push(fragment.next_header);
        bytes.push(0);
        let offset = (fragment.offset << 3) | u16::from(fragment.more_fragments);
        bytes.extend_from_slice(&offset.to_be_bytes());
        bytes.extend_from_slice(&fragment.identification.to_be_bytes());
    }
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn encode_transport(
    network: &NetworkHeader,
    transport: Option<&TransportHeader>,
    payload: &[u8],
) -> Result<Vec<u8>, PacketError> {
    match transport {
        None => Ok(Vec::new()),
        Some(TransportHeader::Tcp(header)) => encode_tcp(network, header, payload),
        Some(TransportHeader::Udp(header)) => encode_udp(network, header, payload),
    }
}

fn encode_tcp(
    network: &NetworkHeader,
    header: &TcpHeader,
    payload: &[u8],
) -> Result<Vec<u8>, PacketError> {
    if header.flags > 0x01ff {
        return Err(error("TCP flags exceed 9 bits"));
    }
    let mut options = encode_tcp_options(&header.options)?;
    options.resize((options.len() + 3) & !3, 0);
    if options.len() > 40 {
        return Err(error("TCP options exceed 40 bytes"));
    }
    let actual_offset = 5 + options.len() / 4;
    let encoded_offset = header.data_offset.unwrap_or(actual_offset as u8);
    if encoded_offset > 15 {
        return Err(error("TCP data offset exceeds 15"));
    }
    let mut bytes = vec![0; 20 + options.len()];
    bytes[0..2].copy_from_slice(&header.source_port.to_be_bytes());
    bytes[2..4].copy_from_slice(&header.destination_port.to_be_bytes());
    bytes[4..8].copy_from_slice(&header.sequence.to_be_bytes());
    bytes[8..12].copy_from_slice(&header.acknowledgment.to_be_bytes());
    bytes[12] = (encoded_offset << 4) | ((header.flags >> 8) as u8 & 1);
    bytes[13] = header.flags as u8;
    bytes[14..16].copy_from_slice(&header.window.to_be_bytes());
    bytes[18..20].copy_from_slice(&header.urgent_pointer.to_be_bytes());
    bytes[20..].copy_from_slice(&options);
    let mut checksum_input = bytes.clone();
    checksum_input.extend_from_slice(payload);
    let calculated = transport_checksum(network, IP_PROTOCOL_TCP, &checksum_input)?;
    bytes[16..18].copy_from_slice(&header.checksum.resolve(calculated).to_be_bytes());
    Ok(bytes)
}

fn encode_udp(
    network: &NetworkHeader,
    header: &UdpHeader,
    payload: &[u8],
) -> Result<Vec<u8>, PacketError> {
    let actual_length = u16::try_from(8usize + payload.len())
        .map_err(|_| error("UDP datagram exceeds 65535 bytes"))?;
    let length = header.length.unwrap_or(actual_length);
    let mut bytes = vec![0; 8];
    bytes[0..2].copy_from_slice(&header.source_port.to_be_bytes());
    bytes[2..4].copy_from_slice(&header.destination_port.to_be_bytes());
    bytes[4..6].copy_from_slice(&length.to_be_bytes());
    let mut checksum_input = bytes.clone();
    checksum_input.extend_from_slice(payload);
    let mut calculated = transport_checksum(network, IP_PROTOCOL_UDP, &checksum_input)?;
    if calculated == 0 {
        calculated = 0xffff;
    }
    bytes[6..8].copy_from_slice(&header.checksum.resolve(calculated).to_be_bytes());
    Ok(bytes)
}

fn encode_tcp_options(options: &[TcpOption]) -> Result<Vec<u8>, PacketError> {
    let mut bytes = Vec::new();
    for option in options {
        match option {
            TcpOption::End => bytes.push(0),
            TcpOption::Nop => bytes.push(1),
            TcpOption::MaximumSegmentSize(value) => {
                bytes.extend_from_slice(&[2, 4]);
                bytes.extend_from_slice(&value.to_be_bytes());
            }
            TcpOption::WindowScale(value) => bytes.extend_from_slice(&[3, 3, *value]),
            TcpOption::SackPermitted => bytes.extend_from_slice(&[4, 2]),
            TcpOption::Sack(blocks) => {
                let length = 2usize + blocks.len() * 8;
                if blocks.is_empty() || length > u8::MAX as usize {
                    return Err(error("TCP SACK needs at least one valid block"));
                }
                bytes.extend_from_slice(&[5, length as u8]);
                for (left, right) in blocks {
                    bytes.extend_from_slice(&left.to_be_bytes());
                    bytes.extend_from_slice(&right.to_be_bytes());
                }
            }
            TcpOption::Timestamp { value, echo } => {
                bytes.extend_from_slice(&[8, 10]);
                bytes.extend_from_slice(&value.to_be_bytes());
                bytes.extend_from_slice(&echo.to_be_bytes());
            }
            TcpOption::Unknown { kind, data } => {
                let length = u8::try_from(data.len() + 2)
                    .map_err(|_| error("unknown TCP option is too long"))?;
                bytes.extend_from_slice(&[*kind, length]);
                bytes.extend_from_slice(data);
            }
        }
    }
    Ok(bytes)
}

fn decode_ipv4(
    bytes: &[u8],
    ethernet: Option<EthernetHeader>,
) -> Result<DecodedPacket, PacketError> {
    if bytes.len() < 20 {
        return Err(error("truncated IPv4 header"));
    }
    let ihl = bytes[0] & 0x0f;
    if ihl < 5 {
        return Err(error(format!("invalid IPv4 IHL {ihl}")));
    }
    let header_len = ihl as usize * 4;
    if bytes.len() < header_len {
        return Err(error("truncated IPv4 options"));
    }
    let total_length = u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize;
    if total_length < header_len || total_length > bytes.len() {
        return Err(error(format!(
            "invalid IPv4 total length {total_length} for {} available bytes",
            bytes.len()
        )));
    }
    let protocol = bytes[9];
    let source = Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[12..16]).unwrap());
    let destination = Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[16..20]).unwrap());
    let fragment = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
    let header = Ipv4Header {
        dscp: bytes[1] >> 2,
        ecn: bytes[1] & 3,
        identification: u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
        dont_fragment: fragment & 0x4000 != 0,
        more_fragments: fragment & 0x2000 != 0,
        fragment_offset: fragment & 0x1fff,
        ttl: bytes[8],
        protocol: Some(protocol),
        source,
        destination,
        options: bytes[20..header_len].to_vec(),
        ihl: Some(ihl),
        total_length: Some(total_length as u16),
        checksum: Checksum::Value(u16::from_be_bytes(bytes[10..12].try_into().unwrap())),
    };
    let checksum_valid = internet_checksum(&bytes[..header_len]) == 0;
    let ip_payload = &bytes[header_len..total_length];
    let fragmented = header.fragment_offset != 0 || header.more_fragments;
    let (transport, payload, transport_checksum_valid) = if fragmented
        && (header.fragment_offset != 0 || !complete_transport_header(protocol, ip_payload))
    {
        (None, ip_payload.to_vec(), None)
    } else {
        decode_transport(
            &NetworkHeader::Ipv4(header.clone()),
            protocol,
            ip_payload,
            fragmented,
        )?
    };
    Ok(DecodedPacket {
        packet: Packet {
            ethernet,
            network: NetworkHeader::Ipv4(header),
            transport,
            payload,
        },
        network_payload: ip_payload.to_vec(),
        ipv4_checksum_valid: Some(checksum_valid),
        transport_checksum_valid,
        trailing: bytes[total_length..].to_vec(),
    })
}

fn decode_ipv6(
    bytes: &[u8],
    ethernet: Option<EthernetHeader>,
) -> Result<DecodedPacket, PacketError> {
    if bytes.len() < 40 {
        return Err(error("truncated IPv6 header"));
    }
    let first = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    let payload_length = u16::from_be_bytes(bytes[4..6].try_into().unwrap()) as usize;
    let total_length = 40usize + payload_length;
    if total_length > bytes.len() {
        return Err(error(format!(
            "invalid IPv6 payload length {payload_length} for {} available bytes",
            bytes.len()
        )));
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).unwrap());
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).unwrap());
    let mut protocol = bytes[6];
    let mut offset = 40;
    let fragment = if protocol == IP_PROTOCOL_FRAGMENT {
        if total_length < 48 {
            return Err(error("truncated IPv6 fragment header"));
        }
        protocol = bytes[40];
        let bits = u16::from_be_bytes(bytes[42..44].try_into().unwrap());
        offset = 48;
        Some(Ipv6Fragment {
            next_header: protocol,
            offset: bits >> 3,
            more_fragments: bits & 1 != 0,
            identification: u32::from_be_bytes(bytes[44..48].try_into().unwrap()),
        })
    } else {
        None
    };
    let header = Ipv6Header {
        traffic_class: ((first >> 20) & 0xff) as u8,
        flow_label: first & 0x000f_ffff,
        payload_length: Some(payload_length as u16),
        next_header: Some(bytes[6]),
        hop_limit: bytes[7],
        source,
        destination,
        fragment,
    };
    let fragmented =
        fragment.is_some_and(|fragment| fragment.offset != 0 || fragment.more_fragments);
    let ip_payload = &bytes[offset..total_length];
    let (transport, payload, transport_checksum_valid) = if fragment.is_some_and(|fragment| {
        fragment.offset != 0 || !complete_transport_header(protocol, ip_payload)
    }) {
        (None, ip_payload.to_vec(), None)
    } else {
        decode_transport(
            &NetworkHeader::Ipv6(header.clone()),
            protocol,
            ip_payload,
            fragmented,
        )?
    };
    Ok(DecodedPacket {
        packet: Packet {
            ethernet,
            network: NetworkHeader::Ipv6(header),
            transport,
            payload,
        },
        network_payload: ip_payload.to_vec(),
        ipv4_checksum_valid: None,
        transport_checksum_valid,
        trailing: bytes[total_length..].to_vec(),
    })
}

fn complete_transport_header(protocol: u8, bytes: &[u8]) -> bool {
    match protocol {
        IP_PROTOCOL_TCP => bytes.get(12).is_some_and(|offset| {
            (*offset >> 4) >= 5 && bytes.len() >= (*offset >> 4) as usize * 4
        }),
        IP_PROTOCOL_UDP => bytes.len() >= 8,
        _ => true,
    }
}

type DecodedTransport = (Option<TransportHeader>, Vec<u8>, Option<bool>);

fn decode_transport(
    network: &NetworkHeader,
    protocol: u8,
    bytes: &[u8],
    fragmented: bool,
) -> Result<DecodedTransport, PacketError> {
    match protocol {
        IP_PROTOCOL_TCP => {
            if bytes.len() < 20 {
                return Err(error("truncated TCP header"));
            }
            let data_offset = bytes[12] >> 4;
            if data_offset < 5 {
                return Err(error(format!("invalid TCP data offset {data_offset}")));
            }
            let header_len = data_offset as usize * 4;
            if bytes.len() < header_len {
                return Err(error("truncated TCP options"));
            }
            let header = TcpHeader {
                source_port: u16::from_be_bytes(bytes[0..2].try_into().unwrap()),
                destination_port: u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
                sequence: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                acknowledgment: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
                flags: (((bytes[12] & 1) as u16) << 8) | bytes[13] as u16,
                window: u16::from_be_bytes(bytes[14..16].try_into().unwrap()),
                urgent_pointer: u16::from_be_bytes(bytes[18..20].try_into().unwrap()),
                options: decode_tcp_options(&bytes[20..header_len])?,
                data_offset: Some(data_offset),
                checksum: Checksum::Value(u16::from_be_bytes(bytes[16..18].try_into().unwrap())),
            };
            let valid = if fragmented {
                None
            } else {
                Some(transport_checksum(network, protocol, bytes)? == 0)
            };
            Ok((
                Some(TransportHeader::Tcp(header)),
                bytes[header_len..].to_vec(),
                valid,
            ))
        }
        IP_PROTOCOL_UDP => {
            if bytes.len() < 8 {
                return Err(error("truncated UDP header"));
            }
            let declared = u16::from_be_bytes(bytes[4..6].try_into().unwrap()) as usize;
            if declared < 8 || (!fragmented && declared > bytes.len()) {
                return Err(error(format!("invalid UDP length {declared}")));
            }
            let available = declared.min(bytes.len());
            let checksum_value = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
            let header = UdpHeader {
                source_port: u16::from_be_bytes(bytes[0..2].try_into().unwrap()),
                destination_port: u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
                length: Some(declared as u16),
                checksum: Checksum::Value(checksum_value),
            };
            let valid = if fragmented {
                None
            } else if checksum_value == 0 && matches!(network, NetworkHeader::Ipv4(_)) {
                Some(true)
            } else {
                Some(transport_checksum(network, protocol, &bytes[..available])? == 0)
            };
            Ok((
                Some(TransportHeader::Udp(header)),
                bytes[8..available].to_vec(),
                valid,
            ))
        }
        _ => Ok((None, bytes.to_vec(), None)),
    }
}

fn decode_tcp_options(bytes: &[u8]) -> Result<Vec<TcpOption>, PacketError> {
    let mut options = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let kind = bytes[offset];
        match kind {
            0 => {
                options.push(TcpOption::End);
                break;
            }
            1 => {
                options.push(TcpOption::Nop);
                offset += 1;
            }
            _ => {
                if offset + 2 > bytes.len() {
                    return Err(error("truncated TCP option length"));
                }
                let length = bytes[offset + 1] as usize;
                if length < 2 || offset + length > bytes.len() {
                    return Err(error(format!("invalid TCP option {kind} length {length}")));
                }
                let data = &bytes[offset + 2..offset + length];
                let option = match (kind, data) {
                    (2, [a, b]) => TcpOption::MaximumSegmentSize(u16::from_be_bytes([*a, *b])),
                    (3, [scale]) => TcpOption::WindowScale(*scale),
                    (4, []) => TcpOption::SackPermitted,
                    (5, data) if !data.is_empty() && data.len() % 8 == 0 => {
                        let blocks = data
                            .chunks_exact(8)
                            .map(|block| {
                                (
                                    u32::from_be_bytes(block[0..4].try_into().unwrap()),
                                    u32::from_be_bytes(block[4..8].try_into().unwrap()),
                                )
                            })
                            .collect();
                        TcpOption::Sack(blocks)
                    }
                    (8, [a, b, c, d, e, f, g, h]) => TcpOption::Timestamp {
                        value: u32::from_be_bytes([*a, *b, *c, *d]),
                        echo: u32::from_be_bytes([*e, *f, *g, *h]),
                    },
                    _ => TcpOption::Unknown {
                        kind,
                        data: data.to_vec(),
                    },
                };
                options.push(option);
                offset += length;
            }
        }
    }
    Ok(options)
}

/// Split an IPv4 packet at the IP layer. `mtu` excludes the optional Ethernet
/// header, matching operating-system interface MTU semantics.
pub fn fragment_ipv4(packet: &Packet, mtu: usize) -> Result<Vec<Vec<u8>>, PacketError> {
    let NetworkHeader::Ipv4(base) = &packet.network else {
        return Err(error("fragment_ipv4 requires an IPv4 packet"));
    };
    if base.fragment_offset != 0 || base.more_fragments {
        return Err(error("cannot fragment an already fragmented IPv4 packet"));
    }
    let protocol = packet.protocol()?;
    let mut network_payload =
        encode_transport(&packet.network, packet.transport.as_ref(), &packet.payload)?;
    network_payload.extend_from_slice(&packet.payload);
    let first_options = padded_ipv4_options(&base.options)?;
    let first_header_len = 20 + first_options.len();
    if first_header_len + network_payload.len() <= mtu {
        return Ok(vec![packet.encode()?]);
    }
    if base.dont_fragment {
        return Err(error(format!(
            "IPv4 packet exceeds MTU {mtu} while dont_fragment is set"
        )));
    }
    let later_options = copied_ipv4_options(&base.options)?;
    let mut fragments = Vec::new();
    let mut offset = 0usize;
    while offset < network_payload.len() {
        let options = if offset == 0 {
            first_options.clone()
        } else {
            later_options.clone()
        };
        let header_len = 20 + options.len();
        if mtu < header_len + 8 {
            return Err(error(format!(
                "MTU {mtu} is too small for an IPv4 fragment header"
            )));
        }
        let capacity = ((mtu - header_len) / 8) * 8;
        let remaining = network_payload.len() - offset;
        let length = if remaining > capacity {
            capacity
        } else {
            remaining
        };
        let more = offset + length < network_payload.len();
        let mut header = base.clone();
        header.options = options;
        header.ihl = None;
        header.total_length = None;
        header.protocol = Some(protocol);
        header.fragment_offset =
            u16::try_from(offset / 8).map_err(|_| error("IPv4 fragment offset overflow"))?;
        header.more_fragments = more;
        header.dont_fragment = false;
        let fragment = Packet {
            ethernet: packet.ethernet.clone(),
            network: NetworkHeader::Ipv4(header),
            transport: None,
            payload: network_payload[offset..offset + length].to_vec(),
        };
        fragments.push(fragment.encode()?);
        offset += length;
    }
    Ok(fragments)
}

/// Split an IPv6 packet using the IPv6 Fragment extension header.
pub fn fragment_ipv6(
    packet: &Packet,
    mtu: usize,
    identification: u32,
) -> Result<Vec<Vec<u8>>, PacketError> {
    let NetworkHeader::Ipv6(base) = &packet.network else {
        return Err(error("fragment_ipv6 requires an IPv6 packet"));
    };
    if base.fragment.is_some() {
        return Err(error("cannot fragment an already fragmented IPv6 packet"));
    }
    let protocol = packet.protocol()?;
    let mut network_payload =
        encode_transport(&packet.network, packet.transport.as_ref(), &packet.payload)?;
    network_payload.extend_from_slice(&packet.payload);
    if 40 + network_payload.len() <= mtu {
        return Ok(vec![packet.encode()?]);
    }
    if mtu < 56 {
        return Err(error(format!(
            "MTU {mtu} is too small for an IPv6 fragment"
        )));
    }
    let capacity = ((mtu - 48) / 8) * 8;
    let mut fragments = Vec::new();
    let mut offset = 0usize;
    while offset < network_payload.len() {
        let remaining = network_payload.len() - offset;
        let length = if remaining > capacity {
            capacity
        } else {
            remaining
        };
        let more = offset + length < network_payload.len();
        let mut header = base.clone();
        header.payload_length = None;
        header.next_header = Some(IP_PROTOCOL_FRAGMENT);
        header.fragment = Some(Ipv6Fragment {
            next_header: protocol,
            offset: u16::try_from(offset / 8)
                .map_err(|_| error("IPv6 fragment offset overflow"))?,
            more_fragments: more,
            identification,
        });
        let fragment = Packet {
            ethernet: packet.ethernet.clone(),
            network: NetworkHeader::Ipv6(header),
            transport: None,
            payload: network_payload[offset..offset + length].to_vec(),
        };
        fragments.push(fragment.encode()?);
        offset += length;
    }
    Ok(fragments)
}

fn padded_ipv4_options(options: &[u8]) -> Result<Vec<u8>, PacketError> {
    if options.len() > 40 {
        return Err(error("IPv4 options exceed 40 bytes"));
    }
    let mut options = options.to_vec();
    options.resize((options.len() + 3) & !3, 0);
    Ok(options)
}

fn copied_ipv4_options(options: &[u8]) -> Result<Vec<u8>, PacketError> {
    let mut copied = Vec::new();
    let mut offset = 0;
    while offset < options.len() {
        let kind = options[offset];
        match kind {
            0 => break,
            1 => offset += 1,
            _ => {
                if offset + 2 > options.len() {
                    return Err(error("truncated IPv4 option length"));
                }
                let length = options[offset + 1] as usize;
                if length < 2 || offset + length > options.len() {
                    return Err(error(format!("invalid IPv4 option {kind} length {length}")));
                }
                if kind & 0x80 != 0 {
                    copied.extend_from_slice(&options[offset..offset + length]);
                }
                offset += length;
            }
        }
    }
    copied.resize((copied.len() + 3) & !3, 0);
    Ok(copied)
}

#[derive(Debug, Clone)]
pub struct ReassemblyConfig {
    pub max_datagrams: usize,
    pub max_buffered_bytes: usize,
    pub timeout: Duration,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            max_datagrams: 1024,
            max_buffered_bytes: 16 * 1024 * 1024,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Bounded IPv4/IPv6 fragment reassembly. Overlapping fragments are rejected
/// (except byte-identical duplicates) to avoid ambiguous evasion behavior.
pub struct FragmentReassembler {
    config: ReassemblyConfig,
    datagrams: HashMap<FragmentKey, FragmentSet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FragmentKey {
    Ipv4(Ipv4Addr, Ipv4Addr, u16, u8),
    Ipv6(Ipv6Addr, Ipv6Addr, u32, u8),
}

struct FragmentSet {
    created: Instant,
    ethernet: Option<EthernetHeader>,
    network: NetworkHeader,
    protocol: u8,
    chunks: BTreeMap<usize, Vec<u8>>,
    total_length: Option<usize>,
}

impl FragmentReassembler {
    pub fn new(config: ReassemblyConfig) -> Self {
        Self {
            config,
            datagrams: HashMap::new(),
        }
    }

    pub fn push(&mut self, fragment: &DecodedPacket) -> Result<Option<Packet>, PacketError> {
        self.push_at(fragment, Instant::now())
    }

    pub fn push_at(
        &mut self,
        fragment: &DecodedPacket,
        now: Instant,
    ) -> Result<Option<Packet>, PacketError> {
        self.expire(now);
        let Some((key, offset, more, protocol)) = fragment_identity(fragment) else {
            return Ok(Some(fragment.packet.clone()));
        };
        if more && !fragment.network_payload.len().is_multiple_of(8) {
            return Err(error("non-final IP fragment length is not a multiple of 8"));
        }
        if !self.datagrams.contains_key(&key) && self.datagrams.len() >= self.config.max_datagrams {
            return Err(error(format!(
                "fragment reassembly reached max_datagrams {}",
                self.config.max_datagrams
            )));
        }
        let buffered = self
            .datagrams
            .values()
            .flat_map(|set| set.chunks.values())
            .map(Vec::len)
            .sum::<usize>();
        let duplicate = self
            .datagrams
            .get(&key)
            .and_then(|set| set.chunks.get(&offset))
            .is_some_and(|existing| existing == &fragment.network_payload);
        if !duplicate
            && buffered.saturating_add(fragment.network_payload.len())
                > self.config.max_buffered_bytes
        {
            return Err(error(format!(
                "fragment reassembly reached max_buffered_bytes {}",
                self.config.max_buffered_bytes
            )));
        }

        let set = self
            .datagrams
            .entry(key.clone())
            .or_insert_with(|| FragmentSet {
                created: now,
                ethernet: fragment.packet.ethernet.clone(),
                network: fragment.packet.network.clone(),
                protocol,
                chunks: BTreeMap::new(),
                total_length: None,
            });
        let end = offset
            .checked_add(fragment.network_payload.len())
            .ok_or_else(|| error("fragment range overflow"))?;
        for (existing_offset, existing) in &set.chunks {
            let existing_end = existing_offset + existing.len();
            if offset < existing_end && *existing_offset < end {
                if *existing_offset == offset && existing == &fragment.network_payload {
                    return Ok(None);
                }
                self.datagrams.remove(&key);
                return Err(error("overlapping IP fragments are rejected"));
            }
        }
        if offset == 0 {
            set.ethernet = fragment.packet.ethernet.clone();
            set.network = fragment.packet.network.clone();
        }
        if !more {
            if set.total_length.is_some_and(|total| total != end) {
                self.datagrams.remove(&key);
                return Err(error("conflicting final IP fragment lengths"));
            }
            set.total_length = Some(end);
        }
        set.chunks.insert(offset, fragment.network_payload.clone());

        let Some(total) = set.total_length else {
            return Ok(None);
        };
        let mut cursor = 0;
        for (offset, bytes) in &set.chunks {
            if *offset != cursor {
                return Ok(None);
            }
            cursor += bytes.len();
        }
        if cursor != total {
            return Ok(None);
        }
        let set = self.datagrams.remove(&key).unwrap();
        let mut bytes = Vec::with_capacity(total);
        for chunk in set.chunks.into_values() {
            bytes.extend_from_slice(&chunk);
        }
        let network = clear_fragment_header(set.network, set.protocol);
        let (transport, payload, _) = decode_transport(&network, set.protocol, &bytes, false)?;
        Ok(Some(Packet {
            ethernet: set.ethernet,
            network,
            transport,
            payload,
        }))
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.datagrams.len();
        self.datagrams.retain(|_, set| {
            now.checked_duration_since(set.created).unwrap_or_default() <= self.config.timeout
        });
        before - self.datagrams.len()
    }

    pub fn pending(&self) -> usize {
        self.datagrams.len()
    }
}

fn fragment_identity(fragment: &DecodedPacket) -> Option<(FragmentKey, usize, bool, u8)> {
    match &fragment.packet.network {
        NetworkHeader::Ipv4(header) if header.fragment_offset != 0 || header.more_fragments => {
            let protocol = header.protocol?;
            Some((
                FragmentKey::Ipv4(
                    header.source,
                    header.destination,
                    header.identification,
                    protocol,
                ),
                header.fragment_offset as usize * 8,
                header.more_fragments,
                protocol,
            ))
        }
        NetworkHeader::Ipv6(header) => header.fragment.map(|fragment| {
            (
                FragmentKey::Ipv6(
                    header.source,
                    header.destination,
                    fragment.identification,
                    fragment.next_header,
                ),
                fragment.offset as usize * 8,
                fragment.more_fragments,
                fragment.next_header,
            )
        }),
        _ => None,
    }
}

fn clear_fragment_header(mut network: NetworkHeader, protocol: u8) -> NetworkHeader {
    match &mut network {
        NetworkHeader::Ipv4(header) => {
            header.fragment_offset = 0;
            header.more_fragments = false;
            header.total_length = None;
            header.ihl = None;
            header.protocol = Some(protocol);
            header.checksum = Checksum::Auto;
        }
        NetworkHeader::Ipv6(header) => {
            header.fragment = None;
            header.next_header = Some(protocol);
            header.payload_length = None;
        }
    }
    network
}

fn transport_checksum(
    network: &NetworkHeader,
    protocol: u8,
    segment: &[u8],
) -> Result<u16, PacketError> {
    let length = u32::try_from(segment.len()).map_err(|_| error("transport segment too long"))?;
    let mut sum = 0u64;
    match network {
        NetworkHeader::Ipv4(header) => {
            sum = checksum_add(sum, &header.source.octets());
            sum = checksum_add(sum, &header.destination.octets());
            sum += protocol as u64;
            sum += length as u64;
        }
        NetworkHeader::Ipv6(header) => {
            sum = checksum_add(sum, &header.source.octets());
            sum = checksum_add(sum, &header.destination.octets());
            sum += ((length >> 16) + (length & 0xffff)) as u64;
            sum += protocol as u64;
        }
    }
    sum = checksum_add(sum, segment);
    Ok(checksum_finish(sum))
}

pub fn internet_checksum(bytes: &[u8]) -> u16 {
    checksum_finish(checksum_add(0, bytes))
}

fn checksum_add(mut sum: u64, bytes: &[u8]) -> u64 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u64;
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += (*byte as u64) << 8;
    }
    sum
}

fn checksum_finish(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp_packet() -> Packet {
        Packet {
            ethernet: Some(EthernetHeader {
                destination: "02:00:00:00:00:02".parse().unwrap(),
                source: "02:00:00:00:00:01".parse().unwrap(),
                vlan: Some(VlanTag {
                    priority: 3,
                    drop_eligible: true,
                    id: 42,
                }),
                ether_type: None,
            }),
            network: NetworkHeader::Ipv4(Ipv4Header {
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(198, 51, 100, 2),
                identification: 0x1234,
                dont_fragment: true,
                ttl: 37,
                options: vec![1, 1, 0, 0],
                ..Ipv4Header::default()
            }),
            transport: Some(TransportHeader::Tcp(TcpHeader {
                source_port: 40_000,
                destination_port: 443,
                sequence: 0x0102_0304,
                acknowledgment: 0x1122_3344,
                flags: tcp_flag::SYN | tcp_flag::ACK | tcp_flag::ECE,
                window: 32_000,
                options: vec![
                    TcpOption::MaximumSegmentSize(1460),
                    TcpOption::Nop,
                    TcpOption::WindowScale(7),
                    TcpOption::SackPermitted,
                    TcpOption::Timestamp {
                        value: 123,
                        echo: 45,
                    },
                ],
                ..TcpHeader::default()
            })),
            payload: b"hello".to_vec(),
        }
    }

    #[test]
    fn ethernet_ipv4_tcp_options_round_trip_with_valid_checksums() {
        let packet = ipv4_tcp_packet();
        let bytes = packet.encode().unwrap();
        let decoded = decode_ethernet(&bytes).unwrap();
        assert_eq!(decoded.ipv4_checksum_valid, Some(true));
        assert_eq!(decoded.transport_checksum_valid, Some(true));
        assert!(decoded.trailing.is_empty());
        assert_eq!(decoded.packet.payload, b"hello");
        let ethernet = decoded.packet.ethernet.as_ref().unwrap();
        assert_eq!(ethernet.source, packet.ethernet.as_ref().unwrap().source);
        assert_eq!(
            ethernet.destination,
            packet.ethernet.as_ref().unwrap().destination
        );
        assert_eq!(ethernet.vlan, packet.ethernet.as_ref().unwrap().vlan);
        assert_eq!(ethernet.ether_type, Some(ETHERTYPE_IPV4));
        let NetworkHeader::Ipv4(ip) = decoded.packet.network else {
            panic!("expected IPv4")
        };
        assert_eq!(ip.ttl, 37);
        let Some(TransportHeader::Tcp(tcp)) = decoded.packet.transport else {
            panic!("expected TCP")
        };
        assert_eq!(tcp.flags, tcp_flag::SYN | tcp_flag::ACK | tcp_flag::ECE);
        assert!(tcp.options.contains(&TcpOption::MaximumSegmentSize(1460)));
        assert!(tcp.options.contains(&TcpOption::WindowScale(7)));
    }

    #[test]
    fn ipv6_udp_round_trip_and_deliberate_checksum_damage() {
        let mut packet = Packet {
            ethernet: None,
            network: NetworkHeader::Ipv6(Ipv6Header {
                traffic_class: 0xab,
                flow_label: 0x54321,
                source: "2001:db8::1".parse().unwrap(),
                destination: "2001:db8::2".parse().unwrap(),
                ..Ipv6Header::default()
            }),
            transport: Some(TransportHeader::Udp(UdpHeader {
                source_port: 5353,
                destination_port: 53,
                ..UdpHeader::default()
            })),
            payload: b"dns".to_vec(),
        };
        let decoded = decode_ip(&packet.encode().unwrap()).unwrap();
        assert_eq!(decoded.transport_checksum_valid, Some(true));
        assert_eq!(decoded.packet.payload, b"dns");

        let Some(TransportHeader::Udp(udp)) = packet.transport.as_mut() else {
            unreachable!()
        };
        udp.checksum = Checksum::Invalid;
        let decoded = decode_ip(&packet.encode().unwrap()).unwrap();
        assert_eq!(decoded.transport_checksum_valid, Some(false));
    }

    #[test]
    fn checksum_and_malformed_lengths_are_checked_without_panics() {
        assert_eq!(
            internet_checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
        let mut bytes = ipv4_tcp_packet().encode().unwrap();
        bytes[18 + 8] ^= 1;
        let decoded = decode_ethernet(&bytes).unwrap();
        assert_eq!(decoded.ipv4_checksum_valid, Some(false));

        let ip_offset = 18;
        bytes[ip_offset + 2..ip_offset + 4].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(decode_ethernet(&bytes).is_err());
        assert!(decode_ip(&[]).is_err());
    }

    #[test]
    fn mac_address_parser_is_strict() {
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
        assert!("aa:bb:cc".parse::<MacAddr>().is_err());
        assert!("gg:bb:cc:dd:ee:ff".parse::<MacAddr>().is_err());
    }

    #[test]
    fn ipv4_fragments_reassemble_out_of_order_and_reject_overlap() {
        let mut packet = ipv4_tcp_packet();
        packet.payload = vec![0x5a; 2_000];
        let NetworkHeader::Ipv4(header) = &mut packet.network else {
            unreachable!()
        };
        header.dont_fragment = false;
        let fragments = fragment_ipv4(&packet, 576).unwrap();
        assert!(fragments.len() >= 4);
        let decoded: Vec<_> = fragments
            .iter()
            .map(|fragment| decode_ethernet(fragment).unwrap())
            .collect();
        assert!(decoded
            .iter()
            .all(|fragment| fragment.ipv4_checksum_valid == Some(true)));
        assert!(decoded[..decoded.len() - 1].iter().all(|fragment| {
            matches!(
                &fragment.packet.network,
                NetworkHeader::Ipv4(header) if header.more_fragments
            )
        }));

        let mut reassembler = FragmentReassembler::new(ReassemblyConfig::default());
        let mut reassembled = None;
        for fragment in decoded.iter().rev() {
            if let Some(packet) = reassembler.push(fragment).unwrap() {
                reassembled = Some(packet);
            }
        }
        let reassembled = reassembled.unwrap();
        assert_eq!(reassembled.payload, vec![0x5a; 2_000]);
        let verified = decode_ethernet(&reassembled.encode().unwrap()).unwrap();
        assert_eq!(verified.transport_checksum_valid, Some(true));
        assert_eq!(reassembler.pending(), 0);

        let mut reassembler = FragmentReassembler::new(ReassemblyConfig::default());
        assert!(reassembler.push(&decoded[0]).unwrap().is_none());
        let mut overlap = decoded[0].clone();
        overlap.network_payload[0] ^= 1;
        assert!(reassembler.push(&overlap).is_err());
        assert_eq!(reassembler.pending(), 0);
    }

    #[test]
    fn ipv6_fragments_reassemble_and_expire_with_bounds() {
        let packet = Packet {
            ethernet: None,
            network: NetworkHeader::Ipv6(Ipv6Header {
                source: "2001:db8::10".parse().unwrap(),
                destination: "2001:db8::20".parse().unwrap(),
                ..Ipv6Header::default()
            }),
            transport: Some(TransportHeader::Udp(UdpHeader {
                source_port: 10_000,
                destination_port: 20_000,
                ..UdpHeader::default()
            })),
            payload: vec![7; 3_000],
        };
        let fragments = fragment_ipv6(&packet, 1280, 0x1234_5678).unwrap();
        assert!(fragments.len() >= 3);
        let decoded: Vec<_> = fragments
            .iter()
            .map(|fragment| decode_ip(fragment).unwrap())
            .collect();
        let start = Instant::now();
        let mut reassembler = FragmentReassembler::new(ReassemblyConfig {
            max_datagrams: 1,
            max_buffered_bytes: 4_000,
            timeout: Duration::from_millis(10),
        });
        let mut output = None;
        for fragment in &decoded {
            output = reassembler.push_at(fragment, start).unwrap().or(output);
        }
        let output = output.unwrap();
        assert_eq!(output.payload, vec![7; 3_000]);
        let verified = decode_ip(&output.encode().unwrap()).unwrap();
        assert_eq!(verified.transport_checksum_valid, Some(true));

        assert!(reassembler.push_at(&decoded[0], start).unwrap().is_none());
        assert_eq!(reassembler.pending(), 1);
        assert_eq!(reassembler.expire(start + Duration::from_millis(11)), 1);
        assert_eq!(reassembler.pending(), 0);
    }

    #[test]
    fn tcp_state_tracker_accepts_handshake_and_teardown_and_rejects_bad_start() {
        let mut client = TcpStateTracker::default();
        assert_eq!(
            client
                .observe(TcpDirection::Outbound, tcp_flag::SYN)
                .unwrap(),
            TcpState::SynSent
        );
        assert_eq!(
            client
                .observe(TcpDirection::Inbound, tcp_flag::SYN | tcp_flag::ACK)
                .unwrap(),
            TcpState::Established
        );
        client
            .observe(TcpDirection::Outbound, tcp_flag::ACK)
            .unwrap();
        assert_eq!(
            client
                .observe(TcpDirection::Outbound, tcp_flag::FIN | tcp_flag::ACK)
                .unwrap(),
            TcpState::FinWait1
        );
        assert_eq!(
            client
                .observe(TcpDirection::Inbound, tcp_flag::ACK)
                .unwrap(),
            TcpState::FinWait2
        );
        assert_eq!(
            client
                .observe(TcpDirection::Inbound, tcp_flag::FIN | tcp_flag::ACK)
                .unwrap(),
            TcpState::TimeWait
        );

        let mut invalid = TcpStateTracker::default();
        assert!(invalid
            .observe(TcpDirection::Outbound, tcp_flag::ACK)
            .is_err());
    }
}
