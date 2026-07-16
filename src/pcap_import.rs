//! PCAP/PCAPNG decoding and starter DSL generation.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedPacket {
    pub timestamp_ns: u64,
    pub source: String,
    pub destination: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub transport: String,
    pub flags: Vec<String>,
    pub sequence: Option<u32>,
    pub acknowledgement: Option<u32>,
    pub payload: Vec<u8>,
    pub frame_length: usize,
}

#[derive(Debug, Clone)]
struct Session {
    client: (String, u16),
    number: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CaptureInference {
    pub schema_version: &'static str,
    pub packet_count: usize,
    pub sessions: Vec<SessionInference>,
    pub fields: Vec<FieldInference>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionInference {
    pub id: String,
    pub transport: String,
    pub client: String,
    pub server: String,
    pub packet_count: usize,
    pub states: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FieldInference {
    pub session: String,
    pub direction: String,
    pub name: String,
    pub offset: usize,
    pub length: usize,
    pub kind: String,
    pub confidence: f64,
    pub examples_hex: Vec<String>,
}

pub fn import_capture(bytes: &[u8], protocol: &str) -> Result<String, String> {
    validate_name(protocol)?;
    let packets = decode_capture(bytes)?;
    if packets.is_empty() {
        return Err("capture contains no supported IPv4/IPv6 TCP or UDP packets".into());
    }
    Ok(render_dsl(&packets, protocol))
}

pub fn analyze_capture(bytes: &[u8]) -> Result<CaptureInference, String> {
    let packets = decode_capture(bytes)?;
    if packets.is_empty() {
        return Err("capture contains no supported IPv4/IPv6 TCP or UDP packets".into());
    }
    Ok(analyze_packets(&packets))
}

pub fn decode_capture(bytes: &[u8]) -> Result<Vec<CapturedPacket>, String> {
    if bytes.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        decode_pcapng(bytes)
    } else {
        decode_pcap(bytes)
    }
}

fn decode_pcap(bytes: &[u8]) -> Result<Vec<CapturedPacket>, String> {
    if bytes.len() < 24 {
        return Err("truncated PCAP header".into());
    }
    let (endian, nanoseconds) = match &bytes[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, true),
        _ => return Err("unsupported capture format (expected PCAP or PCAPNG)".into()),
    };
    let link_type = read_u32(bytes, 20, endian)?;
    let mut offset = 24;
    let mut packets = Vec::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 16 {
            return Err(format!("truncated PCAP record at byte {offset}"));
        }
        let seconds = read_u32(bytes, offset, endian)? as u64;
        let fraction = read_u32(bytes, offset + 4, endian)? as u64;
        let captured = read_u32(bytes, offset + 8, endian)? as usize;
        offset += 16;
        let frame = bytes
            .get(offset..offset + captured)
            .ok_or_else(|| format!("truncated PCAP packet at byte {offset}"))?;
        let timestamp_ns = seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(if nanoseconds {
                fraction
            } else {
                fraction.saturating_mul(1_000)
            });
        if let Some(packet) = decode_frame(frame, link_type, timestamp_ns) {
            packets.push(packet);
        }
        offset += captured;
    }
    Ok(packets)
}

fn decode_pcapng(bytes: &[u8]) -> Result<Vec<CapturedPacket>, String> {
    if bytes.len() < 28 {
        return Err("truncated PCAPNG section header".into());
    }
    let endian = match bytes.get(8..12) {
        Some([0x4d, 0x3c, 0x2b, 0x1a]) => Endian::Little,
        Some([0x1a, 0x2b, 0x3c, 0x4d]) => Endian::Big,
        _ => return Err("invalid PCAPNG byte-order magic".into()),
    };
    let mut offset = 0usize;
    let mut interfaces = Vec::<(u32, u64)>::new();
    let mut packets = Vec::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return Err(format!("truncated PCAPNG block at byte {offset}"));
        }
        let block_type = read_u32(bytes, offset, endian)?;
        let length = read_u32(bytes, offset + 4, endian)? as usize;
        if length < 12 || !length.is_multiple_of(4) || offset + length > bytes.len() {
            return Err(format!(
                "invalid PCAPNG block length {length} at byte {offset}"
            ));
        }
        if read_u32(bytes, offset + length - 4, endian)? as usize != length {
            return Err(format!("PCAPNG block length mismatch at byte {offset}"));
        }
        match block_type {
            1 if length >= 20 => {
                let link_type = read_u16(bytes, offset + 8, endian)? as u32;
                let resolution =
                    interface_resolution(&bytes[offset + 16..offset + length - 4], endian);
                interfaces.push((link_type, resolution));
            }
            6 if length >= 32 => {
                let interface = read_u32(bytes, offset + 8, endian)? as usize;
                let high = read_u32(bytes, offset + 12, endian)? as u64;
                let low = read_u32(bytes, offset + 16, endian)? as u64;
                let captured = read_u32(bytes, offset + 20, endian)? as usize;
                let frame_start = offset + 28;
                if let (Some((link_type, units)), Some(frame)) = (
                    interfaces.get(interface),
                    bytes.get(frame_start..frame_start.saturating_add(captured)),
                ) {
                    let ticks = (high << 32) | low;
                    let timestamp_ns = ticks.saturating_mul(1_000_000_000) / units.max(&1);
                    if let Some(packet) = decode_frame(frame, *link_type, timestamp_ns) {
                        packets.push(packet);
                    }
                }
            }
            _ => {}
        }
        offset += length;
    }
    Ok(packets)
}

fn interface_resolution(options: &[u8], endian: Endian) -> u64 {
    let mut offset = 0;
    while offset + 4 <= options.len() {
        let code = read_u16(options, offset, endian).unwrap_or(0);
        let length = read_u16(options, offset + 2, endian).unwrap_or(0) as usize;
        if code == 0 || offset + 4 + length > options.len() {
            break;
        }
        if code == 9 && length == 1 {
            let value = options[offset + 4];
            return if value & 0x80 == 0 {
                10u64.saturating_pow(value as u32)
            } else {
                2u64.saturating_pow((value & 0x7f) as u32)
            };
        }
        offset += 4 + ((length + 3) & !3);
    }
    1_000_000
}

fn decode_frame(frame: &[u8], link_type: u32, timestamp_ns: u64) -> Option<CapturedPacket> {
    let (network, frame_length) = match link_type {
        1 if frame.len() >= 14 => (&frame[14..], frame.len()),
        101 => (frame, frame.len()),
        _ => return None,
    };
    match network.first()? >> 4 {
        4 => decode_ipv4(network, timestamp_ns, frame_length),
        6 => decode_ipv6(network, timestamp_ns, frame_length),
        _ => None,
    }
}

fn decode_ipv4(packet: &[u8], timestamp_ns: u64, frame_length: usize) -> Option<CapturedPacket> {
    let header = ((packet.first()? & 0x0f) as usize) * 4;
    if header < 20 || packet.len() < header {
        return None;
    }
    let total = u16::from_be_bytes(packet.get(2..4)?.try_into().ok()?) as usize;
    let end = total.min(packet.len());
    let source = Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(12..16)?).ok()?).to_string();
    let destination = Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(16..20)?).ok()?).to_string();
    decode_transport(
        &packet[header..end],
        packet[9],
        timestamp_ns,
        frame_length,
        source,
        destination,
    )
}

fn decode_ipv6(packet: &[u8], timestamp_ns: u64, frame_length: usize) -> Option<CapturedPacket> {
    if packet.len() < 40 {
        return None;
    }
    let payload = u16::from_be_bytes(packet.get(4..6)?.try_into().ok()?) as usize;
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?).to_string();
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?).to_string();
    decode_transport(
        &packet[40..(40 + payload).min(packet.len())],
        packet[6],
        timestamp_ns,
        frame_length,
        source,
        destination,
    )
}

fn decode_transport(
    packet: &[u8],
    protocol: u8,
    timestamp_ns: u64,
    frame_length: usize,
    source: String,
    destination: String,
) -> Option<CapturedPacket> {
    let source_port = u16::from_be_bytes(packet.get(0..2)?.try_into().ok()?);
    let destination_port = u16::from_be_bytes(packet.get(2..4)?.try_into().ok()?);
    match protocol {
        6 => {
            let header = ((packet.get(12)? >> 4) as usize) * 4;
            if header < 20 || packet.len() < header {
                return None;
            }
            let bits = packet[13];
            let names = [
                (0x01, "FIN"),
                (0x02, "SYN"),
                (0x04, "RST"),
                (0x08, "PSH"),
                (0x10, "ACK"),
                (0x20, "URG"),
                (0x40, "ECE"),
                (0x80, "CWR"),
            ];
            Some(CapturedPacket {
                timestamp_ns,
                source,
                destination,
                source_port,
                destination_port,
                transport: "tcp".into(),
                flags: names
                    .into_iter()
                    .filter(|(mask, _)| bits & mask != 0)
                    .map(|(_, name)| name.into())
                    .collect(),
                sequence: Some(u32::from_be_bytes(packet.get(4..8)?.try_into().ok()?)),
                acknowledgement: Some(u32::from_be_bytes(packet.get(8..12)?.try_into().ok()?)),
                payload: packet[header..].to_vec(),
                frame_length,
            })
        }
        17 if packet.len() >= 8 => Some(CapturedPacket {
            timestamp_ns,
            source,
            destination,
            source_port,
            destination_port,
            transport: "udp".into(),
            flags: vec!["UDP".into()],
            sequence: None,
            acknowledgement: None,
            payload: packet[8..].to_vec(),
            frame_length,
        }),
        _ => None,
    }
}

fn render_dsl(packets: &[CapturedPacket], protocol: &str) -> String {
    let sessions = build_sessions(packets);
    let inference = analyze_packets_with_sessions(packets, &sessions);
    let mut out = format!("tcpform {{ dsl_version = 2 }}\n\n# Generated from a packet capture. Review roles, secrets, and assertions before use.\nprotocol \"{protocol}\" {{\n  description = \"Imported {} packet(s) across {} session(s)\"\n  clock = \"virtual\"\n", packets.len(), sessions.len());
    render_inferred_schemas(&mut out, &inference.fields);
    let mut previous = None::<String>;
    let mut last_timestamp = packets[0].timestamp_ns;
    let mut role_states = HashMap::<String, String>::new();
    for (index, packet) in packets.iter().enumerate() {
        let session = &sessions[&session_key(packet)];
        let source_is_client = session.client == (packet.source.clone(), packet.source_port);
        let suffix = if sessions.len() == 1 {
            String::new()
        } else {
            format!("_{}", session.number)
        };
        let source_role = if source_is_client {
            format!("client{suffix}")
        } else {
            format!("server{suffix}")
        };
        let destination_role = if source_is_client {
            format!("server{suffix}")
        } else {
            format!("client{suffix}")
        };
        let send_name = format!("frame_{:04}_send", index + 1);
        let recv_name = format!("frame_{:04}_recv", index + 1);
        let delta_us = packet.timestamp_ns.saturating_sub(last_timestamp) / 1_000;
        let flags = packet
            .flags
            .iter()
            .map(|flag| format!("\"{flag}\""))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "\n  # frame {} · {}:{} -> {}:{} · {} · {} bytes · +{}us\n",
            index + 1,
            packet.source,
            packet.source_port,
            packet.destination,
            packet.destination_port,
            packet.transport,
            packet.frame_length,
            delta_us
        ));
        out.push_str(&format!("  step \"{send_name}\" {{\n    role = \"{source_role}\"\n    action = \"send\"\n    to = \"{destination_role}\"\n"));
        if let Some(dependency) = &previous {
            out.push_str(&format!("    depends_on = [\"{dependency}\"]\n"));
        }
        let source_before = role_states
            .get(&source_role)
            .cloned()
            .unwrap_or_else(|| "initial".into());
        let source_after = infer_endpoint_state(&source_before, packet, false);
        out.push_str(&format!(
            "    from_state = \"{source_before}\"\n    to_state = \"{source_after}\"\n"
        ));
        out.push_str("    segment {\n");
        out.push_str(&format!("      flags = [{flags}]\n"));
        if let Some(sequence) = packet.sequence {
            out.push_str(&format!("      seq = {sequence}\n"));
        }
        if let Some(acknowledgement) = packet.acknowledgement {
            out.push_str(&format!("      ack = {acknowledgement}\n"));
        }
        if !packet.payload.is_empty() {
            out.push_str(&format!(
                "      hex = \"{}\"\n",
                crate::bytes_to_hex(&packet.payload)
            ));
        }
        if delta_us > 0 {
            out.push_str(&format!(
                "      delay = \"{}ms\"\n",
                delta_us.div_ceil(1_000)
            ));
        }
        out.push_str("    }\n  }\n");
        role_states.insert(source_role.clone(), source_after);
        let destination_before = role_states
            .get(&destination_role)
            .cloned()
            .unwrap_or_else(|| "initial".into());
        let destination_after = infer_endpoint_state(&destination_before, packet, true);
        out.push_str(&format!("  step \"{recv_name}\" {{\n    role = \"{destination_role}\"\n    action = \"recv\"\n    depends_on = [\"{send_name}\"]\n    from_state = \"{destination_before}\"\n    to_state = \"{destination_after}\"\n    expect {{ from = \"{source_role}\" flags = [{flags}] }}\n  }}\n"));
        role_states.insert(destination_role, destination_after);
        previous = Some(recv_name);
        last_timestamp = packet.timestamp_ns;
    }
    out.push_str(&format!("}}\n\ncases \"{protocol}\" {{\n  case \"capture_smoke\" {{ expect = \"pass\" tags = [\"smoke\", \"pcap-import\"] }}\n}}\n"));
    out
}

fn build_sessions(packets: &[CapturedPacket]) -> HashMap<String, Session> {
    let mut order = Vec::<String>::new();
    let mut grouped = HashMap::<String, Vec<&CapturedPacket>>::new();
    for packet in packets {
        let key = session_key(packet);
        if !grouped.contains_key(&key) {
            order.push(key.clone());
        }
        grouped.entry(key).or_default().push(packet);
    }
    order
        .into_iter()
        .enumerate()
        .map(|(index, key)| {
            let packets = &grouped[&key];
            let initiator = packets
                .iter()
                .find(|packet| {
                    packet.transport == "tcp"
                        && packet.flags.iter().any(|flag| flag == "SYN")
                        && !packet.flags.iter().any(|flag| flag == "ACK")
                })
                .copied()
                .unwrap_or(packets[0]);
            (
                key,
                Session {
                    client: (initiator.source.clone(), initiator.source_port),
                    number: index + 1,
                },
            )
        })
        .collect()
}

fn analyze_packets(packets: &[CapturedPacket]) -> CaptureInference {
    let sessions = build_sessions(packets);
    analyze_packets_with_sessions(packets, &sessions)
}

fn analyze_packets_with_sessions(
    packets: &[CapturedPacket],
    sessions: &HashMap<String, Session>,
) -> CaptureInference {
    let mut grouped = BTreeMap::<usize, Vec<&CapturedPacket>>::new();
    for packet in packets {
        grouped
            .entry(sessions[&session_key(packet)].number)
            .or_default()
            .push(packet);
    }
    let mut session_reports = Vec::new();
    let mut fields = Vec::new();
    for (number, packets) in grouped {
        let session = &sessions[&session_key(packets[0])];
        let client = format!("{}:{}", session.client.0, session.client.1);
        let first = packets[0];
        let server = if session.client == (first.source.clone(), first.source_port) {
            format!("{}:{}", first.destination, first.destination_port)
        } else {
            format!("{}:{}", first.source, first.source_port)
        };
        let mut states = vec!["initial".to_string()];
        let mut current = "initial".to_string();
        for packet in &packets {
            let next = infer_session_state(&current, packet);
            if next != current {
                states.push(next.clone());
                current = next;
            }
        }
        let id = format!("session_{number}");
        fields.extend(infer_payload_fields(&id, session, &packets));
        session_reports.push(SessionInference {
            id,
            transport: first.transport.clone(),
            client,
            server,
            packet_count: packets.len(),
            states,
        });
    }
    let mut warnings = vec![
        "inferred states and fields are hypotheses; review them before testing an implementation"
            .into(),
    ];
    if fields.is_empty() {
        warnings
            .push("no repeated same-direction payloads were available for field inference".into());
    }
    CaptureInference {
        schema_version: "1.0",
        packet_count: packets.len(),
        sessions: session_reports,
        fields,
        warnings,
    }
}

fn infer_payload_fields(
    session_id: &str,
    session: &Session,
    packets: &[&CapturedPacket],
) -> Vec<FieldInference> {
    let mut directions = BTreeMap::<&str, Vec<&[u8]>>::new();
    for packet in packets.iter().filter(|packet| !packet.payload.is_empty()) {
        let direction = if session.client == (packet.source.clone(), packet.source_port) {
            "client_to_server"
        } else {
            "server_to_client"
        };
        directions
            .entry(direction)
            .or_default()
            .push(&packet.payload);
    }
    let mut result = Vec::new();
    for (direction, samples) in directions {
        if samples.len() < 2 {
            continue;
        }
        let width = samples.iter().map(|sample| sample.len()).min().unwrap_or(0);
        if width == 0 {
            continue;
        }
        let constant = (0..width)
            .map(|offset| {
                samples
                    .iter()
                    .all(|sample| sample[offset] == samples[0][offset])
            })
            .collect::<Vec<_>>();
        let mut offset = 0;
        let mut constant_index = 1;
        let mut variable_index = 1;
        while offset < width {
            let fixed = constant[offset];
            let start = offset;
            while offset < width && constant[offset] == fixed {
                offset += 1;
            }
            let length = offset - start;
            let (name, kind, confidence) = if fixed {
                let ascii = samples[0][start..offset]
                    .iter()
                    .all(|byte| byte.is_ascii_graphic() || *byte == b' ');
                let name = format!("constant_{constant_index}");
                constant_index += 1;
                (name, if ascii { "ascii" } else { "hex" }, 1.0)
            } else {
                let name = format!("variable_{variable_index}");
                variable_index += 1;
                (name, "variable", 0.75)
            };
            let examples_hex = samples
                .iter()
                .map(|sample| crate::bytes_to_hex(&sample[start..offset]))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .take(3)
                .collect();
            result.push(FieldInference {
                session: session_id.into(),
                direction: direction.into(),
                name,
                offset: start,
                length,
                kind: kind.into(),
                confidence,
                examples_hex,
            });
        }
        if samples.iter().any(|sample| sample.len() != width) {
            result.push(FieldInference {
                session: session_id.into(),
                direction: direction.into(),
                name: "variable_tail".into(),
                offset: width,
                length: samples
                    .iter()
                    .map(|sample| sample.len())
                    .max()
                    .unwrap_or(width)
                    - width,
                kind: "variable_length".into(),
                confidence: 1.0,
                examples_hex: samples
                    .iter()
                    .filter(|sample| sample.len() > width)
                    .map(|sample| crate::bytes_to_hex(&sample[width..]))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .take(3)
                    .collect(),
            });
        }
    }
    result
}

fn render_inferred_schemas(out: &mut String, fields: &[FieldInference]) {
    let mut groups = BTreeMap::<(&str, &str), Vec<&FieldInference>>::new();
    for field in fields.iter().filter(|field| field.length > 0) {
        groups
            .entry((&field.session, &field.direction))
            .or_default()
            .push(field);
    }
    for ((session, direction), fields) in groups {
        out.push_str(&format!(
            "\n  # Inferred from repeated payloads; verify before relying on these boundaries.\n  header_schema \"{session}_{direction}\" {{\n    offset = 0\n    endian = \"big\"\n    fields = {{\n"
        ));
        for field in fields {
            let format = if field.kind == "ascii" {
                "ascii"
            } else {
                "hex"
            };
            out.push_str(&format!(
                "      {} = {{ offset = {} length = {} format = \"{}\" }}\n",
                field.name, field.offset, field.length, format
            ));
        }
        out.push_str("    }\n  }\n");
    }
}

fn infer_session_state(current: &str, packet: &CapturedPacket) -> String {
    if packet.transport == "udp" {
        return "active".into();
    }
    let has = |flag: &str| packet.flags.iter().any(|candidate| candidate == flag);
    if has("RST") {
        "reset".into()
    } else if has("FIN") {
        if current == "closing" {
            "closed".into()
        } else {
            "closing".into()
        }
    } else if has("SYN") && has("ACK") {
        "syn_ack".into()
    } else if has("SYN") {
        "syn".into()
    } else if (has("ACK") && matches!(current, "syn_ack" | "syn")) || !packet.payload.is_empty() {
        "established".into()
    } else if current == "closing" && has("ACK") {
        "closed".into()
    } else {
        current.into()
    }
}

fn infer_endpoint_state(current: &str, packet: &CapturedPacket, receiving: bool) -> String {
    if packet.transport == "udp" {
        return "active".into();
    }
    let has = |flag: &str| packet.flags.iter().any(|candidate| candidate == flag);
    if has("RST") {
        return "reset".into();
    }
    if has("FIN") {
        return if receiving {
            "fin_received"
        } else {
            "fin_sent"
        }
        .into();
    }
    if has("SYN") && has("ACK") {
        return if receiving {
            "syn_ack_received"
        } else {
            "syn_ack_sent"
        }
        .into();
    }
    if has("SYN") {
        return if receiving {
            "syn_received"
        } else {
            "syn_sent"
        }
        .into();
    }
    if !packet.payload.is_empty()
        || has("ACK")
            && matches!(
                current,
                "syn_sent" | "syn_received" | "syn_ack_sent" | "syn_ack_received"
            )
    {
        return "established".into();
    }
    current.into()
}

fn session_key(packet: &CapturedPacket) -> String {
    let left = format!("{}:{}", packet.source, packet.source_port);
    let right = format!("{}:{}", packet.destination, packet.destination_port);
    if left <= right {
        format!("{}|{left}|{right}", packet.transport)
    } else {
        format!("{}|{right}|{left}", packet.transport)
    }
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '_' | '-'))
    {
        Err("protocol name may contain only ASCII letters, numbers, `_`, and `-`".into())
    } else {
        Ok(())
    }
}

fn read_u16(bytes: &[u8], offset: usize, endian: Endian) -> Result<u16, String> {
    let value: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or("truncated capture")?
        .try_into()
        .unwrap();
    Ok(match endian {
        Endian::Little => u16::from_le_bytes(value),
        Endian::Big => u16::from_be_bytes(value),
    })
}

fn read_u32(bytes: &[u8], offset: usize, endian: Endian) -> Result<u32, String> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or("truncated capture")?
        .try_into()
        .unwrap();
    Ok(match endian {
        Endian::Little => u32::from_le_bytes(value),
        Endian::Big => u32::from_be_bytes(value),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(pcapng: bool) -> Vec<u8> {
        let source = r#"protocol "udp_capture" {
          step "send" { role="client" action="send" to="server" segment { flags=["UDP"] hex="010203" } }
          step "recv" { role="server" action="recv" expect { from="client" flags=["UDP"] } }
        }"#;
        let protocols = crate::model::interpret(&crate::parse_file(source).unwrap()).unwrap();
        let trace = crate::Engine::new(protocols[0].clone())
            .unwrap()
            .run()
            .unwrap();
        if pcapng {
            crate::output::trace_pcapng(&trace)
        } else {
            crate::output::trace_pcap(&trace)
        }
    }

    fn ipv4_udp_capture() -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&31u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[192, 0, 2, 2]);
        frame.extend(ip);
        frame.extend_from_slice(&53000u16.to_be_bytes());
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(&11u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(b"dns");
        let mut capture = Vec::new();
        capture.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        capture.extend_from_slice(&2u16.to_le_bytes());
        capture.extend_from_slice(&4u16.to_le_bytes());
        capture.extend_from_slice(&[0; 12]);
        capture.extend_from_slice(&1u32.to_le_bytes());
        capture.extend_from_slice(&0u32.to_le_bytes());
        capture.extend_from_slice(&123u32.to_le_bytes());
        capture.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        capture.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        capture.extend(frame);
        capture
    }

    #[test]
    fn classic_and_next_generation_captures_generate_runnable_dsl() {
        for bytes in [capture(false), capture(true)] {
            let packets = decode_capture(&bytes).unwrap();
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].transport, "tcp");
            assert_eq!(packets[0].payload, [1, 2, 3]);
            let generated = import_capture(&bytes, "imported_udp").unwrap();
            assert!(generated.contains("frame_0001_send"));
            assert!(generated.contains("capture_smoke"));
            let blocks = crate::parse_file(&generated).unwrap();
            let protocols = crate::model::interpret(&blocks).unwrap();
            let cases = crate::model::interpret_cases(&blocks).unwrap();
            let results = crate::Engine::new(protocols[0].clone())
                .unwrap()
                .run_cases(&cases[0].cases);
            assert!(
                results.iter().all(|result| result.passed),
                "{results:?}\n{generated}"
            );
        }
    }

    #[test]
    fn malformed_and_empty_captures_are_rejected() {
        assert!(decode_capture(&[]).is_err());
        let mut empty = vec![0u8; 24];
        empty[..4].copy_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        empty[20..24].copy_from_slice(&1u32.to_le_bytes());
        assert!(import_capture(&empty, "empty").is_err());
        assert!(import_capture(&capture(false), "bad name").is_err());
    }

    #[test]
    fn udp_endpoints_headers_and_payload_are_decoded() {
        let packets = decode_capture(&ipv4_udp_capture()).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].transport, "udp");
        assert_eq!(packets[0].source, "192.0.2.1");
        assert_eq!(packets[0].source_port, 53000);
        assert_eq!(packets[0].destination_port, 53);
        assert_eq!(packets[0].payload, b"dns");
        assert_eq!(packets[0].timestamp_ns, 123_000);
    }

    #[test]
    fn infers_handshake_states_and_repeated_payload_fields() {
        let packet = |timestamp_ns: u64,
                      source: &str,
                      destination: &str,
                      flags: &[&str],
                      payload: &[u8]|
         -> CapturedPacket {
            CapturedPacket {
                timestamp_ns,
                source: source.into(),
                destination: destination.into(),
                source_port: if source == "client" { 40_000 } else { 9000 },
                destination_port: if destination == "server" {
                    9000
                } else {
                    40_000
                },
                transport: "tcp".into(),
                flags: flags.iter().map(|flag| (*flag).into()).collect(),
                sequence: Some(timestamp_ns as u32),
                acknowledgement: Some(0),
                payload: payload.into(),
                frame_length: 54 + payload.len(),
            }
        };
        let packets = vec![
            packet(1, "client", "server", &["SYN"], b""),
            packet(2, "server", "client", &["SYN", "ACK"], b""),
            packet(3, "client", "server", &["ACK"], b""),
            packet(4, "client", "server", &["PSH", "ACK"], b"TF\x01alpha"),
            packet(5, "client", "server", &["PSH", "ACK"], b"TF\x02bravo"),
        ];
        let report = analyze_packets(&packets);
        assert_eq!(report.sessions.len(), 1);
        assert_eq!(report.sessions[0].client, "client:40000");
        assert_eq!(
            report.sessions[0].states,
            ["initial", "syn", "syn_ack", "established"]
        );
        assert!(report
            .fields
            .iter()
            .any(|field| { field.offset == 0 && field.length == 2 && field.kind == "ascii" }));
        assert!(report
            .fields
            .iter()
            .any(|field| { field.offset == 2 && field.length >= 1 && field.kind == "variable" }));

        let generated = render_dsl(&packets, "inferred");
        assert!(generated.contains("header_schema \"session_1_client_to_server\""));
        assert!(generated.contains("from_state = \"syn_ack_received\""));
        assert!(generated.contains("to_state = \"established\""));
        let blocks = crate::parse_file(&generated).unwrap();
        let protocols = crate::model::interpret(&blocks).unwrap();
        let cases = crate::model::interpret_cases(&blocks).unwrap();
        let results = crate::Engine::new(protocols[0].clone())
            .unwrap()
            .run_cases(&cases[0].cases);
        assert!(results.iter().all(|result| result.passed), "{results:?}");
    }
}
