//! PCAP/PCAPNG decoding and starter DSL generation.

use std::collections::HashMap;
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

pub fn import_capture(bytes: &[u8], protocol: &str) -> Result<String, String> {
    validate_name(protocol)?;
    let packets = decode_capture(bytes)?;
    if packets.is_empty() {
        return Err("capture contains no supported IPv4/IPv6 TCP or UDP packets".into());
    }
    Ok(render_dsl(&packets, protocol))
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
    let mut sessions = HashMap::<String, Session>::new();
    let mut next_session = 1;
    for packet in packets {
        let key = session_key(packet);
        sessions.entry(key).or_insert_with(|| {
            let number = next_session;
            next_session += 1;
            Session {
                client: (packet.source.clone(), packet.source_port),
                number,
            }
        });
    }
    let mut out = format!("tcpform {{ dsl_version = 2 }}\n\n# Generated from a packet capture. Review roles, secrets, and assertions before use.\nprotocol \"{protocol}\" {{\n  description = \"Imported {} packet(s) across {} session(s)\"\n  clock = \"virtual\"\n", packets.len(), sessions.len());
    let mut previous = None::<String>;
    let mut last_timestamp = packets[0].timestamp_ns;
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
        out.push_str(&format!("  step \"{recv_name}\" {{\n    role = \"{destination_role}\"\n    action = \"recv\"\n    depends_on = [\"{send_name}\"]\n    expect {{ from = \"{source_role}\" flags = [{flags}] }}\n  }}\n"));
        previous = Some(recv_name);
        last_timestamp = packet.timestamp_ns;
    }
    out.push_str(&format!("}}\n\ncases \"{protocol}\" {{\n  case \"capture_smoke\" {{ expect = \"pass\" tags = [\"smoke\", \"pcap-import\"] }}\n}}\n"));
    out
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
}
