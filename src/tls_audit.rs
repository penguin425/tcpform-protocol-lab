//! TLS certificate and negotiated-session auditing.

use rustls::pki_types::{CertificateDer, ServerName};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufReader, Cursor};
use std::net::TcpStream;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize)]
pub struct CertificateAudit {
    pub sha256: String,
    pub not_before: String,
    pub not_after: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    pub days_remaining: i64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsAudit {
    pub address: Option<String>,
    pub server_name: Option<String>,
    pub protocol: Option<String>,
    pub cipher_suite: Option<String>,
    pub alpn: Option<String>,
    pub certificates: Vec<CertificateAudit>,
}

pub fn audit_certificate_file(path: &str, warn_days: u64) -> Result<TlsAudit, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read certificate {path}: {error}"))?;
    let certificates = parse_certificates(&bytes)?
        .iter()
        .map(|certificate| audit_certificate(certificate, warn_days))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TlsAudit {
        address: None,
        server_name: None,
        protocol: None,
        cipher_suite: None,
        alpn: None,
        certificates,
    })
}

pub fn audit_tls_endpoint(
    address: &str,
    server_name: &str,
    ca_file: Option<&str>,
    warn_days: u64,
    alpn: &[String],
) -> Result<TlsAudit, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        let bytes = fs::read(path).map_err(|error| format!("cannot read CA {path}: {error}"))?;
        for certificate in parse_certificates(&bytes)? {
            roots
                .add(certificate)
                .map_err(|error| format!("invalid CA certificate: {error}"))?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|error| format!("invalid TLS server name: {error}"))?;
    let connection = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|error| format!("cannot create TLS client: {error}"))?;
    let socket = TcpStream::connect(address)
        .map_err(|error| format!("cannot connect TLS endpoint {address}: {error}"))?;
    let mut stream = rustls::StreamOwned::new(connection, socket);
    stream
        .conn
        .complete_io(&mut stream.sock)
        .map_err(|error| format!("TLS handshake failed: {error}"))?;
    let certificates = stream
        .conn
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(|certificate| audit_certificate(certificate, warn_days))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TlsAudit {
        address: Some(address.to_string()),
        server_name: Some(server_name.to_string()),
        protocol: stream
            .conn
            .protocol_version()
            .map(|version| format!("{version:?}")),
        cipher_suite: stream
            .conn
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite())),
        alpn: stream
            .conn
            .alpn_protocol()
            .map(|value| String::from_utf8_lossy(value).into_owned()),
        certificates,
    })
}

fn parse_certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    if bytes.starts_with(b"-----BEGIN") {
        let mut reader = BufReader::new(Cursor::new(bytes));
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("invalid PEM certificate: {error}"))?;
        if certificates.is_empty() {
            return Err("certificate file contains no certificates".into());
        }
        Ok(certificates)
    } else {
        Ok(vec![CertificateDer::from(bytes.to_vec())])
    }
}

fn audit_certificate(
    certificate: &CertificateDer<'_>,
    warn_days: u64,
) -> Result<CertificateAudit, String> {
    let times = certificate_times(certificate.as_ref())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs() as i64;
    let days_remaining = (times.1 - now).div_euclid(86_400);
    let status = if now < times.0 {
        "not_yet_valid"
    } else if now > times.1 {
        "expired"
    } else if days_remaining <= warn_days as i64 {
        "expiring"
    } else {
        "valid"
    };
    Ok(CertificateAudit {
        sha256: Sha256::digest(certificate.as_ref())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        not_before: times.2,
        not_after: times.3,
        not_before_unix: times.0,
        not_after_unix: times.1,
        days_remaining,
        status: status.to_string(),
    })
}

fn certificate_times(der: &[u8]) -> Result<(i64, i64, String, String), String> {
    let mut values = Vec::new();
    let mut offset = 0;
    while offset + 2 < der.len() && values.len() < 2 {
        let tag = der[offset];
        let length = der[offset + 1] as usize;
        if matches!((tag, length), (0x17, 13) | (0x18, 15)) && offset + 2 + length <= der.len() {
            if let Ok(text) = std::str::from_utf8(&der[offset + 2..offset + 2 + length]) {
                if let Ok(timestamp) = parse_asn1_time(text) {
                    values.push((timestamp, text.to_string()));
                }
            }
        }
        offset += 1;
    }
    if values.len() != 2 {
        return Err("certificate validity period could not be decoded".into());
    }
    Ok((
        values[0].0,
        values[1].0,
        values[0].1.clone(),
        values[1].1.clone(),
    ))
}

fn parse_asn1_time(value: &str) -> Result<i64, String> {
    if !value.ends_with('Z') {
        return Err("certificate time is not UTC".into());
    }
    let (year, rest) = if value.len() == 13 {
        let year = parse_part(value, 0, 2)?;
        (if year >= 50 { 1900 + year } else { 2000 + year }, 2)
    } else if value.len() == 15 {
        (parse_part(value, 0, 4)?, 4)
    } else {
        return Err("unsupported certificate time".into());
    };
    let month = parse_part(value, rest, 2)?;
    let day = parse_part(value, rest + 2, 2)?;
    let hour = parse_part(value, rest + 4, 2)?;
    let minute = parse_part(value, rest + 6, 2)?;
    let second = parse_part(value, rest + 8, 2)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err("invalid certificate time component".into());
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

fn parse_part(value: &str, start: usize, length: usize) -> Result<i64, String> {
    value
        .get(start..start + length)
        .ok_or("truncated certificate time")?
        .parse::<i64>()
        .map_err(|_| "invalid certificate time".to_string())
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * shifted_month + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asn1_time_parser_handles_utc_and_generalized_dates() {
        assert_eq!(parse_asn1_time("700101000000Z").unwrap(), 0);
        assert_eq!(parse_asn1_time("19700101000000Z").unwrap(), 0);
        assert!(parse_asn1_time("19700101000000+0100").is_err());
    }

    #[test]
    fn generated_certificate_reports_validity_and_fingerprint() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let audit = audit_certificate(certificate.der(), 30).unwrap();
        assert_eq!(audit.sha256.len(), 64);
        assert!(audit.not_before.ends_with('Z'));
        assert!(audit.not_after_unix > audit.not_before_unix);
    }

    #[test]
    fn endpoint_audit_reports_protocol_cipher_alpn_and_chain() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let directory = std::env::temp_dir().join(format!("tcpform-audit-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let ca = directory.join("ca.pem");
        std::fs::write(&ca, certificate.pem()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let cert_der = certificate.der().clone();
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into();
        let server = std::thread::spawn(move || {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .unwrap();
            config.alpn_protocols = vec![b"h2".to_vec()];
            let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let (socket, _) = listener.accept().unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            stream.conn.complete_io(&mut stream.sock).unwrap();
        });
        let report = audit_tls_endpoint(
            &address.to_string(),
            "localhost",
            Some(ca.to_str().unwrap()),
            30,
            &["h2".to_string()],
        )
        .unwrap();
        assert_eq!(report.alpn.as_deref(), Some("h2"));
        assert!(report.protocol.is_some());
        assert!(report.cipher_suite.is_some());
        assert_eq!(report.certificates.len(), 1);
        server.join().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}
