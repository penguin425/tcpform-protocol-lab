use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::fs::{self, File};
use std::io::{BufReader, Write};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct ProxyOptions {
    pub listen: String,
    pub upstream: String,
    pub downstream_cert: Option<String>,
    pub downstream_key: Option<String>,
    pub upstream_tls: bool,
    pub upstream_ca: Option<String>,
    pub server_name: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub alpn: Vec<String>,
    pub capture: Option<String>,
    pub timeout_ms: u64,
}

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

pub fn run(options: ProxyOptions) -> Result<(), String> {
    if options.downstream_cert.is_some() != options.downstream_key.is_some() {
        return Err("proxy downstream certificate and key must be specified together".into());
    }
    if options.client_cert.is_some() != options.client_key.is_some() {
        return Err("proxy upstream client certificate and key must be specified together".into());
    }
    if options.upstream_tls && options.server_name.is_none() {
        return Err("TLS upstream requires --server-name".into());
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&options.listen)
            .await
            .map_err(|e| format!("cannot bind proxy {}: {e}", options.listen))?;
        let (downstream, _) = tokio::time::timeout(
            std::time::Duration::from_millis(options.timeout_ms),
            listener.accept(),
        )
        .await
        .map_err(|_| "proxy accept timed out".to_string())?
        .map_err(|e| e.to_string())?;
        let downstream: Box<dyn AsyncStream> = if let (Some(cert), Some(key)) = (
            options.downstream_cert.as_deref(),
            options.downstream_key.as_deref(),
        ) {
            let mut config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(load_certificates(cert)?, load_private_key(key)?)
                .map_err(|e| e.to_string())?;
            config.alpn_protocols = options.alpn.iter().map(|v| v.as_bytes().to_vec()).collect();
            Box::new(
                tokio_rustls::TlsAcceptor::from(Arc::new(config))
                    .accept(downstream)
                    .await
                    .map_err(|e| format!("downstream TLS handshake failed: {e}"))?,
            )
        } else {
            Box::new(downstream)
        };
        let upstream = tokio::time::timeout(
            std::time::Duration::from_millis(options.timeout_ms),
            tokio::net::TcpStream::connect(&options.upstream),
        )
        .await
        .map_err(|_| "proxy upstream connect timed out".to_string())?
        .map_err(|e| format!("cannot connect proxy upstream {}: {e}", options.upstream))?;
        let upstream: Box<dyn AsyncStream> = if options.upstream_tls {
            let mut roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(ca) = options.upstream_ca.as_deref() {
                for cert in load_certificates(ca)? {
                    roots.add(cert).map_err(|e| e.to_string())?
                }
            }
            let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
            let mut config = match (
                options.client_cert.as_deref(),
                options.client_key.as_deref(),
            ) {
                (Some(cert), Some(key)) => builder
                    .with_client_auth_cert(load_certificates(cert)?, load_private_key(key)?)
                    .map_err(|e| e.to_string())?,
                _ => builder.with_no_client_auth(),
            };
            config.alpn_protocols = options.alpn.iter().map(|v| v.as_bytes().to_vec()).collect();
            let name = ServerName::try_from(options.server_name.clone().unwrap())
                .map_err(|e| e.to_string())?;
            Box::new(
                tokio_rustls::TlsConnector::from(Arc::new(config))
                    .connect(name, upstream)
                    .await
                    .map_err(|e| format!("upstream TLS handshake failed: {e}"))?,
            )
        } else {
            Box::new(upstream)
        };
        let capture = options
            .capture
            .map(File::create)
            .transpose()
            .map_err(|e| e.to_string())?
            .map(|file| Arc::new(Mutex::new(file)));
        proxy_bidirectional(downstream, upstream, capture).await
    })
}

async fn proxy_bidirectional(
    downstream: Box<dyn AsyncStream>,
    upstream: Box<dyn AsyncStream>,
    capture: Option<Arc<Mutex<File>>>,
) -> Result<(), String> {
    let (dr, dw) = tokio::io::split(downstream);
    let (ur, uw) = tokio::io::split(upstream);
    let left = tokio::spawn(pump(dr, uw, "downstream_to_upstream", capture.clone()));
    let right = tokio::spawn(pump(ur, dw, "upstream_to_downstream", capture));
    left.await.map_err(|e| e.to_string())??;
    right.await.map_err(|e| e.to_string())??;
    Ok(())
}
async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    direction: &str,
    capture: Option<Arc<Mutex<File>>>,
) -> Result<(), String> {
    let mut buffer = vec![0u8; 65_536];
    loop {
        let length = match reader.read(&mut buffer).await {
            Ok(length) => length,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                let _ = writer.shutdown().await;
                return Ok(());
            }
            Err(error) => return Err(error.to_string()),
        };
        if length == 0 {
            if let Err(error) = writer.shutdown().await {
                if !matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ) {
                    return Err(error.to_string());
                }
            }
            return Ok(());
        }
        if let Some(file) = &capture {
            let hex: String = buffer[..length]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            writeln!(
                file.lock().map_err(|_| "proxy capture lock poisoned")?,
                "{{\"direction\":\"{direction}\",\"length\":{length},\"hex\":\"{hex}\"}}"
            )
            .map_err(|e| e.to_string())?
        }
        writer
            .write_all(&buffer[..length])
            .await
            .map_err(|e| e.to_string())?
    }
}

fn load_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = File::open(path).map_err(|e| format!("cannot open certificate `{path}`: {e}"))?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read key `{path}`: {e}"))?;
    rustls_pemfile::private_key(&mut &bytes[..])
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no private key in `{path}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    #[test]
    fn tls_termination_reencryption_and_capture_round_trip() {
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let directory = std::env::temp_dir().join(format!("tcpform-proxy-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let cert_path = directory.join("cert.pem");
        let key_path = directory.join("key.pem");
        let capture = directory.join("capture.jsonl");
        fs::write(&cert_path, certificate.pem()).unwrap();
        fs::write(&key_path, key.serialize_pem()).unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let certs = load_certificates(cert_path.to_str().unwrap()).unwrap();
        let key_der = load_private_key(key_path.to_str().unwrap()).unwrap();
        let upstream = std::thread::spawn(move || {
            let (stream, _) = upstream_listener.accept().unwrap();
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key_der)
                .unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(Arc::new(config)).unwrap(),
                stream,
            );
            let mut request = [0; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.flush().unwrap();
            stream.conn.send_close_notify();
            stream.flush().unwrap();
        });
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);
        let proxy_cert = cert_path.display().to_string();
        let proxy_key = key_path.display().to_string();
        let proxy_ca = proxy_cert.clone();
        let capture_path = capture.display().to_string();
        let proxy = std::thread::spawn(move || {
            run(ProxyOptions {
                listen: listen.to_string(),
                upstream: upstream_address.to_string(),
                downstream_cert: Some(proxy_cert),
                downstream_key: Some(proxy_key),
                upstream_tls: true,
                upstream_ca: Some(proxy_ca),
                server_name: Some("localhost".into()),
                client_cert: None,
                client_key: None,
                alpn: Vec::new(),
                capture: Some(capture_path),
                timeout_ms: 2_000,
            })
        });
        let socket = (0..100)
            .find_map(|_| match TcpStream::connect(listen) {
                Ok(stream) => Some(stream),
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    None
                }
            })
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in load_certificates(cert_path.to_str().unwrap()).unwrap() {
            roots.add(cert).unwrap()
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from("localhost").unwrap();
        let mut client = rustls::StreamOwned::new(
            rustls::ClientConnection::new(Arc::new(config), name).unwrap(),
            socket,
        );
        client.write_all(b"ping").unwrap();
        client.flush().unwrap();
        let mut response = [0; 4];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"pong");
        client.conn.send_close_notify();
        client.flush().unwrap();
        drop(client);
        upstream.join().unwrap();
        proxy.join().unwrap().unwrap();
        let log = fs::read_to_string(&capture).unwrap();
        assert!(log.contains("70696e67") && log.contains("706f6e67"));
        let _ = fs::remove_dir_all(directory);
    }
}
