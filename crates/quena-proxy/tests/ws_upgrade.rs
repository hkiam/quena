//! A WebSocket upgrade to a server that also speaks HTTP/2 (Codex's Responses API over
//! WebSocket to chatgpt.com): Quena must ask it over HTTP/1.1, where `Upgrade` exists.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quena_body::BodyConfig;
use quena_proxy::{Proxy, ProxyConfig};
use quena_store::Capture;
use rustls::pki_types::pem::PemObject;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

/// `/ws`: switches protocols and echoes; anything else (and an upgrade over HTTP/2): 405.
async fn app(mut req: Request<hyper::body::Incoming>) -> Result<Response<TBody>, Infallible> {
    let upgrade = req.headers().get("upgrade").is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    if req.uri().path() != "/ws" || !upgrade || req.version() != hyper::Version::HTTP_11 {
        return Ok(Response::builder().status(405).body(Full::new(Bytes::from(format!("{:?}", req.version()))).boxed()).unwrap());
    }
    let up = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        if let Ok(up) = up.await {
            let mut io = TokioIo::new(up);
            let mut buf = [0u8; 256];
            while let Ok(n) = io.read(&mut buf).await {
                if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    });
    Ok(Response::builder().status(101).header("Upgrade", "websocket").header("Connection", "Upgrade").header("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=").body(Full::new(Bytes::new()).boxed()).unwrap())
}

#[test]
fn websocket_upgrade_to_an_h2_server_goes_over_http1() {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    // The server offers h2 and http/1.1 like most CDNs.
    let server_ca = quena_tls::CertAuthority::load_or_create(dir.path().join("server-ca")).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(server_ca.server_config("localhost", true).unwrap());
    let server = rt.block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(t) = acc.accept(s).await {
                        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(TokioIo::new(t), service_fn(app)).await;
                    }
                });
            }
        });
        addr
    });
    let capture = Capture::open(dir.path().join("cap"), BodyConfig::default(), true).unwrap();
    let ca = Arc::new(quena_tls::CertAuthority::load_or_create(dir.path().join("quena-ca")).unwrap());
    let quena_ca = ca.cert_path();
    let proxy = Proxy::new(capture.clone(), ProxyConfig { port: 0, decrypt: true, ignore_cert_errors: true, ..Default::default() }, Some(ca)).unwrap();
    let proxy_addr = *proxy.start().unwrap().iter().find(|a| a.is_ipv4()).unwrap();

    let reply = rt.block_on(async move {
        tokio::time::timeout(Duration::from_secs(20), async move {
            // CONNECT, then TLS to Quena (trusting its CA), then the upgrade over HTTP/1.1.
            let mut tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
            tcp.write_all(format!("CONNECT localhost:{0} HTTP/1.1\r\nHost: localhost:{0}\r\n\r\n", server.port()).as_bytes()).await.unwrap();
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                tcp.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
            }
            assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
            let mut roots = rustls::RootCertStore::empty();
            roots.add(rustls::pki_types::CertificateDer::from_pem_file(&quena_ca).unwrap()).unwrap();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut cfg = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await.unwrap();
            tls.write_all(format!("GET /ws HTTP/1.1\r\nHost: localhost:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", server.port()).as_bytes()).await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                if tls.read_exact(&mut b).await.is_err() {
                    break;
                }
                head.push(b[0]);
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            if !head.starts_with("HTTP/1.1 101") {
                return head;
            }
            // Frames go both ways once switched: a masked text frame, echoed as it is.
            let mask = [1u8, 2, 3, 4];
            let mut frame = vec![0x81, 0x80 | 4];
            frame.extend_from_slice(&mask);
            frame.extend(b"ping".iter().enumerate().map(|(i, c)| c ^ mask[i % 4]));
            tls.write_all(&frame).await.unwrap();
            let mut echo = vec![0u8; frame.len()];
            tls.read_exact(&mut echo).await.unwrap();
            let text: Vec<u8> = echo[6..].iter().enumerate().map(|(i, c)| c ^ mask[i % 4]).collect();
            format!("{} | {}", head.lines().next().unwrap_or(""), String::from_utf8_lossy(&text))
        })
        .await
        .expect("timed out")
    });
    assert!(reply.starts_with("HTTP/1.1 101") && reply.ends_with("| ping"), "{reply}");
    proxy.stop();
}
