//! Sessions to servers whose certificate expires soon (or has expired) are flagged.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quena_body::BodyConfig;
use quena_model::{CERT_FLAG, SessionDetail};
use quena_proxy::{Proxy, ProxyConfig};
use quena_store::Capture;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

type TBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

async fn app(_: Request<hyper::body::Incoming>) -> Result<Response<TBody>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("ok")).boxed()))
}

/// An HTTPS server for `localhost` whose certificate is valid until now + `days`.
fn server(rt: &tokio::runtime::Runtime, days: i64) -> SocketAddr {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::days(400);
    p.not_after = now + time::Duration::days(days);
    let cert = p.self_signed(&key).unwrap();
    let pk = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], pk)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    rt.block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(t) = acc.accept(s).await {
                        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(t), service_fn(app)).await;
                    }
                });
            }
        });
        addr
    })
}

fn session(capture: &Arc<Capture>, port: u16) -> SessionDetail {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        capture.index.tick();
        for id in capture.index.find_all(|s| s.state.is_final()) {
            if let Some(d) = capture.detail(id).filter(|d| d.request.url.contains(&format!(":{port}/"))) {
                return d;
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("no session for port {port}");
}

#[test]
fn soon_expiring_and_expired_server_certificates_are_flagged() {
    quena_tls::init();
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let soon = server(&rt, 5);
    let fine = server(&rt, 200);
    let expired = server(&rt, -3);
    let capture = Capture::open(dir.path().join("cap"), BodyConfig::default(), true).unwrap();
    let ca = Arc::new(quena_tls::CertAuthority::load_or_create(dir.path().join("ca")).unwrap());
    let quena_ca = ca.cert_path();
    // The test servers' certificates are self-signed: only an ignored error lets them through.
    let cfg = ProxyConfig { port: 0, decrypt: true, ignore_cert_errors: true, cert_warn_days: 30, ..Default::default() };
    let proxy = Proxy::new(capture.clone(), cfg, Some(ca)).unwrap();
    let proxy_addr = *proxy.start().unwrap().iter().find(|a| a.is_ipv4()).unwrap();
    for a in [soon, fine, expired] {
        let mut c = Command::new("curl");
        if cfg!(windows) {
            c.arg("--ssl-no-revoke");
        }
        let out = c.args(["-sS", "--max-time", "20", "-x", &format!("http://{proxy_addr}"), "--cacert", quena_ca.to_str().unwrap()]).arg(format!("https://localhost:{}/", a.port())).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "ok", "{}", String::from_utf8_lossy(&out.stderr));
    }
    let flag = |d: &SessionDetail| d.extra_flags.iter().find(|(k, _)| k == CERT_FLAG).map(|(_, v)| v.clone());
    let d = session(&capture, soon.port());
    let w = flag(&d).expect("flag for a certificate expiring in 5 days");
    assert!(w.contains("expires on") && (w.contains("in 4 days") || w.contains("in 5 days")), "{w}");
    let tls = d.connection.server_tls.as_ref().unwrap();
    assert!(tls.subject.as_deref().unwrap_or("").contains("rcgen") || tls.subject.is_some());
    assert_eq!(d.summary.cert_expires, tls.not_after);
    assert!(d.summary.cert_expires.is_some());
    assert_eq!(flag(&session(&capture, fine.port())), None);
    let e = flag(&session(&capture, expired.port())).expect("flag for an expired certificate");
    assert!(e.contains("expired on"), "{e}");
    proxy.stop();
}

#[test]
fn warnings_by_date() {
    use quena_proxy::cert_warning;
    let now = 1_800_000_000;
    assert_eq!(cert_warning(None, 30, now), None);
    assert_eq!(cert_warning(Some(now + 40 * 86_400), 30, now), None);
    assert!(cert_warning(Some(now + 10 * 86_400), 30, now).unwrap().contains("in 10 days"));
    assert!(cert_warning(Some(now - 1), 30, now).unwrap().contains("expired"));
    // 0 days: only expired certificates.
    assert_eq!(cert_warning(Some(now + 86_400), 0, now), None);
}
