//! Host remapping through the proxy: connections to a host go to another host or port.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quena_body::BodyConfig;
use quena_model::SessionDetail;
use quena_proxy::remap::HostRemap;
use quena_proxy::{Proxy, ProxyConfig};
use quena_store::Capture;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

type TBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

/// Answers with the path and the Host it saw.
async fn app(req: Request<hyper::body::Incoming>) -> Result<Response<TBody>, Infallible> {
    // HTTP/1 Host header, or the HTTP/2 :authority.
    let host = req.headers().get("host").and_then(|v| v.to_str().ok()).map(str::to_string).or_else(|| req.uri().authority().map(|a| a.to_string())).unwrap_or("-".into());
    Ok(Response::new(Full::new(Bytes::from(format!("{} host={host}", req.uri().path()))).boxed()))
}

struct Env {
    _rt: tokio::runtime::Runtime,
    proxy: Arc<Proxy>,
    capture: Arc<Capture>,
    proxy_addr: SocketAddr,
    http: SocketAddr,
    https: SocketAddr,
    quena_ca: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

fn setup(rules: Vec<HostRemap>) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let server_ca = quena_tls::CertAuthority::load_or_create(dir.path().join("server-ca")).unwrap();
    let tls_cfg = server_ca.server_config("localhost", true).unwrap();
    let (http, https) = rt.block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(s), service_fn(app)).await;
                });
            }
        });
        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let https = l2.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
        tokio::spawn(async move {
            loop {
                let (s, _) = l2.accept().await.unwrap();
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(t) = acc.accept(s).await {
                        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(t), service_fn(app)).await;
                    }
                });
            }
        });
        (http, https)
    });
    let capture = Capture::open(dir.path().join("cap"), BodyConfig::default(), true).unwrap();
    let ca = Arc::new(quena_tls::CertAuthority::load_or_create(dir.path().join("quena-ca")).unwrap());
    let quena_ca = ca.cert_path();
    let cfg = ProxyConfig {
        port: 0,
        decrypt: true,
        ignore_cert_errors: true,
        skip_decryption: vec!["tunnel.invalid".into()],
        // A dead upstream proxy: remapped hosts must not use it.
        upstream: Some(("127.0.0.1".into(), 1)),
        host_remap: rules,
        ..Default::default()
    };
    let proxy = Proxy::new(capture.clone(), cfg, Some(ca)).unwrap();
    let proxy_addr = *proxy.start().unwrap().iter().find(|a| a.is_ipv4()).unwrap();
    Env { _rt: rt, proxy, capture, proxy_addr, http, https, quena_ca, _dir: dir }
}

fn curl(env: &Env, args: &[&str]) -> (String, String) {
    let mut c = Command::new("curl");
    if cfg!(windows) {
        c.arg("--ssl-no-revoke");
    }
    let out = c.args(["-sS", "--max-time", "20", "-x", &format!("http://{}", env.proxy_addr), "--cacert", env.quena_ca.to_str().unwrap()]).args(args).output().expect("curl");
    (String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn session(env: &Env, pred: impl Fn(&SessionDetail) -> bool) -> SessionDetail {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        env.capture.index.tick();
        for id in env.capture.index.find_all(|s| s.state.is_final()) {
            if let Some(d) = env.capture.detail(id) {
                if pred(&d) {
                    return d;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let all: Vec<_> = env.capture.index.find_all(|_| true).into_iter().filter_map(|id| env.capture.detail(id)).map(|d| d.request.url).collect();
    panic!("session not found; have: {all:#?}");
}

fn flag<'a>(d: &'a SessionDetail, k: &str) -> Option<&'a str> {
    d.extra_flags.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

fn r(p: &str, t: &str, keep: bool) -> HostRemap {
    HostRemap::parse(p, t, keep).unwrap()
}

#[test]
fn plain_http_keeps_or_changes_the_host() {
    let env = setup(vec![]);
    let port = env.http.port();
    let mut cfg = (*env.proxy.shared.cfg()).clone();
    cfg.host_remap = vec![r("api.remap.invalid", &format!("127.0.0.1:{port}"), true), r("moved.remap.invalid", &format!("127.0.0.1:{port}"), false), r("*.wild.invalid", &format!("127.0.0.1:{port}"), true)];
    env.proxy.reconfigure(cfg).unwrap();

    // Keep host: only the connection moves; the upstream proxy (dead) is not used.
    let (out, err) = curl(&env, &["http://api.remap.invalid/a"]);
    assert_eq!(out, "/a host=api.remap.invalid", "{err}");
    let d = session(&env, |d| d.request.url == "http://api.remap.invalid/a");
    assert_eq!(flag(&d, quena_proxy::remap::FLAG), Some(format!("api.remap.invalid:80 → 127.0.0.1:{port}").as_str()));
    assert_eq!(d.connection.server_addr.as_deref(), Some(format!("127.0.0.1:{port}").as_str()));

    // Without keep host the request is addressed to the target.
    let (out, err) = curl(&env, &["http://moved.remap.invalid/b"]);
    assert_eq!(out, format!("/b host=127.0.0.1:{port}"), "{err}");
    session(&env, |d| d.request.url == format!("http://127.0.0.1:{port}/b"));

    // Wildcards.
    let (out, _) = curl(&env, &["http://x.wild.invalid/c"]);
    assert_eq!(out, "/c host=x.wild.invalid");
}

#[test]
fn https_keeps_the_host_and_tunnels_follow_the_remap() {
    let env = setup(vec![]);
    let port = env.https.port();
    let mut cfg = (*env.proxy.shared.cfg()).clone();
    cfg.host_remap = vec![r("secure.remap.invalid", &format!("127.0.0.1:{port}"), true), r("tunnel.invalid", &format!("127.0.0.1:{port}"), true)];
    env.proxy.reconfigure(cfg).unwrap();

    // Decrypted: Quena connects to the target with the original name.
    let (out, err) = curl(&env, &["https://secure.remap.invalid/s"]);
    assert_eq!(out, "/s host=secure.remap.invalid", "{err}");
    let d = session(&env, |d| d.request.url == "https://secure.remap.invalid/s");
    assert!(flag(&d, quena_proxy::remap::FLAG).is_some());

    // Not decrypted (skip list): the tunnel goes to the target as well.
    let (out, err) = curl(&env, &["-k", "https://tunnel.invalid/t"]);
    assert_eq!(out, "/t host=tunnel.invalid", "{err}");
    let t = session(&env, |d| d.summary.kind == quena_model::SessionKind::Tunnel && d.request.url == "tunnel.invalid:443");
    assert_eq!(flag(&t, quena_proxy::remap::FLAG), Some(format!("tunnel.invalid:443 → 127.0.0.1:{port}").as_str()));
}

#[test]
fn a_remap_to_quena_itself_is_refused() {
    let env = setup(vec![]);
    let mut cfg = (*env.proxy.shared.cfg()).clone();
    cfg.host_remap = vec![r("loop.remap.invalid", &format!("127.0.0.1:{}", env.proxy_addr.port()), true)];
    env.proxy.reconfigure(cfg).unwrap();
    let (out, _) = curl(&env, &["http://loop.remap.invalid/x"]);
    assert!(out.contains("Quena itself"), "{out}");
}
