//! End-to-end tests: curl → Quena → test server (HTTP, HTTPS/h1, HTTPS/h2).

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quena_body::BodyConfig;
use quena_model::{SessionKind, SessionState};
use quena_proxy::{Proxy, ProxyConfig};
use quena_store::Capture;
use std::convert::Infallible;
use std::io::Write;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

/// `curl` for the tests. On Windows, curl uses Schannel, which insists on revocation
/// information (CRL/OCSP) that locally generated interception certificates don't
/// carry — like Fiddler's; browsers don't hard-fail on that, so skip the check.
/// Where curl discards output (`-o`): Windows has no /dev/null.
const NULL_DEVICE: &str = if cfg!(windows) { "NUL" } else { "/dev/null" };

fn curl_supports_http2() -> bool {
    Command::new("curl").arg("-V").output().map(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP2")).unwrap_or(false)
}

fn curl_cmd() -> Command {
    let mut c = Command::new("curl");
    if cfg!(windows) {
        c.arg("--ssl-no-revoke");
    }
    c
}

type TBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

async fn app(req: Request<hyper::body::Incoming>) -> Result<Response<TBody>, Infallible> {
    let path = req.uri().path().to_string();
    let r = match path.as_str() {
        "/hello" => Response::builder().header("Content-Type", "text/plain").body(Full::new(Bytes::from("hello world")).boxed()),
        "/echo" => {
            let b = req.into_body().collect().await.map(|c| c.to_bytes()).unwrap_or_default();
            Response::builder().header("Content-Type", "application/octet-stream").body(Full::new(b).boxed())
        }
        "/gzip" => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(br#"{"compressed":true,"items":[1,2,3]}"#).unwrap();
            Response::builder()
                .header("Content-Type", "application/json")
                .header("Content-Encoding", "gzip")
                .body(Full::new(Bytes::from(e.finish().unwrap())).boxed())
        }
        "/big" => {
            // 64 MiB, streamed in 64 KiB chunks.
            let (mut tx, body) = http_body_util::channel::Channel::<Bytes, Infallible>::new(4);
            tokio::spawn(async move {
                let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
                for _ in 0..1024 {
                    if tx.send_data(chunk.clone()).await.is_err() {
                        break;
                    }
                }
            });
            Response::builder().header("Content-Type", "application/octet-stream").body(body.boxed())
        }
        "/status/404" => Response::builder().status(404).body(Full::new(Bytes::from("nope")).boxed()),
        "/version" => Response::builder().body(Full::new(Bytes::from(format!("{:?}", req.version()))).boxed()),
        _ => Response::builder().status(404).body(Full::new(Bytes::new()).boxed()),
    };
    Ok(r.unwrap())
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

fn setup() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    // Upstream test servers.
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
    let cfg = ProxyConfig { port: 0, decrypt: true, ignore_cert_errors: true, ..Default::default() };
    let proxy = Proxy::new(capture.clone(), cfg, Some(ca)).unwrap();
    let addrs = proxy.start().unwrap();
    let proxy_addr = *addrs.iter().find(|a| a.is_ipv4()).unwrap();
    Env { _rt: rt, proxy, capture, proxy_addr, http, https, quena_ca, _dir: dir }
}

fn curl(env: &Env, args: &[&str]) -> (String, String) {
    let out = curl_cmd()
        .args(["-sS", "--max-time", "30", "-x", &format!("http://{}", env.proxy_addr), "--cacert", env.quena_ca.to_str().unwrap()])
        .args(args)
        .output()
        .expect("curl");
    (String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn wait_done(env: &Env, pred: impl Fn(&quena_model::SessionSummary) -> bool) -> quena_model::SessionSummary {
    for _ in 0..200 {
        env.capture.index.tick();
        let ids = env.capture.index.find_all(|s| pred(s) && s.state.is_final());
        if let Some(id) = ids.last() {
            return env.capture.index.get(*id).unwrap();
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let all: Vec<_> = env.capture.index.find_all(|_| true).into_iter().filter_map(|id| env.capture.index.get(id)).collect();
    panic!("session not found; have: {all:#?}");
}

#[test]
fn http_https_h2_and_big_bodies() {
    let env = setup();
    // --- plain HTTP
    let (out, err) = curl(&env, &[&format!("http://{}/hello", env.http)]);
    assert_eq!(out, "hello world", "{err}");
    let s = wait_done(&env, |s| s.url == "/hello" && s.protocol == "HTTP");
    assert_eq!(s.status, 200);
    assert_eq!(s.response_body_len, 11);
    assert_eq!(s.state, SessionState::Done);
    let (_, resp) = env.capture.bodies_of(s.id).unwrap();
    assert_eq!(resp.read_range(0, 100).unwrap(), b"hello world");
    // process lookup found curl
    assert!(s.process.starts_with("curl"), "process = {}", s.process);

    // --- POST body echo
    let (out, _) = curl(&env, &["--data-binary", "quena-post-body", &format!("http://{}/echo", env.http)]);
    assert_eq!(out, "quena-post-body");
    let s = wait_done(&env, |s| s.url == "/echo");
    let (req, _) = env.capture.bodies_of(s.id).unwrap();
    assert_eq!(req.read_range(0, 100).unwrap(), b"quena-post-body");

    // --- HTTPS (MITM) over HTTP/1.1
    let url = format!("https://localhost:{}/hello", env.https.port());
    let (out, err) = curl(&env, &["--http1.1", &url]);
    assert_eq!(out, "hello world", "{err}");
    let s = wait_done(&env, |s| s.url == "/hello" && s.protocol == "HTTPS");
    assert_eq!(s.status, 200);
    let t = wait_done(&env, |s| s.kind == SessionKind::Tunnel);
    assert_eq!(t.status, 200);

    // --- HTTPS with HTTP/2 on both sides (needs a curl built with HTTP/2; the curl.exe
    // that ships with Windows is not, so the h2 leg is skipped there).
    if curl_supports_http2() {
        let url = format!("https://localhost:{}/version", env.https.port());
        let (out, err) = curl(&env, &["--http2", &url]);
        assert_eq!(out, "HTTP/2.0", "upstream should see h2: {err}");
        let s = wait_done(&env, |s| s.url == "/version" && s.protocol == "HTTP/2");
        let d = env.capture.detail(s.id).unwrap();
        assert_eq!(d.request.version, quena_model::HttpVersion::Http2);
        assert_eq!(d.connection.client_tls.as_ref().and_then(|t| t.alpn.clone()).as_deref(), Some("h2"));
    } else {
        eprintln!("curl has no HTTP/2 support - skipping the h2 leg");
    }

    // --- gzip recorded raw
    let (out, _) = curl(&env, &["--compressed", &format!("http://{}/gzip", env.http)]);
    assert!(out.contains("compressed"));
    let s = wait_done(&env, |s| s.url == "/gzip");
    let d = env.capture.detail(s.id).unwrap();
    assert_eq!(d.response.unwrap().headers.get("content-encoding"), Some("gzip"));

    // --- 64 MiB streamed through the proxy
    let t = std::time::Instant::now();
    let out = curl_cmd()
        .args(["-sS", "-o", NULL_DEVICE, "-w", "%{size_download}", "-x", &format!("http://{}", env.proxy_addr), &format!("http://{}/big", env.http)])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), (64u64 << 20).to_string());
    let s = wait_done(&env, |s| s.url == "/big");
    assert_eq!(s.response_body_len, 64 << 20);
    let (_, resp) = env.capture.bodies_of(s.id).unwrap();
    assert_eq!(resp.len(), 64 << 20, "fully recorded");
    eprintln!("64 MiB through proxy in {:?}", t.elapsed());

    // --- upstream failure -> 502 generated by Quena
    let (out, _) = curl(&env, &["http://127.0.0.1:1/nothing"]);
    assert!(out.contains("[Quena]"), "{out}");
    let s = wait_done(&env, |s| s.url == "/nothing");
    assert_eq!(s.status, 502);

    // --- landing page
    let (out, _) = curl(&env, &["http://quena.cert/"]);
    assert!(out.contains("Quena Echo Service"));
    let (out, _) = curl(&env, &["http://quena.cert/quena-root-ca.crt"]);
    assert!(out.starts_with("-----BEGIN CERTIFICATE-----"));

    env.proxy.stop();
}
