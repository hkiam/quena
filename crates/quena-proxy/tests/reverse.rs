//! Reverse proxy ports: client → Quena (fixed port) → target, recorded like proxied traffic.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quena_body::BodyConfig;
use quena_model::SessionDetail;
use quena_proxy::reverse::{ClientProtocol, PathRoute, ReverseRoute, Target};
use quena_proxy::{Proxy, ProxyConfig};
use quena_store::Capture;
use std::convert::Infallible;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

type TBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

fn text(s: impl Into<String>) -> TBody {
    Full::new(Bytes::from(s.into())).boxed()
}

/// The target: reports what it received (path, Host, forwarding headers, version).
async fn app(mut req: Request<hyper::body::Incoming>) -> Result<Response<TBody>, Infallible> {
    let path = req.uri().path().to_string();
    let header = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
    let r = match path.as_str() {
        "/hello" | "/api/hello" => Response::builder().body(text(format!("hello {path}"))),
        "/host" => Response::builder().body(text(header("host"))),
        "/forwarded" => Response::builder().body(text(format!("{} | {} | {}", header("x-forwarded-for"), header("x-forwarded-proto"), header("x-forwarded-host")))),
        "/version" => Response::builder().body(text(format!("{:?}", req.version()))),
        "/redirect" => {
            let host = header("host");
            Response::builder().status(302).header("Location", format!("http://{host}/hello")).header("Set-Cookie", "sid=1; Domain=127.0.0.1; Path=/").body(text(""))
        }
        "/ws" => {
            let up = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                if let Ok(up) = up.await {
                    let mut io = TokioIo::new(up);
                    let mut buf = [0u8; 256];
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    while let Ok(n) = io.read(&mut buf).await {
                        if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            });
            Response::builder().status(101).header("Upgrade", "websocket").header("Connection", "Upgrade").header("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=").body(text(""))
        }
        _ => Response::builder().status(404).body(text("")),
    };
    Ok(r.unwrap())
}

struct Env {
    rt: tokio::runtime::Runtime,
    proxy: Arc<Proxy>,
    capture: Arc<Capture>,
    http: SocketAddr,
    https: SocketAddr,
    quena_ca: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

fn setup() -> Env {
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
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(TokioIo::new(s), service_fn(app)).await;
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
    proxy.start().unwrap();
    Env { rt, proxy, capture, http, https, quena_ca, _dir: dir }
}

fn route(id: &str, target: &str) -> ReverseRoute {
    ReverseRoute {
        id: id.into(),
        name: format!("rp-{id}"),
        port: 0,
        allow_remote: false,
        client_protocol: ClientProtocol::Auto,
        target: Target::parse(target).unwrap(),
        paths: vec![],
        preserve_host: false,
        tls_host: "localhost".into(),
        rewrite_location: true,
        rewrite_cookie_domain: false,
        forwarded_headers: false,
    }
}

/// Configure the routes; returns the IPv4 port of each (in order).
fn set_routes(env: &Env, routes: Vec<ReverseRoute>) -> Vec<u16> {
    let ids: Vec<String> = routes.iter().map(|r| r.id.clone()).collect();
    let mut cfg = (*env.proxy.shared.cfg()).clone();
    cfg.reverse = routes;
    env.proxy.reconfigure(cfg).unwrap();
    let status = env.proxy.listener_status();
    ids.iter()
        .map(|id| {
            let s = status.iter().find(|s| &s.id == id).unwrap();
            assert!(s.error.is_none(), "{s:?}");
            s.listen.iter().filter_map(|a| a.parse::<SocketAddr>().ok()).find(|a| a.is_ipv4()).unwrap().port()
        })
        .collect()
}

fn curl(args: &[&str]) -> (String, String) {
    let mut c = Command::new("curl");
    if cfg!(windows) {
        c.arg("--ssl-no-revoke");
    }
    // Talk to the port directly, unless a test uses a proxy (`-x`, SOCKS).
    if !args.iter().any(|a| *a == "-x" || a.starts_with("--socks")) {
        c.args(["--noproxy", "*"]);
    }
    let out = c.args(["-sS", "--max-time", "20"]).args(args).output().expect("curl");
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
    let all: Vec<_> = env.capture.index.find_all(|_| true).into_iter().filter_map(|id| env.capture.detail(id)).map(|d| (d.summary.kind, d.summary.state, d.via(), d.request.url)).collect();
    panic!("session not found; have: {all:#?}");
}

fn flag<'a>(d: &'a SessionDetail, k: &str) -> Option<&'a str> {
    d.extra_flags.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

#[test]
fn http_to_http_with_base_path_and_host() {
    let env = setup();
    let mut keep = route("keep", &format!("http://127.0.0.1:{}", env.http.port()));
    keep.preserve_host = true;
    let ports = set_routes(&env, vec![route("api", &format!("http://127.0.0.1:{}/api", env.http.port())), route("plain", &format!("http://127.0.0.1:{}", env.http.port())), keep]);

    let (out, err) = curl(&[&format!("http://127.0.0.1:{}/hello", ports[0])]);
    assert_eq!(out, "hello /api/hello", "{err}");
    let d = session(&env, |d| d.request.url.ends_with("/api/hello"));
    assert_eq!(d.request.url, format!("http://127.0.0.1:{}/api/hello", env.http.port()));
    assert_eq!(flag(&d, quena_proxy::reverse::FLAG), Some("rp-api"));
    assert_eq!(d.response.as_ref().unwrap().status, 200);

    // The target sees its own name as Host, unless the client's is kept.
    let (out, _) = curl(&[&format!("http://127.0.0.1:{}/host", ports[1])]);
    assert_eq!(out, format!("127.0.0.1:{}", env.http.port()));
    let (out, _) = curl(&[&format!("http://127.0.0.1:{}/host", ports[2])]);
    assert_eq!(out, format!("127.0.0.1:{}", ports[2]));
}

#[test]
fn forwarded_headers_are_optional() {
    let env = setup();
    let mut fwd = route("fwd", &format!("http://127.0.0.1:{}", env.http.port()));
    fwd.forwarded_headers = true;
    let ports = set_routes(&env, vec![fwd, route("plain", &format!("http://127.0.0.1:{}", env.http.port()))]);
    let (out, _) = curl(&[&format!("http://127.0.0.1:{}/forwarded", ports[0])]);
    assert_eq!(out, format!("127.0.0.1 | http | 127.0.0.1:{}", ports[0]));
    let (out, _) = curl(&[&format!("http://127.0.0.1:{}/forwarded", ports[1])]);
    assert_eq!(out, "- | - | -");
}

#[test]
fn location_and_cookies_point_back_to_quena() {
    let env = setup();
    let mut r = route("r", &format!("http://127.0.0.1:{}", env.http.port()));
    r.rewrite_cookie_domain = true;
    let ports = set_routes(&env, vec![r]);
    let (out, _) = curl(&["-D", "-", "-o", if cfg!(windows) { "NUL" } else { "/dev/null" }, &format!("http://127.0.0.1:{}/redirect", ports[0])]);
    let lower = out.to_ascii_lowercase();
    assert!(lower.contains(&format!("location: http://127.0.0.1:{}/hello", ports[0])), "{out}");
    assert!(lower.contains("set-cookie: sid=1; path=/"), "{out}");
    // The session keeps what the target sent and notes the change.
    let d = session(&env, |d| d.request.url.ends_with("/redirect"));
    let resp = d.response.as_ref().unwrap();
    assert_eq!(resp.headers.get("location"), Some(format!("http://127.0.0.1:{}/hello", env.http.port()).as_str()));
    assert!(flag(&d, quena_proxy::reverse::REWRITE_FLAG).is_some_and(|v| v.contains("Location")), "{:?}", d.extra_flags);
}

#[test]
fn https_clients_and_targets() {
    let env = setup();
    let ports = set_routes(&env, vec![route("tls", &format!("https://localhost:{}", env.https.port()))]);
    let ca = env.quena_ca.to_str().unwrap();
    // TLS from the client (certificate for localhost from the Quena CA), HTTPS to the target.
    let (out, err) = curl(&["--cacert", ca, &format!("https://localhost:{}/hello", ports[0])]);
    assert_eq!(out, "hello /hello", "{err}");
    let d = session(&env, |d| d.request.url.ends_with("/hello"));
    assert!(d.connection.client_tls.is_some());
    assert_eq!(d.request.url, format!("https://localhost:{}/hello", env.https.port()));
    // Plain HTTP on the same port (Auto) works as well.
    let (out, err) = curl(&[&format!("http://127.0.0.1:{}/hello", ports[0])]);
    assert_eq!(out, "hello /hello", "{err}");
}

#[test]
fn https_only_entries_refuse_plain_http() {
    let env = setup();
    let mut r = route("tls", &format!("http://127.0.0.1:{}", env.http.port()));
    r.client_protocol = ClientProtocol::Https;
    let ports = set_routes(&env, vec![r]);
    let (out, err) = curl(&[&format!("http://127.0.0.1:{}/hello", ports[0])]);
    assert!(out.contains("expects HTTPS"), "{out} / {err}");
    // Nothing reached the target.
    std::thread::sleep(Duration::from_millis(200));
    env.capture.index.tick();
    assert_eq!(env.capture.index.find_all(|_| true).len(), 0);
}

#[test]
fn cleartext_http2_prior_knowledge() {
    let env = setup();
    let has_h2 = Command::new("curl").arg("-V").output().map(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP2")).unwrap_or(false);
    if !has_h2 {
        eprintln!("curl without HTTP/2; skipped");
        return;
    }
    let ports = set_routes(&env, vec![route("h2c", &format!("http://127.0.0.1:{}", env.http.port()))]);
    let (out, err) = curl(&["--http2-prior-knowledge", &format!("http://127.0.0.1:{}/hello", ports[0])]);
    assert_eq!(out, "hello /hello", "{err}");
    let d = session(&env, |d| d.request.url.ends_with("/hello"));
    assert_eq!(d.request.version, quena_model::HttpVersion::Http2);
}

#[test]
fn connect_is_refused_and_loops_are_caught() {
    let env = setup();
    let ports = set_routes(&env, vec![route("self", "http://127.0.0.1:1")]);
    // The port is no general forward proxy.
    let (_, err) = curl(&["-x", &format!("http://127.0.0.1:{}", ports[0]), "https://example.com/"]);
    assert!(err.contains("405"), "{err}");
    // A target that is one of Quena's own ports is refused (no request loop).
    let ports = set_routes(&env, vec![route("self", "http://127.0.0.1:1"), route("loop", &format!("http://127.0.0.1:{}", ports[0]))]);
    let (out, err) = curl(&[&format!("http://127.0.0.1:{}/x", ports[1])]);
    assert!(out.contains("Quena itself"), "{out} / {err}");
}

#[test]
fn a_taken_port_is_reported_and_the_proxy_keeps_running() {
    let env = setup();
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut r = route("busy", &format!("http://127.0.0.1:{}", env.http.port()));
    r.port = taken.local_addr().unwrap().port();
    let mut cfg = (*env.proxy.shared.cfg()).clone();
    cfg.reverse = vec![r, route("ok", &format!("http://127.0.0.1:{}", env.http.port()))];
    env.proxy.reconfigure(cfg).unwrap();
    let status = env.proxy.listener_status();
    assert!(status[0].error.is_some() && status[0].listen.is_empty(), "{status:?}");
    assert!(status[1].error.is_none() && !status[1].listen.is_empty(), "{status:?}");
    assert!(env.proxy.is_running());
    // Stopping the proxy stops the reverse listeners too.
    env.proxy.stop();
    assert!(env.proxy.listener_status().is_empty());
}

#[test]
fn websocket_through_a_reverse_port() {
    let env = setup();
    let ports = set_routes(&env, vec![route("ws", &format!("http://127.0.0.1:{}", env.http.port()))]);
    let mut s = std::net::TcpStream::connect(("127.0.0.1", ports[0])).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(s, "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", ports[0]).unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).unwrap();
        head.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
    // A masked text frame "hi"; the target echoes the bytes.
    let frame = [0x81u8, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2];
    s.write_all(&frame).unwrap();
    let mut back = [0u8; 8];
    s.read_exact(&mut back).unwrap();
    assert_eq!(back, frame);
    drop(s);
    let _ = &env.rt;
}

#[test]
fn path_routes_pick_their_target() {
    let env = setup();
    let mut r = route("paths", &format!("http://127.0.0.1:{}", env.http.port()));
    r.paths = vec![
        PathRoute { prefix: "/other".into(), target: Target::parse(&format!("http://127.0.0.1:{}/api", env.http.port())).unwrap(), strip_prefix: true },
        PathRoute { prefix: "/tls".into(), target: Target::parse(&format!("https://localhost:{}", env.https.port())).unwrap(), strip_prefix: true },
        PathRoute { prefix: "/plain".into(), target: Target::parse(&format!("http://127.0.0.1:{}", env.http.port())).unwrap(), strip_prefix: true },
    ];
    let ports = set_routes(&env, vec![r]);
    let (out, err) = curl(&[&format!("http://127.0.0.1:{}/hello", ports[0])]);
    assert_eq!(out, "hello /hello", "{err}");
    let (out, err) = curl(&[&format!("http://127.0.0.1:{}/other/hello", ports[0])]);
    assert_eq!(out, "hello /api/hello", "{err}");
    let (out, err) = curl(&[&format!("http://127.0.0.1:{}/tls/host", ports[0])]);
    assert_eq!(out, format!("localhost:{}", env.https.port()), "{err}");
    // A redirect from a stripped route keeps its prefix for the client.
    let (out, _) = curl(&["-D", "-", "-o", if cfg!(windows) { "NUL" } else { "/dev/null" }, &format!("http://127.0.0.1:{}/plain/redirect", ports[0])]);
    assert!(out.to_ascii_lowercase().contains(&format!("location: http://127.0.0.1:{}/plain/hello", ports[0])), "{out}");
}

/// Start the SOCKS and transparent listeners on free ports → (socks, transparent).
fn extra_ports(env: &Env) -> (u16, u16) {
    let mut cfg = (*env.proxy.shared.cfg()).clone();
    cfg.socks = Some(quena_proxy::listener::ExtraPort { port: 0, allow_remote: false });
    cfg.transparent = Some(quena_proxy::listener::ExtraPort { port: 0, allow_remote: false });
    env.proxy.reconfigure(cfg).unwrap();
    let st = env.proxy.listener_status();
    let port = |id: &str| {
        let s = st.iter().find(|s| s.id == id).unwrap();
        assert!(s.error.is_none(), "{s:?}");
        s.listen.iter().filter_map(|a| a.parse::<SocketAddr>().ok()).find(|a| a.is_ipv4()).unwrap().port()
    };
    (port("socks"), port("transparent"))
}

#[test]
fn socks_clients_are_recorded() {
    let env = setup();
    let (socks, _) = extra_ports(&env);
    // Plain HTTP through SOCKS5 (host name resolved by Quena) is recorded as a session.
    let (out, err) = curl(&["--socks5-hostname", &format!("127.0.0.1:{socks}"), &format!("http://127.0.0.1:{}/hello", env.http.port())]);
    assert_eq!(out, "hello /hello", "{err}");
    let d = session(&env, |d| d.request.url == format!("http://127.0.0.1:{}/hello", env.http.port()));
    assert_eq!(d.via(), "SOCKS5");
    // HTTPS through SOCKS5 is decrypted like a CONNECT tunnel.
    let ca = env.quena_ca.to_str().unwrap();
    let (out, err) = curl(&["--socks5-hostname", &format!("127.0.0.1:{socks}"), "--cacert", ca, &format!("https://localhost:{}/hello", env.https.port())]);
    assert_eq!(out, "hello /hello", "{err}");
    let d = session(&env, |d| d.request.url == format!("https://localhost:{}/hello", env.https.port()));
    assert!(d.summary.has_flag(quena_model::flags::DECRYPTED));
    assert_eq!(d.via(), "SOCKS5");
    let t = session(&env, |d| d.summary.kind == quena_model::SessionKind::Tunnel && d.request.url == format!("localhost:{}", env.https.port()));
    assert_eq!(t.via(), "SOCKS5");
    // SOCKS4a.
    let (out, err) = curl(&["--socks4a", &format!("127.0.0.1:{socks}"), &format!("http://127.0.0.1:{}/version", env.http.port())]);
    assert_eq!(out, "HTTP/1.1", "{err}");
}

#[test]
fn transparent_connections_use_the_host_header_or_the_server_name() {
    let env = setup();
    let (_, tp) = extra_ports(&env);
    // Plain HTTP: the Host header names the target.
    let (out, err) = curl(&["-H", &format!("Host: 127.0.0.1:{}", env.http.port()), &format!("http://127.0.0.1:{tp}/hello")]);
    assert_eq!(out, "hello /hello", "{err}");
    let d = session(&env, |d| d.request.url == format!("http://127.0.0.1:{}/hello", env.http.port()));
    assert_eq!(d.via(), "transparent");
    // TLS: the server name decides (port 443); Quena answers with its certificate.
    let ca = env.quena_ca.to_str().unwrap();
    let (out, _) = curl(&["--cacert", ca, "--resolve", &format!("transparent.invalid:{tp}:127.0.0.1"), &format!("https://transparent.invalid:{tp}/x")]);
    // The client trusted Quena's certificate; the made-up target itself is unreachable.
    assert!(out.contains("Bad Gateway"), "{out}");
    let t = session(&env, |d| d.summary.kind == quena_model::SessionKind::Tunnel && d.request.url == "transparent.invalid:443");
    assert_eq!(t.via(), "transparent");
    // (The client's Host header names the port it called, here the test port.)
    let d = session(&env, |d| d.request.url == format!("https://transparent.invalid:{tp}/x"));
    assert!(d.summary.has_flag(quena_model::flags::DECRYPTED));
}

/// The original destination of an iptables REDIRECT (Linux). Needs root and iptables; the
/// client runs as `nobody`, so Quena's own connection to the target is not redirected.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs root and iptables: QUENA_TEST_IPTABLES=1 cargo test -- --ignored"]
fn transparent_original_destination_linux() {
    if std::env::var_os("QUENA_TEST_IPTABLES").is_none() {
        return;
    }
    let env = setup();
    let (_, tp) = extra_ports(&env);
    let port = env.http.port().to_string();
    let tp = tp.to_string();
    let rule = |op: &str| {
        let st = Command::new("iptables")
            .args(["-t", "nat", op, "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "--dport", &port, "-m", "owner", "--uid-owner", "nobody", "-j", "REDIRECT", "--to-ports", &tp])
            .status()
            .unwrap();
        assert!(st.success(), "iptables {op}");
    };
    rule("-A");
    let out = Command::new("su").args(["nobody", "-s", "/bin/sh", "-c", &format!("curl -sS --noproxy '*' --max-time 20 http://127.0.0.1:{port}/hello")]).output().unwrap();
    rule("-D");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello /hello", "{}", String::from_utf8_lossy(&out.stderr));
    // The tunnel names the original destination, not the transparent port.
    let t = session(&env, |d| d.summary.kind == quena_model::SessionKind::Tunnel && d.request.url == format!("127.0.0.1:{port}"));
    assert_eq!(t.via(), "transparent");
    assert_eq!(t.request.headers.get("Quena-Original-Destination"), Some(format!("127.0.0.1:{port}").as_str()));
}
