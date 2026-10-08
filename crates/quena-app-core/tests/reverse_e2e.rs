//! Reverse proxy entries through the settings and the real proxy engine: validation,
//! listening while capturing, rules on reverse traffic, the Via column.

use quena_app_core::rules::{AutoResponderState, Rule};
use quena_app_core::settings::{ReverseProxyEntry, ReverseProxySettings};
use quena_app_core::{AppCore, Paths};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

/// Minimal HTTP/1.1 server answering with the received request head.
fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    head.push_str(&line);
                }
                let mut s = s;
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", head.len(), head);
            });
        }
    });
    port
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn get(url: &str) -> String {
    let o = Command::new("curl").args(["-sS", "--noproxy", "*", "--max-time", "20", url]).output().unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn reverse_proxy_entries() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        r#"{"proxy":{"port":18881,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#,
    )
    .unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let echo = echo_server();
    let port = free_port();
    let entry = ReverseProxyEntry { id: "a".into(), name: "api".into(), listen_port: port, target: format!("http://127.0.0.1:{echo}/base"), ..Default::default() };

    // --- Validation: bad target, the proxy's port, two entries on one port.
    let mut s = core.settings();
    s.reverse_proxy = ReverseProxySettings { enabled: true, entries: vec![ReverseProxyEntry { target: "example.com".into(), ..entry.clone() }] };
    assert!(core.update_settings(s.clone()).is_err());
    s.reverse_proxy.entries = vec![ReverseProxyEntry { listen_port: 18881, ..entry.clone() }];
    assert!(core.update_settings(s.clone()).unwrap_err().to_string().contains("proxy port"));
    s.reverse_proxy.entries = vec![entry.clone(), ReverseProxyEntry { id: "b".into(), name: "other".into(), ..entry.clone() }];
    assert!(core.update_settings(s.clone()).unwrap_err().to_string().contains("both use port"));
    // Old settings files without the section still load.
    assert_eq!(quena_app_core::settings::Settings::load(&dir.path().join("missing.json")).reverse_proxy, ReverseProxySettings::default());

    // --- A valid entry listens while capturing and forwards to the target with its base path.
    s.reverse_proxy.entries = vec![entry.clone()];
    core.update_settings(s.clone()).unwrap();
    let status = core.status().engine.listeners;
    assert_eq!(status.len(), 1, "{status:?}");
    assert!(status[0].error.is_none() && !status[0].listen.is_empty(), "{status:?}");
    let out = get(&format!("http://127.0.0.1:{port}/x?q=1"));
    assert!(out.starts_with("GET /base/x?q=1 HTTP/1.1"), "{out}");
    assert!(out.to_ascii_lowercase().contains(&format!("host: 127.0.0.1:{echo}")), "{out}");

    // --- The session names the entry (Via column, `via == api` filter).
    let cap = core.capture();
    let t = Instant::now();
    let d = loop {
        cap.index.tick();
        if let Some(d) = cap.index.find_all(|s| s.via == "api" && s.state.is_final()).first().and_then(|id| cap.detail(*id)) {
            break d;
        }
        assert!(t.elapsed() < Duration::from_secs(10), "no reverse session");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(d.request.url, format!("http://127.0.0.1:{echo}/base/x?q=1"));
    let q = quena_query::expr::parse("via == api").unwrap();
    assert!(q.eval(&d.summary), "{q:?} {:?}", d.summary.via);

    // --- Rules see reverse traffic like proxied traffic.
    let rules = core.rules.clone().unwrap();
    rules
        .set_autoresponder(
            AutoResponderState { enabled: true, unmatched_passthrough: true, enable_latency: false, rules: vec![Rule { match_: "regex:/base/mocked$".into(), action: "*404".into(), ..Default::default() }] },
            true,
        )
        .unwrap();
    let out = get(&format!("http://127.0.0.1:{port}/mocked"));
    assert!(out.contains("Mock Rules: 404"), "{out}");
    rules.set_autoresponder(AutoResponderState::default(), true).unwrap();

    // --- The master switch and stopping the capture close the port.
    s.reverse_proxy.enabled = false;
    core.update_settings(s.clone()).unwrap();
    assert!(core.status().engine.listeners.is_empty());
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    s.reverse_proxy.enabled = true;
    core.update_settings(s.clone()).unwrap();
    assert_eq!(core.status().engine.listeners.len(), 1);
    core.stop_capture().unwrap();
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    core.shutdown();
}

#[test]
fn path_routes_socks_and_transparent_settings() {
    use quena_app_core::settings::ReversePathEntry;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        r#"{"proxy":{"port":18882,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#,
    )
    .unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let (a, b) = (echo_server(), echo_server());
    let (port, socks, transparent) = (free_port(), free_port(), free_port());

    // Off by default, with their own default ports.
    let s0 = core.settings();
    assert!(!s0.socks.enabled && !s0.transparent.enabled);
    assert_eq!((s0.socks.port, s0.transparent.port), (8868, 8869));

    // Ports must differ from each other and from the proxy port.
    let mut s = core.settings();
    s.socks.enabled = true;
    s.socks.port = 18882;
    assert!(core.update_settings(s.clone()).unwrap_err().to_string().contains("proxy port"));
    s.socks.port = socks;
    s.transparent.enabled = true;
    s.transparent.port = socks;
    assert!(core.update_settings(s.clone()).is_err());
    s.transparent.port = transparent;
    // A path route needs a prefix starting with / and a valid target.
    let entry = ReverseProxyEntry {
        id: "p".into(),
        name: "web".into(),
        listen_port: port,
        target: format!("http://127.0.0.1:{a}"),
        paths: vec![ReversePathEntry { prefix: "auth".into(), target: format!("http://127.0.0.1:{b}/sso"), strip_prefix: true }],
        ..Default::default()
    };
    s.reverse_proxy = ReverseProxySettings { enabled: true, entries: vec![entry.clone()] };
    assert!(core.update_settings(s.clone()).is_err());
    s.reverse_proxy.entries[0].paths[0].prefix = "/auth".into();
    core.update_settings(s.clone()).unwrap();

    let st = core.status().engine.listeners;
    assert_eq!(st.len(), 3, "{st:?}");
    assert!(st.iter().all(|l| l.error.is_none() && !l.listen.is_empty()), "{st:?}");
    assert!(get(&format!("http://127.0.0.1:{port}/page")).starts_with("GET /page HTTP/1.1"));
    let out = get(&format!("http://127.0.0.1:{port}/auth/login"));
    assert!(out.starts_with("GET /sso/login HTTP/1.1") && out.contains(&format!("127.0.0.1:{b}")), "{out}");
    // SOCKS forwards to the target the client names.
    let o = Command::new("curl").args(["-sS", "--max-time", "20", "--socks5-hostname", &format!("127.0.0.1:{socks}"), &format!("http://127.0.0.1:{a}/via-socks")]).output().unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("GET /via-socks HTTP/1.1"));

    // Switched off: the ports close.
    s.socks.enabled = false;
    s.transparent.enabled = false;
    core.update_settings(s).unwrap();
    assert_eq!(core.status().engine.listeners.len(), 1);
    assert!(std::net::TcpStream::connect(("127.0.0.1", socks)).is_err());
    core.shutdown();
}
