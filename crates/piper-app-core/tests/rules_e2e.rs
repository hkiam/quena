//! AutoResponder + breakpoints through the real proxy engine.

use piper_app_core::rules::{AutoResponderState, Resume, Rule};
use piper_app_core::{AppCore, Paths};
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

fn curl(proxy: &str, url: &str) -> std::thread::JoinHandle<String> {
    let proxy = proxy.to_string();
    let url = url.to_string();
    std::thread::spawn(move || {
        let o = Command::new("curl").args(["-sS", "--max-time", "20", "-x", &proxy, &url]).output().unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    })
}

#[test]
fn autoresponder_and_breakpoints() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        r#"{"proxy":{"port":18866,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#,
    )
    .unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), piper_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = piper_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let addr = engine.proxy.listen_addrs().into_iter().find(|a| a.is_ipv4()).unwrap();
    let proxy = format!("http://{addr}");
    let port = echo_server();
    let rules = core.rules.clone().unwrap();

    // --- AutoResponder
    let mut file = dir.path().join("mock.json");
    std::fs::write(&file, br#"{"mocked":true}"#).unwrap();
    rules
        .set_autoresponder(
            AutoResponderState {
                enabled: true,
                unmatched_passthrough: true,
                enable_latency: false,
                rules: vec![
                    Rule { match_: "blocked".into(), action: "*404".into(), ..Default::default() },
                    Rule { match_: "regex:/api/(\\w+)$".into(), action: file.to_string_lossy().into_owned(), ..Default::default() },
                    Rule { match_: "METHOD:GET /redirect".into(), action: "*redir:http://example.invalid/new".into(), ..Default::default() },
                ],
            },
            true,
        )
        .unwrap();
    let out = curl(&proxy, &format!("http://127.0.0.1:{port}/blocked")).join().unwrap();
    assert!(out.contains("Mock Rules: 404"), "{out}");
    let out = curl(&proxy, &format!("http://127.0.0.1:{port}/api/users")).join().unwrap();
    assert_eq!(out, r#"{"mocked":true}"#);
    let o = Command::new("curl").args(["-sS", "-o", if cfg!(windows) { "NUL" } else { "/dev/null" }, "-w", "%{http_code} %{redirect_url}", "-x", &proxy, &format!("http://127.0.0.1:{port}/redirect")]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&o.stdout), "307 http://example.invalid/new");
    let out = curl(&proxy, &format!("http://127.0.0.1:{port}/passthrough")).join().unwrap();
    assert!(out.starts_with("GET /passthrough HTTP/1.1"), "{out}");
    assert!(rules.autoresponder().rules[0].hits >= 1);
    file.set_extension("x");
    rules.set_autoresponder(AutoResponderState::default(), true).unwrap();

    // --- Breakpoint before request: edit the head, then continue
    let r = core.quickexec("bpu /hold");
    assert!(r.error.is_none());
    let h = curl(&proxy, &format!("http://127.0.0.1:{port}/hold"));
    let t = Instant::now();
    let paused = loop {
        let p = rules.paused();
        if !p.is_empty() {
            break p;
        }
        assert!(t.elapsed() < Duration::from_secs(10), "no paused session");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(paused[0].phase, "request");
    let id = paused[0].id;
    let head = format!("GET http://127.0.0.1:{port}/hold HTTP/1.1\nHost: 127.0.0.1:{port}\nX-Tampered: yes\n");
    rules.resume(id, Resume { action: "breakOnResponse".into(), head_text: Some(head), body_text: None, body_file: None, status: None }).unwrap();
    // Now paused at the response.
    let t = Instant::now();
    let p = loop {
        let p = rules.paused();
        if let Some(x) = p.into_iter().find(|x| x.phase == "response") {
            break x;
        }
        assert!(t.elapsed() < Duration::from_secs(10), "response breakpoint not hit");
        std::thread::sleep(Duration::from_millis(20));
    };
    rules
        .resume(p.id, Resume { action: "continue".into(), head_text: None, body_text: Some("tampered response".into()), body_file: None, status: None })
        .unwrap();
    let out = h.join().unwrap();
    assert_eq!(out, "tampered response");
    // The recorded request has the tampered header.
    let d = core.capture().detail(id).unwrap();
    assert_eq!(d.request.headers.get("x-tampered"), Some("yes"));

    // --- g resumes everything
    core.quickexec("bpu");
    core.quickexec("bps 200");
    let h = curl(&proxy, &format!("http://127.0.0.1:{port}/status"));
    let t = Instant::now();
    while rules.paused().is_empty() {
        assert!(t.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(20));
    }
    let r = core.quickexec("g");
    assert!(r.message.unwrap().contains("Resumed 1"));
    assert!(h.join().unwrap().starts_with("GET /status"));
    core.shutdown();
}

/// The scripting engine (M14) through the real proxy: request-header rewrite,
/// local respond(), and response-header rewrite while the body streams.
#[test]
fn scripting_through_proxy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        r#"{"proxy":{"port":18868,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#,
    )
    .unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), piper_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = piper_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let addr = engine.proxy.listen_addrs().into_iter().find(|a| a.is_ipv4()).unwrap();
    let proxy = format!("http://{addr}");
    let port = echo_server();
    let rules = core.rules.clone().unwrap();

    let script = r#"
        function onBeforeRequest(s) {
            s.requestHeaders.set('X-Piper', 'yes');
            if (s.path.indexOf('/mock') === 0) s.respond(200, 'mocked-by-script', {'Content-Type':'text/plain'});
            if (s.path.indexOf('/redir') === 0) s.redirect('http://127.0.0.1:' + '__PORT__' + '/moved');
        }
        function onBeforeResponse(s) {
            s.responseHeaders.set('X-Script', '1');
        }
    "#
    .replace("__PORT__", &port.to_string());

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        rules.set_script(script).await.expect("script compiles");
        rules.set_script_enabled(true).await.expect("script enabled");
    });
    assert!(rules.script_active());

    // 1. Request header rewrite reaches the upstream (echo returns the request head),
    //    and the response carries the script-added header.
    let o = Command::new("curl")
        .args(["-sS", "-i", "--max-time", "20", "-x", &proxy, &format!("http://127.0.0.1:{port}/echo")])
        .output()
        .unwrap();
    let full = String::from_utf8_lossy(&o.stdout);
    assert!(full.to_lowercase().contains("x-script: 1"), "response header not rewritten:\n{full}");
    assert!(full.to_lowercase().contains("x-piper: yes"), "request header not rewritten (echoed body):\n{full}");

    // 2. Local respond() short-circuits the upstream.
    let out = curl(&proxy, &format!("http://127.0.0.1:{port}/mock")).join().unwrap();
    assert_eq!(out, "mocked-by-script");

    // 3. redirect() rewrites the target; the echoed request path is /moved.
    let out = curl(&proxy, &format!("http://127.0.0.1:{port}/redir")).join().unwrap();
    assert!(out.starts_with("GET /moved "), "redirect not applied:\n{out}");

    core.shutdown();
}
