//! Grouping the session list by connection, trace id and session cookie, with real
//! keep-alive traffic through the proxy engine.

use quena_app_core::{AppCore, Paths};
use quena_index::GroupBy;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

/// HTTP/1.1 server that keeps connections open (several requests per connection).
fn keep_alive_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut s = s;
                loop {
                    let mut first = String::new();
                    if r.read_line(&mut first).unwrap_or(0) == 0 {
                        return;
                    }
                    let mut len = 0usize;
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                            break;
                        }
                        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                    }
                    let mut body = vec![0u8; len];
                    let _ = r.read_exact(&mut body);
                    let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok");
                }
            });
        }
    });
    port
}

const NULL: &str = if cfg!(windows) { "NUL" } else { "/dev/null" };

fn curl(proxy: &str, args: &[&str]) {
    let o = Command::new("curl").args(["-sS", "--max-time", "20", "-x", proxy, "-o", NULL]).args(args).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

#[test]
fn groups_real_keep_alive_connections() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        r#"{"proxy":{"port":18896,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#,
    )
    .unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let addr = engine.proxy.listen_addrs().into_iter().find(|a| a.is_ipv4()).unwrap();
    let proxy = format!("http://{addr}");
    let port = keep_alive_server();
    let url = |p: &str| format!("http://127.0.0.1:{port}{p}");

    // One curl reuses its connection for all its URLs; the second curl is another one.
    let trace = "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    curl(&proxy, &["-H", trace, "-H", "Cookie: JSESSIONID=S1", &url("/a1"), "-o", NULL, &url("/a2"), "-o", NULL, &url("/a3")]);
    curl(&proxy, &["-H", "Cookie: JSESSIONID=S1", &url("/b1"), "-o", NULL, &url("/b2")]);
    curl(&proxy, &["-H", trace, &url("/a4")]);

    let cap = core.capture();
    let t = Instant::now();
    while cap.index.find_all(|s| s.state.is_final()).len() < 6 {
        assert!(t.elapsed() < Duration::from_secs(10), "sessions did not finish");
        std::thread::sleep(Duration::from_millis(20));
        cap.index.tick();
    }
    let by_path = |p: &str| cap.index.find_all(|s| s.url == p).first().and_then(|id| cap.index.get(*id)).unwrap();
    let (a1, a2, a3, b1, b2, a4) = (by_path("/a1"), by_path("/a2"), by_path("/a3"), by_path("/b1"), by_path("/b2"), by_path("/a4"));
    assert!(a1.conn != 0 && a1.conn == a2.conn && a2.conn == a3.conn, "keep-alive: one connection");
    assert!(b1.conn == b2.conn && b1.conn != a1.conn && a4.conn != a1.conn && a4.conn != b1.conn);
    assert_eq!((a1.trace.as_str(), a4.trace.as_str()), ("4bf92f3577b34da6a3ce929d0e0e4736", "4bf92f3577b34da6a3ce929d0e0e4736"));
    assert!(b1.trace.is_empty());
    assert!(a1.session.starts_with("JSESSIONID #") && a1.session == b1.session && !a1.session.contains("S1"));

    let ids = |v: &[&quena_model::SessionSummary]| v.iter().map(|s| s.id).collect::<Vec<_>>();
    core.set_group(GroupBy::Connection);
    cap.index.tick();
    assert_eq!(core.view_ids(0, 10), ids(&[&a1, &a2, &a3, &b1, &b2, &a4]));
    core.set_group(GroupBy::Trace);
    cap.index.tick();
    let v = core.view_ids(0, 10);
    assert_eq!(&v[..4], &ids(&[&a1, &a2, &a3, &a4])[..], "one trace across connections");
    core.set_group(GroupBy::Session);
    cap.index.tick();
    assert_eq!(&core.view_ids(0, 10)[..5], &ids(&[&a1, &a2, &a3, &b1, &b2])[..]);
    assert_eq!(core.group_ids(b2.id).len(), 5);
    // The filter fields select a connection or a trace.
    assert_eq!(core.remove_where(&format!("conn == {}", b1.conn)).unwrap(), 2);
    core.shutdown();
}
