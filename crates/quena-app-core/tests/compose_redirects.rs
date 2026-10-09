//! Composer: redirects followed on request (307 keeps method and body, 302 after a POST
//! becomes a GET), each hop its own session; header lines starting with `#` are off.

use quena_app_core::compose::ComposeRequest;
use quena_app_core::{AppCore, Paths};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

fn server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut first = String::new();
                r.read_line(&mut first).unwrap_or(0);
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
                let mut body = vec![0; len];
                let _ = r.read_exact(&mut body);
                let path = first.split_whitespace().nth(1).unwrap_or("").to_string();
                let (status, loc) = match path.as_str() {
                    "/a" => ("307 Temporary Redirect", "/b"),
                    "/b" => ("302 Found", "c"),
                    _ => ("200 OK", ""),
                };
                let loc = if loc.is_empty() { String::new() } else { format!("Location: {loc}\r\n") };
                let mut s = s;
                let _ = write!(s, "HTTP/1.1 {status}\r\n{loc}Content-Length: 2\r\nConnection: close\r\n\r\nok");
            });
        }
    });
    port
}

#[test]
fn redirects_followed_hop_by_hop() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine);
    core.start_capture().unwrap();
    let port = server();
    let req = |follow: bool| ComposeRequest {
        method: "POST".into(),
        url: format!("http://127.0.0.1:{port}/a"),
        version: None,
        headers: "Content-Type: text/plain\n# X-Off: 1\nX-On: 1".into(),
        body: "hello".into(),
        body_charset: None,
        body_from_session: None,
        body_file: None,
        fix_content_length: true,
        breakpoint: false,
        follow_redirects: follow,
    };
    let first = core.compose(req(true)).unwrap();
    let t = Instant::now();
    let rows = loop {
        let cap = core.capture();
        cap.index.tick();
        let mut ids = cap.index.find_all(|s| s.state.is_final());
        ids.sort_unstable();
        if ids.len() == 3 {
            break ids.into_iter().filter_map(|id| cap.detail(id)).collect::<Vec<_>>();
        }
        assert!(t.elapsed() < Duration::from_secs(20), "{ids:?}");
        std::thread::sleep(Duration::from_millis(30));
    };
    assert_eq!(rows[0].summary.id, first);
    let got: Vec<(String, String, u16)> = rows.iter().map(|d| (d.request.method.clone(), d.summary.url.clone(), d.summary.status)).collect();
    assert_eq!(got, [("POST".into(), "/a".into(), 307), ("POST".into(), "/b".into(), 302), ("GET".into(), "/c".into(), 200)]);
    assert_eq!(rows[1].summary.request_body_len, 5, "307 keeps the body");
    assert_eq!(rows[2].summary.request_body_len, 0, "302 after POST: GET without a body");
    assert!(rows[2].summary.comment.contains("Redirect 2"), "{}", rows[2].summary.comment);
    assert!(rows[0].request.headers.get("x-off").is_none() && rows[0].request.headers.get("x-on").is_some());

    // Without following: one session.
    core.compose(req(false)).unwrap();
    std::thread::sleep(Duration::from_millis(600));
    core.capture().index.tick();
    assert_eq!(core.capture().index.find_all(|_| true).len(), 4);
}
