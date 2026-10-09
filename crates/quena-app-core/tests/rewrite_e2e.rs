//! Rewrite rules through the real proxy engine.

use quena_app_core::rewrite::{Op, Phase, RewriteRule, RewriteState};
use quena_app_core::rules::Resume;
use quena_app_core::{AppCore, Paths};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

/// Upstream with a few fixed answers; `/echo` returns the request body.
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
                let mut chunked = false;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    let l = line.to_ascii_lowercase();
                    if let Some(v) = l.strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    chunked |= l.starts_with("transfer-encoding:") && l.contains("chunked");
                }
                let mut req_body = vec![0u8; len];
                let _ = r.read_exact(&mut req_body);
                if chunked {
                    loop {
                        let mut size = String::new();
                        r.read_line(&mut size).unwrap_or(0);
                        let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
                        let mut chunk = vec![0u8; n + 2];
                        let _ = r.read_exact(&mut chunk);
                        if n == 0 {
                            break;
                        }
                        req_body.extend_from_slice(&chunk[..n]);
                    }
                }
                let path = first.split_whitespace().nth(1).unwrap_or("").to_string();
                let mut s = s;
                let send = |s: &mut std::net::TcpStream, ct: &str, extra: &str, body: &[u8]| {
                    let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                    let _ = s.write_all(body);
                };
                match path.as_str() {
                    "/list" | "/list2" => {
                        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                        gz.write_all(br#"{"items":[{"id":1,"name":"a"}],"count":1}"#).unwrap();
                        send(&mut s, "application/json", "Content-Encoding: gzip\r\n", &gz.finish().unwrap());
                    }
                    "/big" => send(&mut s, "application/json", "", &vec![b' '; 5 << 20]),
                    "/sse" => {
                        let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: [1]\n\n");
                    }
                    "/echo" => send(&mut s, "application/json", "", &req_body),
                    "/echo-len" => send(&mut s, "text/plain", "", req_body.len().to_string().as_bytes()),
                    "/c/big" | "/c/small" => {
                        // Chunked, no Content-Length (as HTTP/2 and gzip-on-the-fly APIs send it).
                        let body: Vec<u8> = if path == "/c/big" { format!("[{}0]", "0,".repeat(3 << 20)).into_bytes() } else { b"[1,2]".to_vec() };
                        let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
                        for c in body.chunks(64 << 10) {
                            let _ = write!(s, "{:x}\r\n", c.len());
                            let _ = s.write_all(c);
                            let _ = s.write_all(b"\r\n");
                        }
                        let _ = s.write_all(b"0\r\n\r\n");
                    }
                    "/c/ndjson" => send(&mut s, "application/x-ndjson", "", b"[1]\n[2]\n"),
                    "/c/partial" => {
                        let _ = write!(s, "HTTP/1.1 206 Partial Content\r\nContent-Type: application/json\r\nContent-Range: bytes 0-4/10\r\nContent-Length: 5\r\nConnection: close\r\n\r\n[1,2]");
                    }
                    _ => send(&mut s, "text/plain", "", b"plain"),
                }
            });
        }
    });
    port
}

fn curl(args: &[&str]) -> std::thread::JoinHandle<(String, String)> {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    std::thread::spawn(move || {
        let o = Command::new("curl").args(["-sS", "--max-time", "20"]).args(&args).output().unwrap();
        (String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
    })
}

fn last_session(core: &AppCore, path: &str) -> quena_model::SessionDetail {
    let cap = core.capture();
    let t = Instant::now();
    loop {
        let mut ids = cap.index.find_all(|s| s.url.ends_with(path) && s.state.is_final());
        ids.sort();
        if let Some(id) = ids.last() {
            return cap.detail(*id).unwrap();
        }
        assert!(t.elapsed() < Duration::from_secs(10), "no session for {path}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn rewrite_rules() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        r#"{"proxy":{"port":18886,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#,
    )
    .unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let addr = engine.proxy.listen_addrs().into_iter().find(|a| a.is_ipv4()).unwrap();
    let proxy = format!("http://{addr}");
    let port = server();
    let url = |p: &str| format!("http://127.0.0.1:{port}{p}");
    let rules = core.rules.clone().unwrap();

    // Without rules nothing is buffered or changed.
    let (out, _) = curl(&["-x", &proxy, "--compressed", &url("/list")]).join().unwrap();
    assert_eq!(out, r#"{"items":[{"id":1,"name":"a"}],"count":1}"#);

    let rw = |m: &str, phase: Phase, ops: Vec<Op>| RewriteRule { match_: m.into(), phase, ops, comment: m.into(), ..Default::default() };
    rules
        .rewrite
        .set(RewriteState {
            rules: vec![
                rw("/list", Phase::Response, vec![Op::JsonAppendAll { value: None }, Op::JsonSet { path: "$.count".into(), value: json!(99) }]),
                rw("/big", Phase::Response, vec![Op::RegexReplace { pattern: " ".into(), replacement: "x".into() }]),
                rw("/sse", Phase::Response, vec![Op::RegexReplace { pattern: "1".into(), replacement: "2".into() }]),
                rw("/hdr", Phase::Response, vec![Op::SetHeader { name: "X-Rewritten".into(), value: "yes".into() }, Op::SetStatus { code: 503 }]),
                rw("METHOD:POST /echo", Phase::Request, vec![Op::JsonSet { path: "$.injected".into(), value: json!(true) }]),
                rw("/c/", Phase::Response, vec![Op::JsonAppendAll { value: Some(json!("X")) }]),
                rw("/mark", Phase::Request, vec![Op::SetQuery { name: "lang".into(), value: "de".into() }, Op::Mark { color: quena_model::MarkColor::Red }]),
                rw("/mark", Phase::Response, vec![Op::Comment { text: "seen by a rule".into() }]),
            ],
            ..Default::default()
        })
        .unwrap();

    // Query changed, session marked and commented (the response itself unchanged).
    let _ = curl(&["-x", &proxy, &url("/mark?x=1")]).join().unwrap();
    let d = last_session(&core, "/mark?x=1&lang=de");
    assert_eq!(d.summary.color, Some(quena_model::MarkColor::Red));
    assert!(d.summary.comment.contains("seen by a rule"), "{}", d.summary.comment);

    // gzip JSON: decoded, every list gets a broken element, sent back uncompressed.
    let (out, err) = curl(&["-x", &proxy, "-D", "-", &url("/list")]).join().unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or_else(|| panic!("{out} {err}"));
    assert!(!head.to_ascii_lowercase().contains("content-encoding"), "{head}");
    assert!(head.to_ascii_lowercase().contains(&format!("content-length: {}", body.len())), "{head}");
    let v: Value = serde_json::from_str(body).unwrap();
    assert_eq!(v, json!({ "items": [{ "id": 1, "name": "a" }, { "id": null, "name": null }], "count": 99 }));
    let d = last_session(&core, "/list");
    assert!(d.summary.has_flag(quena_model::flags::TAMPERED));
    assert!(d.summary.comment.contains("Rewrite: /list"), "{}", d.summary.comment);
    assert_eq!(d.summary.state, quena_model::SessionState::Done);

    // Larger than the limit: streamed unchanged.
    let (out, _) = curl(&["-x", &proxy, &url("/big")]).join().unwrap();
    assert_eq!(out.len(), 5 << 20);
    assert!(out.bytes().all(|b| b == b' '));
    assert!(!last_session(&core, "/big").summary.has_flag(quena_model::flags::TAMPERED));

    // Event streams are never buffered (or changed).
    let (out, _) = curl(&["-x", &proxy, &url("/sse")]).join().unwrap();
    assert_eq!(out, "data: [1]\n\n");

    // Header and status only: no buffering needed.
    let (out, _) = curl(&["-x", &proxy, "-D", "-", &url("/hdr")]).join().unwrap();
    assert!(out.starts_with("HTTP/1.1 503"), "{out}");
    assert!(out.to_ascii_lowercase().contains("x-rewritten: yes") && out.ends_with("plain"), "{out}");

    // Request body: the server sees the change.
    let (out, _) = curl(&["-x", &proxy, "-H", "Content-Type: application/json", "--data", r#"{"a":1}"#, &url("/echo")]).join().unwrap();
    assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), json!({ "a": 1, "injected": true }));
    // GET without a body is not buffered and still reaches the server.
    let (out, _) = curl(&["-x", &proxy, &url("/echo")]).join().unwrap();
    assert_eq!(out, "");

    // Without a length: small bodies are rewritten, larger ones stream through unchanged
    // (no 502, no waiting for the whole body), with a note in the session.
    let (out, _) = curl(&["-x", &proxy, &url("/c/small")]).join().unwrap();
    assert_eq!(out, r#"[1,2,"X"]"#);
    let (out, err) = curl(&["-x", &proxy, &url("/c/big")]).join().unwrap();
    assert_eq!(out.len(), (3 << 20) * 2 + 3, "{err}");
    assert!(out.ends_with("0,0]"));
    let d = last_session(&core, "/c/big");
    assert!(!d.summary.has_flag(quena_model::flags::TAMPERED));
    assert!(d.extra_flags.iter().any(|(k, v)| k == "x-quena-held-back" && v.contains("larger than")), "{:?}", d.extra_flags);
    // Streams of JSON lines and partial content are left alone.
    let (out, _) = curl(&["-x", &proxy, &url("/c/ndjson")]).join().unwrap();
    assert_eq!(out, "[1]\n[2]\n");
    let (out, _) = curl(&["-x", &proxy, &url("/c/partial")]).join().unwrap();
    assert_eq!(out, "[1,2]");
    // A chunked upload larger than the limit reaches the server whole.
    let big = dir.path().join("upload.json");
    std::fs::write(&big, format!("[{}0]", "0,".repeat(3 << 20))).unwrap();
    let up = format!("@{}", big.display());
    let (out, _) = curl(&["-x", &proxy, "-H", "Content-Type: application/json", "-H", "Transfer-Encoding: chunked", "--data-binary", &up, &url("/echo-len")]).join().unwrap();
    assert_eq!(out, ((3 << 20) * 2 + 3).to_string());

    // A breakpoint after the response shows the rewritten body; resuming keeps it.
    core.quickexec("bpafter /list2");
    let h = curl(&["-x", &proxy, &url("/list2")]);
    let t = Instant::now();
    let p = loop {
        if let Some(p) = rules.paused().into_iter().find(|p| p.phase == "response") {
            break p;
        }
        assert!(t.elapsed() < Duration::from_secs(10), "response breakpoint not hit");
        std::thread::sleep(Duration::from_millis(20));
    };
    let (_, resp_body) = core.capture().bodies_of(p.id).unwrap();
    assert!(String::from_utf8_lossy(&resp_body.read_range(0, 1000).unwrap()).contains("\"count\":99"));
    rules.resume(p.id, Resume { action: "continue".into(), head_text: None, body_text: None, body_charset: None, body_file: None, status: None }).unwrap();
    let (out, _) = h.join().unwrap();
    assert!(out.contains("\"count\":99"), "{out}");
    core.quickexec("bpafter");

    // Hits are counted; disabling all rules restores the original traffic.
    let st = rules.rewrite.state();
    assert!(st.rules[0].hits >= 2, "{:?}", st.rules[0]);
    rules.rewrite.update(|s| s.enabled = false).unwrap();
    let (out, _) = curl(&["-x", &proxy, "--compressed", &url("/list")]).join().unwrap();
    assert_eq!(out, r#"{"items":[{"id":1,"name":"a"}],"count":1}"#);
    // Saved and loaded again.
    let again = quena_app_core::rewrite::Rewriter::load(dir.path());
    assert_eq!(again.state().rules.len(), 8);
    core.shutdown();
}
