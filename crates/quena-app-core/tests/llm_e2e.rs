//! LLM API calls through the proxy are recognised: flags, list fields, filter, statistics.

use quena_app_core::{AppCore, Paths};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

/// Answers every POST like Anthropic's Messages API (streamed) or OpenAI's (JSON).
fn fake_llm() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let (mut path, mut len) = (String::new(), 0usize);
                let mut first = String::new();
                r.read_line(&mut first).unwrap();
                path.push_str(first.split_whitespace().nth(1).unwrap_or(""));
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
                r.read_exact(&mut body).unwrap();
                let (ct, out) = if path.ends_with("/v1/messages") {
                    ("text/event-stream", concat!(
                        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":1000,\"output_tokens\":1}}}\n\n",
                        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
                        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
                        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":500}}\n\n",
                        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
                    ).to_string())
                } else {
                    ("application/json", r#"{"model":"gpt-4o","choices":[{"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":20}}"#.to_string())
                };
                let mut s = s;
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
            });
        }
    });
    port
}

#[test]
fn llm_calls_are_marked_and_counted() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let addr = engine.proxy.listen_addrs().into_iter().find(|a| a.is_ipv4()).unwrap();
    let port = fake_llm();
    let post = |path: &str, body: &str| {
        let o = Command::new("curl").args(["-sS", "--max-time", "20", "-x", &format!("http://{addr}"), "-H", "Content-Type: application/json", "--data-binary", body, &format!("http://127.0.0.1:{port}{path}")]).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    };
    post("/v1/messages", r#"{"model":"claude-sonnet-4-20250514","max_tokens":10,"stream":true,"messages":[{"role":"user","content":"Hi"}]}"#);
    post("/v1/chat/completions", r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#);
    post("/v1/other", r#"{"x":1}"#);
    // Marking runs after the session completes.
    let t = Instant::now();
    let rows = loop {
        core.capture().index.tick();
        let rows: Vec<_> = core.capture().index.find_all(|s| !s.llm.is_empty()).into_iter().filter_map(|id| core.capture().index.get(id)).collect();
        if rows.len() == 2 && rows.iter().all(|r| r.llm_tokens.is_some()) {
            break rows;
        }
        assert!(t.elapsed() < Duration::from_secs(20), "not marked: {rows:?}");
        std::thread::sleep(Duration::from_millis(50));
    };
    let claude = rows.iter().find(|r| r.llm.contains("claude")).unwrap();
    // The host is not Anthropic's, so the provider is named by host.
    assert_eq!(claude.llm, "127.0.0.1/claude-sonnet-4-20250514");
    assert_eq!(claude.llm_tokens, Some(1500));
    // 1000 × 3 + 500 × 15 per million dollars.
    assert_eq!(claude.llm_cost_micros, Some(10_500));
    let d = core.capture().detail(claude.id).unwrap();
    assert!(d.extra_flags.iter().any(|(k, v)| k == "x-quena-llm-usage" && v.starts_with("in 1000 · out 500")), "{:?}", d.extra_flags);
    let call = core.llm(claude.id).unwrap();
    assert_eq!(call.output[0].text, "Hello");
    // Filter and statistics.
    let e = quena_query::expr::parse("tokens > 1000").unwrap();
    assert_eq!(core.capture().index.find_all(|s| e.eval(s)), vec![claude.id]);
    let e = quena_query::expr::parse("llm ~ gpt").unwrap();
    assert_eq!(core.capture().index.find_all(|s| e.eval(s)).len(), 1);
    let st = core.statistics(vec![]);
    assert_eq!(st.llm_tokens, 1620);
    assert_eq!(st.llm_models.len(), 2);
    assert!((st.llm_cost - (0.0105 + (100.0 * 2.5 + 20.0 * 10.0) / 1e6)).abs() < 1e-9, "{}", st.llm_cost);
    core.shutdown();
}
