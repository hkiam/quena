//! MCP servers: exchanges over HTTP through the proxy are marked with method, tool and server;
//! recordings of stdio servers (`quena-cli mcp-tap`) become sessions.

use quena_app_core::{AppCore, Paths};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

/// A Streamable HTTP MCP server: `initialize` answered as a stream with a session id, the rest
/// as JSON.
fn fake_mcp() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut len = 0usize;
                let mut first = String::new();
                r.read_line(&mut first).unwrap();
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
                let m: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let id = m["id"].clone();
                let (ct, extra, out) = match m["method"].as_str() {
                    Some("initialize") => ("text/event-stream", "Mcp-Session-Id: sess-7\r\n", format!("event: message\ndata: {}\n\n", serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"jira","version":"1.0"}}}))),
                    Some("tools/list") => ("application/json", "", serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{"name":"get_issue","description":"Get an issue","inputSchema":{"type":"object"}}]}}).to_string()),
                    Some("tools/call") => ("application/json", "", serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"PRJ-1: Login fails"}],"isError":false}}).to_string()),
                    _ => ("application/json", "", String::new()),
                };
                let status = if out.is_empty() { "202 Accepted" } else { "200 OK" };
                let mut s = s;
                let _ = write!(s, "HTTP/1.1 {status}\r\nContent-Type: {ct}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
            });
        }
    });
    port
}

fn core_at(dir: &std::path::Path) -> (std::sync::Arc<AppCore>, std::net::SocketAddr) {
    std::fs::write(dir.join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let addr = engine.proxy.listen_addrs().into_iter().find(|a| a.is_ipv4()).unwrap();
    (core, addr)
}

#[test]
fn mcp_over_http_is_marked() {
    let dir = tempfile::tempdir().unwrap();
    let (core, addr) = core_at(dir.path());
    let port = fake_mcp();
    let post = |body: &str, session: bool| {
        let mut args = vec!["-sS".to_string(), "--max-time".into(), "20".into(), "-x".into(), format!("http://{addr}"), "-H".into(), "Content-Type: application/json".into(), "-H".into(), "Accept: application/json, text/event-stream".into()];
        if session {
            args.extend(["-H".into(), "Mcp-Session-Id: sess-7".into(), "-H".into(), "MCP-Protocol-Version: 2025-06-18".into()]);
        }
        args.extend(["--data-binary".into(), body.into(), format!("http://127.0.0.1:{port}/mcp")]);
        let o = Command::new("curl").args(&args).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    };
    post(r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#, false);
    post(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#, true);
    post(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#, true);
    post(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_issue","arguments":{"key":"PRJ-1"}}}"#, true);
    let t = Instant::now();
    let rows = loop {
        core.capture().index.tick();
        let rows: Vec<_> = core.capture().index.find_all(|s| !s.mcp.is_empty()).into_iter().filter_map(|id| core.capture().index.get(id)).collect();
        if rows.len() == 4 {
            break rows;
        }
        assert!(t.elapsed() < Duration::from_secs(20), "not marked: {rows:?}");
        std::thread::sleep(Duration::from_millis(50));
    };
    let labels: Vec<&str> = rows.iter().map(|r| r.mcp.as_str()).collect();
    assert_eq!(labels, ["initialize", "notifications/initialized", "tools/list", "tools/call get_issue"]);
    assert!(rows.iter().all(|r| r.mcp_server == "jira"), "named by its initialize: {rows:?}");
    let e = quena_query::expr::parse(r#"mcp ~ "tools/call" and mcpserver == jira"#).unwrap();
    assert_eq!(core.capture().index.find_all(|s| e.eval(s)).len(), 1);
    let ex = core.mcp_exchange(rows[3].id).unwrap();
    assert_eq!(ex.call.unwrap().content[0].text, "PRJ-1: Login fails");
    let list = core.mcp_exchange(rows[2].id).unwrap();
    assert_eq!(list.tools[0].name, "get_issue");
    core.shutdown();
}

#[test]
fn stdio_recordings_become_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let (core, _) = core_at(dir.path());
    let taps = dir.path().join("mcp-tap");
    std::fs::create_dir_all(&taps).unwrap();
    let file = taps.join("notes-1.jsonl");
    let lines = [
        r#"{"tap":{"name":"notes","command":"python3 notes.py","pid":4242,"started":1791622717000000}}"#,
        r#"{"exchange":{"t0":1791622717627115,"t1":1791622717655096,"from":"client","request":{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}},"response":{"jsonrpc":"2.0","id":0,"result":{"serverInfo":{"name":"notes","version":"0.3"}}}}}"#,
        r#"{"exchange":{"t0":1791622717627519,"t1":1791622717655288,"from":"client","request":{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add_note","arguments":{"text":"hi"}}},"response":{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"added"}]}}}}"#,
    ];
    std::fs::write(&file, format!("{}\n{}\n{}", lines[0], lines[1], lines[2])).unwrap();
    core.mcp_tap_tick();
    core.capture().index.tick();
    let rows: Vec<_> = core.capture().index.find_all(|s| !s.mcp.is_empty()).into_iter().filter_map(|id| core.capture().index.get(id)).collect();
    assert_eq!(rows.len(), 1, "the last line is not complete yet: {rows:?}");
    assert_eq!((rows[0].mcp.as_str(), rows[0].mcp_server.as_str(), rows[0].host.as_str()), ("initialize", "notes", "notes"));
    assert_eq!(rows[0].process, "python3:4242");
    // The writer finishes the line; read once.
    std::fs::OpenOptions::new().append(true).open(&file).unwrap().write_all(b"\n").unwrap();
    core.mcp_tap_tick();
    core.mcp_tap_tick();
    core.capture().index.tick();
    let rows: Vec<_> = core.capture().index.find_all(|s| !s.mcp.is_empty()).into_iter().filter_map(|id| core.capture().index.get(id)).collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].mcp, "tools/call add_note");
    assert_eq!(rows[1].url, "/tools/call");
    assert!(std::fs::read_to_string(taps.join("notes-1.jsonl.read")).unwrap().trim().parse::<u64>().unwrap() > 0, "the read position is kept");
    core.shutdown();
}

/// Answers like Anthropic: the first turn asks for the Jira tool and loads a skill, later
/// turns answer with text.
fn fake_claude() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut len = 0usize;
                let mut first = String::new();
                r.read_line(&mut first).unwrap();
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
                let m: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let content = if m["messages"].as_array().unwrap().len() == 1 {
                    serde_json::json!([{"type":"tool_use","id":"tu1","name":"mcp__jira__get_issue","input":{"key":"PRJ-1"}},{"type":"tool_use","id":"tu2","name":"Skill","input":{"skill":"pdf"}}])
                } else {
                    serde_json::json!([{"type":"text","text":"The login fails."}])
                };
                let out = serde_json::json!({"model":"claude-sonnet-4-5","content":content,"stop_reason":"end_turn","usage":{"input_tokens":3000,"output_tokens":20}}).to_string();
                let mut s = s;
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
            });
        }
    });
    port
}

#[test]
fn a_tool_call_is_followed_from_the_model_to_the_server_and_back() {
    let dir = tempfile::tempdir().unwrap();
    let (core, addr) = core_at(dir.path());
    let (mcp, llm) = (fake_mcp(), fake_claude());
    let curl = |url: String, body: String, headers: &[&str]| {
        let mut args = vec!["-sS".to_string(), "--max-time".into(), "20".into(), "-x".into(), format!("http://{addr}"), "-H".into(), "Content-Type: application/json".into()];
        for h in headers {
            args.extend(["-H".into(), h.to_string()]);
        }
        args.extend(["--data-binary".into(), body, url]);
        let o = Command::new("curl").args(&args).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    };
    let tools = r#"[{"name":"mcp__jira__get_issue","description":"Get a Jira issue","input_schema":{"type":"object","properties":{"key":{"type":"string"}}}},{"name":"mcp__jira__create_issue","description":"Create a Jira issue","input_schema":{"type":"object"}},{"name":"Skill","description":"Load a skill","input_schema":{"type":"object"}}]"#;
    let first = r#"{"role":"user","content":[{"type":"text","text":"<system-reminder>The following skills are available for use with the Skill tool:\n- pdf: work with PDF files\n- xlsx: spreadsheets\n</system-reminder>"},{"type":"text","text":"Why does PRJ-1 fail?"}]}"#;
    let msgs = |rest: &str| format!(r#"{{"model":"claude-sonnet-4-5","max_tokens":100,"system":"You are Claude Code.","tools":{tools},"messages":[{first}{rest}]}}"#);
    curl(format!("http://127.0.0.1:{llm}/v1/messages"), msgs(""), &["X-Claude-Code-Session-Id: s-9"]);
    std::thread::sleep(Duration::from_millis(30));
    curl(format!("http://127.0.0.1:{mcp}/mcp"), r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}"#.into(), &[]);
    curl(format!("http://127.0.0.1:{mcp}/mcp"), r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_issue","arguments":{"key":"PRJ-1"}}}"#.into(), &["Mcp-Session-Id: sess-7"]);
    std::thread::sleep(Duration::from_millis(30));
    curl(
        format!("http://127.0.0.1:{llm}/v1/messages"),
        msgs(r#",{"role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"mcp__jira__get_issue","input":{"key":"PRJ-1"}},{"type":"tool_use","id":"tu2","name":"Skill","input":{"skill":"pdf"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu1","content":"PRJ-1: Login fails"},{"type":"tool_result","tool_use_id":"tu2","content":"PDF skill loaded"}]}"#),
        &["X-Claude-Code-Session-Id: s-9"],
    );
    let t = Instant::now();
    let (llm_ids, call_id) = loop {
        core.capture().index.tick();
        let llm_ids = core.capture().index.find_all(|s| !s.llm_conv.is_empty());
        let calls = core.capture().index.find_all(|s| s.mcp.starts_with("tools/call"));
        if llm_ids.len() == 2 && calls.len() == 1 {
            break (llm_ids, calls[0]);
        }
        assert!(t.elapsed() < Duration::from_secs(20), "not marked");
        std::thread::sleep(Duration::from_millis(50));
    };
    let trail = core.mcp_trail(call_id).unwrap();
    assert_eq!((trail.requested_by, trail.result_in), (Some(llm_ids[0]), Some(llm_ids[1])));
    assert_eq!(trail.offered, 2);
    assert!(trail.def_tokens > 0);
    let back = core.llm_tool_trails(llm_ids[0]);
    assert_eq!(back[0].mcp, Some(call_id), "{back:?}");
    assert_eq!(back[1].mcp, None, "the Skill tool runs in the agent");
    let r = core.tool_report();
    let get = r.tools.iter().find(|t| t.name == "mcp__jira__get_issue").unwrap();
    assert_eq!((get.offered, get.model_calls, get.mcp_calls, get.errors, get.server.as_deref()), (2, 1, 1, 0, Some("jira")));
    assert!(get.result_tokens > 0);
    let create = r.tools.iter().find(|t| t.name == "mcp__jira__create_issue").unwrap();
    assert_eq!((create.offered, create.model_calls), (2, 0), "offered, never called");
    let pdf = r.skills.iter().find(|s| s.name == "pdf").unwrap();
    assert_eq!((pdf.offered, pdf.used), (1, 1));
    assert_eq!(r.skills.iter().find(|s| s.name == "xlsx").unwrap().used, 0);
    core.shutdown();
}

/// The older HTTP+SSE transport: the POST is answered with 202, the result comes on the stream.
#[test]
fn old_sse_transport_results_come_from_the_stream() {
    let dir = tempfile::tempdir().unwrap();
    let (core, addr) = core_at(dir.path());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut first = String::new();
            r.read_line(&mut first).unwrap();
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
            r.read_exact(&mut body).unwrap();
            let mut s = s;
            if first.starts_with("GET") {
                let out = "event: endpoint\ndata: /messages?sessionId=abc\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"serverInfo\":{\"name\":\"notes\",\"version\":\"1\"}}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"saved\"}]}}\n\n";
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
            } else {
                let _ = write!(s, "HTTP/1.1 202 Accepted\r\nContent-Length: 8\r\nConnection: close\r\n\r\nAccepted");
            }
        }
    });
    let curl = |args: &[&str]| {
        let mut a = vec!["-sS", "--max-time", "20"];
        let proxy = format!("http://{addr}");
        a.extend(["-x", proxy.as_str()]);
        a.extend(args);
        let o = Command::new("curl").args(&a).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    };
    curl(&[&format!("http://127.0.0.1:{port}/sse")]);
    std::thread::sleep(Duration::from_millis(20));
    curl(&["-H", "Content-Type: application/json", "--data-binary", r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"save","arguments":{}}}"#, &format!("http://127.0.0.1:{port}/messages?sessionId=abc")]);
    let t = Instant::now();
    let rows = loop {
        core.capture().index.tick();
        let rows: Vec<_> = core.capture().index.find_all(|s| !s.mcp.is_empty()).into_iter().filter_map(|id| core.capture().index.get(id)).collect();
        if rows.len() == 2 {
            break rows;
        }
        assert!(t.elapsed() < Duration::from_secs(20), "not marked: {rows:?}");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(rows[0].mcp, "stream");
    assert_eq!(rows[1].mcp, "tools/call save");
    let ex = core.mcp_exchange(rows[1].id).unwrap();
    assert_eq!((ex.transport, ex.session.as_deref()), ("sse", Some("abc")));
    assert_eq!(ex.call.unwrap().content[0].text, "saved", "the result from the stream");
    core.shutdown();
}

/// MCP exchanges in an archive from elsewhere get their flags when the report asks.
#[test]
fn archived_mcp_exchanges_get_their_flags() {
    let dir = tempfile::tempdir().unwrap();
    let (core, _) = core_at(dir.path());
    let entry = |body: &str, resp: &str| {
        serde_json::json!({
            "startedDateTime": "2026-10-10T10:00:00.000Z", "time": 10,
            "request": {"method": "POST", "url": "https://mcp.example.com/mcp", "httpVersion": "HTTP/1.1", "headers": [{"name": "Content-Type", "value": "application/json"}], "queryString": [], "cookies": [], "headersSize": -1, "bodySize": body.len(), "postData": {"mimeType": "application/json", "text": body}},
            "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1", "headers": [{"name": "Content-Type", "value": "application/json"}], "cookies": [], "content": {"size": resp.len(), "mimeType": "application/json", "text": resp}, "redirectURL": "", "headersSize": -1, "bodySize": resp.len()},
            "cache": {}, "timings": {"send": 0, "wait": 10, "receive": 0}
        })
    };
    let har = serde_json::json!({"log": {"version": "1.2", "creator": {"name": "other", "version": "1"}, "entries": [
        entry(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_issue","arguments":{}}}"#, r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"x"}],"isError":true}}"#)
    ]}});
    let f = dir.path().join("mcp.har");
    std::fs::write(&f, serde_json::to_vec(&har).unwrap()).unwrap();
    let job = core.import_archive(f).unwrap();
    core.jobs.wait(job, Duration::from_secs(20)).unwrap();
    let r = core.tool_report();
    let t = r.tools.iter().find(|t| t.name == "get_issue").unwrap();
    assert_eq!((t.mcp_calls, t.errors, t.server.as_deref()), (1, 1, Some("mcp.example.com")));
    core.capture().index.tick();
    assert_eq!(core.capture().index.find_all(|s| s.mcp == "tools/call get_issue").len(), 1);
    core.shutdown();
}
