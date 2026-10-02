//! The MCP server over real HTTP, against a headless core with the proxy engine.

use quena_app_core::{AppCore, Paths};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

const TOKEN: &str = "test-token";

/// HTTP/1.1 server answering JSON with the request path.
fn json_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut first = String::new();
                r.read_line(&mut first).unwrap_or(0);
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                let path = first.split_whitespace().nth(1).unwrap_or("").to_string();
                let body = format!(r#"{{"path":"{path}","items":[1,2]}}"#);
                let mut s = s;
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            });
        }
    });
    port
}

/// One raw HTTP request to the MCP endpoint; returns (status, body).
fn post(addr: SocketAddr, host: &str, token: Option<&str>, body: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    write!(
        s,
        "POST /mcp HTTP/1.1\r\nHost: {host}\r\n{auth}Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let status = out.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = out.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (status, body)
}

fn rpc(addr: SocketAddr, method: &str, params: Value) -> Value {
    let host = format!("127.0.0.1:{}", addr.port());
    let (status, body) = post(addr, &host, Some(TOKEN), &json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string());
    assert_eq!(status, 200, "{body}");
    serde_json::from_str(&body).unwrap()
}

/// Call a tool; returns its parsed JSON result and whether it was an error.
fn tool(addr: SocketAddr, name: &str, args: Value) -> (Value, bool) {
    let r = rpc(addr, "tools/call", json!({ "name": name, "arguments": args }));
    let res = &r["result"];
    let text = res["content"][0]["text"].as_str().unwrap_or("").to_string();
    let err = res["isError"].as_bool().unwrap_or(false);
    (serde_json::from_str(&text).unwrap_or(Value::String(text)), err)
}

fn set_access(core: &Arc<AppCore>, full: bool) {
    let mut s = core.settings();
    s.mcp.access = if full { quena_app_core::settings::McpAccess::Full } else { quena_app_core::settings::McpAccess::ReadOnly };
    core.update_settings(s).unwrap();
}

#[test]
fn mcp_over_http() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        format!(r#"{{"proxy":{{"port":18876,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}},"mcp":{{"enabled":true,"port":0,"token":"{TOKEN}"}}}}"#),
    )
    .unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine);
    core.start_capture().unwrap();
    let mcp = quena_mcp::McpService::new();
    mcp.apply(&core);
    let addr = mcp.addr().expect("MCP server running");
    let host = format!("127.0.0.1:{}", addr.port());

    // --- Transport security
    let init = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-03-26" } }).to_string();
    assert_eq!(post(addr, &host, None, &init).0, 401);
    assert_eq!(post(addr, &host, Some("wrong"), &init).0, 401);
    assert_eq!(post(addr, "evil.example", Some(TOKEN), &init).0, 403);

    // --- Lifecycle
    let r = rpc(addr, "initialize", json!({ "protocolVersion": "2025-03-26" }));
    assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(r["result"]["serverInfo"]["name"], "quena");
    let (status, body) = post(addr, &host, Some(TOKEN), r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    assert_eq!((status, body.as_str()), (202, ""));
    assert_eq!(rpc(addr, "nope", json!({}))["error"]["code"], -32601);

    // --- Read-only: write tools are neither listed nor callable
    let names = |r: Value| r["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    let ro = names(rpc(addr, "tools/list", json!({})));
    assert!(ro.contains(&"list_sessions".into()) && !ro.contains(&"send_request".into()));
    let port = json_server();
    let (msg, err) = tool(addr, "send_request", json!({ "method": "GET", "url": format!("http://127.0.0.1:{port}/a") }));
    assert!(err && msg.as_str().unwrap().contains("full control"), "{msg}");

    // --- Full control: send a request, read it back
    set_access(&core, true);
    assert!(names(rpc(addr, "tools/list", json!({}))).contains(&"send_request".into()));
    let (s, err) = tool(addr, "send_request", json!({ "method": "GET", "url": format!("http://127.0.0.1:{port}/hello"), "headers": { "X-Agent": "yes" } }));
    assert!(!err, "{s}");
    assert_eq!(s["response"]["status"], 200);
    assert_eq!(s["response"]["body"]["text"], r#"{"path":"/hello","items":[1,2]}"#);
    let id = s["session"]["id"].as_u64().unwrap();
    assert!(s["request"]["headers"].as_array().unwrap().iter().any(|h| h[0] == "X-Agent"));

    let (l, _) = tool(addr, "list_sessions", json!({ "filter": "url ~ hello" }));
    assert_eq!(l["total"], 1);
    assert_eq!(l["sessions"][0]["id"], id);
    let (l, _) = tool(addr, "list_sessions", json!({ "since_id": id }));
    assert_eq!(l["total"], 0);
    let (b, _) = tool(addr, "get_body", json!({ "id": id, "part": "response", "offset": 9, "length": 6 }));
    assert_eq!(b["text"], "/hello");
    assert_eq!(b["more"], true);
    let (e, err) = tool(addr, "list_sessions", json!({ "filter": "status >=" }));
    assert!(err, "{e}");

    // --- Mock rules
    let (r, err) = tool(addr, "add_mock_rule", json!({ "match": "exact:http://127.0.0.1:1/mocked", "action": "*418" }));
    assert!(!err, "{r}");
    let rule = r["id"].as_u64().unwrap();
    let (s, _) = tool(addr, "send_request", json!({ "method": "GET", "url": "http://127.0.0.1:1/mocked" }));
    assert_eq!(s["response"]["status"], 418);
    assert!(s["session"]["flags"].as_array().unwrap().contains(&json!("mocked")));
    let (_, err) = tool(addr, "update_mock_rule", json!({ "id": rule, "enabled": false }));
    assert!(!err);
    let (m, _) = tool(addr, "list_mock_rules", json!({}));
    assert_eq!(m["rules"][0]["enabled"], false);
    let (_, err) = tool(addr, "remove_mock_rule", json!({ "id": rule }));
    assert!(!err);
    let (_, err) = tool(addr, "remove_mock_rule", json!({ "id": rule }));
    assert!(err);
    let (_, err) = tool(addr, "add_mock_rule", json!({ "match": "regex:(", "action": "*404" }));
    assert!(err, "invalid patterns are rejected");

    // --- Search, statistics, export, clear
    let (f, _) = tool(addr, "search_sessions", json!({ "text": "items", "examine": "bodies" }));
    assert_eq!(f["total"], 1);
    let (st, _) = tool(addr, "statistics", json!({}));
    assert!(st["sessions"].as_u64().unwrap() >= 2);
    let har = dir.path().join("out.har");
    let (x, err) = tool(addr, "export_archive", json!({ "path": har.to_string_lossy(), "filter": "url ~ hello" }));
    assert!(!err, "{x}");
    assert!(std::fs::read_to_string(&har).unwrap().contains("/hello"));
    let (_, err) = tool(addr, "export_archive", json!({ "path": har.to_string_lossy() }));
    assert!(err, "existing files are not overwritten");
    let (c, _) = tool(addr, "clear_sessions", json!({ "filter": "status == 418" }));
    assert_eq!(c["removed"], 1);

    // --- Disabling stops the server
    let mut s = core.settings();
    s.mcp.enabled = false;
    core.update_settings(s).unwrap();
    mcp.apply(&core);
    assert!(!mcp.status().running);
    assert!(TcpStream::connect(addr).is_err());
    core.shutdown();
}
