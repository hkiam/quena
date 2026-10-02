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
    let files = dir.path().join("agent");
    std::fs::create_dir(&files).unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        serde_json::to_string(&json!({
            "proxy": { "port": 18876, "actAsSystemProxy": false, "captureOnStartup": false, "useSystemUpstream": false },
            "mcp": { "enabled": true, "port": 0, "token": TOKEN, "filesDir": files.to_string_lossy() }
        }))
        .unwrap(),
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

    // --- Read-only: write tools are marked and refused
    let tools = rpc(addr, "tools/list", json!({}));
    let send = tools["result"]["tools"].as_array().unwrap().iter().find(|t| t["name"] == "send_request").unwrap().clone();
    assert!(send["description"].as_str().unwrap().starts_with("[Needs full control"));
    let port = json_server();
    let (msg, err) = tool(addr, "send_request", json!({ "method": "GET", "url": format!("http://127.0.0.1:{port}/a") }));
    assert!(err && msg.as_str().unwrap().contains("full control"), "{msg}");

    // --- Full control: send a request, read it back
    set_access(&core, true);
    let (s, err) = tool(addr, "send_request", json!({ "method": "GET", "url": format!("http://127.0.0.1:{port}/hello"), "headers": { "X-Agent": "yes", "Authorization": "Bearer s3cr3t-value" } }));
    assert!(!err, "{s}");
    assert_eq!(s["response"]["status"], 200);
    assert_eq!(s["response"]["body"]["text"], r#"{"path":"/hello","items":[1,2]}"#);
    let id = s["session"]["id"].as_u64().unwrap();
    assert!(s["request"]["headers"].as_array().unwrap().iter().any(|h| h[0] == "X-Agent"));
    // Secrets are replaced by default ...
    assert!(!s.to_string().contains("s3cr3t-value"), "{s}");
    assert!(s["redacted"].is_string());
    // ... and shown only when the user allows it.
    let mut st = core.settings();
    st.mcp.include_secrets = true;
    core.update_settings(st).unwrap();
    let (s2, _) = tool(addr, "get_session", json!({ "id": id }));
    assert!(s2.to_string().contains("s3cr3t-value") && s2["redacted"].is_null());
    let mut st = core.settings();
    st.mcp.include_secrets = false;
    core.update_settings(st).unwrap();

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
    // Files only from the agents' folder.
    let (e, err) = tool(addr, "add_mock_rule", json!({ "match": "x", "action": dir.path().join("settings.json").to_string_lossy() }));
    assert!(err && e.as_str().unwrap().contains("outside"), "{e}");
    let (e, err) = tool(addr, "add_mock_rule", json!({ "match": "x", "action": "dir:/" }));
    assert!(err && e.as_str().unwrap().contains("outside"), "{e}");
    std::fs::write(files.join("answer.json"), "{}").unwrap();
    let (r, err) = tool(addr, "add_mock_rule", json!({ "match": "x", "action": files.join("answer.json").to_string_lossy() }));
    assert!(!err, "{r}");
    tool(addr, "remove_mock_rule", json!({ "id": r["id"] }));

    // --- Rewrite rules: preview on a captured session, then live
    let rule = json!({ "match": "/rw", "ops": [{ "op": "jsonAppendAll" }, { "op": "setHeader", "name": "X-Rw", "value": "1" }] });
    let (p, err) = tool(addr, "preview_rewrite", json!({ "rule": rule, "id": id }));
    assert!(!err, "{p}");
    assert_eq!(p["changed"], true);
    assert_eq!(p["text"], r#"{"path":"/hello","items":[1,2,null]}"#);
    let (r, err) = tool(addr, "add_rewrite_rule", rule);
    assert!(!err, "{r}");
    let rw = r["id"].as_u64().unwrap();
    let (s, _) = tool(addr, "send_request", json!({ "method": "GET", "url": format!("http://127.0.0.1:{port}/rw") }));
    assert_eq!(s["response"]["body"]["text"], r#"{"path":"/rw","items":[1,2,null]}"#);
    assert!(s["response"]["headers"].as_array().unwrap().iter().any(|h| h[0] == "X-Rw"));
    assert!(s["session"]["flags"].as_array().unwrap().contains(&json!("tampered")));
    let (l, _) = tool(addr, "list_rewrite_rules", json!({}));
    assert_eq!(l["rules"][0]["hits"], 1);
    let (_, err) = tool(addr, "update_rewrite_rule", json!({ "id": rw, "enabled": false }));
    assert!(!err);
    let (s, _) = tool(addr, "send_request", json!({ "method": "GET", "url": format!("http://127.0.0.1:{port}/rw") }));
    assert_eq!(s["response"]["body"]["text"], r#"{"path":"/rw","items":[1,2]}"#);
    let (e, err) = tool(addr, "add_rewrite_rule", json!({ "match": "*", "ops": [{ "op": "jsonSet", "path": "no-dollar", "value": 1 }] }));
    assert!(err && e.as_str().unwrap().contains("JSONPath"), "{e}");
    let (_, err) = tool(addr, "remove_rewrite_rule", json!({ "id": rw }));
    assert!(!err);

    // --- .http collections
    let http = files.join("api.http");
    std::fs::write(&http, "### first\nGET {{base}}/coll/one\nX-Token: {{token}}\n\n### second\nPOST {{base}}/coll/two\nContent-Type: application/json\n\n{\"n\": 1}\n").unwrap();
    std::fs::write(files.join("http-client.env.json"), format!(r#"{{"local":{{"base":"http://127.0.0.1:{port}"}}}}"#)).unwrap();
    std::fs::write(files.join("http-client.private.env.json"), r#"{"local":{"token":"t0"}}"#).unwrap();
    let (l, err) = tool(addr, "list_http_requests", json!({ "path": "api.http", "env": "local" }));
    assert!(!err, "{l}");
    assert_eq!(l["environments"], json!(["local"]));
    assert_eq!(l["requests"][1]["url"], format!("http://127.0.0.1:{port}/coll/two"));
    let (r, err) = tool(addr, "run_http_file", json!({ "path": http.to_string_lossy(), "env": "local" }));
    assert!(!err, "{r}");
    assert_eq!(r["results"][0]["status"], 200);
    assert_eq!(r["results"][1]["name"], "second");
    let first = r["results"][0]["session"].as_u64().unwrap();
    let (s, _) = tool(addr, "get_session", json!({ "id": first }));
    // Sent with the private value, shown redacted.
    let token = s["request"]["headers"].as_array().unwrap().iter().find(|h| h[0] == "X-Token").unwrap()[1].as_str().unwrap().to_string();
    assert_ne!(token, "t0");
    assert_eq!(core.capture().detail(first).unwrap().request.headers.get("x-token"), Some("t0"));
    let (e, err) = tool(addr, "run_http_file", json!({ "path": dir.path().join("elsewhere.http").to_string_lossy() }));
    assert!(err && e.as_str().unwrap().contains("outside"), "{e}");
    let (r, _) = tool(addr, "run_http_file", json!({ "path": http.to_string_lossy() }));
    assert!(r["results"][0]["error"].as_str().unwrap().contains("unknown variable {{base}}"), "{r}");
    let (r, err) = tool(addr, "run_http_file", json!({ "path": http.to_string_lossy(), "env": "nope" }));
    assert!(err && r.as_str().unwrap().contains("known: local"), "{r}");
    // Captured sessions back to a file, and run again from it.
    let out_dir = files.join("out");
    std::fs::create_dir(&out_dir).unwrap();
    let written = out_dir.join("captured.http");
    let (w, err) = tool(addr, "sessions_to_http_file", json!({ "path": written.to_string_lossy(), "filter": "url ~ /coll/" }));
    assert!(!err, "{w}");
    assert_eq!(w["requests"], 2);
    let text = std::fs::read_to_string(&written).unwrap();
    assert!(text.contains("POST {{host}}/coll/two") && text.contains("{\"n\": 1}"), "{text}");
    let (r, _) = tool(addr, "run_http_file", json!({ "path": written.to_string_lossy(), "env": "captured", "names": ["line:2"] }));
    assert_eq!(r["results"].as_array().unwrap().len(), 1);
    assert_eq!(r["results"][0]["status"], 200, "{r}");

    // --- Search, statistics, export, clear
    let (f, _) = tool(addr, "search_sessions", json!({ "text": "hello", "examine": "bodies" }));
    assert_eq!(f["total"], 1);
    let (st, _) = tool(addr, "statistics", json!({}));
    assert!(st["sessions"].as_u64().unwrap() >= 2);
    let har = files.join("out.har");
    let (x, err) = tool(addr, "export_archive", json!({ "path": har.to_string_lossy(), "filter": "url ~ hello" }));
    assert!(!err, "{x}");
    let har_text = std::fs::read_to_string(&har).unwrap();
    assert!(har_text.contains("/hello"));
    // Agents read files with their own tools: exports are redacted as well.
    assert!(!har_text.contains("s3cr3t-value"), "secret in the export");
    assert!(!files.join("out").join("http-client.private.env.json").exists(), "no private environment while redacting");
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
