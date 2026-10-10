//! `quena-cli mcp-tap`: an MCP server over stdio is passed through unchanged and its exchanges
//! are written to the data folder.

#[cfg(unix)]
#[test]
fn stdio_server_is_passed_through_and_recorded() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("python3 missing: skipped");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = dir.path().join("server.py");
    std::fs::write(
        &server,
        "import sys, json\nfor line in sys.stdin:\n    m = json.loads(line)\n    if 'id' in m:\n        print(json.dumps({'jsonrpc': '2.0', 'id': m['id'], 'result': {'echo': m['method']}}), flush=True)\n",
    )
    .unwrap();
    let data = dir.path().join("data");
    let mut c = Command::new(env!("CARGO_BIN_EXE_quena-cli"))
        .args(["mcp-tap", "--name", "echo", "--data-dir", data.to_str().unwrap(), "--", "python3", server.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").unwrap();
    let out = c.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "{\"jsonrpc\": \"2.0\", \"id\": 1, \"result\": {\"echo\": \"tools/list\"}}\n", "passed through unchanged");
    let files: Vec<_> = std::fs::read_dir(data.join("mcp-tap")).unwrap().flatten().collect();
    assert_eq!(files.len(), 1);
    let text = std::fs::read_to_string(files[0].path()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    assert!(lines[0].starts_with("{\"tap\":{\"name\":\"echo\""));
    assert!(text.contains("\"method\":\"tools/list\"") && text.contains("\"echo\":\"tools/list\""));
}
