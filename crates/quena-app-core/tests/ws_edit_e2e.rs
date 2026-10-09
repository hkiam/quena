//! WebSocket messages changed on the way (rules script, rewrite rules with the WebSocket
//! phase), logged as edited or dropped, and Socket.IO packets decoded.

use quena_app_core::rewrite::{Op, Phase, RewriteRule, WsDirection};
use quena_app_core::{AppCore, Paths};
use quena_model::wslog::parse_frame;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// Answers the upgrade and echoes every text frame (unmasked, as servers send).
fn echo_ws() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && s.read(&mut b).unwrap_or(0) == 1 {
                    head.push(b[0]);
                }
                let _ = s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n");
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while let Ok(Some((f, n))) = parse_frame(&buf) {
                        buf.drain(..n);
                        if f.opcode == 0x8 {
                            return;
                        }
                        let mut out = vec![0x81, f.payload.len() as u8];
                        out.extend_from_slice(&f.payload);
                        if s.write_all(&out).is_err() {
                            return;
                        }
                    }
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
            });
        }
    });
    port
}

fn masked_text(payload: &[u8]) -> Vec<u8> {
    let key = [9u8, 8, 7, 6];
    let mut f = vec![0x81, 0x80 | payload.len() as u8];
    f.extend_from_slice(&key);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i & 3]));
    f
}

#[test]
fn websocket_messages_are_changed_dropped_and_decoded() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let addr = engine.proxy.listen_addrs().into_iter().find(|a| a.is_ipv4()).unwrap();
    let port = echo_ws();
    let rules = core.rules.clone().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        rules
            .set_script(
                r#"function onWebSocketMessage(m) {
                    if (m.direction === 'up' && m.text === 'secret') m.drop();
                    if (m.direction === 'up' && m.text === 'hello') m.text = 'HELLO';
                }"#
                .into(),
            )
            .await
            .unwrap();
        rules.set_script_enabled(true).await.unwrap();
    });
    // Server → client: JSON inside Socket.IO packets.
    let mut s = rules.rewrite.state();
    s.enabled = true;
    s.rules.push(RewriteRule {
        match_: "/socket.io/".into(),
        phase: Phase::WebSocket,
        direction: WsDirection::Down,
        ops: vec![Op::JsonSet { path: "$[1].text".into(), value: serde_json::json!("changed") }],
        ..Default::default()
    });
    rules.rewrite.set(s).unwrap();

    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(c, "GET http://127.0.0.1:{port}/socket.io/?EIO=4&transport=websocket HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        c.read_exact(&mut b).unwrap();
        head.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
    for m in [&b"secret"[..], b"hello", br#"42["chat",{"text":"hi"}]"#] {
        c.write_all(&masked_text(m)).unwrap();
    }
    // Two echoes arrive: the dropped message never reached the server.
    let mut buf = Vec::new();
    let mut got = Vec::new();
    let mut chunk = [0u8; 1024];
    while got.len() < 2 {
        let n = c.read(&mut chunk).unwrap();
        assert!(n > 0, "connection closed after {got:?}");
        buf.extend_from_slice(&chunk[..n]);
        while let Ok(Some((f, n))) = parse_frame(&buf) {
            buf.drain(..n);
            got.push(String::from_utf8(f.payload).unwrap());
        }
    }
    assert_eq!(got, vec!["HELLO".to_string(), r#"42["chat",{"text":"changed"}]"#.to_string()]);
    drop(c);

    // The log shows what was sent, marked; Socket.IO packets are decoded.
    let id = core.capture().index.find_all(|s| s.url.contains("socket.io"))[0];
    let t = std::time::Instant::now();
    let frames = loop {
        let f = core.ws_frames(id, 0, 100).frames;
        if f.len() >= 5 {
            break f;
        }
        assert!(t.elapsed() < Duration::from_secs(10), "{f:?}");
        std::thread::sleep(Duration::from_millis(50));
    };
    let up: Vec<_> = frames.iter().filter(|f| f.dir == 0).collect();
    assert!(up[0].dropped && up[0].text.as_deref() == Some("secret"), "dropped, logged as the client sent it");
    assert_eq!((up[1].edited, up[1].text.as_deref()), (true, Some("HELLO")));
    assert!(!up[2].edited);
    let ev = up[2].sio.as_ref().unwrap();
    assert_eq!((ev.sio.as_deref(), ev.event.as_deref()), (Some("event"), Some("chat")));
    let down: Vec<_> = frames.iter().filter(|f| f.dir == 1).collect();
    assert_eq!((down[1].edited, down[1].sio.as_ref().unwrap().data.as_deref().unwrap_or("").contains("changed")), (true, true));
    core.shutdown();
}
