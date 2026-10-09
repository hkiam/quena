//! `quena-cli reverse`: a headless reverse proxy that records and saves on exit.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_quena-cli"));
    c.env("QUENA_CACHE_DIR", std::env::temp_dir().join("quena-cli-test-cache"));
    c
}

/// HTTP/1.1 server answering every request with `hello <path>`.
fn target() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut first = String::new();
                let _ = r.read_line(&mut first);
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                let body = format!("hello {}", first.split_whitespace().nth(1).unwrap_or(""));
                let mut s = s;
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            });
        }
    });
    port
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// GET through the reverse port, retried until it listens.
fn get(port: u16, path: &str) -> String {
    let t = Instant::now();
    loop {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            write!(s, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").unwrap();
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            // Listening already, but closed before answering (still starting): try again.
            if out.starts_with("HTTP/") {
                return out;
            }
        }
        assert!(t.elapsed() < Duration::from_secs(20), "reverse port {port} never listened");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn records_and_saves_after_max_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let t = target();
    let port = free_port();
    let har = dir.path().join("run.har");
    let child = bin()
        .args(["reverse", "--route", &format!("api={port}=http://127.0.0.1:{t}/base"), "--max-sessions", "2", "--save", har.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let one = get(port, "/one");
    assert!(one.ends_with("hello /base/one"), "{one}");
    let two = get(port, "/two?x=1");
    assert!(two.ends_with("hello /base/two?x=1"), "{two}");
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stdout.contains(&format!("GET     http://127.0.0.1:{t}/base/one  [api]")), "{stdout}");
    assert!(stderr.contains(&format!("api 127.0.0.1:{port} → http://127.0.0.1:{t}/base")), "{stderr}");
    let saved = std::fs::read_to_string(&har).unwrap();
    assert!(saved.contains("/base/two?x=1"), "{saved}");
}

#[cfg(unix)]
#[test]
fn sigint_stops_and_still_saves() {
    let dir = tempfile::tempdir().unwrap();
    let t = target();
    let port = free_port();
    let saz = dir.path().join("run.saz");
    let child = bin()
        .args(["reverse", "-q", "--route", &format!("{port}=http://127.0.0.1:{t}"), "--save", saz.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(get(port, "/x").ends_with("hello /x"));
    // Give the session a moment to complete before stopping.
    std::thread::sleep(Duration::from_millis(300));
    Command::new("kill").args(["-INT", &child.id().to_string()]).status().unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.stdout.is_empty(), "-q prints no access log");
    assert!(std::fs::metadata(&saz).unwrap().len() > 0);
}

#[test]
fn usage_errors() {
    let run = |args: &[&str]| bin().args(args).output().unwrap();
    // Bad route syntax, bad target, unsupported save format.
    assert_eq!(run(&["reverse", "--route", "nonsense"]).status.code(), Some(2));
    assert_eq!(run(&["reverse", "--route", "8080=api.example.com"]).status.code(), Some(2));
    assert_eq!(run(&["reverse", "--route", "8080=http://x", "--save", "out.txt"]).status.code(), Some(2));
    // A port that is taken.
    let busy = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = busy.local_addr().unwrap().port();
    let out = run(&["reverse", "--route", &format!("{p}=http://127.0.0.1:1"), "--duration", "1"]);
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn path_routes_and_socks() {
    let dir = tempfile::tempdir().unwrap();
    let (web, auth) = (target(), target());
    let (port, socks) = (free_port(), free_port());
    let har = dir.path().join("run.har");
    let child = bin()
        .args([
            "serve",
            "--route",
            &format!("web={port}=http://127.0.0.1:{web}"),
            "--path",
            &format!("{port}/auth=http://127.0.0.1:{auth}/sso"),
            "--strip-prefix",
            "--socks",
            &socks.to_string(),
            "--max-sessions",
            "3",
            "--save",
            har.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(get(port, "/page").ends_with("hello /page"));
    assert!(get(port, "/auth/login").ends_with("hello /sso/login"));
    // SOCKS5 by hand: no auth, CONNECT to the target by IP, then plain HTTP.
    let mut s = TcpStream::connect(("127.0.0.1", socks)).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut b = [0u8; 2];
    s.read_exact(&mut b).unwrap();
    assert_eq!(b, [5, 0]);
    let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
    req.extend_from_slice(&web.to_be_bytes());
    s.write_all(&req).unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).unwrap();
    assert_eq!(rep[1], 0);
    write!(s, "GET /socks HTTP/1.1\r\nHost: 127.0.0.1:{web}\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.ends_with("hello /socks"), "{out}");
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("[SOCKS5]") && stdout.contains("/sso/login  [web]"), "{stdout}");
}

#[test]
fn path_needs_a_route_on_its_port() {
    let out = bin().args(["reverse", "--route", "8080=http://x", "--path", "9090/a=http://y"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no --route on port 9090"));
}

#[test]
fn remap_sends_a_name_to_another_address() {
    let t = target();
    let port = free_port();
    let child = bin()
        .args(["reverse", "-q", "--route", &format!("{port}=http://app.remap.invalid:{t}"), "--remap", "app.remap.invalid=127.0.0.1", "--max-sessions", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(get(port, "/r").ends_with("hello /r"));
    assert!(child.wait_with_output().unwrap().status.success());
    let bad = bin().args(["reverse", "--route", "8080=http://x", "--remap", "nonsense"]).output().unwrap();
    assert_eq!(bad.status.code(), Some(2));
}
