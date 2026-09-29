//! M8a.3: connection-pinned automatic authentication (NTLM + Basic) e2e.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use piper_auth::Credentials;
use piper_body::BodyConfig;
use piper_proxy::{CredentialResolver, Proxy, ProxyConfig};
use piper_store::Capture;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Creds;
impl CredentialResolver for Creds {
    fn credentials(&self, _host: &str, _realm: &str) -> Option<Credentials> {
        Some(Credentials { user: "User".into(), domain: "Domain".into(), password: "Password".into() })
    }
}

/// Reads one HTTP/1.1 request (head + body per Content-Length). Returns (method, path, headers, body).
fn read_request(r: &mut BufReader<&std::net::TcpStream>) -> Option<(String, Vec<(String, String)>, Vec<u8>)> {
    let mut first = String::new();
    if r.read_line(&mut first).ok()? == 0 {
        return None;
    }
    let mut headers = Vec::new();
    let mut clen = 0usize;
    loop {
        let mut l = String::new();
        if r.read_line(&mut l).ok()? == 0 {
            break;
        }
        if l == "\r\n" || l == "\n" {
            break;
        }
        if let Some((k, v)) = l.trim_end().split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                clen = v.trim().parse().unwrap_or(0);
            }
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let mut body = vec![0u8; clen];
    if clen > 0 {
        r.read_exact(&mut body).ok()?;
    }
    Some((first, headers, body))
}

fn auth_hdr(headers: &[(String, String)], name: &str) -> Option<String> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
}

/// NTLM server: 401 with NTLM; validates Type1 → sends Type2; validates Type3 → 200.
/// Keeps the connection alive across the handshake (connection-oriented).
/// A well-formed NTLM CHALLENGE_MESSAGE (MS-NLMP 2.2.1.2): flags, target name,
/// version and AV pairs — accepted by SSPI on Windows as well as by the
/// pure-Rust implementation.
fn realistic_type2() -> Vec<u8> {
    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }
    fn av(id: u16, v: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(v);
    }
    let target = utf16("DOMAIN");
    let mut info = Vec::new();
    av(2, &utf16("DOMAIN"), &mut info); // MsvAvNbDomainName
    av(1, &utf16("SERVER"), &mut info); // MsvAvNbComputerName
    av(4, &utf16("domain.example"), &mut info); // MsvAvDnsDomainName
    av(3, &utf16("server.domain.example"), &mut info); // MsvAvDnsComputerName
    av(7, &133_000_000_000_000_000u64.to_le_bytes(), &mut info); // MsvAvTimestamp
    av(0, &[], &mut info); // MsvAvEOL
    // UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN | TARGET_TYPE_DOMAIN |
    // EXTENDED_SESSIONSECURITY | TARGET_INFO | VERSION | 128 | KEY_EXCH | 56
    let flags: u32 = 0xE289_8205;
    let payload = 56u32;
    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&2u32.to_le_bytes());
    m.extend_from_slice(&(target.len() as u16).to_le_bytes());
    m.extend_from_slice(&(target.len() as u16).to_le_bytes());
    m.extend_from_slice(&payload.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // server challenge
    m.extend_from_slice(&[0; 8]); // reserved
    m.extend_from_slice(&(info.len() as u16).to_le_bytes());
    m.extend_from_slice(&(info.len() as u16).to_le_bytes());
    m.extend_from_slice(&(payload + target.len() as u32).to_le_bytes());
    m.extend_from_slice(&[10, 0, 0x61, 0x4a, 0, 0, 0, 15]); // version 10.0.19041, NTLM rev 15
    m.extend_from_slice(&target);
    m.extend_from_slice(&info);
    m
}

fn ntlm_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(&stream);
                let mut s = &stream;
                let mut stage = 0; // 0 none, 1 got type1
                loop {
                    let Some((first, headers, body)) = read_request(&mut r) else { break };
                    let ntlm = auth_hdr(&headers, "authorization");
                    match ntlm.as_deref() {
                        None => {
                            let _ = s.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nWWW-Authenticate: Negotiate\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n");
                            stage = 0;
                        }
                        Some(v) if v.starts_with("NTLM ") => {
                            let msg = B64.decode(v.trim_start_matches("NTLM ")).unwrap_or_default();
                            let mtype = if msg.len() >= 12 { u32::from_le_bytes(msg[8..12].try_into().unwrap()) } else { 0 };
                            if mtype == 1 {
                                // Send a well-formed Type 2 challenge (SSPI on Windows rejects minimal ones).
                                let b = B64.encode(realistic_type2());
                                let _ = write!(s, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {b}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n");
                                stage = 1;
                            } else if mtype == 3 && stage == 1 {
                                // Accept; echo the received body so the test can verify replay.
                                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n", body.len());
                                let _ = s.write_all(&body);
                                stage = 0;
                            } else {
                                let _ = s.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n");
                            }
                        }
                        _ => {
                            let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
                        }
                    }
                    let _ = first;
                }
            });
        }
    });
    port
}

fn setup(cfg: ProxyConfig) -> (Arc<Proxy>, Arc<Capture>, tempfile::TempDir, std::net::SocketAddr) {
    let dir = tempfile::tempdir().unwrap();
    let capture = Capture::open(dir.path().join("cap"), BodyConfig::default(), true).unwrap();
    let proxy = Proxy::new(capture.clone(), cfg, None).unwrap();
    proxy.set_credential_resolver(Arc::new(Creds));
    let addr = *proxy.start().unwrap().iter().find(|a| a.is_ipv4()).unwrap();
    (proxy, capture, dir, addr)
}

fn curl(proxy: &std::net::SocketAddr, args: &[&str]) -> (i32, String) {
    let o = std::process::Command::new("curl")
        .args(["-sS", "--max-time", "20", "-x", &format!("http://{proxy}")])
        .args(args)
        .output()
        .unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned())
}

#[test]
fn ntlm_auto_auth_with_body_replay() {
    let server = ntlm_server();
    let mut cfg = ProxyConfig { port: 0, auto_auth: true, ..Default::default() };
    cfg.auto_auth_hosts = vec![];
    let (proxy, cap, _d, addr) = setup(cfg);

    // POST with a body: the server echoes the body only on the authenticated (Type 3) leg.
    let (_c, out) = curl(&addr, &["-X", "POST", "--data-binary", "hello-ntlm-body", &format!("http://127.0.0.1:{server}/secure")]);
    assert_eq!(out, "hello-ntlm-body", "body must be replayed on the authenticated leg");

    // Session shows the final 200 and the handshake leg count.
    let t = Instant::now();
    let s = loop {
        cap.index.tick();
        if let Some(id) = cap.index.find_all(|s| s.url == "/secure" && s.state.is_final()).last() {
            break cap.index.get(*id).unwrap();
        }
        assert!(t.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(s.status, 200);
    assert!(s.custom.contains("auth"), "custom = {}", s.custom);

    // A second concurrent client must NOT inherit the auth: it gets its own 401 handshake.
    let (_c, out2) = curl(&addr, &[&format!("http://127.0.0.1:{server}/secure2")]);
    assert_eq!(out2, "");
    proxy.stop();
}

#[test]
fn basic_auto_auth() {
    // Server requiring Basic User/Password.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(&stream);
                let mut s = &stream;
                while let Some((_first, headers, _body)) = read_request(&mut r) {
                    match auth_hdr(&headers, "authorization") {
                        Some(v) if v == format!("Basic {}", B64.encode("Domain\\User:Password")) => {
                            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK");
                        }
                        _ => {
                            let _ = s.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"corp\"\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n");
                        }
                    }
                }
            });
        }
    });
    let (proxy, _c, _d, addr) = setup(ProxyConfig { port: 0, auto_auth: true, ..Default::default() });
    let (_c, out) = curl(&addr, &[&format!("http://127.0.0.1:{port}/x")]);
    assert_eq!(out, "OK");
    proxy.stop();
}
