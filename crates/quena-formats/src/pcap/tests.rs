use super::file::tests::{pcap, pcapng};
use super::net::tests::{ACK, FIN, PSH, RST, SYN, ipv4_tcp_ack};
use super::*;
use crate::NoProgress;
use quena_body::BodyConfig;

const T0: Micros = 1_760_000_000_000_000;

/// One TCP connection written packet by packet, 1 ms apart.
struct Flow {
    c: ([u8; 4], u16),
    s: ([u8; 4], u16),
    cseq: u32,
    sseq: u32,
    ts: Micros,
    frames: Vec<(Micros, Vec<u8>)>,
}

impl Flow {
    fn new(cport: u16, sport: u16) -> Flow {
        Flow { c: ([10, 0, 0, 1], cport), s: ([10, 0, 0, 2], sport), cseq: 1000, sseq: 5000, ts: T0, frames: Vec::new() }
    }
    fn at(mut self, ts: Micros) -> Flow {
        self.ts = ts;
        self
    }
    fn push(&mut self, from_client: bool, seq: u32, flags: u8, data: &[u8]) {
        self.ts += 1000;
        // Each side acknowledges everything the other one sent, captured or not.
        let f = if from_client { ipv4_tcp_ack(self.c, self.s, seq, self.sseq, flags, data) } else { ipv4_tcp_ack(self.s, self.c, seq, self.cseq, flags, data) };
        self.frames.push((self.ts, f));
    }
    fn handshake(&mut self) -> &mut Self {
        self.push(true, self.cseq, SYN, b"");
        self.push(false, self.sseq, SYN | ACK, b"");
        self.cseq += 1;
        self.sseq += 1;
        self
    }
    fn client(&mut self, data: &[u8]) -> &mut Self {
        self.push(true, self.cseq, ACK | PSH, data);
        self.cseq = self.cseq.wrapping_add(data.len() as u32);
        self
    }
    fn server(&mut self, data: &[u8]) -> &mut Self {
        self.push(false, self.sseq, ACK | PSH, data);
        self.sseq = self.sseq.wrapping_add(data.len() as u32);
        self
    }
    fn close(&mut self) -> &mut Self {
        self.push(true, self.cseq, FIN | ACK, b"");
        self.push(false, self.sseq, FIN | ACK, b"");
        self
    }
}

fn load(file: &[u8]) -> (tempfile::TempDir, Arc<Capture>, Result<Vec<SessionId>>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.pcap");
    std::fs::write(&path, file).unwrap();
    let cap = Capture::open(dir.path().join("cap"), BodyConfig::default(), true).unwrap();
    let r = import(&cap, &path, &NoProgress);
    (dir, cap, r)
}

fn bodies(cap: &Arc<Capture>, id: SessionId) -> (Vec<u8>, Vec<u8>) {
    let (q, s) = cap.bodies_of(id).unwrap();
    (q.read_range(0, 1 << 20).unwrap(), s.read_range(0, 1 << 20).unwrap())
}

#[test]
fn keep_alive_chunked_and_timers() {
    let mut f = Flow::new(50000, 80);
    f.handshake()
        .client(b"GET /a?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .server(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel")
        .server(b"lo\r\n6;x=y\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n")
        .client(b"POST /b HTTP/1.1\r\nHost: example.com\r\nContent-Length: 7\r\n\r\n{\"a\":")
        .client(b"1}")
        .server(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")
        .close();
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let ids = ids.unwrap();
    assert_eq!(ids.len(), 2);
    let a = cap.detail(ids[0]).unwrap();
    assert_eq!(a.request.url, "http://example.com/a?x=1");
    assert_eq!(a.response.as_ref().unwrap().status, 200);
    assert_eq!(bodies(&cap, ids[0]).1, b"hello world");
    assert_eq!(a.summary.state, SessionState::Done);
    assert!(a.summary.has_flag(flags::IMPORTED));
    assert_eq!(a.connection.client_addr.as_deref(), Some("10.0.0.1:50000"));
    assert_eq!(a.connection.server_addr.as_deref(), Some("10.0.0.2:80"));
    assert_eq!(a.timers.tcp_connect_ms, Some(1));
    assert_eq!(a.timers.client_begin_request, Some(T0 + 3000));
    assert_eq!(a.timers.client_done_response, Some(T0 + 5000));
    assert!(!a.connection.server_conn_reused);
    let b = cap.detail(ids[1]).unwrap();
    assert_eq!(b.request.method, "POST");
    assert_eq!(bodies(&cap, ids[1]), (b"{\"a\":1}".to_vec(), b"ok".to_vec()));
    assert!(b.connection.server_conn_reused);
    assert_eq!(b.connection.client_conn_id, a.connection.client_conn_id);
    assert_eq!(b.timers.tcp_connect_ms, None);
}

#[test]
fn pipelining_head_continue_and_close_delimited() {
    let mut f = Flow::new(50001, 8080);
    f.handshake()
        .client(b"HEAD /h HTTP/1.1\r\nHost: h\r\n\r\nGET /n HTTP/1.1\r\nHost: h\r\n\r\n")
        .server(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\nHTTP/1.1 304 Not Modified\r\n\r\n")
        .client(b"PUT /p HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n")
        .server(b"HTTP/1.1 100 Continue\r\n\r\n")
        .client(b"abc")
        .server(b"HTTP/1.0 200 OK\r\n\r\nuntil the end")
        .close();
    let (_d, cap, ids) = load(&pcapng(1, &f.frames));
    let ids = ids.unwrap();
    let urls: Vec<String> = ids.iter().map(|i| cap.detail(*i).unwrap().request.url).collect();
    assert_eq!(urls, ["http://h/h", "http://h/n", "http://h/p"]);
    assert_eq!(cap.detail(ids[1]).unwrap().response.unwrap().status, 304);
    let p = cap.detail(ids[2]).unwrap();
    assert_eq!(p.response.unwrap().status, 200);
    assert_eq!(bodies(&cap, ids[2]), (b"abc".to_vec(), b"until the end".to_vec()));
    assert_eq!(p.summary.state, SessionState::Done);
}

#[test]
fn reordered_retransmitted_and_missing_segments() {
    let mut f = Flow::new(50002, 80);
    f.handshake().client(b"GET / HTTP/1.1\r\nHost: r\r\n\r\n");
    let s0 = f.sseq;
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
    f.push(false, s0 + head.len() as u32 + 5, ACK, b"56789"); // early
    f.push(false, s0, ACK, head);
    f.push(false, s0, ACK, head); // retransmission
    f.push(false, s0 + head.len() as u32, ACK, b"01234");
    f.sseq = s0 + head.len() as u32 + 10;
    // Second exchange: 4 body bytes never captured.
    f.client(b"GET /2 HTTP/1.1\r\nHost: r\r\n\r\n");
    let s1 = f.sseq;
    let head2 = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n";
    f.push(false, s1, ACK, head2);
    f.push(false, s1 + head2.len() as u32 + 4, ACK, b"wxyz");
    f.sseq = s1 + head2.len() as u32 + 8;
    f.close();
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let ids = ids.unwrap();
    assert_eq!(ids.len(), 2);
    assert_eq!(bodies(&cap, ids[0]).1, b"0123456789");
    assert_eq!(cap.detail(ids[0]).unwrap().summary.state, SessionState::Done);
    let d = cap.detail(ids[1]).unwrap();
    assert_eq!(bodies(&cap, ids[1]).1, b"wxyz");
    assert_eq!(d.summary.state, SessionState::Aborted);
    assert!(d.error.unwrap().contains("4 bytes of the response body are missing"), "error");
}

#[test]
fn picked_up_mid_connection() {
    let mut f = Flow::new(50003, 80);
    // No handshake; the capture starts in the middle of a response body, the server's segment first.
    f.server(b"rest of an earlier body\r\n");
    f.client(b"GET /next HTTP/1.1\r\nHost: m\r\n\r\n");
    f.server(b"HTTP/1.1 204 No Content\r\n\r\n");
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let ids = ids.unwrap();
    assert_eq!(ids.len(), 1);
    let d = cap.detail(ids[0]).unwrap();
    assert_eq!(d.request.url, "http://m/next");
    assert_eq!(d.connection.client_addr.as_deref(), Some("10.0.0.1:50003"));
    assert_eq!(d.response.unwrap().status, 204);
}

#[test]
fn websocket_frames() {
    let mut f = Flow::new(50004, 80);
    f.handshake()
        .client(b"GET /ws HTTP/1.1\r\nHost: w\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        .server(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x02hi");
    let key = [1u8, 2, 3, 4];
    let masked: Vec<u8> = b"hello".iter().enumerate().map(|(i, b)| b ^ key[i & 3]).collect();
    f.client(&[&[0x81, 0x85][..], &key, &masked].concat());
    f.server(&[0x88, 0x00]).close();
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let ids = ids.unwrap();
    assert_eq!(ids.len(), 1);
    let d = cap.detail(ids[0]).unwrap();
    assert_eq!(d.summary.kind, SessionKind::WebSocket);
    assert_eq!(d.response.unwrap().status, 101);
    let log = bodies(&cap, ids[0]).1;
    // dir opcode fin rsv ts(8) len(4) payload
    assert_eq!(&log[..4], &[1, 1, 1, 0]);
    assert_eq!(&log[16..18], b"hi");
    assert_eq!(&log[18..22], &[0, 1, 1, 0]);
    assert_eq!(&log[34..39], b"hello");
    assert_eq!(log[40], 8); // close
}

fn h2_frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let l = payload.len() as u32;
    let mut f = vec![(l >> 16) as u8, (l >> 8) as u8, l as u8, ty, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

#[test]
fn http2_cleartext() {
    let mut enc = fluke_hpack::Encoder::new();
    let req = enc.encode(vec![(&b":method"[..], &b"POST"[..]), (b":scheme", b"http"), (b":authority", b"api.test:8080"), (b":path", b"/v1"), (b"x-id", b"7")]);
    let req3 = enc.encode(vec![(&b":method"[..], &b"GET"[..]), (b":scheme", b"http"), (b":authority", b"api.test:8080"), (b":path", b"/v3")]);
    let mut senc = fluke_hpack::Encoder::new();
    let resp = senc.encode(vec![(&b":status"[..], &b"200"[..]), (b"content-type", b"application/json")]);
    let mut client = h2::PREFACE.to_vec();
    client.extend(h2_frame(4, 0, 0, &[]));
    client.extend(h2_frame(1, END_HEADERS_T, 1, &req[..3]));
    let mut f = Flow::new(50005, 8080);
    f.handshake().client(&client);
    // Header block split over CONTINUATION, then a DATA frame with padding.
    f.client(&[h2_frame(9, 0x4, 1, &req[3..]), h2_frame(0, 0x1 | 0x8, 1, &[2, b'{', b'}', 0, 0])].concat());
    f.client(&h2_frame(1, 0x4 | 0x1, 3, &req3));
    f.server(&[h2_frame(4, 0, 0, &[]), h2_frame(1, 0x4, 1, &resp), h2_frame(0, 0x1, 1, b"[1]"), h2_frame(3, 0, 3, &8u32.to_be_bytes())].concat());
    f.close();
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let ids = ids.unwrap();
    assert_eq!(ids.len(), 2);
    let a = cap.detail(ids[0]).unwrap();
    assert_eq!(a.request.url, "http://api.test:8080/v1");
    assert_eq!(a.request.version, HttpVersion::Http2);
    assert_eq!(a.request.headers.get("x-id"), Some("7"));
    assert_eq!(a.connection.stream_id, Some(1));
    let r = a.response.unwrap();
    assert_eq!((r.status, r.reason.as_str()), (200, "OK"));
    assert_eq!(bodies(&cap, ids[0]), (b"{}".to_vec(), b"[1]".to_vec()));
    let b = cap.detail(ids[1]).unwrap();
    assert_eq!(b.request.url, "http://api.test:8080/v3");
    assert!(b.error.unwrap().contains("CANCEL"));
}

/// HEADERS without END_HEADERS (continued).
const END_HEADERS_T: u8 = 0;

#[test]
fn tls_is_a_tunnel() {
    let mut f = Flow::new(50006, 443);
    f.handshake().client(&tls::tests::client_hello_record("secure.test")).server(&tls::tests::server_hello_record()).client(&[0x17, 3, 3, 0, 2, 9, 9]).close();
    // The same through an explicit proxy.
    let mut p = Flow::new(50007, 3128).at(T0 + 10_000_000);
    p.handshake()
        .client(b"CONNECT other.test:443 HTTP/1.1\r\nHost: other.test:443\r\n\r\n")
        .server(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .client(&tls::tests::client_hello_record("other.test"))
        .server(&tls::tests::server_hello_record())
        .close();
    let mut frames = f.frames.clone();
    frames.extend(p.frames.clone());
    let (_d, cap, ids) = load(&pcap(1, &frames));
    let ids = ids.unwrap();
    assert_eq!(ids.len(), 2);
    let a = cap.detail(ids[0]).unwrap();
    assert_eq!(a.summary.kind, SessionKind::Tunnel);
    assert_eq!(a.request.url, "secure.test:443");
    let tls = a.connection.client_tls.unwrap();
    assert_eq!((tls.version.as_str(), tls.alpn.as_deref()), ("TLS 1.3", Some("h2")));
    assert!(a.summary.custom.starts_with('↑'));
    let b = cap.detail(ids[1]).unwrap();
    assert_eq!(b.summary.kind, SessionKind::Tunnel);
    assert_eq!(b.request.url, "other.test:443");
    assert_eq!(b.response.unwrap().status, 200);
    assert_eq!(b.connection.client_tls.unwrap().sni.as_deref(), Some("other.test"));
}

#[test]
fn reset_and_no_response() {
    let mut f = Flow::new(50008, 80);
    f.handshake().client(b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    f.push(false, f.sseq, RST | ACK, b"");
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let d = cap.detail(ids.unwrap()[0]).unwrap();
    assert_eq!(d.summary.state, SessionState::Aborted);
    assert_eq!(d.error.as_deref(), Some("no response in the capture"));
}

#[test]
fn not_a_capture_or_no_http() {
    let (_d, _cap, r) = load(b"{\"log\":{}}");
    assert!(matches!(r, Err(FormatError::Invalid(_))));
    let mut f = Flow::new(50009, 25);
    f.handshake().server(b"220 mail ESMTP\r\n").client(b"EHLO x\r\n").close();
    let (_d, _cap, r) = load(&pcap(1, &f.frames));
    let Err(FormatError::Invalid(msg)) = r else { panic!() };
    assert!(msg.contains("no HTTP traffic") && msg.contains("1 connection(s) not HTTP"), "{msg}");
}

impl Flow {
    /// A packet of which the capture kept only `keep` payload bytes (snapshot length).
    fn server_cut(&mut self, data: &[u8], keep: usize) -> &mut Self {
        self.ts += 1000;
        let f = ipv4_tcp_ack(self.s, self.c, self.sseq, self.cseq, ACK | PSH, data);
        self.frames.push((self.ts, f[..f.len() - (data.len() - keep)].to_vec()));
        self.sseq = self.sseq.wrapping_add(data.len() as u32);
        self
    }
    /// Bytes sent but missing from the capture.
    fn lost(&mut self, from_client: bool, n: usize) -> &mut Self {
        if from_client {
            self.cseq = self.cseq.wrapping_add(n as u32);
        } else {
            self.sseq = self.sseq.wrapping_add(n as u32);
        }
        self
    }
}

#[test]
fn lost_response_keeps_the_pairing() {
    let mut f = Flow::new(50010, 80);
    let resp1 = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none";
    f.handshake()
        .client(b"GET /1 HTTP/1.1\r\nHost: l\r\n\r\nGET /2 HTTP/1.1\r\nHost: l\r\n\r\n")
        .lost(false, resp1.len())
        .client(b"") // the client acknowledges the response the capture missed
        .server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\ntwo")
        .close();
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let ids = ids.unwrap();
    assert_eq!(ids.len(), 2);
    let a = cap.detail(ids[0]).unwrap();
    assert!(a.response.is_none());
    assert!(a.error.unwrap().contains("the response is missing in the capture"));
    let b = cap.detail(ids[1]).unwrap();
    assert_eq!(b.request.url, "http://l/2");
    assert_eq!(b.response.unwrap().status, 404);
    assert_eq!(bodies(&cap, ids[1]).1, b"two");
}

#[test]
fn lost_request_keeps_the_pairing() {
    let mut f = Flow::new(50011, 80);
    f.handshake()
        .lost(true, 30) // the first request
        .client(b"GET /2 HTTP/1.1\r\nHost: l\r\n\r\n")
        .server(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none")
        .server(b"HTTP/1.1 201 Created\r\nContent-Length: 3\r\n\r\ntwo")
        .close();
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let ids = ids.unwrap();
    assert_eq!(ids.len(), 1);
    let d = cap.detail(ids[0]).unwrap();
    assert_eq!(d.request.url, "http://l/2");
    assert_eq!(d.response.unwrap().status, 201);
    assert_eq!(bodies(&cap, ids[0]).1, b"two");
}

#[test]
fn upgrade_without_its_request() {
    let mut f = Flow::new(50012, 80);
    // The capture starts after the upgrade request.
    f.server(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x02hi").client(&[0x81, 0x80, 0, 0, 0, 0]).close();
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let d = cap.detail(ids.unwrap()[0]).unwrap();
    assert_eq!(d.summary.kind, SessionKind::WebSocket);
    assert_eq!(d.request.url, "http://10.0.0.2/");
    assert_eq!(d.error.as_deref(), Some("the request is not in the capture"));
    assert_eq!(&bodies(&cap, d.summary.id).1[16..18], b"hi");
}

#[test]
fn snapshot_length_and_damaged_end() {
    let mut f = Flow::new(50013, 80);
    let body = [b'x'; 100];
    f.handshake().client(b"GET /big HTTP/1.1\r\nHost: s\r\n\r\n");
    f.server_cut(&[&b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"[..], &body].concat(), 60).close();
    let mut file = pcap(1, &f.frames);
    file.extend_from_slice(&[0; 8]);
    file.extend_from_slice(&u32::MAX.to_le_bytes()); // damaged record: absurd length
    file.extend_from_slice(&u32::MAX.to_le_bytes());
    let (_d, cap, ids) = load(&file);
    let d = cap.detail(ids.unwrap()[0]).unwrap();
    assert_eq!(d.response.unwrap().status, 200);
    assert_eq!(bodies(&cap, d.summary.id).1, [b'x'; 20]);
    assert!(d.error.unwrap().contains("80 bytes of the response body are missing"));
}

#[test]
fn tunnel_starts_with_its_first_packet() {
    let mut f = Flow::new(50014, 443);
    let ch = tls::tests::client_hello_record("split.test");
    f.handshake().client(&ch[..1]).client(&ch[1..]).close();
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let d = cap.detail(ids.unwrap()[0]).unwrap();
    assert_eq!(d.request.url, "split.test:443");
    assert_eq!(d.timers.client_begin_request, Some(T0 + 3000));
}

#[test]
fn lost_upgrade_response_releases_the_client() {
    let mut f = Flow::new(50015, 80);
    f.handshake()
        .client(b"GET /ws HTTP/1.1\r\nHost: u\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        .lost(false, 40) // the refusal (a plain 200) is not in the capture
        .client(b"GET /next HTTP/1.1\r\nHost: u\r\n\r\n")
        .server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .close();
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let ids = ids.unwrap();
    assert_eq!(ids.len(), 2);
    assert!(cap.detail(ids[0]).unwrap().error.unwrap().contains("the response is missing"));
    let b = cap.detail(ids[1]).unwrap();
    assert_eq!((b.request.url.as_str(), b.response.unwrap().status), ("http://u/next", 200));
}

#[test]
fn picked_up_in_a_long_download() {
    let mut f = Flow::new(50016, 80);
    let chunk = vec![b'z'; 40_000];
    f.server(&chunk).server(&chunk); // the rest of a response that started before the capture
    f.client(b"GET /after HTTP/1.1\r\nHost: d\r\n\r\n").server(b"HTTP/1.1 204 No Content\r\n\r\n");
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let ids = ids.unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(cap.detail(ids[0]).unwrap().request.url, "http://d/after");
}

#[test]
fn any_method_and_data_in_the_syn() {
    let mut f = Flow::new(50017, 80);
    let req = b"MKCALENDAR /cal HTTP/1.1\r\nHost: c\r\n\r\n";
    // TCP Fast Open: the request rides on the SYN.
    f.push(true, f.cseq, SYN, req);
    f.cseq += 1 + req.len() as u32;
    f.push(false, f.sseq, SYN | ACK, b"");
    f.sseq += 1;
    f.server(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n").close();
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let d = cap.detail(ids.unwrap()[0]).unwrap();
    assert_eq!((d.request.method.as_str(), d.request.url.as_str()), ("MKCALENDAR", "http://c/cal"));
    assert_eq!(d.response.unwrap().status, 201);
}

#[test]
fn http2_stream_promised_twice() {
    let mut cenc = fluke_hpack::Encoder::new();
    let req = cenc.encode(vec![(&b":method"[..], &b"GET"[..]), (b":scheme", b"http"), (b":authority", b"p"), (b":path", b"/")]);
    let mut senc = fluke_hpack::Encoder::new();
    let promise = senc.encode(vec![(&b":method"[..], &b"GET"[..]), (b":scheme", b"http"), (b":authority", b"p"), (b":path", b"/style.css")]);
    let promise2 = senc.encode(vec![(&b":method"[..], &b"GET"[..]), (b":scheme", b"http"), (b":authority", b"p"), (b":path", b"/app.js")]);
    let resp = senc.encode(vec![(&b":status"[..], &b"200"[..])]);
    let mut client = h2::PREFACE.to_vec();
    client.extend(h2_frame(1, 0x4 | 0x1, 1, &req));
    let pp = |block: &[u8]| [&2u32.to_be_bytes()[..], block].concat();
    let mut f = Flow::new(50018, 80);
    f.handshake().client(&client);
    f.server(&[h2_frame(5, 0x4, 1, &pp(&promise)), h2_frame(5, 0x4, 1, &pp(&promise2))].concat());
    f.server(&[h2_frame(1, 0x4 | 0x1, 1, &resp), h2_frame(1, 0x4, 2, &resp), h2_frame(0, 0x1, 2, b"js")].concat());
    f.close();
    let (_d, cap, ids) = load(&pcap(1, &f.frames));
    let ids = ids.unwrap();
    let by_url = |u: &str| ids.iter().map(|i| cap.detail(*i).unwrap()).find(|d| d.request.url.ends_with(u)).unwrap();
    assert_eq!(ids.len(), 3);
    assert_eq!(by_url("/style.css").error.as_deref(), Some("the server announced this stream again"));
    let js = by_url("/app.js");
    assert_eq!(js.response.unwrap().status, 200);
    assert_eq!(bodies(&cap, js.summary.id).1, b"js");
    assert!(by_url("p/").error.is_none());
}

#[test]
fn macos_packet_tap() {
    let mut f = Flow::new(50019, 8080);
    f.handshake().client(b"GET /lo HTTP/1.1\r\nHost: localhost:8080\r\n\r\n").server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").close();
    // Each Ethernet frame becomes a loopback frame (NULL) inside a packet tap header.
    let frames: Vec<(Micros, Vec<u8>)> = f
        .frames
        .iter()
        .map(|(ts, e)| {
            let mut tap = vec![0u8; 108];
            tap[0..4].copy_from_slice(&108u32.to_le_bytes());
            tap[4..8].copy_from_slice(&1u32.to_le_bytes());
            tap[8..12].copy_from_slice(&0u32.to_le_bytes());
            tap.extend_from_slice(&2u32.to_le_bytes());
            tap.extend_from_slice(&e[14..]);
            (*ts, tap)
        })
        .collect();
    let (_d, cap, ids) = load(&pcapng(258, &frames));
    let d = cap.detail(ids.unwrap()[0]).unwrap();
    assert_eq!(d.request.url, "http://localhost:8080/lo");
}
