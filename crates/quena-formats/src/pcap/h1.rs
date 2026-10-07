//! HTTP/1.x on a reassembled connection: requests and responses paired in order
//! (keep-alive, pipelining), bodies by Content-Length, chunked or until the connection
//! closes. A request that switches protocols (Upgrade, CONNECT) holds the client side
//! back until its response says how the connection goes on.

use super::{CLIENT, Cx, Exchange, SERVER, side_name};
use crate::raw;
use quena_model::{HttpVersion, Micros, RequestHead, ResponseHead, SessionKind, latin1_to_string};
use std::collections::VecDeque;

/// Longest message head accepted.
const MAX_HEAD: usize = 1 << 20;
/// Longest chunk-size or trailer line accepted.
const MAX_LINE: usize = 8192;

/// What the connection becomes after a protocol switch.
pub enum Switch {
    WebSocket,
    H2c,
    /// CONNECT tunnel or another upgrade: bytes are only counted.
    Tunnel,
}

/// A switched connection: the exchange that switched it and the bytes after its heads.
pub struct Upgraded {
    pub to: Switch,
    pub ex: Exchange,
    /// Unparsed bytes of each side (client, server).
    pub rest: [Vec<u8>; 2],
}

enum Chunk {
    Size,
    Data(u64),
    DataEnd,
    Trailer,
}

enum Left {
    Len(u64),
    Chunked(Chunk),
    Close,
}

#[derive(Default)]
enum St {
    #[default]
    Head,
    Body(Left),
    /// Lost track of message boundaries: look for the next start line.
    Resync,
}

#[derive(Default)]
struct Side {
    buf: Vec<u8>,
    st: St,
    /// When the oldest byte in `buf` arrived.
    start: Option<Micros>,
}

#[derive(Default)]
pub struct H1 {
    sides: [Side; 2],
    ex: VecDeque<Exchange>,
    /// The last request asked to switch protocols: client bytes wait for its response.
    hold: bool,
}

/// Index just past the empty line ending a message head.
fn head_end(b: &[u8]) -> Option<usize> {
    let mut i = 0;
    while let Some(p) = b[i..].iter().position(|c| *c == b'\n') {
        let n = i + p;
        match b.get(n + 1) {
            Some(b'\n') => return Some(n + 2),
            Some(b'\r') if b.get(n + 2) == Some(&b'\n') => return Some(n + 3),
            _ => i = n + 1,
        }
    }
    None
}

fn request_line_ok(l: &str) -> bool {
    let mut p = l.split(' ');
    let (Some(m), Some(t), Some(v), None) = (p.next(), p.next(), p.next(), p.next()) else { return false };
    !m.is_empty() && m.len() <= 24 && m.bytes().all(method_char) && !t.is_empty() && (v == "HTTP/1.1" || v == "HTTP/1.0")
}

fn status_line_ok(l: &str) -> bool {
    l.starts_with("HTTP/1.") && l.as_bytes().get(8) == Some(&b' ') && l.len() >= 12 && l.as_bytes()[9..12].iter().all(u8::is_ascii_digit)
}

fn method_char(b: u8) -> bool {
    b.is_ascii_uppercase() || b == b'-' || b == b'_'
}

/// Does `b` begin with an HTTP/1 request line (any method)? `None` while the line is
/// incomplete and could still be one.
pub fn looks_like_request(b: &[u8]) -> Option<bool> {
    if let Some(p) = b.iter().position(|c| *c == b'\n') {
        let line = latin1_to_string(b[..p].strip_suffix(b"\r").unwrap_or(&b[..p]));
        return Some(request_line_ok(&line));
    }
    let method = b.iter().take_while(|c| method_char(**c)).count();
    let plausible = b.len() <= MAX_LINE && (1..=24).contains(&method.max(b.len().min(1))) && (method == b.len() || (method > 0 && b[method] == b' '));
    if plausible { None } else { Some(false) }
}

/// Does `b` begin (or could it begin, if short) like an HTTP/1 response?
pub fn looks_like_response(b: &[u8]) -> Option<bool> {
    let p = b"HTTP/1.";
    let n = b.len().min(p.len());
    if b[..n] != p[..n] {
        return Some(false);
    }
    if n == p.len() { Some(true) } else { None }
}

/// Drop bytes up to the next line that starts a message of this side. True if found.
fn resync(buf: &mut Vec<u8>, side: usize) -> bool {
    let check = if side == CLIENT { looks_like_request } else { looks_like_response };
    for i in 0..buf.len() {
        if i > 0 && buf[i - 1] != b'\n' {
            continue;
        }
        match check(&buf[i..]) {
            Some(true) => {
                buf.drain(..i);
                return true;
            }
            None => {
                buf.drain(..i); // maybe the start of one: wait for more bytes
                return false;
            }
            Some(false) => {}
        }
    }
    buf.clear();
    false
}

fn body_left(h: &quena_model::Headers) -> Left {
    if raw::is_chunked(h) {
        Left::Chunked(Chunk::Size)
    } else {
        Left::Len(h.get("content-length").and_then(|v| v.trim().parse().ok()).unwrap_or(0))
    }
}

/// Consume body bytes from `buf`. `Ok(true)`: the body is complete.
fn take_body(buf: &mut Vec<u8>, left: &mut Left, ex: &mut Exchange, side: usize) -> Result<bool, String> {
    loop {
        match left {
            Left::Len(rem) => {
                let n = (*rem).min(buf.len() as u64) as usize;
                ex.write(side, &buf[..n]);
                buf.drain(..n);
                *rem -= n as u64;
                return Ok(*rem == 0);
            }
            Left::Close => {
                ex.write(side, buf);
                buf.clear();
                return Ok(false);
            }
            Left::Chunked(c) => match c {
                Chunk::Size => {
                    let Some(p) = buf.iter().position(|b| *b == b'\n') else {
                        return if buf.len() > MAX_LINE { Err("chunk size line too long".into()) } else { Ok(false) };
                    };
                    let line = String::from_utf8_lossy(&buf[..p]);
                    let size = line.trim().split(';').next().unwrap_or("").trim().to_string();
                    let size = u64::from_str_radix(&size, 16).map_err(|_| format!("bad chunk size {size:?}"))?;
                    buf.drain(..p + 1);
                    *c = if size == 0 { Chunk::Trailer } else { Chunk::Data(size) };
                }
                Chunk::Data(rem) => {
                    let n = (*rem).min(buf.len() as u64) as usize;
                    ex.write(side, &buf[..n]);
                    buf.drain(..n);
                    *rem -= n as u64;
                    if *rem > 0 {
                        return Ok(false);
                    }
                    *c = Chunk::DataEnd;
                }
                Chunk::DataEnd => {
                    if buf.starts_with(b"\r\n") {
                        buf.drain(..2);
                    } else if buf.starts_with(b"\n") {
                        buf.drain(..1);
                    } else if buf.is_empty() || buf[..] == b"\r"[..] {
                        return Ok(false);
                    } else {
                        return Err("chunk data not followed by a line end".into());
                    }
                    *c = Chunk::Size;
                }
                Chunk::Trailer => {
                    let Some(p) = buf.iter().position(|b| *b == b'\n') else {
                        return if buf.len() > MAX_LINE { Err("trailer line too long".into()) } else { Ok(false) };
                    };
                    let empty = buf[..p].iter().all(|b| *b == b'\r');
                    buf.drain(..p + 1);
                    if empty {
                        return Ok(true);
                    }
                }
            },
        }
    }
}

impl H1 {
    /// `first`: when the first of these bytes arrived (earlier than `ts` for bytes collected
    /// before the protocol was known).
    pub fn data(&mut self, side: usize, data: &[u8], first: Micros, ts: Micros, cx: &mut Cx) -> Option<Upgraded> {
        let s = &mut self.sides[side];
        if s.buf.is_empty() {
            s.start = Some(first);
        }
        s.buf.extend_from_slice(data);
        self.process(side, ts, cx)
    }

    fn process(&mut self, side: usize, ts: Micros, cx: &mut Cx) -> Option<Upgraded> {
        loop {
            let st = std::mem::take(&mut self.sides[side].st);
            match st {
                St::Resync => {
                    if !resync(&mut self.sides[side].buf, side) {
                        self.sides[side].st = St::Resync;
                        break;
                    }
                    self.sides[side].start = Some(ts);
                }
                St::Body(mut left) => {
                    let s = &mut self.sides[side];
                    let Some(ex) = self.ex.iter_mut().find(|e| e.end[side].is_none()) else {
                        s.st = St::Resync;
                        continue;
                    };
                    match take_body(&mut s.buf, &mut left, ex, side) {
                        Ok(true) => {
                            ex.end[side] = Some(ts);
                            s.start = Some(ts);
                            self.emit_done(cx);
                        }
                        Ok(false) => {
                            s.st = St::Body(left);
                            break;
                        }
                        Err(e) => {
                            ex.fail(format!("the {} body is malformed: {e}", side_name(side)));
                            ex.end[side] = Some(ts);
                            s.st = St::Resync;
                            self.emit_done(cx);
                        }
                    }
                }
                St::Head => {
                    if side == CLIENT && self.hold {
                        break;
                    }
                    let s = &mut self.sides[side];
                    let lead = s.buf.iter().take_while(|b| **b == b'\r' || **b == b'\n').count();
                    s.buf.drain(..lead);
                    if s.buf.is_empty() {
                        break;
                    }
                    let Some(end) = head_end(&s.buf) else {
                        if s.buf.len() > MAX_HEAD || s.buf.first().is_some_and(|b| !b.is_ascii_uppercase()) {
                            s.st = St::Resync;
                            continue;
                        }
                        break;
                    };
                    let parsed = raw::read_head(&mut &s.buf[..end]).ok().flatten();
                    let ok = parsed.as_ref().is_some_and(|(first, _)| if side == CLIENT { request_line_ok(first) } else { status_line_ok(first) });
                    if !ok {
                        // Not a message start: skip this line and look for the next one.
                        let nl = s.buf.iter().position(|b| *b == b'\n').map_or(s.buf.len(), |p| p + 1);
                        s.buf.drain(..nl);
                        s.st = St::Resync;
                        continue;
                    }
                    s.buf.drain(..end);
                    let start = s.start.unwrap_or(ts);
                    s.start = Some(ts);
                    let (first, headers) = parsed.unwrap();
                    if side == CLIENT {
                        self.request(first, headers, start, ts, cx);
                    } else if let Some(up) = self.response(first, headers, start, ts, cx) {
                        return Some(up);
                    }
                }
            }
        }
        None
    }

    fn request(&mut self, first: String, headers: quena_model::Headers, start: Micros, ts: Micros, cx: &mut Cx) {
        let (method, target, version) = raw::parse_request_line(&first);
        let connect = method.eq_ignore_ascii_case("CONNECT");
        let url = if connect || target.contains("://") {
            target
        } else {
            let host = headers.get("host").map(str::to_string).unwrap_or_else(|| cx.conn.server_host());
            let path = if target.starts_with('/') { target } else { format!("/{target}") };
            format!("http://{host}{path}")
        };
        let upgrade = headers.get("upgrade").is_some() && headers.has_token("connection", "upgrade");
        let left = body_left(&headers);
        let mut ex = Exchange::new(cx, RequestHead { method, url, version, headers }, start, ts);
        if connect {
            ex.kind = SessionKind::Tunnel;
        }
        self.hold = connect || upgrade;
        match left {
            Left::Len(0) => ex.end[CLIENT] = Some(ts),
            l => self.sides[CLIENT].st = St::Body(l),
        }
        self.ex.push_back(ex);
    }

    fn response(&mut self, first: String, headers: quena_model::Headers, start: Micros, ts: Micros, cx: &mut Cx) -> Option<Upgraded> {
        let (version, status, reason) = raw::parse_status_line(&first);
        let idx = match self.ex.iter().position(|e| e.end[SERVER].is_none()) {
            Some(i) => i,
            None => {
                // The request is not in the capture (it started earlier): read past the response.
                cx.stats.orphans += 1;
                let mut ex = Exchange::new(cx, RequestHead::default(), start, ts);
                ex.discard = true;
                ex.end[CLIENT] = Some(ts);
                self.ex.push_back(ex);
                self.ex.len() - 1
            }
        };
        if (100..200).contains(&status) && status != 101 {
            return None; // interim response (100 Continue, 103 Early Hints)
        }
        let held = self.hold && idx == self.ex.len() - 1;
        let ex = &mut self.ex[idx];
        let connect = ex.req.method.eq_ignore_ascii_case("CONNECT");
        let switch = if status == 101 {
            let proto = headers.get("upgrade").or(ex.req.headers.get("upgrade")).unwrap_or("").trim().to_ascii_lowercase();
            Some(match proto.as_str() {
                "websocket" => Switch::WebSocket,
                "h2c" => Switch::H2c,
                _ => Switch::Tunnel,
            })
        } else if connect && (200..300).contains(&status) {
            Some(Switch::Tunnel)
        } else {
            None
        };
        let no_body = ex.req.method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304 || switch.is_some() || (connect && (200..300).contains(&status));
        let left = if no_body {
            Left::Len(0)
        } else if raw::is_chunked(&headers) || headers.get("content-length").is_some() {
            body_left(&headers)
        } else {
            Left::Close
        };
        ex.resp = Some(ResponseHead { status, reason, version, headers });
        ex.start[SERVER] = Some(start);
        ex.head[SERVER] = Some(ts);
        if let Some(to) = switch {
            ex.end[SERVER] = Some(ts);
            if ex.discard {
                // The upgrade request is not in the capture: keep what follows it.
                ex.discard = false;
                let (method, url) = match to {
                    Switch::Tunnel => ("CONNECT", cx.conn.server.to_string()),
                    _ => ("GET", format!("http://{}/", cx.conn.server_host())),
                };
                ex.req = RequestHead { method: method.into(), url, version: HttpVersion::Http11, headers: Default::default() };
                ex.fail("the request is not in the capture".into());
            } else if !held {
                ex.fail("the connection switched protocols before the request was complete".into());
            }
            let ex = self.ex.remove(idx).unwrap();
            // Whatever came before the switching exchange is done now.
            for mut e in self.ex.drain(..) {
                e.end[CLIENT].get_or_insert(ts);
                if e.end[SERVER].is_none() {
                    e.fail("no response in the capture".into());
                }
                cx.emit(e);
            }
            let rest = [std::mem::take(&mut self.sides[CLIENT].buf), std::mem::take(&mut self.sides[SERVER].buf)];
            return Some(Upgraded { to, ex, rest });
        }
        match left {
            Left::Len(0) => {
                ex.end[SERVER] = Some(ts);
                self.emit_done(cx);
            }
            l => self.sides[SERVER].st = St::Body(l),
        }
        if held {
            // The switch was refused: requests go on as before.
            self.hold = false;
            return self.process(CLIENT, ts, cx);
        }
        None
    }

    /// Emit exchanges from the front that are complete.
    fn emit_done(&mut self, cx: &mut Cx) {
        while self.ex.front().is_some_and(|e| e.end[CLIENT].is_some() && e.end[SERVER].is_some()) {
            cx.emit(self.ex.pop_front().unwrap());
        }
    }

    /// Bytes of one side are missing from the capture.
    pub fn gap(&mut self, side: usize, n: u64, ts: Micros, cx: &mut Cx) {
        let st = std::mem::take(&mut self.sides[side].st);
        let ex = self.ex.iter_mut().find(|e| e.end[side].is_none());
        self.sides[side].st = match (st, ex) {
            (St::Body(Left::Len(rem)), Some(ex)) if n <= rem => {
                ex.bodies[side].add_dropped(n);
                ex.fail(format!("{n} bytes of the {} body are missing in the capture", side_name(side)));
                if rem == n {
                    ex.end[side] = Some(ts);
                    St::Head
                } else {
                    St::Body(Left::Len(rem - n))
                }
            }
            (St::Body(Left::Close), Some(ex)) => {
                ex.bodies[side].add_dropped(n);
                ex.fail(format!("{n} bytes of the {} body are missing in the capture", side_name(side)));
                St::Body(Left::Close)
            }
            (St::Body(_), Some(ex)) => {
                ex.fail(format!("the {} is incomplete: {n} bytes are missing in the capture", side_name(side)));
                ex.end[side] = Some(ts);
                St::Resync
            }
            // Between messages: the missing bytes held (the start of) the next message. Its
            // exchange is closed here, so that later responses still meet their requests.
            (St::Head, ex) => {
                if side == SERVER {
                    if let Some(ex) = ex {
                        ex.fail(format!("the response is missing in the capture ({n} bytes lost)"));
                        ex.end[SERVER] = Some(ts);
                    }
                } else {
                    // A lost request: a placeholder takes its response.
                    let mut ex = Exchange::new(cx, RequestHead::default(), ts, ts);
                    ex.discard = true;
                    ex.end[CLIENT] = Some(ts);
                    self.ex.push_back(ex);
                }
                St::Resync
            }
            _ => St::Resync,
        };
        if matches!(self.sides[side].st, St::Resync) {
            self.sides[side].buf.clear();
        }
        self.emit_done(cx);
        self.release_hold(ts, cx);
    }

    /// The request that asked to switch protocols got no switch (its response is lost or
    /// ended without one): the client's next requests are read again.
    fn release_hold(&mut self, ts: Micros, cx: &mut Cx) {
        if self.hold && self.ex.back().is_none_or(|e| e.end[SERVER].is_some()) {
            self.hold = false;
            // Client bytes cannot switch the protocol: nothing comes back from them.
            let _ = self.process(CLIENT, ts, cx);
        }
    }

    /// One side closed its half of the connection.
    pub fn fin(&mut self, side: usize, ts: Micros, cx: &mut Cx) {
        if let St::Body(left) = std::mem::take(&mut self.sides[side].st)
            && let Some(ex) = self.ex.iter_mut().find(|e| e.end[side].is_none())
        {
            if !matches!(left, Left::Close) {
                ex.fail(format!("the connection closed before the {} was complete", side_name(side)));
            }
            ex.end[side] = Some(ts);
        }
        self.emit_done(cx);
    }

    /// The connection (or the capture) ended.
    pub fn close(mut self, ts: Micros, cx: &mut Cx) {
        self.fin(CLIENT, ts, cx);
        self.fin(SERVER, ts, cx);
        for mut e in self.ex.drain(..) {
            e.end[CLIENT].get_or_insert(ts);
            if e.resp.is_none() {
                e.fail("no response in the capture".into());
            }
            cx.emit(e);
        }
    }
}

