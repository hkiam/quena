//! Cleartext HTTP/2 (h2c, prior knowledge or upgrade): frames of both sides, header blocks
//! through HPACK, one session per stream.
//!
//! HPACK keeps state over the whole connection: once bytes are missing, header blocks can no
//! longer be decoded, so the rest of the connection is given up.

use super::{CLIENT, Cx, Exchange, SERVER, peer_name};
use fluke_hpack::Decoder;
use quena_model::{Headers, HttpVersion, Micros, RequestHead, ResponseHead, latin1_to_string};
use std::collections::BTreeMap;

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;
const PUSH_PROMISE: u8 = 5;
const CONTINUATION: u8 = 9;

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

/// A header block that continues in CONTINUATION frames.
struct Pending {
    stream: u32,
    end_stream: bool,
    /// Stream announced by a PUSH_PROMISE.
    promised: Option<u32>,
    block: Vec<u8>,
}

pub struct H2 {
    bufs: [Vec<u8>; 2],
    /// The client preface is still expected.
    preface: bool,
    dec: [Decoder<'static>; 2],
    cont: [Option<Pending>; 2],
    streams: BTreeMap<u32, Exchange>,
    /// Why the connection could not be followed any further.
    broken: Option<String>,
    /// When the oldest unparsed byte of each side arrived.
    start: [Option<Micros>; 2],
}

fn reason(status: u16) -> String {
    http::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("")
        .to_string()
}

/// Strip padding (and the priority fields of HEADERS) from a frame payload.
fn unpad(ty: u8, flags: u8, p: &[u8]) -> Option<&[u8]> {
    let mut p = p;
    let mut pad = 0;
    if flags & PADDED != 0 {
        pad = *p.first()? as usize;
        p = &p[1..];
    }
    if ty == HEADERS && flags & PRIORITY != 0 {
        p = p.get(5..)?;
    }
    p.get(..p.len().checked_sub(pad)?)
}

impl H2 {
    /// A connection that starts with the client preface. `upgraded`: the HTTP/1.1 request that
    /// asked for h2c, answered on stream 1.
    pub fn new(upgraded: Option<Exchange>) -> H2 {
        let mut streams = BTreeMap::new();
        if let Some(mut ex) = upgraded {
            ex.resp = None;
            ex.start[SERVER] = None;
            ex.head[SERVER] = None;
            ex.end[SERVER] = None;
            ex.stream_id = Some(1);
            streams.insert(1, ex);
        }
        H2 {
            bufs: [Vec::new(), Vec::new()],
            preface: true,
            dec: [Decoder::new(), Decoder::new()],
            cont: [None, None],
            streams,
            broken: None,
            start: [None, None],
        }
    }

    /// `first`: when the first of these bytes arrived.
    pub fn data(&mut self, side: usize, data: &[u8], first: Micros, ts: Micros, cx: &mut Cx) {
        if self.broken.is_some() {
            return;
        }
        if self.bufs[side].is_empty() {
            self.start[side] = Some(first);
        }
        self.bufs[side].extend_from_slice(data);
        if side == CLIENT && self.preface {
            let b = &self.bufs[CLIENT];
            let n = b.len().min(PREFACE.len());
            if b[..n] != PREFACE[..n] {
                return self.give_up(
                    "the client did not start with the HTTP/2 preface".into(),
                    ts,
                    cx,
                );
            }
            if n < PREFACE.len() {
                return;
            }
            self.bufs[CLIENT].drain(..PREFACE.len());
            self.preface = false;
        }
        let mut used = 0;
        loop {
            let b = &self.bufs[side][used..];
            if b.len() < 9 {
                break;
            }
            let len = u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize;
            if b.len() < 9 + len {
                break;
            }
            let (ty, flags) = (b[3], b[4]);
            let stream = u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff;
            let payload = b[9..9 + len].to_vec();
            used += 9 + len;
            if let Err(e) = self.frame(side, ty, flags, stream, &payload, ts, cx) {
                return self.give_up(e, ts, cx);
            }
            self.start[side] = Some(ts);
        }
        self.bufs[side].drain(..used);
    }

    #[allow(clippy::too_many_arguments)]
    fn frame(
        &mut self,
        side: usize,
        ty: u8,
        flags: u8,
        stream: u32,
        p: &[u8],
        ts: Micros,
        cx: &mut Cx,
    ) -> Result<(), String> {
        if self.cont[side].is_some() && ty != CONTINUATION {
            return Err("a header block was interrupted by another frame".into());
        }
        match ty {
            DATA => {
                let data = unpad(ty, flags, p).ok_or("bad padding in a DATA frame")?;
                if let Some(ex) = self.streams.get_mut(&stream) {
                    if ex.start[side].is_none() {
                        ex.start[side] = Some(ts);
                    }
                    ex.write(side, data);
                    if flags & END_STREAM != 0 {
                        ex.end[side] = Some(ts);
                        self.emit_done(stream, cx);
                    }
                }
            }
            HEADERS => {
                let block = unpad(ty, flags, p)
                    .ok_or("bad padding in a HEADERS frame")?
                    .to_vec();
                let pend = Pending {
                    stream,
                    end_stream: flags & END_STREAM != 0,
                    promised: None,
                    block,
                };
                self.block_part(side, pend, flags & END_HEADERS != 0, ts, cx)?;
            }
            PUSH_PROMISE => {
                let rest = unpad(ty, flags, p).ok_or("bad padding in a PUSH_PROMISE frame")?;
                if rest.len() < 4 {
                    return Err("short PUSH_PROMISE frame".into());
                }
                let promised =
                    u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) & 0x7fff_ffff;
                let pend = Pending {
                    stream,
                    end_stream: false,
                    promised: Some(promised),
                    block: rest[4..].to_vec(),
                };
                self.block_part(side, pend, flags & END_HEADERS != 0, ts, cx)?;
            }
            CONTINUATION => {
                let mut pend = self.cont[side]
                    .take()
                    .ok_or("CONTINUATION without a header block")?;
                pend.block.extend_from_slice(p);
                self.block_part(side, pend, flags & END_HEADERS != 0, ts, cx)?;
            }
            RST_STREAM => {
                let code = p
                    .get(..4)
                    .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                    .unwrap_or(0);
                if let Some(ex) = self.streams.get_mut(&stream) {
                    ex.fail(format!(
                        "the {} reset the stream ({})",
                        peer_name(side),
                        error_name(code)
                    ));
                    ex.end[CLIENT].get_or_insert(ts);
                    ex.end[SERVER].get_or_insert(ts);
                    self.emit_done(stream, cx);
                }
            }
            _ => {} // SETTINGS, PING, GOAWAY, WINDOW_UPDATE, PRIORITY: nothing to show
        }
        Ok(())
    }

    fn block_part(
        &mut self,
        side: usize,
        pend: Pending,
        end_headers: bool,
        ts: Micros,
        cx: &mut Cx,
    ) -> Result<(), String> {
        if !end_headers {
            self.cont[side] = Some(pend);
            return Ok(());
        }
        let mut fields = Vec::new();
        self.dec[side]
            .decode_with_cb(&pend.block, |n, v| {
                fields.push((latin1_to_string(&n), latin1_to_string(&v)))
            })
            .map_err(|e| format!("HPACK: {e:?}"))?;
        let pseudo = |name: &str| {
            fields
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        let (method, scheme, authority, path, status) = (
            pseudo(":method"),
            pseudo(":scheme"),
            pseudo(":authority"),
            pseudo(":path"),
            pseudo(":status"),
        );
        let mut headers = Headers::new();
        for (k, v) in fields.iter().filter(|(k, _)| !k.starts_with(':')) {
            headers.push(k.clone(), v.clone());
        }
        let request = |headers: Headers, cx: &mut Cx| {
            let host = authority
                .clone()
                .or_else(|| headers.get("host").map(str::to_string))
                .unwrap_or_else(|| cx.conn.server_host());
            let method = method.clone().unwrap_or_else(|| "GET".into());
            let url = if method.eq_ignore_ascii_case("CONNECT") && path.is_none() {
                host
            } else {
                format!(
                    "{}://{host}{}",
                    scheme.clone().unwrap_or_else(|| cx.conn.scheme().into()),
                    path.clone().unwrap_or_else(|| "/".into())
                )
            };
            RequestHead {
                method,
                url,
                version: HttpVersion::Http2,
                headers,
            }
        };
        if let Some(promised) = pend.promised {
            // The server announces a pushed response: the request it answers.
            let req = request(headers, cx);
            let mut ex = Exchange::new(cx, req, ts, ts);
            ex.stream_id = Some(promised);
            ex.end[CLIENT] = Some(ts);
            if let Some(mut old) = self.streams.insert(promised, ex) {
                // A stream announced twice: the first one ends here.
                old.fail("the server announced this stream again".into());
                old.end[CLIENT].get_or_insert(ts);
                old.end[SERVER].get_or_insert(ts);
                cx.emit(old);
            }
            return Ok(());
        }
        let stream = pend.stream;
        if side == CLIENT {
            match self.streams.get_mut(&stream) {
                None => {
                    let start = self.start[CLIENT].unwrap_or(ts);
                    let req = request(headers, cx);
                    let mut ex = Exchange::new(cx, req, start, ts);
                    ex.stream_id = Some(stream);
                    if pend.end_stream {
                        ex.end[CLIENT] = Some(ts);
                    }
                    self.streams.insert(stream, ex);
                }
                Some(ex) => {
                    // Trailers
                    ex.req.headers.0.extend(headers.0);
                    if pend.end_stream {
                        ex.end[CLIENT] = Some(ts);
                    }
                }
            }
        } else {
            let Some(ex) = self.streams.get_mut(&stream) else {
                cx.stats.orphans += 1;
                return Ok(());
            };
            match (&mut ex.resp, status.and_then(|s| s.parse::<u16>().ok())) {
                (Some(r), _) => r.headers.0.extend(headers.0), // trailers
                (None, Some(s)) if (100..200).contains(&s) => return Ok(()), // interim
                (None, s) => {
                    let status = s.unwrap_or(0);
                    ex.resp = Some(ResponseHead {
                        status,
                        reason: reason(status),
                        version: HttpVersion::Http2,
                        headers,
                    });
                    ex.start[SERVER].get_or_insert(self.start[SERVER].unwrap_or(ts));
                    ex.head[SERVER] = Some(ts);
                }
            }
            if pend.end_stream {
                ex.end[SERVER] = Some(ts);
            }
        }
        self.emit_done(stream, cx);
        Ok(())
    }

    fn emit_done(&mut self, stream: u32, cx: &mut Cx) {
        if self
            .streams
            .get(&stream)
            .is_some_and(|e| e.end[CLIENT].is_some() && e.end[SERVER].is_some())
        {
            cx.emit(self.streams.remove(&stream).unwrap());
        }
    }

    /// The connection can no longer be followed: its open streams end with `why`.
    pub fn give_up(&mut self, why: String, ts: Micros, cx: &mut Cx) {
        for (_, mut ex) in std::mem::take(&mut self.streams) {
            ex.fail(format!(
                "{why}; the rest of the HTTP/2 connection could not be read"
            ));
            ex.end[CLIENT].get_or_insert(ts);
            ex.end[SERVER].get_or_insert(ts);
            cx.emit(ex);
        }
        self.bufs = [Vec::new(), Vec::new()];
        self.broken = Some(why);
    }

    pub fn gap(&mut self, side: usize, n: u64, ts: Micros, cx: &mut Cx) {
        if self.broken.is_none() {
            self.give_up(
                format!(
                    "{n} bytes from the {} are missing in the capture",
                    peer_name(side)
                ),
                ts,
                cx,
            );
        }
    }

    pub fn close(mut self, ts: Micros, cx: &mut Cx) {
        for (_, mut ex) in std::mem::take(&mut self.streams) {
            if ex.end[CLIENT].is_none() {
                ex.fail("the request did not end in the capture".into());
            } else if ex.resp.is_none() {
                ex.fail("no response in the capture".into());
            } else if ex.end[SERVER].is_none() {
                ex.fail("the response did not end in the capture".into());
            }
            ex.end[CLIENT].get_or_insert(ts);
            ex.end[SERVER].get_or_insert(ts);
            cx.emit(ex);
        }
    }
}

fn error_name(code: u32) -> String {
    match code {
        0x0 => "NO_ERROR".into(),
        0x1 => "PROTOCOL_ERROR".into(),
        0x2 => "INTERNAL_ERROR".into(),
        0x3 => "FLOW_CONTROL_ERROR".into(),
        0x5 => "STREAM_CLOSED".into(),
        0x7 => "REFUSED_STREAM".into(),
        0x8 => "CANCEL".into(),
        0xb => "ENHANCE_YOUR_CALM".into(),
        c => format!("error 0x{c:x}"),
    }
}
