//! Packet captures (pcap, pcapng from Wireshark, tcpdump, dumpcap): TCP connections are
//! reassembled and their HTTP read back into sessions.
//!
//! Plain HTTP/1.x (with WebSocket) and cleartext HTTP/2 (h2c) become sessions with timers
//! from the packet times. TLS connections are decrypted with their secrets from a key log
//! (`SSLKEYLOGFILE`, or embedded in a pcapng file) and read the same way; without them, each
//! one becomes a tunnel session with what its handshake shows (SNI, ALPN, version, cipher).
//! Bytes missing from the capture end the message they fall into, which says so in its error.

mod file;
mod h1;
mod h2;
mod keylog;
mod net;
mod tcp;
mod tls;
mod tlsconn;
mod tlsrec;
mod ws;

pub use keylog::KeyLog;

use crate::{FormatError, Progress, Result};
use quena_body::{Body, BodyWriter};
use quena_model::{
    ConnectionInfo, HttpVersion, Micros, RequestHead, ResponseHead, SessionDetail, SessionId,
    SessionKind, SessionState, TlsInfo, flags,
};
use quena_store::Capture;
use std::cell::Cell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

const CLIENT: usize = 0;
const SERVER: usize = 1;

/// Bytes looked at to tell the protocol of a connection.
const MAX_SNIFF: usize = 64 << 10;

fn side_name(side: usize) -> &'static str {
    if side == CLIENT {
        "request"
    } else {
        "response"
    }
}

fn peer_name(side: usize) -> &'static str {
    if side == CLIENT { "client" } else { "server" }
}

fn host_of(a: &SocketAddr, default_port: u16) -> String {
    let ip = match a.ip() {
        IpAddr::V6(v6) => format!("[{v6}]"),
        IpAddr::V4(v4) => v4.to_string(),
    };
    if a.port() == default_port {
        ip
    } else {
        format!("{ip}:{}", a.port())
    }
}

/// What the importer counted besides sessions; reported in the log.
#[derive(Default)]
struct Stats {
    packets: u64,
    non_tcp: u64,
    fragments: u64,
    unknown_link: u64,
    connections: u64,
    gaps: u64,
    orphans: u64,
    other_conns: u64,
    tls_conns: u64,
    tls_decrypted: u64,
    tls_no_keys: u64,
    tls_unsupported: u64,
    /// Packets the capture cut short (snapshot length).
    cut: u64,
    truncated: bool,
    /// Why reading stopped before the end of the file.
    corrupt: Option<String>,
}

/// One TCP connection's endpoints and handshake times.
struct ConnInfo {
    id: u64,
    client: SocketAddr,
    server: SocketAddr,
    syn: Option<Micros>,
    synack: Option<Micros>,
    first: Micros,
    exchanges: u32,
    /// The TLS connection whose decrypted bytes are being read, once they are.
    tls: Option<TlsInfo>,
    /// From the ClientHello to the first application data.
    tls_handshake_ms: Option<u32>,
    /// The server as the client named it (CONNECT target, SNI), for the sessions inside a
    /// tunnel: `server` is then the proxy, or only an address.
    target: Option<String>,
}

impl ConnInfo {
    fn scheme(&self) -> &'static str {
        if self.tls.is_some() { "https" } else { "http" }
    }

    /// The server as a Host header would name it.
    fn server_host(&self) -> String {
        let default = if self.tls.is_some() { ":443" } else { ":80" };
        match &self.target {
            Some(t) => t.strip_suffix(default).unwrap_or(t).to_string(),
            None => host_of(&self.server, if self.tls.is_some() { 443 } else { 80 }),
        }
    }
}

/// A session being read: request and response with their bodies and times.
struct Exchange {
    kind: SessionKind,
    req: RequestHead,
    resp: Option<ResponseHead>,
    bodies: [BodyWriter; 2],
    /// First byte, end of head and end of message per side.
    start: [Option<Micros>; 2],
    head: [Option<Micros>; 2],
    end: [Option<Micros>; 2],
    error: Option<String>,
    stream_id: Option<u32>,
    tls: Option<TlsInfo>,
    /// Read from decrypted TLS.
    decrypted: bool,
    /// Session flags shown under Properties.
    extra_flags: Vec<(String, String)>,
    /// Tunnel bytes per side.
    bytes: [u64; 2],
    /// Number of the exchange on its connection (0: the first one).
    seq: u32,
    /// Read only to get past it (a response whose request is not in the capture).
    discard: bool,
}

impl Exchange {
    fn new(cx: &mut Cx, req: RequestHead, start: Micros, head: Micros) -> Exchange {
        let seq = cx.conn.exchanges;
        cx.conn.exchanges += 1;
        Exchange::numbered(cx, req, start, head, seq)
    }

    fn numbered(cx: &Cx, req: RequestHead, start: Micros, head: Micros, seq: u32) -> Exchange {
        Exchange {
            kind: SessionKind::Http,
            req,
            resp: None,
            bodies: [cx.cap.bodies.writer(), cx.cap.bodies.writer()],
            start: [Some(start), None],
            head: [Some(head), None],
            end: [None, None],
            error: None,
            stream_id: None,
            tls: cx.conn.tls.clone(),
            decrypted: cx.conn.tls.is_some(),
            extra_flags: Vec::new(),
            bytes: [0, 0],
            seq,
            discard: false,
        }
    }

    fn write(&mut self, side: usize, data: &[u8]) {
        if let Err(e) = self.bodies[side].write(data) {
            tracing::debug!("pcap import: body not stored completely: {e}");
        }
    }

    /// Keep the first error: later ones are mostly its consequences.
    fn fail(&mut self, msg: String) {
        self.error.get_or_insert(msg);
    }
}

/// A finished session, inserted once all are read (in the order of their requests).
struct Built {
    key: (Micros, u64, u32),
    d: SessionDetail,
    req: Body,
    resp: Body,
}

struct Cx<'a> {
    cap: &'a Arc<Capture>,
    keys: &'a KeyLog,
    conn: &'a mut ConnInfo,
    stats: &'a mut Stats,
    out: &'a mut Vec<Built>,
}

impl Cx<'_> {
    fn emit(&mut self, ex: Exchange) {
        let [rq, rs] = ex.bodies;
        let (req, resp) = (rq.finish(), rs.finish());
        if ex.discard {
            self.cap.bodies.delete(&req);
            self.cap.bodies.delete(&resp);
            return;
        }
        let c = &*self.conn;
        let mut d = SessionDetail::default();
        d.summary.kind = ex.kind;
        let start = ex.start[CLIENT].unwrap_or(c.first);
        let t = &mut d.timers;
        t.client_connected = Some(c.syn.unwrap_or(c.first));
        t.client_begin_request = Some(start);
        t.server_begin_request = Some(start);
        t.got_request_headers = ex.head[CLIENT];
        t.client_done_request = ex.end[CLIENT];
        t.server_done_request = ex.end[CLIENT];
        if ex.resp.is_some() || ex.kind != SessionKind::Http {
            t.server_got_first_byte = ex.start[SERVER];
            t.client_begin_response = ex.start[SERVER];
            t.got_response_headers = ex.head[SERVER];
            t.server_done_response = ex.end[SERVER];
            t.client_done_response = ex.end[SERVER];
        }
        if ex.seq == 0
            && let (Some(syn), Some(synack)) = (c.syn, c.synack)
        {
            t.server_connect_start = Some(syn);
            t.server_connected = Some(synack);
            t.tcp_connect_ms = Some(((synack - syn).max(0) / 1000) as u32);
        }
        if ex.decrypted {
            if ex.seq == 0 {
                t.tls_handshake_ms = c.tls_handshake_ms;
            }
            d.summary.flags |= flags::DECRYPTED;
        }
        d.connection = ConnectionInfo {
            client_addr: Some(c.client.to_string()),
            server_addr: Some(c.server.to_string()),
            client_conn_id: Some(c.id),
            server_conn_reused: ex.seq > 0,
            client_tls: ex.tls,
            stream_id: ex.stream_id,
            ..Default::default()
        };
        d.summary.client_ip = c.client.ip().to_canonical().to_string();
        if ex.kind == SessionKind::Tunnel {
            let [up, down] = ex.bytes;
            d.extra_flags
                .push(("x-tunnel-bytes".into(), format!("{up} up / {down} down")));
            d.summary.custom = format!("↑{up} ↓{down}");
        }
        d.extra_flags.extend(ex.extra_flags);
        d.request = ex.req;
        d.response = ex.resp;
        d.summary.state = if ex.error.is_some() {
            SessionState::Aborted
        } else {
            SessionState::Done
        };
        d.error = ex.error;
        d.summary.flags |= flags::IMPORTED;
        d.summary.started_at = start;
        self.out.push(Built {
            key: (start, c.id, ex.seq),
            d,
            req,
            resp,
        });
    }
}

/// What a tunnel carries.
enum Inside {
    /// Nothing seen yet.
    Unknown,
    Tls(Box<tlsconn::TlsConn>),
    /// Plain bytes inside a CONNECT tunnel: read like a connection of their own.
    Plain,
    /// Another protocol after an upgrade: only counted.
    Opaque,
}

/// A TLS connection, the inside of a CONNECT tunnel, or another protocol after an upgrade.
/// TLS is decrypted when the key log has its secrets; the plaintext is read like a
/// connection of its own (`inner`).
struct Tunnel {
    ex: Exchange,
    /// Not inside a CONNECT: named after the server (or its SNI), and not shown as a
    /// session of its own once its content is read.
    direct: bool,
    /// A CONNECT tunnel: plain content is read too.
    connect: bool,
    inside: Inside,
    inner: Box<(Proto, Sniff)>,
    /// Sides of the inner connection ended because decryption stopped.
    cut: [bool; 2],
}

impl Tunnel {
    fn new(ex: Exchange, direct: bool, connect: bool) -> Tunnel {
        // The decrypted bytes start at a message boundary, like a connection with a handshake.
        let sniff = Sniff {
            had_syn: true,
            ..Sniff::default()
        };
        Tunnel {
            ex,
            direct,
            connect,
            inside: Inside::Unknown,
            inner: Box::new((Proto::Sniff, sniff)),
            cut: [false; 2],
        }
    }

    fn direct(cx: &mut Cx, ts: Micros) -> Tunnel {
        let url = host_of(&cx.conn.server, 0);
        let req = RequestHead {
            method: "CONNECT".into(),
            url,
            version: HttpVersion::Http11,
            headers: Default::default(),
        };
        // Not numbered: once decrypted, the sessions inside are the connection's first ones.
        let mut ex = Exchange::numbered(cx, req, ts, ts, 0);
        ex.kind = SessionKind::Tunnel;
        ex.end[CLIENT] = Some(ts);
        Tunnel::new(ex, true, false)
    }

    fn connect(mut ex: Exchange) -> Tunnel {
        let connect = ex.req.method.eq_ignore_ascii_case("CONNECT");
        ex.kind = SessionKind::Tunnel;
        ex.end[SERVER] = None;
        Tunnel::new(ex, false, connect)
    }

    fn data(&mut self, side: usize, data: &[u8], ts: Micros, cx: &mut Cx) {
        self.ex.bytes[side] += data.len() as u64;
        if self.ex.start[SERVER].is_none() && side == SERVER {
            self.ex.start[SERVER] = Some(ts);
        }
        if matches!(self.inside, Inside::Unknown) {
            self.inside = if side == CLIENT
                && (tls::looks_like_tls(data) || (data.len() < 3 && data.first() == Some(&0x16)))
            {
                Inside::Tls(Box::default())
            } else if self.connect {
                cx.conn.target = Some(self.ex.req.url.clone());
                Inside::Plain
            } else {
                Inside::Opaque
            };
        }
        let (proto, sniff) = &mut *self.inner;
        match &mut self.inside {
            Inside::Tls(t) => {
                for plain in t.feed(side, data, cx.keys) {
                    if cx.conn.tls.is_none() {
                        cx.conn.tls = Some(t.info.clone());
                        cx.conn.tls_handshake_ms =
                            self.ex.start[CLIENT].map(|s| ((ts - s).max(0) / 1000) as u32);
                        cx.conn.target = if self.connect {
                            Some(self.ex.req.url.clone())
                        } else {
                            t.info
                                .sni
                                .as_ref()
                                .map(|sni| format!("{sni}:{}", cx.conn.server.port()))
                        };
                    }
                    Conn::data(proto, sniff, side, &plain, ts, ts, cx);
                }
            }
            Inside::Plain => Conn::data(proto, sniff, side, data, ts, ts, cx),
            Inside::Unknown | Inside::Opaque => {}
        }
        self.cut_dead(side, ts, cx);
    }

    fn gap(&mut self, side: usize, n: u64, ts: Micros, cx: &mut Cx) {
        self.ex.bytes[side] += n;
        let (proto, sniff) = &mut *self.inner;
        match &mut self.inside {
            // The plaintext after the gap is not known at all: decryption ends (below).
            Inside::Tls(t) => t.gap(side, n),
            Inside::Plain => Conn::gap(proto, sniff, side, n, ts, cx),
            Inside::Unknown | Inside::Opaque => {}
        }
        self.cut_dead(side, ts, cx);
    }

    /// Decryption of a side stopped: what the inner connection was reading on it ends here.
    fn cut_dead(&mut self, side: usize, ts: Micros, cx: &mut Cx) {
        let Inside::Tls(t) = &self.inside else { return };
        if self.cut[side] || !t.dead(side) || t.keys != tlsconn::Keys::Found {
            return;
        }
        self.cut[side] = true;
        let why = t.broken.clone().unwrap_or_else(|| {
            "the rest of the encrypted connection could not be decrypted".into()
        });
        Conn::cut(&mut self.inner.0, side, &why, ts, cx);
    }

    fn fin(&mut self, side: usize, ts: Micros, cx: &mut Cx) {
        Conn::fin(&mut self.inner.0, side, ts, cx);
    }

    fn close(mut self, ts: Micros, cx: &mut Cx) {
        let (proto, sniff) = *self.inner;
        // Sessions were read from inside: a direct TLS connection needs no session of its own.
        let read_inside = matches!(proto, Proto::H1(_) | Proto::H2(_) | Proto::Ws(_));
        Conn::close(proto, &sniff, ts, cx);
        if let Inside::Tls(t) = self.inside
            && t.seen
        {
            cx.stats.tls_conns += 1;
            match &t.keys {
                tlsconn::Keys::Found => cx.stats.tls_decrypted += 1,
                tlsconn::Keys::Missing => cx.stats.tls_no_keys += 1,
                tlsconn::Keys::Unsupported(what) => {
                    cx.stats.tls_unsupported += 1;
                    self.ex.extra_flags.push((
                        "x-quena-not-decrypted".into(),
                        format!("{what} cannot be decrypted"),
                    ));
                }
                tlsconn::Keys::Pending => {}
            }
            if t.skipped > 0 {
                self.ex.fail(format!(
                    "{} early data record(s) (0-RTT) were not decrypted",
                    t.skipped
                ));
            }
            if let Some(why) = &t.broken {
                self.ex.fail(why.clone());
            }
            if self.direct
                && let Some(sni) = &t.info.sni
            {
                self.ex.req.url = format!("{sni}:{}", cx.conn.server.port());
            }
            self.ex.tls = Some(t.info);
            // Kept when decryption stopped or skipped records: it says why.
            if self.direct
                && read_inside
                && t.keys == tlsconn::Keys::Found
                && self.ex.error.is_none()
            {
                self.ex.discard = true;
            }
        }
        self.ex.end[SERVER] = Some(ts);
        cx.emit(self.ex);
    }
}

/// The first bytes of a connection, collected until they tell its protocol.
#[derive(Default)]
struct Sniff {
    buf: [Vec<u8>; 2],
    /// When the first collected byte of each side arrived.
    ts: [Option<Micros>; 2],
    /// Bytes missing before the collected ones.
    gap: [u64; 2],
    had_syn: bool,
}

enum Proto {
    /// Not known yet: the first bytes are collected.
    Sniff,
    H1(h1::H1),
    H2(Box<h2::H2>),
    Ws(Box<ws::Ws>),
    Tunnel(Box<Tunnel>),
    /// Not HTTP: ignored.
    Other,
    Closed,
}

struct Conn {
    info: ConnInfo,
    /// Reassembly per endpoint: `a` (the sender of the first packet seen), then the other one.
    halves: [tcp::Half; 2],
    a: SocketAddr,
    /// Whether `a` is the client; unknown until a handshake or the first bytes tell.
    a_client: Option<bool>,
    proto: Proto,
    sniff: Sniff,
    closed: bool,
}

/// What the start of one side's bytes says about who sent them.
fn sent_by_client(p: &[u8]) -> Option<bool> {
    if h1::looks_like_request(p) == Some(true)
        || p.starts_with(b"PRI * HTTP/2")
        || (tls::looks_like_tls(p) && p.get(5) == Some(&1))
    {
        Some(true)
    } else if h1::looks_like_response(p) == Some(true)
        || (tls::looks_like_tls(p) && p.get(5) == Some(&2))
    {
        Some(false)
    } else {
        None
    }
}

struct Global<'a> {
    cap: &'a Arc<Capture>,
    keys: KeyLog,
    stats: Stats,
    out: Vec<Built>,
}

impl Conn {
    fn new(a: SocketAddr, b: SocketAddr, id: u64, ts: Micros) -> Conn {
        Conn {
            info: ConnInfo {
                id,
                client: a,
                server: b,
                syn: None,
                synack: None,
                first: ts,
                exchanges: 0,
                tls: None,
                tls_handshake_ms: None,
                target: None,
            },
            halves: Default::default(),
            a,
            a_client: None,
            proto: Proto::Sniff,
            sniff: Sniff::default(),
            closed: false,
        }
    }

    fn endpoint(&self, addr: SocketAddr) -> usize {
        if addr == self.a { 0 } else { 1 }
    }

    fn orient(&mut self, a_client: bool, other: SocketAddr) {
        if self.a_client.is_some() {
            return;
        }
        self.a_client = Some(a_client);
        let (c, s) = if a_client {
            (self.a, other)
        } else {
            (other, self.a)
        };
        self.info.client = c;
        self.info.server = s;
    }

    fn side(&self, endpoint: usize) -> usize {
        if (endpoint == 0) == self.a_client.unwrap_or(true) {
            CLIENT
        } else {
            SERVER
        }
    }

    fn has_data(&self) -> bool {
        self.halves.iter().any(|h| h.delivered() > 0)
    }

    fn segment(&mut self, ts: Micros, seg: &net::Segment, g: &mut Global) {
        if self.closed {
            return;
        }
        let e = self.endpoint(seg.src);
        let other = if e == 0 { seg.dst } else { seg.src };
        if seg.syn {
            self.sniff.had_syn = true;
            // SYN: the sender is the client; SYN/ACK: the sender is the server.
            self.orient((e == 0) != seg.ack, other);
            if seg.ack {
                self.info.synack.get_or_insert(ts);
            } else {
                self.info.syn.get_or_insert(ts);
            }
        }
        if !seg.payload.is_empty() && self.a_client.is_none() {
            // Picked up mid-connection: the bytes tell who is who, or the ports do.
            let client = sent_by_client(seg.payload).unwrap_or(seg.src.port() > seg.dst.port());
            self.orient((e == 0) == client, other);
        }
        let mut evs = Vec::new();
        if seg.ack {
            // Holes in the other direction that this side acknowledged are capture losses.
            self.halves[1 - e].peer_acked(seg.ack_no, &mut evs);
            let other = self.side(1 - e);
            for ev in std::mem::take(&mut evs) {
                self.event(other, ev, ts, g);
            }
        }
        self.halves[e].segment(seg.seq, seg.syn, seg.fin, seg.payload, seg.len, &mut evs);
        if seg.rst {
            self.halves[e].flush(&mut evs);
        }
        let side = self.side(e);
        for ev in evs {
            self.event(side, ev, ts, g);
        }
        if seg.rst || self.halves.iter().all(|h| h.closed) {
            self.finish(ts, g);
        }
    }

    fn event(&mut self, side: usize, ev: tcp::Ev, ts: Micros, g: &mut Global) {
        let mut cx = Cx {
            cap: g.cap,
            keys: &g.keys,
            conn: &mut self.info,
            stats: &mut g.stats,
            out: &mut g.out,
        };
        match ev {
            tcp::Ev::Data(d) => {
                Self::data(&mut self.proto, &mut self.sniff, side, &d, ts, ts, &mut cx)
            }
            tcp::Ev::Gap(n) => {
                cx.stats.gaps += 1;
                Self::gap(&mut self.proto, &mut self.sniff, side, n, ts, &mut cx);
            }
            tcp::Ev::Fin => Self::fin(&mut self.proto, side, ts, &mut cx),
        }
    }

    fn fin(proto: &mut Proto, side: usize, ts: Micros, cx: &mut Cx) {
        match proto {
            Proto::H1(h) => h.fin(side, ts, cx),
            Proto::Tunnel(t) => t.fin(side, ts, cx),
            _ => {}
        }
    }

    /// One side ends for a reason other than its peer closing it.
    fn cut(proto: &mut Proto, side: usize, why: &str, ts: Micros, cx: &mut Cx) {
        match proto {
            Proto::H1(h) => h.cut(side, why, ts, cx),
            Proto::H2(h) => h.give_up(why.to_string(), ts, cx),
            Proto::Ws(w) => w.cut(why),
            Proto::Tunnel(_) | Proto::Sniff | Proto::Other | Proto::Closed => {}
        }
    }

    fn gap(proto: &mut Proto, sniff: &mut Sniff, side: usize, n: u64, ts: Micros, cx: &mut Cx) {
        match proto {
            Proto::H1(h) => h.gap(side, n, ts, cx),
            Proto::H2(h) => h.gap(side, n, ts, cx),
            Proto::Ws(w) => w.gap(side, n),
            Proto::Tunnel(t) => t.gap(side, n, ts, cx),
            // Before the protocol is known: what was collected of this side is incomplete; the
            // gap is handed on once the bytes after it tell the protocol.
            Proto::Sniff => {
                sniff.buf[side].clear();
                sniff.ts[side] = None;
                sniff.gap[side] += n;
            }
            Proto::Other | Proto::Closed => {}
        }
    }

    /// `first`: when the first of the bytes `d` arrived; `ts`: the current packet.
    #[allow(clippy::too_many_arguments)]
    fn data(
        proto: &mut Proto,
        sniff: &mut Sniff,
        side: usize,
        d: &[u8],
        first: Micros,
        ts: Micros,
        cx: &mut Cx,
    ) {
        match proto {
            Proto::Sniff => {
                sniff.buf[side].extend_from_slice(d);
                sniff.ts[side].get_or_insert(first);
                let Some(p) = detect(sniff, cx, ts) else {
                    return;
                };
                *proto = p;
                let bufs = std::mem::take(&mut sniff.buf);
                let gaps = std::mem::take(&mut sniff.gap);
                for s in [CLIENT, SERVER] {
                    if gaps[s] > 0 {
                        Self::gap(proto, sniff, s, gaps[s], sniff.ts[s].unwrap_or(ts), cx);
                    }
                }
                for (s, b) in bufs.into_iter().enumerate() {
                    if !b.is_empty() {
                        Self::data(proto, sniff, s, &b, sniff.ts[s].unwrap_or(ts), ts, cx);
                    }
                }
            }
            Proto::H1(h) => {
                if let Some(up) = h.data(side, d, first, ts, cx) {
                    *proto = match up.to {
                        h1::Switch::WebSocket => Proto::Ws(Box::new(ws::Ws::new(up.ex))),
                        h1::Switch::H2c => Proto::H2(Box::new(h2::H2::new(Some(up.ex)))),
                        h1::Switch::Tunnel => Proto::Tunnel(Box::new(Tunnel::connect(up.ex))),
                    };
                    for (s, b) in up.rest.into_iter().enumerate() {
                        if !b.is_empty() {
                            Self::data(proto, sniff, s, &b, ts, ts, cx);
                        }
                    }
                }
            }
            Proto::H2(h) => h.data(side, d, first, ts, cx),
            Proto::Ws(w) => w.data(side, d, ts),
            Proto::Tunnel(t) => t.data(side, d, ts, cx),
            Proto::Other | Proto::Closed => {}
        }
    }

    /// End of the connection: everything still open is emitted.
    fn finish(&mut self, ts: Micros, g: &mut Global) {
        let mut evs = Vec::new();
        for e in 0..2 {
            self.halves[e].flush(&mut evs);
            let side = self.side(e);
            for ev in evs.drain(..) {
                self.event(side, ev, ts, g);
            }
        }
        let mut cx = Cx {
            cap: g.cap,
            keys: &g.keys,
            conn: &mut self.info,
            stats: &mut g.stats,
            out: &mut g.out,
        };
        Self::close(
            std::mem::replace(&mut self.proto, Proto::Closed),
            &self.sniff,
            ts,
            &mut cx,
        );
        self.sniff = Sniff::default();
        self.closed = true;
    }

    /// Emit what a protocol still holds.
    fn close(proto: Proto, sniff: &Sniff, ts: Micros, cx: &mut Cx) {
        match proto {
            Proto::H1(h) => h.close(ts, cx),
            Proto::H2(h) => h.close(ts, cx),
            Proto::Ws(w) => w.close(ts, cx),
            Proto::Tunnel(t) => t.close(ts, cx),
            Proto::Other => cx.stats.other_conns += 1,
            Proto::Sniff if sniff.buf.iter().any(|b| !b.is_empty()) => cx.stats.other_conns += 1,
            Proto::Sniff | Proto::Closed => {}
        }
    }
}

/// Tell the protocol from the first bytes; `None` while they are not enough.
fn detect(sniff: &Sniff, cx: &mut Cx, ts: Micros) -> Option<Proto> {
    let (c, s) = (&sniff.buf[CLIENT], &sniff.buf[SERVER]);
    let start = sniff.ts[CLIENT].unwrap_or(ts);
    // Mid-connection (no handshake seen, or bytes lost before): a message may start later.
    let mid = !sniff.had_syn || sniff.gap[CLIENT] > 0;
    if c.is_empty() {
        return match h1::looks_like_response(s) {
            Some(true) => Some(Proto::H1(Default::default())),
            // Picked up in the middle of a long response: HTTP/1 from its next message on.
            _ if s.len() > MAX_SNIFF && (!sniff.had_syn || sniff.gap[SERVER] > 0) => {
                Some(Proto::H1(Default::default()))
            }
            _ if s.len() > MAX_SNIFF => Some(Proto::Other),
            _ => None,
        };
    }
    if c.len() < 3 && c[0] == 0x16 {
        return None;
    }
    if tls::looks_like_tls(c) {
        return Some(Proto::Tunnel(Box::new(Tunnel::direct(cx, start))));
    }
    let n = c.len().min(h2::PREFACE.len());
    if c[..n] == h2::PREFACE[..n] {
        return (n == h2::PREFACE.len()).then(|| Proto::H2(Box::new(h2::H2::new(None))));
    }
    match h1::looks_like_request(c) {
        Some(true) => Some(Proto::H1(Default::default())),
        None => None,
        // Picked up mid-connection: TLS by its port, HTTP/1 from its next message on.
        Some(false) if mid && cx.conn.server.port() == 443 => {
            Some(Proto::Tunnel(Box::new(Tunnel::direct(cx, start))))
        }
        Some(false) if mid => Some(Proto::H1(Default::default())),
        Some(false) => Some(Proto::Other),
    }
}

/// Counts the bytes read, for progress.
struct Counting<R> {
    inner: R,
    n: Rc<Cell<u64>>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.n.set(self.n.get() + n as u64);
        Ok(n)
    }
}

fn read_err(e: io::Error) -> FormatError {
    if e.kind() == io::ErrorKind::InvalidData {
        FormatError::Invalid(e.to_string())
    } else {
        FormatError::Io(e)
    }
}

/// Largest key log file read.
const MAX_KEY_LOG: u64 = 64 << 20;

/// Read a key log; of a larger one only the last `max` bytes, from a line start: clients
/// append, so the newest secrets (those of a recent capture) are at the end. True if cut.
fn read_key_log(path: &Path, max: u64) -> io::Result<(Vec<u8>, bool)> {
    use std::io::{Seek, SeekFrom};
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    let cut = len > max;
    if cut {
        f.seek(SeekFrom::Start(len - max))?;
    }
    let mut text = Vec::new();
    f.take(max).read_to_end(&mut text)?;
    if cut {
        let line = text
            .iter()
            .position(|b| *b == b'\n')
            .map_or(text.len(), |p| p + 1);
        text.drain(..line);
    }
    Ok((text, cut))
}

/// How to import a capture.
#[derive(Debug, Clone, Default)]
pub struct PcapOptions {
    /// TLS key log files (NSS format, `SSLKEYLOGFILE`); missing ones are skipped. Secrets
    /// embedded in a pcapng file are used as well.
    pub keylogs: Vec<PathBuf>,
}

/// What an import found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PcapReport {
    /// The new sessions, in the order of their requests.
    pub ids: Vec<SessionId>,
    /// TLS connections, those decrypted, and those the key logs have no secrets for.
    pub tls: u64,
    pub decrypted: u64,
    pub no_keys: u64,
}

/// Import a pcap or pcapng file into `cap`. Returns the new session ids, in the order of
/// their requests.
pub fn import(cap: &Arc<Capture>, path: &Path, p: &dyn Progress) -> Result<Vec<SessionId>> {
    Ok(import_with(cap, path, &PcapOptions::default(), p)?.ids)
}

/// Import a pcap or pcapng file, decrypting TLS with the given key logs.
pub fn import_with(
    cap: &Arc<Capture>,
    path: &Path,
    opts: &PcapOptions,
    p: &dyn Progress,
) -> Result<PcapReport> {
    let total = std::fs::metadata(path)?.len();
    let read = Rc::new(Cell::new(0));
    let src = Counting {
        inner: BufReader::with_capacity(1 << 20, File::open(path)?),
        n: read.clone(),
    };
    let mut reader = file::Reader::new(src).map_err(read_err)?;
    let mut keys = KeyLog::default();
    for k in &opts.keylogs {
        match read_key_log(k, MAX_KEY_LOG) {
            Ok((text, cut)) => {
                if cut {
                    tracing::warn!(target: "quena", "TLS key log {}: larger than {} MiB, only its newest secrets are read", k.display(), MAX_KEY_LOG >> 20);
                }
                keys.add(&text);
            }
            Err(e) => tracing::warn!(target: "quena", "TLS key log {}: {e}", k.display()),
        }
    }
    let mut g = Global {
        cap,
        keys,
        stats: Stats::default(),
        out: Vec::new(),
    };
    let mut conns: HashMap<(SocketAddr, SocketAddr), Conn> = HashMap::new();
    let mut last = 0;
    // Nothing is inserted: the bodies stored so far go again, also those of open connections.
    let discard = |g: &mut Global,
                   conns: HashMap<(SocketAddr, SocketAddr), Conn>,
                   last: Micros,
                   err: FormatError|
     -> Result<PcapReport> {
        for mut c in conns.into_values() {
            c.finish(last, g);
        }
        for b in g.out.drain(..) {
            cap.bodies.delete(&b.req);
            cap.bodies.delete(&b.resp);
        }
        Err(err)
    };
    loop {
        let pkt = match reader.next() {
            Ok(Some(file::Item::Packet(pkt))) => pkt,
            Ok(Some(file::Item::Secrets(text))) => {
                g.keys.add(&text);
                continue;
            }
            Ok(None) => break,
            // A damaged block after some packets: keep what was read, as Wireshark does.
            Err(e) if e.kind() == io::ErrorKind::InvalidData && g.stats.packets > 0 => {
                g.stats.corrupt = Some(e.to_string());
                break;
            }
            Err(e) => return discard(&mut g, conns, last, read_err(e)),
        };
        g.stats.packets += 1;
        if g.stats.packets.is_multiple_of(4096) {
            if p.cancelled() {
                return discard(&mut g, conns, last, FormatError::Cancelled);
            }
            p.progress(read.get(), total);
        }
        last = pkt.ts;
        let seg = match net::decode(pkt.linktype, &pkt.data) {
            net::Decoded::Tcp(s) => s,
            net::Decoded::Fragment => {
                g.stats.fragments += 1;
                continue;
            }
            net::Decoded::UnknownLink => {
                g.stats.unknown_link += 1;
                continue;
            }
            net::Decoded::Other => {
                g.stats.non_tcp += 1;
                continue;
            }
        };
        if (seg.payload.len() as u32) < seg.len {
            g.stats.cut += 1;
        }
        let key = if seg.src <= seg.dst {
            (seg.src, seg.dst)
        } else {
            (seg.dst, seg.src)
        };
        // A new connection on the same addresses and ports: the old one is over.
        if seg.syn
            && !seg.ack
            && let Some(c) = conns.get_mut(&key)
        {
            let e = c.endpoint(seg.src);
            if c.halves[e].isn != Some(seg.seq)
                && (c.closed || c.has_data() || c.halves[e].isn.is_some())
            {
                c.finish(pkt.ts, &mut g);
                conns.remove(&key);
            }
        }
        let conn = conns.entry(key).or_insert_with(|| {
            g.stats.connections += 1;
            Conn::new(seg.src, seg.dst, g.stats.connections, pkt.ts)
        });
        conn.segment(pkt.ts, &seg, &mut g);
    }
    g.stats.truncated = reader.truncated();
    if p.cancelled() {
        return discard(&mut g, conns, last, FormatError::Cancelled);
    }
    let mut open: Vec<Conn> = conns.into_values().filter(|c| !c.closed).collect();
    open.sort_by_key(|c| c.info.id);
    for mut c in open {
        c.finish(last, &mut g);
    }
    g.out.sort_by_key(|b| b.key);
    let ids: Vec<SessionId> = g
        .out
        .drain(..)
        .map(|b| cap.insert(b.d, b.req, b.resp))
        .collect();
    p.progress(total, total);
    let s = &g.stats;
    let mut notes = Vec::new();
    if s.tls_decrypted > 0 {
        notes.push(format!("{} TLS connection(s) decrypted", s.tls_decrypted));
    }
    if s.tls_no_keys > 0 {
        notes.push(format!(
            "{} TLS connection(s) without secrets in the key log, shown as tunnels",
            s.tls_no_keys
        ));
    }
    if s.tls_unsupported > 0 {
        notes.push(format!(
            "{} TLS connection(s) with a version or cipher suite that cannot be decrypted",
            s.tls_unsupported
        ));
    }
    if s.gaps > 0 {
        notes.push(format!("{} place(s) where packets are missing", s.gaps));
    }
    if s.orphans > 0 {
        notes.push(format!("{} response(s) without their request", s.orphans));
    }
    if s.other_conns > 0 {
        notes.push(format!("{} connection(s) not HTTP", s.other_conns));
    }
    if s.fragments > 0 {
        notes.push(format!("{} IP fragment(s) skipped", s.fragments));
    }
    if s.unknown_link > 0 {
        notes.push(format!(
            "{} packet(s) of an unsupported link type",
            s.unknown_link
        ));
    }
    if s.cut > 0 {
        notes.push(format!(
            "{} packet(s) cut short by the capture's snapshot length",
            s.cut
        ));
    }
    if s.truncated {
        notes.push("the file ends in the middle of a packet".into());
    }
    if let Some(e) = &s.corrupt {
        notes.push(format!("reading stopped at a damaged block ({e})"));
    }
    let notes = if notes.is_empty() {
        String::new()
    } else {
        format!(": {}", notes.join(", "))
    };
    tracing::info!(target: "quena", "packet capture {}: {} packet(s), {} TCP connection(s), {} session(s){notes}", path.display(), s.packets, s.connections, ids.len());
    if ids.is_empty() {
        return Err(FormatError::Invalid(format!(
            "no HTTP traffic found in {} packet(s){notes}",
            s.packets
        )));
    }
    Ok(PcapReport {
        ids,
        tls: s.tls_conns,
        decrypted: s.tls_decrypted,
        no_keys: s.tls_no_keys,
    })
}

#[cfg(test)]
mod tests;
