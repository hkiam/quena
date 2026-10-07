//! Packet captures (pcap, pcapng from Wireshark, tcpdump, dumpcap): TCP connections are
//! reassembled and their HTTP read back into sessions.
//!
//! Plain HTTP/1.x (with WebSocket) and cleartext HTTP/2 (h2c) become sessions with timers
//! from the packet times. TLS connections cannot be read without their keys: each one becomes
//! a tunnel session with what its handshake shows (SNI, ALPN, version, cipher). Bytes missing
//! from the capture end the message they fall into, which says so in its error.

mod file;
mod h1;
mod h2;
mod net;
mod tcp;
mod tls;
mod ws;

use crate::{FormatError, Progress, Result};
use quena_body::{Body, BodyWriter};
use quena_model::{ConnectionInfo, HttpVersion, Micros, RequestHead, ResponseHead, SessionDetail, SessionId, SessionKind, SessionState, TlsInfo, flags};
use quena_store::Capture;
use std::cell::Cell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

const CLIENT: usize = 0;
const SERVER: usize = 1;

/// Bytes looked at to tell the protocol of a connection.
const MAX_SNIFF: usize = 64 << 10;

fn side_name(side: usize) -> &'static str {
    if side == CLIENT { "request" } else { "response" }
}

fn peer_name(side: usize) -> &'static str {
    if side == CLIENT { "client" } else { "server" }
}

fn host_of(a: &SocketAddr, default_port: u16) -> String {
    let ip = match a.ip() {
        IpAddr::V6(v6) => format!("[{v6}]"),
        IpAddr::V4(v4) => v4.to_string(),
    };
    if a.port() == default_port { ip } else { format!("{ip}:{}", a.port()) }
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
}

impl ConnInfo {
    /// The server as a Host header would name it.
    fn server_host(&self) -> String {
        host_of(&self.server, 80)
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
            tls: None,
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
            d.extra_flags.push(("x-tunnel-bytes".into(), format!("{up} up / {down} down")));
            d.summary.custom = format!("↑{up} ↓{down}");
        }
        d.request = ex.req;
        d.response = ex.resp;
        d.summary.state = if ex.error.is_some() { SessionState::Aborted } else { SessionState::Done };
        d.error = ex.error;
        d.summary.flags |= flags::IMPORTED;
        d.summary.started_at = start;
        self.out.push(Built { key: (start, c.id, ex.seq), d, req, resp });
    }
}

/// A TLS connection (or another protocol inside a CONNECT tunnel or after an upgrade):
/// counted, and the handshake read for what it tells in the clear.
struct Tunnel {
    ex: Exchange,
    hello: [tls::HelloReader; 2],
    info: TlsInfo,
    tls: bool,
    /// Not inside a CONNECT: the target is named after the server (or its SNI).
    direct: bool,
}

impl Tunnel {
    fn direct(cx: &mut Cx, ts: Micros) -> Tunnel {
        let url = host_of(&cx.conn.server, 0);
        let req = RequestHead { method: "CONNECT".into(), url, version: HttpVersion::Http11, headers: Default::default() };
        let mut ex = Exchange::new(cx, req, ts, ts);
        ex.kind = SessionKind::Tunnel;
        ex.end[CLIENT] = Some(ts);
        Tunnel { ex, hello: Default::default(), info: TlsInfo::default(), tls: false, direct: true }
    }

    fn connect(mut ex: Exchange) -> Tunnel {
        ex.kind = SessionKind::Tunnel;
        ex.end[SERVER] = None;
        Tunnel { ex, hello: Default::default(), info: TlsInfo::default(), tls: false, direct: false }
    }

    fn data(&mut self, side: usize, data: &[u8], ts: Micros) {
        self.ex.bytes[side] += data.len() as u64;
        if self.ex.start[SERVER].is_none() && side == SERVER {
            self.ex.start[SERVER] = Some(ts);
        }
        if let Some((ty, body)) = self.hello[side].feed(data) {
            match (side, ty) {
                (CLIENT, 1) => tls::client_hello(&body, &mut self.info),
                (SERVER, 2) => tls::server_hello(&body, &mut self.info),
                _ => return,
            }
            self.tls = true;
        }
    }

    fn gap(&mut self, side: usize, n: u64) {
        self.ex.bytes[side] += n;
        // The handshake can no longer be followed.
        self.hello[side].done = true;
    }

    fn close(mut self, ts: Micros, cx: &mut Cx) {
        if self.tls {
            cx.stats.tls_conns += 1;
            if self.direct
                && let Some(sni) = &self.info.sni
            {
                self.ex.req.url = format!("{sni}:{}", cx.conn.server.port());
            }
            self.ex.tls = Some(self.info);
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
    Ws(ws::Ws),
    Tunnel(Tunnel),
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
    if h1::looks_like_request(p) == Some(true) || p.starts_with(b"PRI * HTTP/2") || (tls::looks_like_tls(p) && p.get(5) == Some(&1)) {
        Some(true)
    } else if h1::looks_like_response(p) == Some(true) || (tls::looks_like_tls(p) && p.get(5) == Some(&2)) {
        Some(false)
    } else {
        None
    }
}

struct Global<'a> {
    cap: &'a Arc<Capture>,
    stats: Stats,
    out: Vec<Built>,
}

impl Conn {
    fn new(a: SocketAddr, b: SocketAddr, id: u64, ts: Micros) -> Conn {
        Conn {
            info: ConnInfo { id, client: a, server: b, syn: None, synack: None, first: ts, exchanges: 0 },
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
        let (c, s) = if a_client { (self.a, other) } else { (other, self.a) };
        self.info.client = c;
        self.info.server = s;
    }

    fn side(&self, endpoint: usize) -> usize {
        if (endpoint == 0) == self.a_client.unwrap_or(true) { CLIENT } else { SERVER }
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
        let mut cx = Cx { cap: g.cap, conn: &mut self.info, stats: &mut g.stats, out: &mut g.out };
        match ev {
            tcp::Ev::Data(d) => Self::data(&mut self.proto, &mut self.sniff, side, &d, ts, ts, &mut cx),
            tcp::Ev::Gap(n) => {
                cx.stats.gaps += 1;
                Self::gap(&mut self.proto, &mut self.sniff, side, n, ts, &mut cx);
            }
            tcp::Ev::Fin => {
                if let Proto::H1(h) = &mut self.proto {
                    h.fin(side, ts, &mut cx);
                }
            }
        }
    }

    fn gap(proto: &mut Proto, sniff: &mut Sniff, side: usize, n: u64, ts: Micros, cx: &mut Cx) {
        match proto {
            Proto::H1(h) => h.gap(side, n, ts, cx),
            Proto::H2(h) => h.gap(side, n, ts, cx),
            Proto::Ws(w) => w.gap(side, n),
            Proto::Tunnel(t) => t.gap(side, n),
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
    fn data(proto: &mut Proto, sniff: &mut Sniff, side: usize, d: &[u8], first: Micros, ts: Micros, cx: &mut Cx) {
        match proto {
            Proto::Sniff => {
                sniff.buf[side].extend_from_slice(d);
                sniff.ts[side].get_or_insert(first);
                let Some(p) = detect(sniff, cx, ts) else { return };
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
                        h1::Switch::WebSocket => Proto::Ws(ws::Ws::new(up.ex)),
                        h1::Switch::H2c => Proto::H2(Box::new(h2::H2::new(Some(up.ex)))),
                        h1::Switch::Tunnel => Proto::Tunnel(Tunnel::connect(up.ex)),
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
            Proto::Tunnel(t) => t.data(side, d, ts),
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
        let mut cx = Cx { cap: g.cap, conn: &mut self.info, stats: &mut g.stats, out: &mut g.out };
        match std::mem::replace(&mut self.proto, Proto::Closed) {
            Proto::H1(h) => h.close(ts, &mut cx),
            Proto::H2(h) => h.close(ts, &mut cx),
            Proto::Ws(w) => w.close(ts, &mut cx),
            Proto::Tunnel(t) => t.close(ts, &mut cx),
            Proto::Other => cx.stats.other_conns += 1,
            Proto::Sniff if self.sniff.buf.iter().any(|b| !b.is_empty()) => cx.stats.other_conns += 1,
            Proto::Sniff | Proto::Closed => {}
        }
        self.sniff = Sniff::default();
        self.closed = true;
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
            _ if s.len() > MAX_SNIFF && (!sniff.had_syn || sniff.gap[SERVER] > 0) => Some(Proto::H1(Default::default())),
            _ if s.len() > MAX_SNIFF => Some(Proto::Other),
            _ => None,
        };
    }
    if c.len() < 3 && c[0] == 0x16 {
        return None;
    }
    if tls::looks_like_tls(c) {
        return Some(Proto::Tunnel(Tunnel::direct(cx, start)));
    }
    let n = c.len().min(h2::PREFACE.len());
    if c[..n] == h2::PREFACE[..n] {
        return (n == h2::PREFACE.len()).then(|| Proto::H2(Box::new(h2::H2::new(None))));
    }
    match h1::looks_like_request(c) {
        Some(true) => Some(Proto::H1(Default::default())),
        None => None,
        // Picked up mid-connection: TLS by its port, HTTP/1 from its next message on.
        Some(false) if mid && cx.conn.server.port() == 443 => Some(Proto::Tunnel(Tunnel::direct(cx, start))),
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
    if e.kind() == io::ErrorKind::InvalidData { FormatError::Invalid(e.to_string()) } else { FormatError::Io(e) }
}

/// Import a pcap or pcapng file into `cap`. Returns the new session ids, in the order of
/// their requests.
pub fn import(cap: &Arc<Capture>, path: &Path, p: &dyn Progress) -> Result<Vec<SessionId>> {
    let total = std::fs::metadata(path)?.len();
    let read = Rc::new(Cell::new(0));
    let src = Counting { inner: BufReader::with_capacity(1 << 20, File::open(path)?), n: read.clone() };
    let mut reader = file::Reader::new(src).map_err(read_err)?;
    let mut g = Global { cap, stats: Stats::default(), out: Vec::new() };
    let mut conns: HashMap<(SocketAddr, SocketAddr), Conn> = HashMap::new();
    let mut last = 0;
    // Nothing is inserted: the bodies stored so far go again, also those of open connections.
    let discard = |g: &mut Global, conns: HashMap<(SocketAddr, SocketAddr), Conn>, last: Micros, err: FormatError| -> Result<Vec<SessionId>> {
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
            Ok(Some(pkt)) => pkt,
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
        let key = if seg.src <= seg.dst { (seg.src, seg.dst) } else { (seg.dst, seg.src) };
        // A new connection on the same addresses and ports: the old one is over.
        if seg.syn
            && !seg.ack
            && let Some(c) = conns.get_mut(&key)
        {
            let e = c.endpoint(seg.src);
            if c.halves[e].isn != Some(seg.seq) && (c.closed || c.has_data() || c.halves[e].isn.is_some()) {
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
    let ids: Vec<SessionId> = g.out.drain(..).map(|b| cap.insert(b.d, b.req, b.resp)).collect();
    p.progress(total, total);
    let s = &g.stats;
    let mut notes = Vec::new();
    if s.tls_conns > 0 {
        notes.push(format!("{} TLS connection(s) shown as tunnels (not decrypted)", s.tls_conns));
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
        notes.push(format!("{} packet(s) of an unsupported link type", s.unknown_link));
    }
    if s.cut > 0 {
        notes.push(format!("{} packet(s) cut short by the capture's snapshot length", s.cut));
    }
    if s.truncated {
        notes.push("the file ends in the middle of a packet".into());
    }
    if let Some(e) = &s.corrupt {
        notes.push(format!("reading stopped at a damaged block ({e})"));
    }
    let notes = if notes.is_empty() { String::new() } else { format!(": {}", notes.join(", ")) };
    tracing::info!(target: "quena", "packet capture {}: {} packet(s), {} TCP connection(s), {} session(s){notes}", path.display(), s.packets, s.connections, ids.len());
    if ids.is_empty() {
        return Err(FormatError::Invalid(format!("no HTTP traffic found in {} packet(s){notes}", s.packets)));
    }
    Ok(ids)
}

#[cfg(test)]
mod tests;
