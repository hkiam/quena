//! WebSocket frame log reader (M15). The frame records live in the session's
//! response body (format: `quena_model::wslog`).

use crate::AppCore;
use quena_model::SessionId;
use quena_model::wslog::{self, RECORD_HEAD, opcode_name};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WsFrame {
    pub seq: u64,
    /// 0 = client→server, 1 = server→client.
    pub dir: u8,
    pub opcode: u8,
    pub opcode_name: String,
    pub fin: bool,
    pub time: i64,
    pub len: u32,
    /// UTF-8 text for text frames (truncated), else None.
    pub text: Option<String>,
    /// Hex/preview for binary/control frames.
    pub preview: Option<String>,
    /// Byte offset of the payload in the log (for "load full").
    pub offset: u64,
    /// Changed by Quena on the way (rules script, rewrite rule).
    pub edited: bool,
    /// Not sent at all (dropped by the rules script); the text is what arrived.
    pub dropped: bool,
    /// The Socket.IO packet, for Socket.IO sessions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sio: Option<crate::socketio::SioPacket>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WsMessages {
    pub total: u64,
    pub frames: Vec<WsFrame>,
    pub complete: bool,
    pub truncated: bool,
}

const PREVIEW: usize = 4096;

/// Largest message inflated (permessage-deflate); a larger one stays as it is.
const MAX_INFLATED: usize = 64 << 20;

/// permessage-deflate (RFC 7692) as the server accepted it: messages with RSV1 are raw
/// DEFLATE, each direction one stream unless `*_no_context_takeover` resets it per message.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct Deflate {
    pub on: bool,
    /// Per direction (0 client→server, 1 server→client): a new window for every message.
    pub reset: [bool; 2],
}

impl Deflate {
    /// From the response's `Sec-WebSocket-Extensions`.
    pub(crate) fn of(resp: Option<&quena_model::ResponseHead>) -> Deflate {
        let Some(ext) = resp.and_then(|r| r.headers.get("sec-websocket-extensions")) else { return Deflate::default() };
        let Some(pmd) = ext.split(',').map(str::trim).find(|e| e.split(';').next().is_some_and(|n| n.trim().eq_ignore_ascii_case("permessage-deflate"))) else { return Deflate::default() };
        let has = |p: &str| pmd.split(';').skip(1).any(|x| x.trim().split('=').next().is_some_and(|k| k.trim().eq_ignore_ascii_case(p)));
        Deflate { on: true, reset: [has("client_no_context_takeover"), has("server_no_context_takeover")] }
    }
}

/// Puts the frames of both directions together into messages, inflating compressed ones.
pub(crate) struct Assembler {
    deflate: Deflate,
    inflate: [Option<flate2::Decompress>; 2],
    /// Per direction: opcode, compressed, payload so far, time of the first frame.
    cur: [Option<(u8, bool, Vec<u8>, i64)>; 2],
}

/// A whole message.
pub(crate) struct Message {
    pub dir: u8,
    pub opcode: u8,
    pub time: i64,
    pub data: Vec<u8>,
    /// It was compressed and could be inflated.
    pub inflated: bool,
}

impl Assembler {
    pub(crate) fn new(deflate: Deflate) -> Assembler {
        Assembler { deflate, inflate: [None, None], cur: [None, None] }
    }

    /// Frame `h` with its payload; a message once its last frame is in. Control frames come
    /// as they are.
    pub(crate) fn push(&mut self, h: &wslog::Head, payload: &[u8]) -> Option<Message> {
        let d = (h.dir & 1) as usize;
        if h.opcode >= 0x8 {
            return Some(Message { dir: h.dir, opcode: h.opcode, time: h.ts_us, data: payload.to_vec(), inflated: false });
        }
        if h.opcode != 0 {
            self.cur[d] = Some((h.opcode, self.deflate.on && h.rsv & 0x4 != 0, Vec::new(), h.ts_us));
        }
        let (_, _, buf, _) = self.cur[d].as_mut()?;
        if buf.len() + payload.len() <= MAX_INFLATED {
            buf.extend_from_slice(payload);
        }
        if !h.fin {
            return None;
        }
        let (opcode, compressed, buf, time) = self.cur[d].take()?;
        if !compressed {
            return Some(Message { dir: h.dir, opcode, time, data: buf, inflated: false });
        }
        match self.inflate_msg(d, &buf) {
            Some(data) => Some(Message { dir: h.dir, opcode, time, data, inflated: true }),
            None => Some(Message { dir: h.dir, opcode, time, data: buf, inflated: false }),
        }
    }

    fn inflate_msg(&mut self, d: usize, raw: &[u8]) -> Option<Vec<u8>> {
        if self.deflate.reset[d] {
            self.inflate[d] = None;
        }
        let z = self.inflate[d].get_or_insert_with(|| flate2::Decompress::new(false));
        let mut input = raw.to_vec();
        input.extend_from_slice(&[0, 0, 0xff, 0xff]);
        let start = z.total_in();
        let mut out = Vec::with_capacity((raw.len() * 4).min(MAX_INFLATED));
        loop {
            let used = (z.total_in() - start) as usize;
            if used >= input.len() || out.len() >= MAX_INFLATED {
                break;
            }
            out.reserve(64 * 1024);
            let before = out.len();
            if z.decompress_vec(&input[used..], &mut out, flate2::FlushDecompress::Sync).is_err() {
                // A broken stream: later messages of this direction cannot be read either.
                self.inflate[d] = None;
                return None;
            }
            if out.len() == before && (z.total_in() - start) as usize == used {
                break;
            }
        }
        Some(out)
    }
}

/// Cap a (lossily decoded) text preview at `PREVIEW` bytes on a char boundary;
/// replacement chars make the string longer than the bytes read.
fn cut_preview(t: String) -> String {
    if t.len() <= PREVIEW {
        return t;
    }
    let mut end = PREVIEW;
    while !t.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &t[..end])
}

impl AppCore {
    /// Parse WebSocket frames `[start, start+count)` from the log.
    pub fn ws_frames(&self, id: SessionId, start: u64, count: usize) -> WsMessages {
        let cap = self.capture();
        let Some((_, body)) = cap.bodies_of(id) else { return WsMessages::default() };
        let total_len = body.len();
        let mut out = WsMessages { complete: body.is_complete(), ..Default::default() };
        let detail = cap.detail(id);
        let sio = detail.as_ref().is_some_and(|d| crate::socketio::is_socketio(&d.request.url));
        // Compressed messages are shown inflated: every data frame up to the page is read, as
        // each compressed message may depend on those before it.
        let deflate = Deflate::of(detail.as_ref().and_then(|d| d.response.as_ref()));
        let mut asm = deflate.on.then(|| Assembler::new(deflate));
        let mut pos = 0u64;
        let mut seq = 0u64;
        let mut header = [0u8; RECORD_HEAD];
        while pos + RECORD_HEAD as u64 <= total_len {
            if body.read_at(pos, &mut header).unwrap_or(0) < RECORD_HEAD {
                break;
            }
            let Some(wslog::Head { dir, opcode, fin, rsv, ts_us: time, len }) = wslog::Head::parse(&header) else { break };
            let payload_off = pos + RECORD_HEAD as u64;
            let in_page = seq >= start && out.frames.len() < count;
            let mut inflated: Option<Vec<u8>> = None;
            if let Some(a) = asm.as_mut()
                && (in_page || seq < start)
                && opcode < 0x8
            {
                let full = body.read_range(payload_off, len as usize).unwrap_or_default();
                if let Some(m) = a.push(&wslog::Head { dir, opcode, fin, rsv, ts_us: time, len }, &full)
                    && m.inflated
                {
                    inflated = Some(m.data);
                }
            }
            if in_page {
                let take = (len as usize).min(PREVIEW);
                let data = match &inflated {
                    Some(m) => m[..m.len().min(PREVIEW)].to_vec(),
                    None => body.read_range(payload_off, take).unwrap_or_default(),
                };
                let (text, preview) = if opcode == 0x1 || (opcode == 0x8 && len >= 2) {
                    (Some(String::from_utf8_lossy(&data).into_owned()), None)
                } else if opcode == 0x2 || opcode == 0x9 || opcode == 0xa {
                    (None, Some(data.iter().take(64).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")))
                } else {
                    (None, None)
                };
                let packet = match (sio, opcode) {
                    (true, 0x1) => text.as_deref().and_then(crate::socketio::decode_packet),
                    (true, 0x2) => Some(crate::socketio::SioPacket { eio: "attachment".into(), ..Default::default() }),
                    _ => None,
                };
                out.frames.push(WsFrame {
                    edited: rsv & wslog::EDITED != 0,
                    dropped: rsv & wslog::DROPPED != 0,
                    sio: packet,
                    seq,
                    dir,
                    opcode,
                    opcode_name: opcode_name(opcode).into(),
                    fin,
                    time,
                    len,
                    text: text.map(cut_preview),
                    preview,
                    offset: payload_off,
                });
            }
            seq += 1;
            pos = payload_off + len as u64;
        }
        out.total = seq;
        out
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{AppCore, Paths};
    use quena_model::{SessionDetail, SessionKind};

    fn rec(dir: u8, opcode: u8, payload: &[u8], ts: i64) -> Vec<u8> {
        let mut r = vec![dir, opcode, 1, 0];
        r.extend_from_slice(&ts.to_le_bytes());
        r.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        r.extend_from_slice(payload);
        r
    }

    #[test]
    fn parse_frames() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("settings.json"), "{}").unwrap();
        let core = AppCore::new(Paths::at(dir.path().to_path_buf()), crate::logbuf::LogBuffer::new(10)).unwrap();
        let cap = core.capture();
        let mut log = rec(0, 1, b"hello", 100);
        log.extend(rec(1, 1, b"{\"tick\":1}", 200));
        log.extend(rec(0, 9, &[1, 2, 3], 300)); // ping
        let mut d = SessionDetail::default();
        d.summary.kind = SessionKind::WebSocket;
        let body = cap.bodies.store_bytes(&log);
        let empty = cap.bodies.store_bytes(&[]);
        let id = cap.insert(d, empty, body);
        let m = core.ws_frames(id, 0, 100);
        assert_eq!(m.total, 3);
        assert_eq!(m.frames[0].dir, 0);
        assert_eq!(m.frames[0].text.as_deref(), Some("hello"));
        assert_eq!(m.frames[1].opcode_name, "text");
        assert_eq!(m.frames[1].text.as_deref(), Some("{\"tick\":1}"));
        assert_eq!(m.frames[2].opcode_name, "ping");
        assert!(m.frames[2].preview.is_some());
        // pagination
        let m2 = core.ws_frames(id, 1, 1);
        assert_eq!(m2.frames.len(), 1);
        assert_eq!(m2.frames[0].seq, 1);
    }

    /// A log record with RSV bits.
    pub(crate) fn rec_rsv(dir: u8, opcode: u8, rsv: u8, payload: &[u8], ts: i64) -> Vec<u8> {
        let mut r = vec![dir, opcode, 1, rsv];
        r.extend_from_slice(&ts.to_le_bytes());
        r.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        r.extend_from_slice(payload);
        r
    }

    /// Messages of one direction compressed like permessage-deflate (one stream, context kept).
    pub(crate) fn deflate_all(msgs: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut z = flate2::Compress::new(flate2::Compression::default(), false);
        msgs.iter()
            .map(|m| {
                let mut out = Vec::with_capacity(m.len() + 64);
                z.compress_vec(m, &mut out, flate2::FlushCompress::Sync).unwrap();
                assert!(out.ends_with(&[0, 0, 0xff, 0xff]));
                out.truncate(out.len() - 4);
                out
            })
            .collect()
    }

    #[test]
    fn compressed_messages_are_shown_inflated() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("settings.json"), "{}").unwrap();
        let core = AppCore::new(Paths::at(dir.path().to_path_buf()), crate::logbuf::LogBuffer::new(10)).unwrap();
        let cap = core.capture();
        // The second message refers back to the first (context takeover).
        let z = deflate_all(&[b"{\"hello\":\"world\",\"n\":1}", b"{\"hello\":\"world\",\"n\":2}"]);
        let mut log = rec_rsv(1, 1, 4, &z[0], 100);
        log.extend(rec_rsv(0, 1, 0, b"plain", 150));
        log.extend(rec_rsv(1, 1, 4, &z[1], 200));
        let mut d = SessionDetail::default();
        d.summary.kind = SessionKind::WebSocket;
        let mut h = quena_model::Headers::default();
        h.push("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits=15");
        d.response = Some(quena_model::ResponseHead { status: 101, headers: h, ..Default::default() });
        let id = cap.insert(d, cap.bodies.store_bytes(&[]), cap.bodies.store_bytes(&log));
        let m = core.ws_frames(id, 0, 10);
        let texts: Vec<_> = m.frames.iter().map(|f| f.text.clone().unwrap_or_default()).collect();
        assert_eq!(texts, ["{\"hello\":\"world\",\"n\":1}", "plain", "{\"hello\":\"world\",\"n\":2}"]);
        // A page past the first message still inflates the second.
        assert_eq!(core.ws_frames(id, 2, 1).frames[0].text.as_deref(), Some("{\"hello\":\"world\",\"n\":2}"));
        assert_eq!(Deflate::of(None), Deflate::default());
    }

    #[test]
    fn preview_cut_on_char_boundary() {
        // Invalid bytes turn into 3-byte U+FFFD, multi-byte chars straddle PREVIEW.
        let t = String::from_utf8_lossy(&[0xffu8; PREVIEW]).into_owned();
        assert!(cut_preview(t).ends_with('…'));
        let t = format!("a{}", "ä".repeat(PREVIEW));
        let c = cut_preview(t);
        assert!(c.len() <= PREVIEW + '…'.len_utf8());
        assert_eq!(cut_preview("short".into()), "short");
    }
}
