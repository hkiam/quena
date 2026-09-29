//! WebSocket frame log reader (M15). The frame records live in the session's
//! response body (see quena-proxy::wsframe).

use crate::AppCore;
use quena_model::SessionId;
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

fn opcode_name(op: u8) -> &'static str {
    match op {
        0x0 => "continuation",
        0x1 => "text",
        0x2 => "binary",
        0x8 => "close",
        0x9 => "ping",
        0xa => "pong",
        _ => "reserved",
    }
}

impl AppCore {
    /// Parse WebSocket frames `[start, start+count)` from the log.
    pub fn ws_frames(&self, id: SessionId, start: u64, count: usize) -> WsMessages {
        let cap = self.capture();
        let Some((_, body)) = cap.bodies_of(id) else { return WsMessages::default() };
        let total_len = body.len();
        let mut out = WsMessages { complete: body.is_complete(), ..Default::default() };
        let mut pos = 0u64;
        let mut seq = 0u64;
        let mut header = [0u8; 16];
        while pos + 16 <= total_len {
            if body.read_at(pos, &mut header).unwrap_or(0) < 16 {
                break;
            }
            let dir = header[0];
            let opcode = header[1];
            let fin = header[2] != 0;
            let time = i64::from_le_bytes(header[4..12].try_into().unwrap());
            let len = u32::from_le_bytes(header[12..16].try_into().unwrap());
            let payload_off = pos + 16;
            if seq >= start && out.frames.len() < count {
                let take = (len as usize).min(PREVIEW);
                let data = body.read_range(payload_off, take).unwrap_or_default();
                let (text, preview) = if opcode == 0x1 || (opcode == 0x8 && len >= 2) {
                    (Some(String::from_utf8_lossy(&data).into_owned()), None)
                } else if opcode == 0x2 || opcode == 0x9 || opcode == 0xa {
                    (None, Some(data.iter().take(64).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")))
                } else {
                    (None, None)
                };
                out.frames.push(WsFrame {
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
mod tests {
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
