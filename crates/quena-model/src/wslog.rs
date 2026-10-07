//! WebSocket frames (RFC 6455) and the message log of a WebSocket session.
//!
//! The log is the session's response body, one record per frame with the payload unmasked:
//!   dir(1) opcode(1) fin(1) rsv(1) ts_us(8 LE) len(4 LE) payload(len)
//! `rsv` holds the frame's RSV1-3 bits (RSV1 = 0x4: compressed with permessage-deflate);
//! older logs have 0 there. The proxy and the packet capture import write the log, the
//! WebSocket inspector and the sanitized export read it.

/// Direction of a frame: client → server.
pub const DIR_CLIENT: u8 = 0;
/// Direction of a frame: server → client.
pub const DIR_SERVER: u8 = 1;

/// Length of a record's head (before the payload).
pub const RECORD_HEAD: usize = 16;

/// Largest frame accepted.
pub const MAX_FRAME: u64 = 64 << 20;

/// A frame as logged: header bits and unmasked payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    /// RSV1-3 (RSV1 = 0x4).
    pub rsv: u8,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// A frame larger than [`MAX_FRAME`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLarge(pub u64);

impl std::fmt::Display for TooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a {}-byte websocket frame is larger than the message log takes", self.0)
    }
}

impl std::error::Error for TooLarge {}

/// The frame at the start of `b` and its length on the wire; `Ok(None)` while `b` holds only
/// part of it.
pub fn parse_frame(b: &[u8]) -> Result<Option<(Frame, usize)>, TooLarge> {
    if b.len() < 2 {
        return Ok(None);
    }
    let masked = b[1] & 0x80 != 0;
    let (len, mut off) = match b[1] & 0x7f {
        126 if b.len() >= 4 => (u16::from_be_bytes([b[2], b[3]]) as u64, 4),
        127 if b.len() >= 10 => (u64::from_be_bytes(b[2..10].try_into().unwrap()), 10),
        126 | 127 => return Ok(None),
        n => (n as u64, 2),
    };
    if len > MAX_FRAME {
        return Err(TooLarge(len));
    }
    let key = if masked {
        let Some(k) = b.get(off..off + 4) else { return Ok(None) };
        off += 4;
        Some([k[0], k[1], k[2], k[3]])
    } else {
        None
    };
    let len = len as usize;
    let Some(p) = b.get(off..off + len) else { return Ok(None) };
    let mut payload = p.to_vec();
    if let Some(k) = key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= k[i & 3];
        }
    }
    let frame = Frame { fin: b[0] & 0x80 != 0, rsv: (b[0] >> 4) & 0x7, opcode: b[0] & 0x0f, payload };
    Ok(Some((frame, off + len)))
}

/// The head of a log record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub dir: u8,
    pub opcode: u8,
    pub fin: bool,
    pub rsv: u8,
    pub ts_us: i64,
    /// Payload length.
    pub len: u32,
}

impl Head {
    /// The head at the start of `b` (at least [`RECORD_HEAD`] bytes).
    pub fn parse(b: &[u8]) -> Option<Head> {
        let b = b.get(..RECORD_HEAD)?;
        Some(Head {
            dir: b[0],
            opcode: b[1],
            fin: b[2] != 0,
            rsv: b[3],
            ts_us: i64::from_le_bytes(b[4..12].try_into().unwrap()),
            len: u32::from_le_bytes(b[12..16].try_into().unwrap()),
        })
    }

    /// Append the record: this head with `payload` (its length replaces `len`).
    pub fn write(&self, payload: &[u8], out: &mut Vec<u8>) {
        out.push(self.dir);
        out.push(self.opcode);
        out.push(self.fin as u8);
        out.push(self.rsv);
        out.extend_from_slice(&self.ts_us.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
    }
}

/// The log record of `frame`, sent in direction `dir` at `ts_us`.
pub fn record(dir: u8, frame: &Frame, ts_us: i64) -> Vec<u8> {
    let mut r = Vec::with_capacity(RECORD_HEAD + frame.payload.len());
    let head = Head { dir, opcode: frame.opcode, fin: frame.fin, rsv: frame.rsv, ts_us, len: 0 };
    head.write(&frame.payload, &mut r);
    r
}

pub fn opcode_name(op: u8) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_and_records() {
        // Masked client text frame "Hi", compressed (RSV1), then a 200-byte server frame.
        let key = [1u8, 2, 3, 4];
        let mut wire = vec![0xc1, 0x82];
        wire.extend_from_slice(&key);
        wire.extend(b"Hi".iter().enumerate().map(|(i, b)| b ^ key[i & 3]));
        let first = wire.len();
        wire.extend_from_slice(&[0x02, 126, 0, 200]);
        wire.extend(std::iter::repeat_n(7u8, 200));
        let (f, n) = parse_frame(&wire).unwrap().unwrap();
        assert_eq!((f.fin, f.rsv, f.opcode, f.payload.as_slice(), n), (true, 4, 1, &b"Hi"[..], first));
        assert!(parse_frame(&wire[first..first + 100]).unwrap().is_none());
        let (f2, _) = parse_frame(&wire[first..]).unwrap().unwrap();
        assert_eq!((f2.fin, f2.opcode, f2.payload.len()), (false, 2, 200));
        let mut huge = vec![0x82, 127];
        huge.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
        assert_eq!(parse_frame(&huge), Err(TooLarge(MAX_FRAME + 1)));

        let r = record(DIR_SERVER, &f, 12345);
        let h = Head::parse(&r).unwrap();
        assert_eq!(h, Head { dir: DIR_SERVER, opcode: 1, fin: true, rsv: 4, ts_us: 12345, len: 2 });
        assert_eq!(&r[RECORD_HEAD..], b"Hi");
    }
}
