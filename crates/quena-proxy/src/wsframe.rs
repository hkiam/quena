//! WebSocket frame parsing for the message log (RFC 6455). Frames are forwarded
//! raw and unchanged; a copy of each frame is logged (payload unmasked) so the
//! WebSocket inspector can show messages. Record format in the log body:
//!   dir(1) opcode(1) fin(1) reserved(1) ts_us(8 LE) len(4 LE) payload(len)

use crate::body::BoxError;
use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DIR_CLIENT: u8 = 0; // client → server
pub const DIR_SERVER: u8 = 1; // server → client

#[derive(Debug)]
pub struct Frame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
    /// Raw bytes as seen on the wire (header + masked payload), forwarded unchanged.
    pub raw: Vec<u8>,
}

/// Incremental WebSocket frame reader.
pub struct FrameReader {
    buf: BytesMut,
    eof: bool,
}

impl Default for FrameReader {
    fn default() -> Self {
        FrameReader { buf: BytesMut::with_capacity(16 * 1024), eof: false }
    }
}

impl FrameReader {
    /// Read the next frame from `src`, returning None at clean EOF.
    pub async fn next<R: AsyncRead + Unpin>(&mut self, src: &mut R) -> Result<Option<Frame>, BoxError> {
        loop {
            if let Some(frame) = self.try_parse()? {
                return Ok(Some(frame));
            }
            if self.eof {
                return Ok(None);
            }
            let mut tmp = [0u8; 16 * 1024];
            let n = src.read(&mut tmp).await?;
            if n == 0 {
                self.eof = true;
                if self.buf.is_empty() {
                    return Ok(None);
                }
            } else {
                self.buf.extend_from_slice(&tmp[..n]);
            }
        }
    }

    fn try_parse(&mut self) -> Result<Option<Frame>, BoxError> {
        let b = &self.buf;
        if b.len() < 2 {
            return Ok(None);
        }
        let fin = b[0] & 0x80 != 0;
        let opcode = b[0] & 0x0f;
        let masked = b[1] & 0x80 != 0;
        let len7 = (b[1] & 0x7f) as usize;
        let mut off = 2;
        let payload_len = match len7 {
            126 => {
                if b.len() < 4 {
                    return Ok(None);
                }
                let l = u16::from_be_bytes([b[2], b[3]]) as usize;
                off = 4;
                l
            }
            127 => {
                if b.len() < 10 {
                    return Ok(None);
                }
                let l = u64::from_be_bytes(b[2..10].try_into().unwrap());
                if l > (64 << 20) {
                    return Err("websocket frame too large".into());
                }
                off = 10;
                l as usize
            }
            n => n,
        };
        let mask_key = if masked {
            if b.len() < off + 4 {
                return Ok(None);
            }
            let k = [b[off], b[off + 1], b[off + 2], b[off + 3]];
            off += 4;
            Some(k)
        } else {
            None
        };
        if b.len() < off + payload_len {
            return Ok(None);
        }
        let raw = b[..off + payload_len].to_vec();
        let mut payload = b[off..off + payload_len].to_vec();
        if let Some(k) = mask_key {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= k[i & 3];
            }
        }
        self.buf.advance(off + payload_len);
        Ok(Some(Frame { fin, opcode, payload, raw }))
    }
}

/// Encode one log record.
pub fn record(dir: u8, frame: &Frame, ts_us: i64) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + frame.payload.len());
    r.push(dir);
    r.push(frame.opcode);
    r.push(frame.fin as u8);
    r.push(0);
    r.extend_from_slice(&ts_us.to_le_bytes());
    r.extend_from_slice(&(frame.payload.len() as u32).to_le_bytes());
    r.extend_from_slice(&frame.payload);
    r
}

/// Forward frames from `src` to `dst`, sending each parsed frame to `log`.
/// Returns bytes forwarded. Stops at EOF or a close frame passing through.
pub async fn pump<R, W>(mut src: R, mut dst: W, dir: u8, log: &tokio::sync::mpsc::Sender<Vec<u8>>) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = FrameReader::default();
    let mut total = 0u64;
    loop {
        match reader.next(&mut src).await {
            Ok(Some(frame)) => {
                if dst.write_all(&frame.raw).await.is_err() {
                    break;
                }
                let _ = dst.flush().await;
                total += frame.raw.len() as u64;
                let rec = record(dir, &frame, quena_model::now_us());
                let _ = log.try_send(rec);
                if frame.opcode == 0x8 {
                    // close: forward and stop this direction
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    let _ = dst.shutdown().await;
    total
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
    use tokio::io::BufReader;

    #[tokio::test]
    async fn parse_masked_and_unmasked() {
        // Client text frame "Hi" masked with key 0x01020304
        let key = [1u8, 2, 3, 4];
        let payload = b"Hi";
        let masked: Vec<u8> = payload.iter().enumerate().map(|(i, b)| b ^ key[i & 3]).collect();
        let mut frame = vec![0x81, 0x82];
        frame.extend_from_slice(&key);
        frame.extend_from_slice(&masked);
        // Server binary frame of 200 bytes, unmasked, len 126 path
        let mut big = vec![0x82, 126, 0, 200];
        big.extend(std::iter::repeat_n(7u8, 200));
        let mut data = frame.clone();
        data.extend_from_slice(&big);
        let mut r = FrameReader::default();
        let mut src = BufReader::new(&data[..]);
        let f1 = r.next(&mut src).await.unwrap().unwrap();
        assert_eq!(f1.opcode, 1);
        assert_eq!(f1.payload, b"Hi");
        assert_eq!(f1.raw, frame);
        let f2 = r.next(&mut src).await.unwrap().unwrap();
        assert_eq!(f2.opcode, 2);
        assert_eq!(f2.payload.len(), 200);
        assert!(r.next(&mut src).await.unwrap().is_none());
    }
}
