//! WebSocket frames passing the proxy. Frames are forwarded raw and unchanged, unless
//! rules change messages ([`Editor`]); a copy of each frame goes to the session's message
//! log (format: `quena_model::wslog`) so the WebSocket inspector can show messages.

use crate::body::BoxError;
use bytes::{Buf, BytesMut};
use quena_model::wslog;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use quena_model::wslog::{DIR_CLIENT, DIR_SERVER, opcode_name, record};

/// A frame read from the wire: as logged, and its raw bytes.
#[derive(Debug)]
pub struct Frame {
    pub frame: wslog::Frame,
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
        let Some((frame, n)) = wslog::parse_frame(&self.buf)? else { return Ok(None) };
        let raw = self.buf[..n].to_vec();
        self.buf.advance(n);
        Ok(Some(Frame { frame, raw }))
    }
}

/// Where pumps send frame records, with a byte budget for records not yet stored.
pub struct FrameLog<'a> {
    pub tx: &'a tokio::sync::mpsc::Sender<Vec<u8>>,
    pub queued: &'a std::sync::atomic::AtomicUsize,
    pub budget: usize,
    /// Time of the last frame in either direction (idle detection).
    pub last: &'a std::sync::atomic::AtomicI64,
}

/// Messages larger than this pass unchanged.
pub const MAX_EDITED: usize = 1 << 20;

/// Rules that may change messages of one WebSocket.
pub struct Editor {
    pub hooks: std::sync::Arc<dyn crate::hooks::Interceptor>,
    pub view: crate::hooks::SessionView,
}

/// A frame with `payload` instead, like `orig` (FIN, RSV, opcode); masked with a new key
/// when the original was masked (client → server).
pub fn reframe(orig: &[u8], payload: &[u8]) -> Vec<u8> {
    let masked = orig.get(1).is_some_and(|b| b & 0x80 != 0);
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(orig[0]);
    let m = if masked { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => out.push(m | n as u8),
        n if n <= u16::MAX as usize => {
            out.push(m | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(m | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    if masked {
        let key: [u8; 4] = rand::random();
        out.extend_from_slice(&key);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i & 3]));
    } else {
        out.extend_from_slice(payload);
    }
    out
}

/// Forward frames from `src` to `dst`, sending each parsed frame to `log`; with an
/// `editor`, whole uncompressed text and binary messages may be changed or dropped.
/// Returns bytes forwarded and, if the direction ended abnormally, why.
/// Stops at EOF or a close frame passing through.
pub async fn pump<R, W>(mut src: R, mut dst: W, dir: u8, log: &FrameLog<'_>, editor: Option<&Editor>) -> (u64, Option<String>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering;
    let mut reader = FrameReader::default();
    let mut total = 0u64;
    let mut dropped = 0u64;
    let mut error = None;
    // Inside a fragmented message (its frames pass unchanged).
    let mut fragmented = false;
    loop {
        match reader.next(&mut src).await {
            Ok(Some(mut frame)) => {
                log.last.store(quena_model::now_us(), Ordering::Relaxed);
                let op = frame.frame.opcode;
                let whole = frame.frame.fin && !fragmented && matches!(op, 0x1 | 0x2);
                if op == 0x1 || op == 0x2 || op == 0x0 {
                    fragmented = !frame.frame.fin;
                }
                let mut send = true;
                if let Some(ed) = editor
                    && whole
                    && frame.frame.rsv == 0
                    && frame.frame.payload.len() <= MAX_EDITED
                {
                    match ed.hooks.on_ws_message(ed.view.clone(), dir, op, frame.frame.payload.clone()).await {
                        crate::hooks::WsAction::Forward => {}
                        crate::hooks::WsAction::Replace(p) => {
                            frame.raw = reframe(&frame.raw, &p);
                            frame.frame.payload = p;
                            frame.frame.rsv |= wslog::EDITED;
                        }
                        crate::hooks::WsAction::Drop => {
                            send = false;
                            frame.frame.rsv |= wslog::EDITED | wslog::DROPPED;
                        }
                    }
                }
                if send {
                    if let Err(e) = dst.write_all(&frame.raw).await {
                        error = Some(format!("write failed: {e}"));
                        break;
                    }
                    let _ = dst.flush().await;
                    total += frame.raw.len() as u64;
                }
                // Log the frame unless the store is too far behind (memory bound).
                let rec = record(dir, &frame.frame, quena_model::now_us());
                let n = rec.len();
                if log.queued.load(Ordering::Relaxed) + n <= log.budget && log.tx.try_send(rec).is_ok() {
                    log.queued.fetch_add(n, Ordering::Relaxed);
                } else {
                    dropped += 1;
                }
                if frame.frame.opcode == 0x8 {
                    // close: forward and stop this direction
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                error = Some(e.to_string());
                break;
            }
        }
    }
    let _ = dst.shutdown().await;
    if dropped > 0 && error.is_none() {
        error = Some(format!("{dropped} frames were forwarded but not logged (recording could not keep up)"));
    }
    (total, error)
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
        assert_eq!(f1.frame.opcode, 1);
        assert_eq!(f1.frame.payload, b"Hi");
        assert_eq!(f1.raw, frame);
        let f2 = r.next(&mut src).await.unwrap().unwrap();
        assert_eq!(f2.frame.opcode, 2);
        assert_eq!(f2.frame.payload.len(), 200);
        assert!(r.next(&mut src).await.unwrap().is_none());
    }

    #[test]
    fn reframe_keeps_type_and_masks_client_frames() {
        // Masked client text frame "Hi" → "Hello, longer text"; unmasked server frame of 300 bytes.
        let mut orig = vec![0x81, 0x82, 1, 2, 3, 4];
        orig.extend(b"Hi".iter().enumerate().map(|(i, b)| b ^ [1u8, 2, 3, 4][i & 3]));
        let out = reframe(&orig, b"Hello, longer text");
        let (f, n) = wslog::parse_frame(&out).unwrap().unwrap();
        assert_eq!((f.fin, f.opcode, f.payload.as_slice(), n), (true, 1, &b"Hello, longer text"[..], out.len()));
        assert!(out[1] & 0x80 != 0, "still masked");
        let big = vec![b'x'; 300];
        let out = reframe(&[0x82, 0x01, 0], &big);
        assert_eq!(&out[..4], &[0x82, 126, 1, 44]);
        let (f, _) = wslog::parse_frame(&out).unwrap().unwrap();
        assert_eq!(f.payload, big);
    }
}
