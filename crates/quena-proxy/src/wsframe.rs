//! WebSocket frames passing the proxy. Frames are forwarded raw and unchanged; a copy of
//! each frame goes to the session's message log (format: `quena_model::wslog`) so the
//! WebSocket inspector can show messages.

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

/// Forward frames from `src` to `dst`, sending each parsed frame to `log`.
/// Returns bytes forwarded and, if the direction ended abnormally, why.
/// Stops at EOF or a close frame passing through.
pub async fn pump<R, W>(mut src: R, mut dst: W, dir: u8, log: &FrameLog<'_>) -> (u64, Option<String>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering;
    let mut reader = FrameReader::default();
    let mut total = 0u64;
    let mut dropped = 0u64;
    let mut error = None;
    loop {
        match reader.next(&mut src).await {
            Ok(Some(frame)) => {
                log.last.store(quena_model::now_us(), Ordering::Relaxed);
                if let Err(e) = dst.write_all(&frame.raw).await {
                    error = Some(format!("write failed: {e}"));
                    break;
                }
                let _ = dst.flush().await;
                total += frame.raw.len() as u64;
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
}
