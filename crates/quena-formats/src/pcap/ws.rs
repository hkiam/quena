//! WebSocket frames after an upgrade, written to the session's message log
//! (`quena_model::wslog`), as the proxy does.

use super::{Cx, Exchange, peer_name};
use quena_model::{Micros, SessionKind, wslog};

pub struct Ws {
    ex: Exchange,
    bufs: [Vec<u8>; 2],
    broken: bool,
}

impl Ws {
    pub fn new(mut ex: Exchange) -> Ws {
        ex.kind = SessionKind::WebSocket;
        // The response body becomes the message log: what the handshake response carried goes.
        ex.end[super::SERVER] = None;
        Ws {
            ex,
            bufs: [Vec::new(), Vec::new()],
            broken: false,
        }
    }

    pub fn data(&mut self, side: usize, data: &[u8], ts: Micros) {
        if self.broken {
            return;
        }
        let buf = &mut self.bufs[side];
        buf.extend_from_slice(data);
        let mut used = 0;
        loop {
            match wslog::parse_frame(&buf[used..]) {
                Ok(Some((frame, n))) => {
                    self.ex
                        .write(super::SERVER, &wslog::record(side as u8, &frame, ts));
                    used += n;
                }
                Ok(None) => break,
                Err(e) => {
                    self.ex.fail(format!(
                        "{} frames: {e}; later frames are not shown",
                        peer_name(side)
                    ));
                    self.broken = true;
                    break;
                }
            }
        }
        buf.drain(..used);
    }

    pub fn gap(&mut self, side: usize, n: u64) {
        if !self.broken {
            self.ex.fail(format!(
                "{n} bytes of the {} frames are missing in the capture; later frames are not shown",
                peer_name(side)
            ));
            self.broken = true;
        }
    }

    /// The frames end here (decryption stopped).
    pub fn cut(&mut self, why: &str) {
        if !self.broken {
            self.ex.fail(format!("{why}; later frames are not shown"));
            self.broken = true;
        }
    }

    pub fn close(mut self, ts: Micros, cx: &mut Cx) {
        self.ex.end[super::SERVER] = Some(ts);
        cx.emit(self.ex);
    }
}
