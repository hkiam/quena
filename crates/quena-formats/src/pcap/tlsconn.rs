//! One TLS connection followed record by record in both directions: the hellos in the
//! clear, then, with the connection's secrets from a key log, the protected records
//! decrypted into the application data of each side.

use super::keylog::KeyLog;
use super::tls::{self, ServerHello};
use super::tlsrec::{self, Protection};
use super::{CLIENT, SERVER};
use quena_model::TlsInfo;

/// Largest record on the wire (2^14 plus the largest expansion).
const MAX_RECORD: usize = (1 << 14) + 2048;
/// Handshake bytes kept while a message is incomplete.
const MAX_HANDSHAKE: usize = 1 << 20;

const CHANGE_CIPHER_SPEC: u8 = 20;
const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;

/// Whether the connection can be read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Keys {
    /// No ServerHello yet.
    #[default]
    Pending,
    /// Decrypting.
    Found,
    /// The key log has no secrets for this connection.
    Missing,
    /// A version or cipher suite that cannot be decrypted.
    Unsupported(String),
}

#[derive(Default)]
pub struct TlsConn {
    bufs: [Vec<u8>; 2],
    /// Handshake messages in the clear, and decrypted ones (TLS 1.3), being reassembled.
    plain_hs: [Vec<u8>; 2],
    sealed_hs: [Vec<u8>; 2],
    pub info: TlsInfo,
    client_random: Option<[u8; 32]>,
    server: Option<ServerHello>,
    pub keys: Keys,
    /// Current protection per side.
    prot: [Option<Protection>; 2],
    /// Protection that takes over: TLS 1.2 after ChangeCipherSpec, TLS 1.3 after Finished.
    next: [Option<Protection>; 2],
    /// Sides that can no longer be followed (bytes lost, not TLS).
    dead: [bool; 2],
    /// Why decryption stopped, if it did.
    pub broken: Option<String>,
    /// Encrypted records that were skipped (0-RTT early data).
    pub skipped: u32,
    /// Any handshake seen: this is TLS.
    pub seen: bool,
}

impl TlsConn {
    /// Feed bytes of one side; returns the application data decrypted from them.
    pub fn feed(&mut self, side: usize, data: &[u8], keys: &KeyLog) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.dead[side] {
            return out;
        }
        self.bufs[side].extend_from_slice(data);
        let mut used = 0;
        while self.bufs[side].len() - used >= 5 {
            let b = &self.bufs[side][used..];
            let (ty, version, len) = (
                b[0],
                u16::from_be_bytes([b[1], b[2]]),
                u16::from_be_bytes([b[3], b[4]]) as usize,
            );
            if !(CHANGE_CIPHER_SPEC..=APPLICATION_DATA).contains(&ty)
                || b[1] != 3
                || len > MAX_RECORD
            {
                self.stop(side, "the connection stopped looking like TLS");
                return out;
            }
            if b.len() < 5 + len {
                break;
            }
            let fragment = b[5..5 + len].to_vec();
            used += 5 + len;
            self.record(side, ty, version, &fragment, keys, &mut out);
            if self.dead[side] {
                return out;
            }
        }
        self.bufs[side].drain(..used);
        out
    }

    /// Can this side no longer be followed (gap, damaged record)?
    pub fn dead(&self, side: usize) -> bool {
        self.dead[side]
    }

    /// Bytes of one side are missing: record boundaries and sequence numbers are lost.
    pub fn gap(&mut self, side: usize, n: u64) {
        self.stop(
            side,
            &format!("{n} bytes of the encrypted connection are missing in the capture"),
        );
    }

    fn stop(&mut self, side: usize, why: &str) {
        self.dead[side] = true;
        self.bufs[side].clear();
        if self.keys == Keys::Found && self.broken.is_none() {
            self.broken = Some(format!("{why}; the rest of it could not be decrypted"));
        }
    }

    fn tls13(&self) -> bool {
        self.server.is_some_and(|s| s.version == 0x0304)
    }

    fn record(
        &mut self,
        side: usize,
        ty: u8,
        version: u16,
        fragment: &[u8],
        keys: &KeyLog,
        out: &mut Vec<Vec<u8>>,
    ) {
        let tls13 = self.tls13();
        // TLS 1.3 protects records as application data; TLS 1.2 protects everything after
        // the ChangeCipherSpec of that side.
        let sealed = if tls13 {
            ty == APPLICATION_DATA
        } else {
            self.prot[side].is_some()
        };
        if !sealed {
            match ty {
                HANDSHAKE => {
                    self.seen = true;
                    self.plain_handshake(side, fragment, keys);
                }
                CHANGE_CIPHER_SPEC if !tls13 => {
                    self.prot[side] = self.next[side].take();
                }
                _ => {} // TLS 1.3 compatibility ChangeCipherSpec, alerts in the clear
            }
            return;
        }
        let Some(prot) = self.prot[side].as_mut() else {
            return;
        };
        let Some((real, plain)) = prot.open(ty, version, fragment) else {
            if tls13 && side == CLIENT && self.next[CLIENT].is_some() {
                // Before the client's Finished: 0-RTT early data under keys not logged here.
                self.skipped += 1;
                return;
            }
            self.stop(side, "a record did not decrypt (wrong key or damaged data)");
            return;
        };
        match real {
            APPLICATION_DATA => out.push(plain),
            HANDSHAKE if tls13 => self.sealed_handshake(side, &plain),
            ALERT | HANDSHAKE => {} // TLS 1.2 Finished, alerts
            _ => {}
        }
    }

    /// Handshake messages in the clear: the hellos.
    fn plain_handshake(&mut self, side: usize, fragment: &[u8], keys: &KeyLog) {
        self.plain_hs[side].extend_from_slice(fragment);
        loop {
            let buf = &mut self.plain_hs[side];
            if buf.len() < 4 {
                return;
            }
            let len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
            if buf.len() < 4 + len {
                if buf.len() > MAX_HANDSHAKE {
                    buf.clear();
                }
                return;
            }
            let msg: Vec<u8> = buf.drain(..4 + len).collect();
            match (side, msg[0]) {
                (CLIENT, 1) => {
                    if let Some(r) = tls::client_hello(&msg[4..], &mut self.info) {
                        self.client_random = Some(r);
                    }
                }
                (SERVER, 2) => {
                    if let Some(sh) = tls::server_hello(&msg[4..], &mut self.info)
                        && !sh.retry
                    {
                        self.server = Some(sh);
                        self.set_keys(keys);
                    }
                }
                _ => {}
            }
        }
    }

    /// Decrypted TLS 1.3 handshake messages: Finished switches to the application keys,
    /// KeyUpdate to the next ones.
    fn sealed_handshake(&mut self, side: usize, plain: &[u8]) {
        self.sealed_hs[side].extend_from_slice(plain);
        loop {
            let buf = &mut self.sealed_hs[side];
            if buf.len() < 4 {
                return;
            }
            let len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
            if buf.len() < 4 + len {
                if buf.len() > MAX_HANDSHAKE {
                    buf.clear();
                }
                return;
            }
            let ty = buf[0];
            buf.drain(..4 + len);
            match ty {
                20 => self.prot[side] = self.next[side].take(),
                24 => self.prot[side] = self.prot[side].as_ref().and_then(Protection::updated),
                _ => {}
            }
        }
    }

    /// The ServerHello is known: find the secrets and derive the keys.
    fn set_keys(&mut self, keys: &KeyLog) {
        let Some(sh) = self.server else { return };
        let suite = match (sh.version, tlsrec::suite(sh.suite)) {
            (0x0303 | 0x0304, Some(s)) if s.tls13 == (sh.version == 0x0304) => s,
            _ => {
                let what = if sh.version < 0x0303 {
                    self.info.version.clone()
                } else {
                    self.info.cipher.clone()
                };
                self.keys = Keys::Unsupported(what);
                return;
            }
        };
        let Some(secrets) = self.client_random.and_then(|r| keys.get(&r)) else {
            self.keys = Keys::Missing;
            return;
        };
        if suite.tls13 {
            // The handshake secrets alone would read no application data.
            let (Some(ch), Some(sh_), Some(ct), Some(st)) = (
                &secrets.handshake[CLIENT],
                &secrets.handshake[SERVER],
                &secrets.traffic[CLIENT],
                &secrets.traffic[SERVER],
            ) else {
                self.keys = Keys::Missing;
                return;
            };
            self.prot = [Protection::tls13(suite, ch), Protection::tls13(suite, sh_)];
            self.next = [Protection::tls13(suite, ct), Protection::tls13(suite, st)];
        } else {
            let (Some(master), Some(cr)) = (&secrets.master, self.client_random) else {
                self.keys = Keys::Missing;
                return;
            };
            let Some([c, s]) = tlsrec::tls12_keys(suite, master, &cr, &sh.random, sh.etm) else {
                self.keys = Keys::Missing;
                return;
            };
            self.next = [Some(c), Some(s)];
        }
        self.keys = Keys::Found;
    }
}
