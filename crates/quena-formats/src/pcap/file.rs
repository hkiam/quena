//! pcap and pcapng file readers: packets with their link type and capture time.
//!
//! Both formats are read sequentially. A file that ends in the middle of a packet (a capture
//! that was killed) ends the packet stream instead of failing the import.

use quena_model::Micros;
use std::io::{self, Read};

/// What a capture file holds, in order.
pub enum Item {
    Packet(Packet),
    /// TLS secrets in the NSS key log format (pcapng Decryption Secrets Block).
    Secrets(Vec<u8>),
}

/// One captured frame.
pub struct Packet {
    pub ts: Micros,
    pub linktype: u32,
    pub data: Vec<u8>,
}

/// Snapshot length upper bound; anything larger is a corrupt length field.
const MAX_PACKET: usize = 256 << 20;

const PCAPNG_SHB: u32 = 0x0A0D_0D0A;

pub enum Reader<R> {
    Pcap(Pcap<R>),
    Pcapng(Pcapng<R>),
}

impl<R: Read> Reader<R> {
    pub fn new(mut r: R) -> io::Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic).map_err(|_| invalid("the file is too short for a packet capture"))?;
        if u32::from_le_bytes(magic) == PCAPNG_SHB {
            return Ok(Reader::Pcapng(Pcapng::new(r)?));
        }
        let (le, nanos) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
            [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
            [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
            [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
            _ => return Err(invalid("not a pcap or pcapng file")),
        };
        let mut h = [0u8; 20];
        r.read_exact(&mut h).map_err(|_| invalid("the pcap file header is incomplete"))?;
        let linktype = rd32(le, &h[16..20]) & 0x03ff_ffff;
        Ok(Reader::Pcap(Pcap { r, le, nanos, linktype, truncated: false }))
    }

    /// The next packet or block of secrets; `None` at the end of the file.
    pub fn next(&mut self) -> io::Result<Option<Item>> {
        match self {
            Reader::Pcap(p) => Ok(p.next()?.map(Item::Packet)),
            Reader::Pcapng(p) => p.next(),
        }
    }

    /// The file ended in the middle of a packet or block.
    pub fn truncated(&self) -> bool {
        match self {
            Reader::Pcap(p) => p.truncated,
            Reader::Pcapng(p) => p.truncated,
        }
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn rd16(le: bool, b: &[u8]) -> u16 {
    let a = [b[0], b[1]];
    if le { u16::from_le_bytes(a) } else { u16::from_be_bytes(a) }
}

fn rd32(le: bool, b: &[u8]) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }
}

/// `read_exact` that tells a clean end of file (nothing read) from a cut one.
fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<Fill> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => return Ok(if n == 0 { Fill::Eof } else { Fill::Cut }),
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Fill::Full)
}

#[derive(PartialEq)]
enum Fill {
    Full,
    Eof,
    Cut,
}

pub struct Pcap<R> {
    r: R,
    le: bool,
    nanos: bool,
    linktype: u32,
    truncated: bool,
}

impl<R: Read> Pcap<R> {
    fn next(&mut self) -> io::Result<Option<Packet>> {
        let mut h = [0u8; 16];
        match fill(&mut self.r, &mut h)? {
            Fill::Full => {}
            Fill::Eof => return Ok(None),
            Fill::Cut => {
                self.truncated = true;
                return Ok(None);
            }
        }
        let sec = rd32(self.le, &h[0..4]) as i64;
        let frac = rd32(self.le, &h[4..8]) as i64;
        let len = rd32(self.le, &h[8..12]) as usize;
        if len > MAX_PACKET {
            return Err(invalid("corrupt packet length in the pcap file"));
        }
        let mut data = vec![0u8; len];
        if fill(&mut self.r, &mut data)? != Fill::Full {
            self.truncated = true;
            return Ok(None);
        }
        let ts = sec * 1_000_000 + if self.nanos { frac / 1000 } else { frac };
        Ok(Some(Packet { ts, linktype: self.linktype, data }))
    }
}

/// Timestamp unit of a pcapng interface (option `if_tsresol`) plus `if_tsoffset`.
#[derive(Clone, Copy)]
struct Iface {
    linktype: u32,
    /// Power of ten (`false`) or two (`true`).
    pow2: bool,
    exp: u8,
    offset_s: i64,
}

impl Iface {
    fn micros(&self, ts: u64) -> Micros {
        let us = if self.pow2 {
            ((ts as u128 * 1_000_000) >> self.exp.min(127)) as i64
        } else if self.exp <= 6 {
            (ts as i64).saturating_mul(10i64.pow((6 - self.exp) as u32))
        } else {
            (ts / 10u64.pow((self.exp - 6).min(19) as u32)) as i64
        };
        us.saturating_add(self.offset_s.saturating_mul(1_000_000))
    }
}

pub struct Pcapng<R> {
    r: R,
    le: bool,
    ifaces: Vec<Iface>,
    last_ts: Micros,
    truncated: bool,
}

/// Decryption Secrets Block type of TLS key logs ("TLSK").
const SECRETS_TLS_KEY_LOG: u32 = 0x544c_534b;

impl<R: Read> Pcapng<R> {
    fn new(r: R) -> io::Result<Self> {
        let mut p = Pcapng { r, le: true, ifaces: Vec::new(), last_ts: 0, truncated: false };
        // The block type has been read; the section header follows.
        p.section().map_err(|_| invalid("the pcapng section header is incomplete"))?;
        Ok(p)
    }

    /// Read the rest of a section header block (after its type): byte order, then skip it.
    fn section(&mut self) -> io::Result<()> {
        let mut h = [0u8; 8];
        self.r.read_exact(&mut h)?;
        self.le = match h[4..8] {
            [0x4d, 0x3c, 0x2b, 0x1a] => true,
            [0x1a, 0x2b, 0x3c, 0x4d] => false,
            _ => return Err(invalid("bad pcapng byte-order magic")),
        };
        let total = rd32(self.le, &h[0..4]) as usize;
        if !(28..=MAX_PACKET).contains(&total) {
            return Err(invalid("corrupt pcapng section header"));
        }
        io::copy(&mut (&mut self.r).take((total - 12) as u64), &mut io::sink())?;
        self.ifaces.clear();
        Ok(())
    }

    fn next(&mut self) -> io::Result<Option<Item>> {
        loop {
            let mut h = [0u8; 4];
            match fill(&mut self.r, &mut h)? {
                Fill::Full => {}
                Fill::Eof => return Ok(None),
                Fill::Cut => {
                    self.truncated = true;
                    return Ok(None);
                }
            }
            if u32::from_le_bytes(h) == PCAPNG_SHB {
                if self.section().is_err() {
                    self.truncated = true;
                    return Ok(None);
                }
                continue;
            }
            let ty = rd32(self.le, &h);
            let mut l = [0u8; 4];
            if fill(&mut self.r, &mut l)? != Fill::Full {
                self.truncated = true;
                return Ok(None);
            }
            let total = rd32(self.le, &l) as usize;
            if !(12..=MAX_PACKET).contains(&total) {
                return Err(invalid("corrupt pcapng block length"));
            }
            // Body plus the trailing length copy.
            let mut body = vec![0u8; total - 8];
            if fill(&mut self.r, &mut body)? != Fill::Full {
                self.truncated = true;
                return Ok(None);
            }
            body.truncate(total - 12);
            if let Some(p) = self.block(ty, &body) {
                return Ok(Some(p));
            }
        }
    }

    fn block(&mut self, ty: u32, b: &[u8]) -> Option<Item> {
        let le = self.le;
        match ty {
            // Decryption secrets
            10 if b.len() >= 8 && rd32(le, &b[0..4]) == SECRETS_TLS_KEY_LOG => {
                let len = rd32(le, &b[4..8]) as usize;
                Some(Item::Secrets(b.get(8..8 + len)?.to_vec()))
            }
            // Interface description
            1 if b.len() >= 8 => {
                let mut iface = Iface { linktype: rd16(le, &b[0..2]) as u32, pow2: false, exp: 6, offset_s: 0 };
                let mut opts = &b[8..];
                while opts.len() >= 4 {
                    let code = rd16(le, &opts[0..2]);
                    let len = rd16(le, &opts[2..4]) as usize;
                    let Some(v) = opts.get(4..4 + len) else { break };
                    match code {
                        0 => break,
                        9 if len >= 1 => {
                            iface.pow2 = v[0] & 0x80 != 0;
                            iface.exp = v[0] & 0x7f;
                        }
                        14 if len >= 8 => {
                            let a: [u8; 8] = v[..8].try_into().unwrap();
                            iface.offset_s = if le { i64::from_le_bytes(a) } else { i64::from_be_bytes(a) };
                        }
                        _ => {}
                    }
                    opts = opts.get(4 + len.next_multiple_of(4)..).unwrap_or(&[]);
                }
                self.ifaces.push(iface);
                None
            }
            // Enhanced packet
            6 if b.len() >= 20 => {
                let iface = *self.ifaces.get(rd32(le, &b[0..4]) as usize)?;
                let ts = ((rd32(le, &b[4..8]) as u64) << 32) | rd32(le, &b[8..12]) as u64;
                let caplen = rd32(le, &b[12..16]) as usize;
                let data = b.get(20..20 + caplen)?.to_vec();
                self.last_ts = iface.micros(ts);
                Some(Item::Packet(Packet { ts: self.last_ts, linktype: iface.linktype, data }))
            }
            // Obsolete packet block
            2 if b.len() >= 20 => {
                let iface = *self.ifaces.get(rd16(le, &b[0..2]) as usize)?;
                let ts = ((rd32(le, &b[4..8]) as u64) << 32) | rd32(le, &b[8..12]) as u64;
                let caplen = rd32(le, &b[12..16]) as usize;
                let data = b.get(20..20 + caplen)?.to_vec();
                self.last_ts = iface.micros(ts);
                Some(Item::Packet(Packet { ts: self.last_ts, linktype: iface.linktype, data }))
            }
            // Simple packet: no timestamp, interface 0.
            3 if b.len() >= 4 => {
                let iface = *self.ifaces.first()?;
                let len = (rd32(le, &b[0..4]) as usize).min(b.len() - 4);
                Some(Item::Packet(Packet { ts: self.last_ts, linktype: iface.linktype, data: b[4..4 + len].to_vec() }))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A little-endian pcap file (µs) with the given link type and frames.
    pub fn pcap(linktype: u32, frames: &[(Micros, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&linktype.to_le_bytes());
        for (ts, f) in frames {
            out.extend_from_slice(&((ts / 1_000_000) as u32).to_le_bytes());
            out.extend_from_slice(&((ts % 1_000_000) as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    fn block(ty: u32, body: &[u8]) -> Vec<u8> {
        let mut body = body.to_vec();
        body.resize(body.len().next_multiple_of(4), 0);
        let total = (body.len() + 12) as u32;
        let mut out = ty.to_be_bytes().to_vec();
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&total.to_be_bytes());
        out
    }

    /// A big-endian pcapng file with one interface at nanosecond resolution.
    pub fn pcapng(linktype: u16, frames: &[(Micros, Vec<u8>)]) -> Vec<u8> {
        pcapng_with_secrets(linktype, frames, None)
    }

    /// The same, with a Decryption Secrets Block (TLS key log) before the packets.
    pub fn pcapng_with_secrets(linktype: u16, frames: &[(Micros, Vec<u8>)], secrets: Option<&[u8]>) -> Vec<u8> {
        let mut shb = 0x1a2b_3c4du32.to_be_bytes().to_vec();
        shb.extend_from_slice(&[0, 1, 0, 0]);
        shb.extend_from_slice(&(-1i64).to_be_bytes());
        let mut out = block(PCAPNG_SHB, &shb);
        let mut idb = linktype.to_be_bytes().to_vec();
        idb.extend_from_slice(&[0, 0]);
        idb.extend_from_slice(&65535u32.to_be_bytes());
        idb.extend_from_slice(&[0, 9, 0, 1, 9, 0, 0, 0, 0, 0, 0, 0]); // if_tsresol = 9, end
        out.extend(block(1, &idb));
        if let Some(sec) = secrets {
            let mut dsb = SECRETS_TLS_KEY_LOG.to_be_bytes().to_vec();
            dsb.extend_from_slice(&(sec.len() as u32).to_be_bytes());
            dsb.extend_from_slice(sec);
            out.extend(block(10, &dsb));
        }
        for (ts, f) in frames {
            let ns = (*ts as u64) * 1000;
            let mut epb = 0u32.to_be_bytes().to_vec();
            epb.extend_from_slice(&((ns >> 32) as u32).to_be_bytes());
            epb.extend_from_slice(&(ns as u32).to_be_bytes());
            epb.extend_from_slice(&(f.len() as u32).to_be_bytes());
            epb.extend_from_slice(&(f.len() as u32).to_be_bytes());
            epb.extend_from_slice(f);
            out.extend(block(6, &epb));
        }
        out
    }

    fn all(data: &[u8]) -> (Vec<Packet>, bool) {
        let mut r = Reader::new(data).unwrap();
        let mut v = Vec::new();
        while let Some(i) = r.next().unwrap() {
            if let Item::Packet(p) = i {
                v.push(p);
            }
        }
        let t = r.truncated();
        (v, t)
    }

    #[test]
    fn pcap_and_pcapng() {
        let frames = vec![(1_700_000_000_123_456, b"abc".to_vec()), (1_700_000_001_000_001, b"defgh".to_vec())];
        for file in [pcap(1, &frames), pcapng(1, &frames)] {
            let (p, cut) = all(&file);
            assert!(!cut);
            assert_eq!(p.len(), 2);
            assert_eq!(p[0].ts, 1_700_000_000_123_456);
            assert_eq!(p[1].data, b"defgh");
            assert_eq!(p[1].linktype, 1);
            // Cut in the middle of the last packet: the packets before it survive.
            let (p, cut) = all(&file[..file.len() - 3]);
            assert!(cut);
            assert_eq!(p.len(), 1);
        }
        assert!(Reader::new(&b"GET / HTTP/1.1\r\n"[..]).is_err());
    }

    #[test]
    fn decryption_secrets_block() {
        let file = pcapng_with_secrets(1, &[(1_000_000, b"x".to_vec())], Some(b"CLIENT_RANDOM 00 11\n"));
        let mut r = Reader::new(&file[..]).unwrap();
        assert!(matches!(r.next().unwrap(), Some(Item::Secrets(s)) if s == b"CLIENT_RANDOM 00 11\n"));
        assert!(matches!(r.next().unwrap(), Some(Item::Packet(p)) if p.data == b"x"));
        assert!(r.next().unwrap().is_none());
    }
}
