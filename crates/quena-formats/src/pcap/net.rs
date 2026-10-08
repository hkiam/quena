//! Link, IP and TCP layers: a captured frame to a TCP segment.

use etherparse::{EtherType, LaxNetSlice, LaxSlicedPacket, TransportSlice};
use std::net::{IpAddr, SocketAddr};

pub struct Segment<'a> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub seq: u32,
    /// Acknowledgment number (valid with `ack`).
    pub ack_no: u32,
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    /// The captured payload; shorter than `len` when the capture cut the packet (snapshot
    /// length).
    pub payload: &'a [u8],
    /// Payload length on the wire.
    pub len: u32,
}

pub enum Decoded<'a> {
    Tcp(Segment<'a>),
    /// IP fragment: not reassembled.
    Fragment,
    /// Link type this importer does not know.
    UnknownLink,
    /// Not TCP over IP (ARP, UDP, unparseable…).
    Other,
}

// Link types (https://www.tcpdump.org/linktypes.html)
const NULL: u32 = 0;
const ETHERNET: u32 = 1;
const RAW_BSD: [u32; 2] = [12, 14];
const RAW: u32 = 101;
const LOOP: u32 = 108;
const LINUX_SLL: u32 = 113;
const PKTAP_DARWIN: u32 = 149;
const IPV4: u32 = 228;
const IPV6: u32 = 229;
const PKTAP: u32 = 258;
const LINUX_SLL2: u32 = 276;

pub fn decode(linktype: u32, data: &[u8]) -> Decoded<'_> {
    // Lax parsing: packets cut by the snapshot length, and segments recorded before TCP
    // segmentation offload split them (IPv4 length 0), still yield their TCP header.
    let sliced = match linktype {
        ETHERNET => LaxSlicedPacket::from_ethernet(data).ok(),
        RAW | IPV4 | IPV6 => LaxSlicedPacket::from_ip(data).ok(),
        t if RAW_BSD.contains(&t) => LaxSlicedPacket::from_ip(data).ok(),
        // BSD loopback: address family in host byte order (NULL) or network order (LOOP).
        NULL | LOOP => data.get(4..).and_then(|ip| LaxSlicedPacket::from_ip(ip).ok()),
        LINUX_SLL if data.len() >= 16 => Some(LaxSlicedPacket::from_ether_type(EtherType(u16::from_be_bytes([data[14], data[15]])), &data[16..])),
        LINUX_SLL2 if data.len() >= 20 => Some(LaxSlicedPacket::from_ether_type(EtherType(u16::from_be_bytes([data[0], data[1]])), &data[20..])),
        // macOS packet tap (`tcpdump -i any`, loopback, utun): a header in host byte order,
        // `pth_length`, `pth_type_next` (1: a packet follows) and `pth_dlt`, the link type of
        // the frame after the header.
        PKTAP | PKTAP_DARWIN if data.len() >= 12 => {
            let field = |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
            let (hlen, next, inner) = (field(0) as usize, field(4), field(8));
            return match data.get(hlen..) {
                Some(rest) if hlen >= 12 && next == 1 && inner != PKTAP && inner != PKTAP_DARWIN => decode(inner, rest),
                _ => Decoded::Other,
            };
        }
        _ => return Decoded::UnknownLink,
    };
    let Some(p) = sliced else { return Decoded::Other };
    // IP payload length the header announces, when the capture holds less of it.
    let (src, dst, declared) = match &p.net {
        Some(LaxNetSlice::Ipv4(v4)) => {
            if v4.is_payload_fragmented() {
                return Decoded::Fragment;
            }
            let h = v4.header();
            let declared = v4.payload().incomplete.then(|| (h.total_len() as usize).saturating_sub(h.slice().len()));
            (IpAddr::V4(h.source_addr()), IpAddr::V4(h.destination_addr()), declared)
        }
        Some(LaxNetSlice::Ipv6(v6)) => {
            if v6.is_payload_fragmented() {
                return Decoded::Fragment;
            }
            let h = v6.header();
            let declared = v6.payload().incomplete.then(|| (h.payload_length() as usize).saturating_sub(v6.extensions().slice().len()));
            (IpAddr::V6(h.source_addr()), IpAddr::V6(h.destination_addr()), declared)
        }
        _ => return Decoded::Other,
    };
    let Some(TransportSlice::Tcp(tcp)) = &p.transport else { return Decoded::Other };
    let payload = tcp.payload();
    let header = tcp.slice().len() - payload.len();
    let len = declared.map_or(payload.len(), |d| d.saturating_sub(header).max(payload.len()));
    Decoded::Tcp(Segment {
        src: SocketAddr::new(src, tcp.source_port()),
        dst: SocketAddr::new(dst, tcp.destination_port()),
        seq: tcp.sequence_number(),
        ack_no: tcp.acknowledgment_number(),
        syn: tcp.syn(),
        ack: tcp.ack(),
        fin: tcp.fin(),
        rst: tcp.rst(),
        payload,
        len: len as u32,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Flags for [`ipv4_tcp`].
    pub const SYN: u8 = 0x02;
    pub const ACK: u8 = 0x10;
    pub const FIN: u8 = 0x01;
    pub const PSH: u8 = 0x08;
    pub const RST: u8 = 0x04;

    /// An Ethernet frame with an IPv4/TCP segment (checksums are not checked by the importer).
    pub fn ipv4_tcp(src: ([u8; 4], u16), dst: ([u8; 4], u16), seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        ipv4_tcp_ack(src, dst, seq, 0, flags, payload)
    }

    pub fn ipv4_tcp_ack(src: ([u8; 4], u16), dst: ([u8; 4], u16), seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
        let total = (20 + 20 + payload.len()) as u16;
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
        f.extend_from_slice(&src.0);
        f.extend_from_slice(&dst.0);
        f.extend_from_slice(&src.1.to_be_bytes());
        f.extend_from_slice(&dst.1.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(&ack.to_be_bytes());
        f.extend_from_slice(&[0x50, flags]);
        f.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn ethernet_and_loopback() {
        let f = ipv4_tcp(([10, 0, 0, 1], 50000), ([10, 0, 0, 2], 80), 7, SYN, b"");
        let Decoded::Tcp(s) = decode(ETHERNET, &f) else { panic!() };
        assert_eq!(s.src.to_string(), "10.0.0.1:50000");
        assert_eq!(s.dst.port(), 80);
        assert!(s.syn && !s.ack);
        let mut lo = 2u32.to_le_bytes().to_vec();
        lo.extend_from_slice(&f[14..]);
        let Decoded::Tcp(s) = decode(NULL, &lo) else { panic!() };
        assert_eq!(s.seq, 7);
        assert!(matches!(decode(999, &f), Decoded::UnknownLink));
        // macOS packet tap around a loopback frame (pth_dlt = NULL).
        let mut tap = vec![0u8; 108];
        tap[0..4].copy_from_slice(&108u32.to_le_bytes());
        tap[4..8].copy_from_slice(&1u32.to_le_bytes());
        tap[8..12].copy_from_slice(&NULL.to_le_bytes());
        tap.extend_from_slice(&lo);
        let Decoded::Tcp(s) = decode(PKTAP, &tap) else { panic!() };
        assert_eq!(s.src.to_string(), "10.0.0.1:50000");
    }

    #[test]
    fn cut_by_snapshot_length() {
        let f = ipv4_tcp(([10, 0, 0, 1], 50000), ([10, 0, 0, 2], 80), 7, ACK, b"0123456789");
        let Decoded::Tcp(s) = decode(ETHERNET, &f[..f.len() - 6]) else { panic!() };
        assert_eq!((s.payload, s.len), (&b"0123"[..], 10));
        // Recorded before segmentation offload: IPv4 total length 0.
        let mut tso = f.clone();
        tso[16..18].copy_from_slice(&[0, 0]);
        let Decoded::Tcp(s) = decode(ETHERNET, &tso) else { panic!() };
        assert_eq!((s.payload, s.len), (&b"0123456789"[..], 10));
    }
}
