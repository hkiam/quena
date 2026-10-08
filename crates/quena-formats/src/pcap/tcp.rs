//! TCP stream reassembly for one direction: segments in sequence order, retransmissions and
//! overlaps dropped, segments that arrive early held back until the bytes before them came.

use std::collections::BTreeMap;

/// Bytes held back for a hole in the stream before the hole is given up as lost.
const MAX_PENDING: usize = 8 << 20;

#[derive(Debug, PartialEq)]
pub enum Ev {
    Data(Vec<u8>),
    /// Bytes missing from the capture (dropped by the capture, or before it started).
    Gap(u64),
    /// The sender closed its side (FIN), after all of its data.
    Fin,
}

#[derive(Default)]
pub struct Half {
    /// Sequence number of the next byte in order; unknown before the first segment.
    next: Option<u32>,
    /// Bytes handed out so far: the stream offset of `next`.
    delivered: u64,
    /// Early segments by stream offset: captured bytes and the length on the wire.
    pending: BTreeMap<u64, (Vec<u8>, u64)>,
    pending_bytes: usize,
    /// Stream offset of the FIN.
    fin_at: Option<u64>,
    /// Highest acknowledgment the peer sent for this direction.
    peer_ack: Option<u32>,
    pub isn: Option<u32>,
    pub closed: bool,
}

impl Half {
    /// `len`: the payload length on the wire; bytes beyond the captured `payload` (cut by the
    /// snapshot length) are reported as a gap.
    #[allow(clippy::too_many_arguments)]
    pub fn segment(
        &mut self,
        seq: u32,
        syn: bool,
        fin: bool,
        payload: &[u8],
        len: u32,
        out: &mut Vec<Ev>,
    ) {
        if self.closed {
            return;
        }
        // The SYN takes one sequence number; data in it (TCP Fast Open) follows it.
        let seq = if syn {
            if self.next.is_none() {
                self.isn = Some(seq);
                self.next = Some(seq.wrapping_add(1));
            }
            if len == 0 && payload.is_empty() {
                return;
            }
            seq.wrapping_add(1)
        } else {
            seq
        };
        let next = *self.next.get_or_insert(seq);
        let diff = seq.wrapping_sub(next) as i32 as i64;
        if diff.unsigned_abs() > 1 << 30 {
            return; // not from this stream (or a wrap far beyond any window)
        }
        let at = self.delivered as i64 + diff;
        let len = (len as u64).max(payload.len() as u64);
        if fin {
            self.fin_at = Some((at + len as i64).max(0) as u64);
        }
        if diff <= 0 {
            self.deliver(payload, len, (-diff) as u64, out);
        } else if len > 0 {
            let e = self.pending.entry(at as u64).or_default();
            if e.1 < len || e.0.len() < payload.len() {
                self.pending_bytes = self.pending_bytes + payload.len() - e.0.len();
                *e = (payload.to_vec(), len);
            }
            if self.pending_bytes > MAX_PENDING {
                self.skip_gap(out);
            }
        }
        self.drain(out);
        self.skip_acked(out);
    }

    /// The peer acknowledged up to `ack` (exclusive).
    pub fn peer_acked(&mut self, ack: u32, out: &mut Vec<Ev>) {
        if self
            .peer_ack
            .is_none_or(|p| (ack.wrapping_sub(p) as i32) > 0)
        {
            self.peer_ack = Some(ack);
        }
        self.skip_acked(out);
    }

    /// A hole the peer has acknowledged, with later bytes already here, will not be filled
    /// any more: the capture missed it.
    /// Only the acknowledged part of the hole is given up: bytes after it may still come.
    fn skip_acked(&mut self, out: &mut Vec<Ev>) {
        while !self.closed
            && let Some((&first, _)) = self.pending.first_key_value()
            && let (Some(next), Some(ack)) = (self.next, self.peer_ack)
            && (ack.wrapping_sub(next) as i32) > 0
        {
            let acked = self.delivered + ack.wrapping_sub(next) as u64;
            self.skip_to(acked.min(first), out);
            self.drain(out);
        }
    }

    /// Hand out a segment from `skip` on: its captured bytes, then the rest of its wire
    /// length as a gap.
    fn deliver(&mut self, data: &[u8], len: u64, skip: u64, out: &mut Vec<Ev>) {
        if skip >= len {
            return;
        }
        if skip < data.len() as u64 {
            let d = data[skip as usize..].to_vec();
            self.advance(d.len() as u64);
            out.push(Ev::Data(d));
        }
        let missing = len - skip.max(data.len() as u64);
        if missing > 0 {
            self.advance(missing);
            out.push(Ev::Gap(missing));
        }
    }

    fn advance(&mut self, n: u64) {
        self.delivered += n;
        self.next = self.next.map(|x| x.wrapping_add(n as u32));
    }

    /// Hand out held-back segments that are now in order; the FIN once everything before it is out.
    fn drain(&mut self, out: &mut Vec<Ev>) {
        while let Some((&at, _)) = self.pending.first_key_value() {
            if at > self.delivered {
                break;
            }
            let (data, len) = self.pending.remove(&at).unwrap();
            self.pending_bytes -= data.len();
            self.deliver(&data, len, self.delivered - at, out);
        }
        if self.fin_at.is_some_and(|f| f <= self.delivered) {
            self.closed = true;
            out.push(Ev::Fin);
        }
    }

    /// Give up the first hole: report it and continue after it.
    fn skip_gap(&mut self, out: &mut Vec<Ev>) {
        if let Some((&at, _)) = self.pending.first_key_value() {
            self.skip_to(at, out);
        }
    }

    /// Report the bytes up to stream offset `at` as missing.
    fn skip_to(&mut self, at: u64, out: &mut Vec<Ev>) {
        if at > self.delivered {
            let gap = at - self.delivered;
            self.advance(gap);
            out.push(Ev::Gap(gap));
        }
    }

    /// End of the connection or capture: hand out what is held back, holes reported as gaps.
    pub fn flush(&mut self, out: &mut Vec<Ev>) {
        while !self.closed && !self.pending.is_empty() {
            self.skip_gap(out);
            self.drain(out);
        }
        if !self.closed && self.fin_at.is_some_and(|f| f > self.delivered) {
            out.push(Ev::Gap(self.fin_at.unwrap() - self.delivered));
            self.closed = true;
            out.push(Ev::Fin);
        }
    }

    pub fn delivered(&self) -> u64 {
        self.delivered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(ev: &[Ev]) -> Vec<u8> {
        ev.iter()
            .flat_map(|e| {
                if let Ev::Data(d) = e {
                    d.clone()
                } else {
                    Vec::new()
                }
            })
            .collect()
    }

    #[test]
    fn reorder_retransmit_fin() {
        let mut h = Half::default();
        let mut out = Vec::new();
        h.segment(u32::MAX - 1, true, false, b"", 0, &mut out); // ISN near the wrap
        h.segment(u32::MAX, false, false, b"ab", 2, &mut out);
        h.segment(4, false, true, b"fg", 2, &mut out); // early, carries FIN
        h.segment(2, false, false, b"de", 2, &mut out); // early
        assert_eq!(data(&out), b"ab");
        h.segment(u32::MAX, false, false, b"abc", 3, &mut out); // retransmission with one new byte
        assert_eq!(data(&out), b"abcdefg");
        assert_eq!(out.last(), Some(&Ev::Fin));
        assert!(h.closed);
    }

    #[test]
    fn cut_segments() {
        let mut h = Half::default();
        let mut out = Vec::new();
        h.segment(9, true, false, b"", 0, &mut out);
        h.segment(16, false, false, b"xy", 5, &mut out); // early and cut: 3 bytes not captured
        h.segment(10, false, false, b"abcd", 6, &mut out);
        assert_eq!(
            out,
            [
                Ev::Data(b"abcd".to_vec()),
                Ev::Gap(2),
                Ev::Data(b"xy".to_vec()),
                Ev::Gap(3)
            ]
        );
    }

    #[test]
    fn acknowledged_hole_is_a_gap_at_once() {
        let mut h = Half::default();
        let mut out = Vec::new();
        h.segment(9, true, false, b"", 0, &mut out);
        h.segment(10, false, false, b"ab", 2, &mut out);
        h.peer_acked(15, &mut out); // the peer got bytes up to 14
        h.segment(15, false, false, b"fg", 2, &mut out); // later bytes: the hole is lost
        assert_eq!(
            out,
            [
                Ev::Data(b"ab".to_vec()),
                Ev::Gap(3),
                Ev::Data(b"fg".to_vec())
            ]
        );
        // Without an acknowledgment, the hole waits (reordered packets).
        let mut h = Half::default();
        let mut out = Vec::new();
        h.segment(10, false, false, b"ab", 2, &mut out);
        h.segment(15, false, false, b"fg", 2, &mut out);
        h.peer_acked(12, &mut out);
        assert_eq!(out, [Ev::Data(b"ab".to_vec())]);
    }

    #[test]
    fn only_the_acknowledged_part_of_a_hole_is_lost() {
        let mut h = Half::default();
        let mut out = Vec::new();
        h.segment(9, true, false, b"", 0, &mut out);
        h.segment(30, false, false, b"C", 1, &mut out); // early: offset 20
        h.peer_acked(20, &mut out); // the peer got bytes up to offset 9
        assert_eq!(out, [Ev::Gap(10)]);
        // Inside the hole, after the acknowledged part: still delivered.
        h.segment(20, false, false, b"B", 1, &mut out);
        assert_eq!(out[1..], [Ev::Data(b"B".to_vec())]);
        h.flush(&mut out);
        assert_eq!(out[2..], [Ev::Gap(9), Ev::Data(b"C".to_vec())]);
    }

    #[test]
    fn data_in_the_syn() {
        let mut h = Half::default();
        let mut out = Vec::new();
        h.segment(99, true, false, b"GET", 3, &mut out);
        h.segment(99, true, false, b"GET", 3, &mut out); // retransmitted SYN
        h.segment(103, false, false, b" /", 2, &mut out);
        assert_eq!(out, [Ev::Data(b"GET".to_vec()), Ev::Data(b" /".to_vec())]);
    }

    #[test]
    fn hole_is_a_gap() {
        let mut h = Half::default();
        let mut out = Vec::new();
        h.segment(100, false, false, b"xy", 2, &mut out); // no SYN: starts mid-stream
        h.segment(110, false, true, b"z", 1, &mut out);
        assert_eq!(data(&out), b"xy");
        h.flush(&mut out);
        assert_eq!(out[1..], [Ev::Gap(8), Ev::Data(b"z".to_vec()), Ev::Fin]);
    }
}
