//! Network sensitivity model: how an operation would behave on another network.
//!
//! The capture shows how the traffic behaved on the network it was recorded on. To say
//! how it would behave on a slower network, a deliberately simple and conservative model
//! is used. Everything derived from it is an *estimate* (findings set `estimate: true`).
//!
//! # Critical path ("sequential levels")
//!
//! Within an operation, the critical path is the longest chain of sessions in which every
//! session started after the previous one had ended (client timeline, with a tolerance of
//! [`TOLERANCE_US`] = 2 ms: `next.started + 2 ms ≥ prev.end()`). Sessions that started at
//! the same instant are never chained, and neither are sessions separated by a pause of
//! more than [`MAX_LINK_GAP_US`] = 500 ms (think time or a timer such as polling, not a
//! data dependency). Sessions without a known end (`Session::has_end`: still open at
//! capture end, sparse imports) are left out: their length is unknown, and counting them
//! as zero-length would chain them. Its length is the number of *sequential levels*. Computed with a
//! dynamic programme over the sessions in start order and a segment tree (range maximum
//! over end times): O(n log n).
//!
//! The chain is an **upper bound** of the true dependencies: a request that merely started
//! after another one had finished is counted as if it depended on it. Findings based on it
//! are hypotheses, with medium confidence unless further evidence (e.g. the whole chain
//! on one connection) supports them.
//!
//! # Round trips per chain step
//!
//! [`round_trips`]: 1 for request/response; for a step that opened a new upstream
//! connection additionally 1 for the TCP handshake, the TLS handshake on https (1 round
//! trip for TLS 1.3, 2 for older or unknown versions) and 1 for a DNS lookup if one was
//! measured (`dns_ms > 0`).
//!
//! # Extra time on a slower network
//!
//! [`extra_latency_ms`]: `Δ = round trips × max(0, rtt_target − rtt_observed)`.
//!
//! The observed RTT is estimated from the capture by [`observed_rtt`]:
//! 1. the median `tcp_connect_ms` of the new upstream connections (a TCP handshake takes
//!    one round trip), if any were measured;
//! 2. otherwise 1 ms if the capture looks local: all hosts are loopback/private/`.local`,
//!    or the median request (of those with a known end) took ≤ 5 ms;
//! 3. otherwise 20 ms (a typical good WAN).
//!
//! A higher observed RTT gives a smaller Δ, so the defaults err on the conservative side.
//! Server time, bandwidth and loss are ignored for Δ (see transfer time below).
//!
//! # Transfer time
//!
//! [`transfer_ms`]: `bytes · 8 / throughput`, with the effective throughput
//! [`throughput_bps`] = `min(bandwidth, Mathis limit)`; the Mathis et al. limit of a
//! single TCP flow with packet loss `p > 0` is `MSS · 8 / RTT · C / √p` with
//! MSS = 1460 bytes and C = 1.22 (RTT of the profile, at least 1 ms). Without loss the
//! bandwidth alone limits. Slow start and parallel connections are ignored.
//!
//! [`transfer_estimate_ms`] adds one round trip of the profile (request out, first byte
//! back): `RTT + transfer_ms`. All tables that estimate how long a transfer takes on a
//! network profile use it, so the same bytes give the same estimate everywhere.
use crate::model::{Network, Session};

/// Two sessions are sequential if the second started at most this much before the first
/// ended (µs): timer resolution and client scheduling.
pub const TOLERANCE_US: u64 = 2_000;
/// A request that starts more than this after the previous one ended (µs) is not chained
/// to it: the pause is think time or a timer (polling), not a data dependency.
pub const MAX_LINK_GAP_US: u64 = 500_000;
/// TCP maximum segment size for the Mathis formula (bytes).
pub const MSS_BYTES: f64 = 1460.0;
/// Constant of the Mathis formula.
pub const MATHIS_C: f64 = 1.22;
/// Assumed RTT when nothing was measured and the capture looks local (ms).
pub const LOCAL_RTT_MS: f64 = 1.0;
/// Assumed RTT when nothing was measured otherwise (ms).
pub const DEFAULT_RTT_MS: f64 = 20.0;

// ------------------------------------------------------------------ critical path

/// Segment tree over end-time ranks: range maximum of `(chain length, position)`.
struct MaxTree {
    size: usize,
    t: Vec<(u32, usize)>,
}

impl MaxTree {
    fn new(n: usize) -> MaxTree {
        MaxTree { size: n, t: vec![(0, usize::MAX); 2 * n.max(1)] }
    }
    fn update(&mut self, i: usize, v: (u32, usize)) {
        let mut i = i + self.size;
        if v.0 <= self.t[i].0 {
            return;
        }
        self.t[i] = v;
        while i > 1 {
            i /= 2;
            let (a, b) = (self.t[2 * i], self.t[2 * i + 1]);
            self.t[i] = if b.0 > a.0 { b } else { a };
        }
    }
    /// Maximum over ranks `lo..hi`.
    fn query(&self, lo: usize, hi: usize) -> (u32, usize) {
        let mut best = (0, usize::MAX);
        let (mut l, mut r) = (lo + self.size, hi + self.size);
        while l < r {
            if l & 1 == 1 {
                if self.t[l].0 > best.0 {
                    best = self.t[l];
                }
                l += 1;
            }
            if r & 1 == 1 {
                r -= 1;
                if self.t[r].0 > best.0 {
                    best = self.t[r];
                }
            }
            l /= 2;
            r /= 2;
        }
        best
    }
}

/// The longest chain of sequential sessions among `members` (indexes into `sessions`),
/// as session indexes in time order. Its length is the number of sequential levels.
pub fn critical_path(sessions: &[Session], members: &[usize]) -> Vec<usize> {
    let mut order: Vec<usize> = members.iter().copied().filter(|&i| sessions[i].has_end()).collect();
    if order.is_empty() {
        return vec![];
    }
    let n = order.len();
    order.sort_by_key(|&i| (sessions[i].started, i));
    let end: Vec<u64> = order.iter().map(|&i| sessions[i].end()).collect();
    let mut ends = end.clone();
    ends.sort_unstable();
    ends.dedup();
    let mut tree = MaxTree::new(ends.len());
    // (chain length ending here, previous position in `order`)
    let mut best: Vec<(u32, usize)> = vec![(0, usize::MAX); n];
    let mut k = 0;
    while k < n {
        let start = sessions[order[k]].started;
        let mut e = k;
        while e < n && sessions[order[e]].started == start {
            e += 1;
        }
        // Sessions starting at the same instant are queried before any of them is inserted.
        let lo = ends.partition_point(|&x| x + MAX_LINK_GAP_US < start);
        let hi = ends.partition_point(|&x| x <= start + TOLERANCE_US);
        let (len, prev) = tree.query(lo, hi);
        for b in &mut best[k..e] {
            *b = (len + 1, prev);
        }
        for (p, b) in best.iter().enumerate().take(e).skip(k) {
            let r = ends.partition_point(|&x| x < end[p]);
            tree.update(r, (b.0, p));
        }
        k = e;
    }
    let mut at = (0..n).max_by_key(|&p| (best[p].0, std::cmp::Reverse(p))).unwrap_or(0);
    let mut chain = vec![];
    loop {
        chain.push(order[at]);
        let prev = best[at].1;
        if prev == usize::MAX {
            break;
        }
        at = prev;
    }
    chain.reverse();
    chain
}

// ------------------------------------------------------------------ round trips

/// Round trips of the TLS handshake of a session on https (1 for TLS 1.3, else 2).
pub fn tls_round_trips(s: &Session) -> u32 {
    if !s.is_https() {
        return 0;
    }
    match s.tls_version.as_deref().and_then(crate::util::tls_version) {
        Some(v) if v >= (1, 3) => 1,
        _ => 2,
    }
}

/// Network round trips of one session (see module docs).
pub fn round_trips(s: &Session) -> u32 {
    let mut rt = 1;
    if s.new_connection() {
        rt += 1 + tls_round_trips(s);
        if s.timers.dns_ms.unwrap_or(0) > 0 {
            rt += 1;
        }
    }
    rt
}

/// Round trips of a chain of sessions.
pub fn chain_round_trips(sessions: &[Session], chain: &[usize]) -> u32 {
    chain.iter().map(|&i| round_trips(&sessions[i])).sum()
}

// ------------------------------------------------------------------ observed RTT

/// Where the observed RTT comes from.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RttSource {
    /// Median TCP connect time of this many new connections.
    Measured(usize),
    /// No handshake measured; the capture looks local (loopback/LAN or very fast).
    AssumedLocal,
    /// No handshake measured; default assumption.
    Assumed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RttEstimate {
    pub ms: f64,
    pub source: RttSource,
}

/// Loopback, private (RFC 1918), link-local or `.local` host (port ignored).
pub fn is_local_host(host: &str) -> bool {
    let h = host.trim_start_matches('[');
    let h = match h.find(']') {
        Some(i) => &h[..i],
        None => h.rsplit_once(':').filter(|(a, _)| !a.contains(':')).map(|(a, _)| a).unwrap_or(h),
    };
    let h = h.to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") || h == "::1" || h.starts_with("fe80:") || (h.starts_with("fd") && h.contains(':')) {
        return true;
    }
    let o: Vec<u8> = h.split('.').filter_map(|x| x.parse().ok()).collect();
    if o.len() != 4 || h.split('.').count() != 4 {
        return false;
    }
    o[0] == 127 || o[0] == 10 || (o[0] == 192 && o[1] == 168) || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 169 && o[1] == 254)
}

/// Estimate the RTT of the captured network from the sessions `members` (see module docs).
pub fn observed_rtt(sessions: &[Session], members: &[usize]) -> RttEstimate {
    let tcp: Vec<f64> = members
        .iter()
        .map(|&i| &sessions[i])
        .filter(|s| s.is_http() && s.new_connection())
        .filter_map(|s| s.timers.tcp_connect_ms)
        .map(|x| x as f64)
        .collect();
    if !tcp.is_empty() {
        return RttEstimate { ms: crate::util::percentile(&tcp, 50.0), source: RttSource::Measured(tcp.len()) };
    }
    let http: Vec<&Session> = members.iter().map(|&i| &sessions[i]).filter(|s| s.is_http()).collect();
    let all_local = !http.is_empty() && http.iter().all(|s| is_local_host(&s.host));
    let durations: Vec<f64> = http.iter().filter(|s| s.has_end()).map(|s| s.duration_us() as f64 / 1000.0).collect();
    let fast = !durations.is_empty() && crate::util::percentile(&durations, 50.0) <= 5.0;
    if all_local || fast {
        RttEstimate { ms: LOCAL_RTT_MS, source: RttSource::AssumedLocal }
    } else {
        RttEstimate { ms: DEFAULT_RTT_MS, source: RttSource::Assumed }
    }
}

/// Extra time (ms) of `round_trips` round trips on `net` compared to the observed RTT.
pub fn extra_latency_ms(round_trips: u32, observed: &RttEstimate, net: &Network) -> f64 {
    round_trips as f64 * (net.rtt_ms - observed.ms).max(0.0)
}

// ------------------------------------------------------------------ transfer

/// Effective throughput of one TCP flow on `net` in bit/s (see module docs).
pub fn throughput_bps(net: &Network) -> f64 {
    let bandwidth = net.mbps.max(0.001) * 1e6;
    let p = net.loss_pct / 100.0;
    if p <= 0.0 {
        return bandwidth;
    }
    let rtt_s = net.rtt_ms.max(1.0) / 1000.0;
    let mathis = MSS_BYTES * 8.0 / rtt_s * MATHIS_C / p.sqrt();
    bandwidth.min(mathis)
}

/// Time (ms) to transfer `bytes` on `net` (throughput only, no latency).
pub fn transfer_ms(bytes: u64, net: &Network) -> f64 {
    bytes as f64 * 8.0 / throughput_bps(net) * 1000.0
}

/// Estimated time (ms) of a transfer of `bytes` on `net`: one round trip plus
/// [`transfer_ms`] (see module docs).
pub fn transfer_estimate_ms(bytes: u64, net: &Network) -> f64 {
    net.rtt_ms + transfer_ms(bytes, net)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::*;

    fn net(rtt: f64, mbps: f64, loss: f64) -> Network {
        Network { id: "x".into(), name: "X".into(), rtt_ms: rtt, mbps, loss_pct: loss }
    }

    #[test]
    fn chain_of_sequential_requests() {
        // a → b → c sequential, d parallel to b
        let s = vec![
            get(1, "https://h/a").at(0).took(100),
            get(2, "https://h/b").at(101).took(100),
            get(3, "https://h/d").at(120).took(50),
            get(4, "https://h/c").at(201).took(100),
        ];
        assert_eq!(critical_path(&s, &[0, 1, 2, 3]), vec![0, 1, 3]);
        // All parallel: one level.
        let p: Vec<Session> = (0..5).map(|i| get(i, "https://h/x").at(0).took(100)).collect();
        assert_eq!(critical_path(&p, &[0, 1, 2, 3, 4]).len(), 1);
        assert!(critical_path(&p, &[]).is_empty());
        // Tolerance: starting 1 ms before the previous one ended still counts as sequential.
        let t = vec![get(1, "https://h/a").at(0).took(100), get(2, "https://h/b").at(99).took(100)];
        assert_eq!(critical_path(&t, &[0, 1]).len(), 2);
        let u = vec![get(1, "https://h/a").at(0).took(100), get(2, "https://h/b").at(90).took(100)];
        assert_eq!(critical_path(&u, &[0, 1]).len(), 1);
    }

    #[test]
    fn pauses_break_the_chain() {
        // Polling every second is not a dependency chain.
        let s: Vec<Session> = (0..10).map(|i| get(i, "https://h/poll").at(i * 1000).took(15)).collect();
        let all: Vec<usize> = (0..10).collect();
        assert_eq!(critical_path(&s, &all).len(), 1);
        // 400 ms of client work between requests still is.
        let s: Vec<Session> = (0..10).map(|i| get(i, "https://h/x").at(i * 500).took(100)).collect();
        assert_eq!(critical_path(&s, &all).len(), 10);
    }

    #[test]
    fn sessions_without_end_are_not_chained() {
        let s: Vec<Session> = (0..5)
            .map(|i| {
                let mut x = get(i, "https://h/x").at(i * 10);
                x.duration_ms = None;
                x.timers = Default::default();
                x
            })
            .collect();
        assert!(critical_path(&s, &[0, 1, 2, 3, 4]).is_empty());
        assert_eq!(observed_rtt(&s, &[0, 1, 2, 3, 4]).source, RttSource::Assumed);
    }

    #[test]
    fn zero_length_sessions_at_same_instant_are_not_chained() {
        let s: Vec<Session> = (0..4).map(|i| get(i, "https://h/x").at(0).took(0)).collect();
        assert_eq!(critical_path(&s, &[0, 1, 2, 3]).len(), 1);
    }

    #[test]
    fn round_trip_counting() {
        let reused = get(1, "https://h/a");
        assert_eq!(round_trips(&reused), 1);
        let mut tls12 = get(2, "https://h/a").new_conn(5, 10, 20);
        tls12.tls_version = Some("TLSv1.2".into());
        assert_eq!(round_trips(&tls12), 1 + 1 + 2 + 1);
        let mut tls13 = get(3, "https://h/a").new_conn(0, 10, 10);
        tls13.tls_version = Some("TLSv1.3".into());
        assert_eq!(round_trips(&tls13), 1 + 1 + 1);
        tls13.tls_version = Some("Tls13".into());
        assert_eq!(tls_round_trips(&tls13), 1);
        assert_eq!(round_trips(&get(4, "http://h/a").new_conn(0, 10, 0)), 2);
    }

    #[test]
    fn observed_rtt_estimate() {
        let s = vec![get(1, "https://h/a").new_conn(0, 30, 40), get(2, "https://h/b").new_conn(0, 10, 20), get(3, "https://h/c").new_conn(0, 20, 20)];
        assert_eq!(observed_rtt(&s, &[0, 1, 2]), RttEstimate { ms: 20.0, source: RttSource::Measured(3) });
        let l = vec![get(1, "http://localhost:8080/a").took(40), get(2, "http://192.168.1.4/b").took(40)];
        assert_eq!(observed_rtt(&l, &[0, 1]).source, RttSource::AssumedLocal);
        let w = vec![get(1, "https://api.example.com/a").took(80)];
        assert_eq!(observed_rtt(&w, &[0]).ms, DEFAULT_RTT_MS);
        assert!(is_local_host("[::1]:8080") && is_local_host("172.20.1.1") && !is_local_host("172.32.0.1") && !is_local_host("example.com"));
    }

    #[test]
    fn extra_latency_and_transfer() {
        let obs = RttEstimate { ms: 1.0, source: RttSource::AssumedLocal };
        assert_eq!(extra_latency_ms(10, &obs, &net(61.0, 100.0, 0.0)), 600.0);
        assert_eq!(extra_latency_ms(10, &obs, &net(0.5, 100.0, 0.0)), 0.0);
        // 10 Mbit/s, no loss: 1.25 MB/s → 10 MB in 8 s.
        assert!((transfer_ms(10_000_000, &net(50.0, 10.0, 0.0)) - 8000.0).abs() < 1e-6);
        // Loss limits: 100 ms, 1 % → 1460·8/0.1·1.22/0.1 ≈ 1.42 Mbit/s < 100 Mbit/s.
        let t = throughput_bps(&net(100.0, 100.0, 1.0));
        assert!((t - 1_424_960.0).abs() < 1.0, "{t}");
    }
}
