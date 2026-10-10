//! Statistics tab.

use crate::AppCore;
use quena_model::SessionId;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Statistics {
    pub sessions: usize,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub first_request: Option<i64>,
    pub last_response: Option<i64>,
    pub aggregate_ms: u64,
    pub status_codes: BTreeMap<u16, usize>,
    /// (content type, count, bytes), sorted by bytes.
    pub content_types: Vec<(String, usize, u64)>,
    pub hosts: Vec<(String, usize, u64)>,
    pub processes: Vec<(String, usize)>,
    pub aborted: usize,
    pub in_flight: usize,
    /// LLM API calls: (provider/model, calls, tokens, estimated cost in USD), by tokens.
    pub llm_models: Vec<(String, usize, u64, f64)>,
    pub llm_tokens: u64,
    pub llm_cost: f64,
    /// Durations of the finished sessions (ms).
    pub timing: Option<Spread>,
    /// Requests and response bytes per second over the time from the first request to the
    /// last response.
    pub requests_per_s: Option<f64>,
    pub bytes_per_s: Option<f64>,
    /// Connection phases summed over the sessions that had them (ms): DNS, TCP connect, TLS
    /// handshake, waiting for the first byte.
    pub phases: Option<Phases>,
    /// Bytes of request and response headers (as recorded; all sessions read for `phases`).
    pub request_header_bytes: u64,
    pub response_header_bytes: u64,
}

/// Distribution of values (ms).
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Spread {
    pub count: usize,
    pub min: u64,
    pub max: u64,
    pub mean: f64,
    pub median: u64,
    pub p90: u64,
    pub p95: u64,
    pub p99: u64,
    pub stddev: f64,
}

/// Connection phases: total ms and how many sessions had each.
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Phases {
    pub dns_ms: u64,
    pub dns_count: usize,
    pub connect_ms: u64,
    pub connect_count: usize,
    pub tls_ms: u64,
    pub tls_count: usize,
    pub wait_ms: u64,
    pub wait_count: usize,
    /// Only the first sessions were read (large selections).
    pub sampled: usize,
}

/// Sessions whose details are read for the phases and header sizes: a selection up to this
/// many; without a selection only a capture this small (the tab refreshes while traffic flows).
const PHASE_SAMPLE: usize = 5_000;
const PHASE_ALL: usize = 2_000;

/// Nearest-rank percentile of sorted values.
fn pct(v: &[u64], p: f64) -> u64 {
    if v.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * v.len() as f64).ceil() as usize;
    v[rank.clamp(1, v.len()) - 1]
}

/// The spread of `v` (sorted in place).
pub fn spread(v: &mut [u64]) -> Option<Spread> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    let n = v.len() as f64;
    let mean = v.iter().map(|x| *x as f64).sum::<f64>() / n;
    let var = v.iter().map(|x| (*x as f64 - mean).powi(2)).sum::<f64>() / n;
    Some(Spread { count: v.len(), min: v[0], max: v[v.len() - 1], mean, median: pct(v, 50.0), p90: pct(v, 90.0), p95: pct(v, 95.0), p99: pct(v, 99.0), stddev: var.sqrt() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spread_of_durations() {
        let mut v: Vec<u64> = (1..=100).collect();
        let s = spread(&mut v).unwrap();
        assert_eq!((s.min, s.max, s.median, s.p90, s.p95, s.p99), (1, 100, 50, 90, 95, 99));
        assert!((s.mean - 50.5).abs() < 1e-9 && (s.stddev - 28.866).abs() < 0.01);
        assert_eq!(spread(&mut [7]).unwrap().p99, 7);
        assert!(spread(&mut []).is_none());
    }
}

impl AppCore {
    pub fn statistics(&self, ids: Vec<SessionId>) -> Statistics {
        let cap = self.capture();
        let set: HashSet<SessionId> = ids.into_iter().collect();
        let mut st = Statistics::default();
        let mut cts: HashMap<String, (usize, u64)> = HashMap::new();
        let mut hosts: HashMap<String, (usize, u64)> = HashMap::new();
        let mut procs: HashMap<String, usize> = HashMap::new();
        let mut models: HashMap<String, (usize, u64, u64)> = HashMap::new();
        let mut durations: Vec<u64> = Vec::new();
        let mut finished: Vec<SessionId> = Vec::new();
        cap.index.for_each(|s| {
            if !set.is_empty() && !set.contains(&s.id) {
                return;
            }
            st.sessions += 1;
            st.request_bytes += s.request_body_len;
            st.response_bytes += s.response_body_len;
            st.first_request = Some(st.first_request.map_or(s.started_at, |f| f.min(s.started_at)));
            if let Some(d) = s.duration_ms {
                if s.state.is_final() && s.kind != quena_model::SessionKind::Tunnel {
                    durations.push(u64::from(d));
                }
                st.aggregate_ms += d as u64;
                let end = s.started_at + d as i64 * 1000;
                st.last_response = Some(st.last_response.map_or(end, |l| l.max(end)));
            }
            if s.status != 0 {
                *st.status_codes.entry(s.status).or_default() += 1;
            }
            if s.state.is_final() {
                finished.push(s.id);
            }
            match s.state {
                quena_model::SessionState::Aborted => st.aborted += 1,
                x if !x.is_final() => st.in_flight += 1,
                _ => {}
            }
            let ct = if s.content_type.is_empty() { "(none)".to_string() } else { s.content_type.clone() };
            let e = cts.entry(ct).or_default();
            e.0 += 1;
            e.1 += s.response_body_len;
            let h = hosts.entry(s.host.clone()).or_default();
            h.0 += 1;
            h.1 += s.response_body_len + s.request_body_len;
            if !s.process.is_empty() {
                *procs.entry(s.process.clone()).or_default() += 1;
            }
            if !s.llm.is_empty() {
                let m = models.entry(s.llm.clone()).or_default();
                m.0 += 1;
                m.1 = m.1.saturating_add(s.llm_tokens.unwrap_or(0));
                m.2 = m.2.saturating_add(s.llm_cost_micros.unwrap_or(0));
            }
        });
        st.timing = spread(&mut durations);
        if let (Some(a), Some(b)) = (st.first_request, st.last_response) {
            let secs = (b - a) as f64 / 1_000_000.0;
            if secs >= 0.001 {
                st.requests_per_s = Some(st.sessions as f64 / secs);
                st.bytes_per_s = Some(st.response_bytes as f64 / secs);
            }
        }
        let all_finished = finished.len();
        finished.truncate(PHASE_SAMPLE);
        if !finished.is_empty() && (!set.is_empty() || all_finished <= PHASE_ALL) {
            let mut ph = Phases::default();
            let add = |total: &mut u64, count: &mut usize, v: Option<u32>| {
                if let Some(v) = v {
                    *total += u64::from(v);
                    *count += 1;
                }
            };
            let len = |h: &quena_model::Headers| h.0.iter().map(|(n, v)| (n.len() + v.len() + 4) as u64).sum::<u64>();
            for id in &finished {
                let Some(d) = cap.detail_peek(*id) else { continue };
                let t = &d.timers;
                add(&mut ph.dns_ms, &mut ph.dns_count, t.dns_ms);
                add(&mut ph.connect_ms, &mut ph.connect_count, t.tcp_connect_ms);
                add(&mut ph.tls_ms, &mut ph.tls_count, t.tls_handshake_ms);
                let wait = t.server_got_first_byte.zip(t.server_done_request.or(t.server_begin_request)).map(|(a, b)| ((a - b).max(0) / 1000) as u32);
                add(&mut ph.wait_ms, &mut ph.wait_count, wait);
                st.request_header_bytes += len(&d.request.headers);
                st.response_header_bytes += d.response.as_ref().map(|r| len(&r.headers)).unwrap_or(0);
            }
            ph.sampled = if all_finished > finished.len() { finished.len() } else { 0 };
            st.phases = Some(ph);
        }
        st.llm_tokens = models.values().fold(0u64, |a, m| a.saturating_add(m.1));
        st.llm_cost = models.values().fold(0u64, |a, m| a.saturating_add(m.2)) as f64 / 1_000_000.0;
        let mut m: Vec<_> = models.into_iter().map(|(k, (c, t, cost))| (k, c, t, cost as f64 / 1_000_000.0)).collect();
        m.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)));
        m.truncate(50);
        st.llm_models = m;
        let mut v: Vec<_> = cts.into_iter().map(|(k, (c, b))| (k, c, b)).collect();
        v.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)));
        v.truncate(50);
        st.content_types = v;
        let mut h: Vec<_> = hosts.into_iter().map(|(k, (c, b))| (k, c, b)).collect();
        h.sort_by(|a, b| b.1.cmp(&a.1));
        h.truncate(50);
        st.hosts = h;
        let mut p: Vec<_> = procs.into_iter().collect();
        p.sort_by(|a, b| b.1.cmp(&a.1));
        p.truncate(50);
        st.processes = p;
        st
    }
}
