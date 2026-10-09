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
        cap.index.for_each(|s| {
            if !set.is_empty() && !set.contains(&s.id) {
                return;
            }
            st.sessions += 1;
            st.request_bytes += s.request_body_len;
            st.response_bytes += s.response_body_len;
            st.first_request = Some(st.first_request.map_or(s.started_at, |f| f.min(s.started_at)));
            if let Some(d) = s.duration_ms {
                st.aggregate_ms += d as u64;
                let end = s.started_at + d as i64 * 1000;
                st.last_response = Some(st.last_response.map_or(end, |l| l.max(end)));
            }
            if s.status != 0 {
                *st.status_codes.entry(s.status).or_default() += 1;
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
                m.1 += s.llm_tokens.unwrap_or(0);
                m.2 += s.llm_cost_micros.unwrap_or(0);
            }
        });
        st.llm_tokens = models.values().map(|m| m.1).sum();
        st.llm_cost = models.values().map(|m| m.2).sum::<u64>() as f64 / 1_000_000.0;
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
