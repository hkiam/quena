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
}

impl AppCore {
    pub fn statistics(&self, ids: Vec<SessionId>) -> Statistics {
        let cap = self.capture();
        let set: HashSet<SessionId> = ids.into_iter().collect();
        let mut st = Statistics::default();
        let mut cts: HashMap<String, (usize, u64)> = HashMap::new();
        let mut hosts: HashMap<String, (usize, u64)> = HashMap::new();
        let mut procs: HashMap<String, usize> = HashMap::new();
        cap.index.for_each(|s| {
            if !set.is_empty() && !set.contains(&s.id) {
                return;
            }
            st.sessions += 1;
            st.request_bytes += s.request_body_len;
            st.response_bytes += s.response_body_len;
            st.first_request = Some(
                st.first_request
                    .map_or(s.started_at, |f| f.min(s.started_at)),
            );
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
            let ct = if s.content_type.is_empty() {
                "(none)".to_string()
            } else {
                s.content_type.clone()
            };
            let e = cts.entry(ct).or_default();
            e.0 += 1;
            e.1 += s.response_body_len;
            let h = hosts.entry(s.host.clone()).or_default();
            h.0 += 1;
            h.1 += s.response_body_len + s.request_body_len;
            if !s.process.is_empty() {
                *procs.entry(s.process.clone()).or_default() += 1;
            }
        });
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
