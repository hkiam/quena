//! Builders for synthetic captures in tests: `get(1, "https://h/a").at(0).took(120)`.
use crate::model::{Session, Timers};

/// Base time of synthetic captures (µs since the epoch).
pub const T0: u64 = 1_727_690_000_000_000;

pub fn req(id: u64, method: &str, url: &str) -> Session {
    let host = crate::canon::parse(url).host;
    let mut s = Session { id, method: method.into(), url: url.into(), host, version: "HTTP/1.1".into(), status: 200, process: "app".into(), ..Default::default() };
    s = s.at(0).took(50);
    s.client_connection = Some(1);
    s.server_connection_reused = true;
    s
}

pub fn get(id: u64, url: &str) -> Session {
    req(id, "GET", url)
}

pub fn post(id: u64, url: &str) -> Session {
    req(id, "POST", url)
}

impl Session {
    /// Start `ms` after T0.
    pub fn at(mut self, ms: u64) -> Self {
        let d = self.duration_ms.unwrap_or(50);
        self.started = T0 + ms * 1000;
        self.set_timers(d, 0.2);
        self
    }
    /// Total duration; 80 % of it is server time (TTFB) unless `ttfb` is set afterwards.
    pub fn took(mut self, ms: u32) -> Self {
        self.duration_ms = Some(ms);
        self.set_timers(ms, 0.2);
        self
    }
    /// Share of the duration spent downloading (rest before is TTFB).
    pub fn download_share(mut self, share: f64) -> Self {
        let d = self.duration_ms.unwrap_or(50);
        self.set_timers(d, share);
        self
    }
    fn set_timers(&mut self, ms: u32, download_share: f64) {
        let s = self.started;
        let e = s + ms as u64 * 1000;
        let first = e - ((ms as f64 * download_share) as u64 * 1000);
        self.timers = Timers {
            client_begin_request: Some(s),
            client_done_request: Some(s),
            server_begin_request: Some(s),
            server_done_request: Some(s),
            server_got_first_byte: Some(first.max(s)),
            server_done_response: Some(e),
            client_done_response: Some(e),
            ..std::mem::take(&mut self.timers)
        };
    }
    pub fn status(mut self, st: u16) -> Self {
        self.status = st;
        self
    }
    pub fn failed_with(mut self, err: &str) -> Self {
        self.status = 0;
        self.error = Some(err.into());
        self
    }
    /// Response body size (wire = decoded) and content type.
    pub fn body(mut self, bytes: u64, content_type: &str) -> Self {
        self.response_bytes = bytes;
        self.response_decoded_bytes = bytes;
        self.content_type = content_type.into();
        self
    }
    pub fn req_body(mut self, bytes: u64, hash: u64) -> Self {
        self.request_bytes = bytes;
        self.request_body_hash = Some(hash);
        self
    }
    pub fn resp_hash(mut self, hash: u64) -> Self {
        self.response_body_hash = Some(hash);
        self
    }
    pub fn req_h(mut self, k: &str, v: &str) -> Self {
        self.request_headers.push((k.into(), v.into()));
        self
    }
    pub fn resp_h(mut self, k: &str, v: &str) -> Self {
        self.response_headers.push((k.into(), v.into()));
        self
    }
    /// A fresh upstream connection with the given handshake times.
    pub fn new_conn(mut self, dns: u32, tcp: u32, tls: u32) -> Self {
        self.server_connection_reused = false;
        self.timers.server_connect_start = Some(self.started);
        self.timers.server_connected = Some(self.started + (dns + tcp + tls) as u64 * 1000);
        self.timers.dns_ms = Some(dns);
        self.timers.tcp_connect_ms = Some(tcp);
        self.timers.tls_handshake_ms = Some(tls);
        self
    }
    pub fn conn(mut self, client_connection: u64) -> Self {
        self.client_connection = Some(client_connection);
        self
    }
}

/// Run the analysis on sessions (options as JSON) and return the findings.
pub fn analyse(sessions: Vec<Session>, options: &str) -> Vec<crate::model::Finding> {
    let mut r = crate::Run::new(options);
    r.push(sessions);
    r.analyse().0
}

/// Findings of one rule id.
pub fn of<'a>(f: &'a [crate::model::Finding], id: &str) -> Vec<&'a crate::model::Finding> {
    f.iter().filter(|x| x.id == id).collect()
}
