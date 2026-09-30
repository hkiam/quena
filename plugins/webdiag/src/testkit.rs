//! Builders for synthetic captures in tests: `get(1, "https://h/a").at(0).took(120)`.
use crate::model::{Session, TextInfo, Timers};

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

// ------------------------------------------------------------------ text facts

/// Encoding facts of a clean UTF-8 text: `text_facts("UTF-8", "header")`, then adjust the
/// fields (`TextInfo { decode_errors: 3, ..text_facts(…) }`) or use the helpers below.
pub fn text_facts(effective: &str, source: &str) -> TextInfo {
    TextInfo { effective: effective.into(), source: source.into(), sampled: 2048, utf8_valid: true, ..Default::default() }
}

/// Declared in the Content-Type (`charset=label`, resolved to `resolved`).
pub fn declared(label: &str, resolved: &str) -> TextInfo {
    TextInfo { header_charset: Some(label.into()), header_resolved: Some(resolved.into()), ..text_facts(resolved, "header") }
}

/// Declared UTF-8, but the bytes are not UTF-8 (e.g. Latin-1): decode errors.
pub fn utf8_declared_latin1_sent() -> TextInfo {
    TextInfo { non_ascii: true, utf8_valid: false, decode_errors: 4, ..declared("utf-8", "UTF-8") }
}

/// Declared ISO-8859-1, but the bytes are valid UTF-8 with non-ASCII characters.
pub fn latin1_declared_utf8_sent() -> TextInfo {
    TextInfo { non_ascii: true, utf8_valid: true, ..declared("ISO-8859-1", "windows-1252") }
}

impl Session {
    /// Response body facts (and the response Content-Type as the session content type).
    pub fn text(mut self, content_type: &str, t: TextInfo) -> Self {
        self.content_type = content_type.into();
        self.response_headers.push(("Content-Type".into(), content_type.into()));
        self.response_text = Some(Box::new(t));
        self
    }
    /// Request body facts with the request Content-Type.
    pub fn req_text(mut self, content_type: &str, t: TextInfo) -> Self {
        self.request_headers.push(("Content-Type".into(), content_type.into()));
        self.request_text = Some(Box::new(t));
        self
    }
    pub fn resp_decoding_error(mut self, e: &str) -> Self {
        self.response_decoding_error = Some(e.into());
        self
    }
    pub fn req_decoding_error(mut self, e: &str) -> Self {
        self.request_decoding_error = Some(e.into());
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

/// IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`) for seconds since the epoch.
pub fn http_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // civil_from_days (H. Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    const WD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!("{}, {:02} {} {} {:02}:{:02}:{:02} GMT", WD[(days % 7) as usize], d, MON[(m - 1) as usize], y, rem / 3600, rem / 60 % 60, rem % 60)
}

impl Session {
    /// A `Date` response header from a server whose clock is `offset_s` seconds ahead (or
    /// behind, if negative) of this computer at the time of the first response byte.
    pub fn server_clock(self, offset_s: i64) -> Self {
        let local = self.timers.server_got_first_byte.unwrap_or(self.started) / 1_000_000;
        self.resp_h("Date", &http_date((local as i64 + offset_s) as u64))
    }
}
