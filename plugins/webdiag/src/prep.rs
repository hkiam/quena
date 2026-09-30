//! Per-run preparation shared by all analyzers ([`Prep`], reached through `Ctx::prep`).
//!
//! Deriving the canonical form, template, endpoint, host and MIME type of a session means
//! parsing its URL and allocating strings. Done per analyzer, this dominated the run time
//! of large captures, so it is done once per run: every session's URL is parsed once
//! (`canon::derive`) and the derived strings are interned (`u32` ids per session, one
//! string per distinct value). Analyzers group by the ids instead of by fresh strings.
//! Results that only some analyzers need (critical paths, polling series, retries, N+1
//! clusters) are computed lazily, on first use, and shared as well.
use std::cell::OnceCell;

use crate::analyzers::patterns::{NPlus1, Poll, Retries};
use crate::canon;
use crate::model::{Operation, Session};
use crate::net;
use crate::util::FxHashMap;

/// "No value" in the per-session id vectors (non-HTTP sessions, sessions outside an operation).
pub const NONE: u32 = u32::MAX;

/// String interner used while building.
#[derive(Default)]
struct Interner {
    strs: Vec<String>,
    map: FxHashMap<String, u32>,
}

impl Interner {
    fn id(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.map.get(s) {
            return id;
        }
        self.push(s.to_string())
    }
    fn owned(&mut self, s: String) -> u32 {
        if let Some(&id) = self.map.get(&s) {
            return id;
        }
        self.push(s)
    }
    fn push(&mut self, s: String) -> u32 {
        let id = self.strs.len() as u32;
        self.map.insert(s.clone(), id);
        self.strs.push(s);
        id
    }
}

/// Lower-case form of `s`, borrowed when it already is lower-case.
fn lower(s: &str) -> std::borrow::Cow<'_, str> {
    if s.bytes().any(|b| b.is_ascii_uppercase()) { s.to_ascii_lowercase().into() } else { s.into() }
}

/// Upper-case form of `s`, borrowed when it already is upper-case.
fn upper(s: &str) -> std::borrow::Cow<'_, str> {
    if s.bytes().any(|b| b.is_ascii_lowercase()) { s.to_ascii_uppercase().into() } else { s.into() }
}

/// Per-session data of one run (see module docs). Vectors are indexed by session index;
/// string ids index the matching `*_strs` vector.
pub struct Prep {
    /// Indexes of HTTP sessions, in start order.
    pub http: Vec<usize>,
    /// Index of the (non-background) operation per session, `NONE` otherwise.
    pub op: Vec<u32>,
    /// Upper-case method (HTTP sessions; `NONE` otherwise).
    pub method: Vec<u32>,
    pub method_strs: Vec<String>,
    /// `canon::url_key` with the session start (HTTP sessions).
    pub url_key: Vec<u32>,
    pub url_key_strs: Vec<String>,
    /// Canonical request without body (`canon::canonical_at(method, url, None, start)`).
    pub request: Vec<u32>,
    /// Canonical request with the request body hash (semantic duplicates).
    pub canon: Vec<u32>,
    canon_parts: Vec<(u32, u32, Option<u64>)>,
    /// `canon::template_at` key and replaced values (HTTP sessions).
    pub tmpl: Vec<u32>,
    pub tmpl_strs: Vec<String>,
    pub vars: Vec<Vec<(String, String)>>,
    /// `canon::endpoint` (HTTP sessions).
    pub endpoint: Vec<u32>,
    pub endpoint_strs: Vec<String>,
    /// Lower-case host, from the URL when the host field is empty (all sessions).
    pub host: Vec<u32>,
    pub host_strs: Vec<String>,
    /// `Session::mime` (all sessions).
    pub mime: Vec<u32>,
    pub mime_strs: Vec<String>,
    /// Static resource (`canon::is_static` of MIME type and path; HTTP sessions).
    pub is_static: Vec<bool>,
    /// OData request (`canon::is_odata`; HTTP sessions).
    pub odata: Vec<bool>,
    /// Observed RTT of the whole capture (`net::observed_rtt`).
    pub rtt: net::RttEstimate,
    pub(crate) retries: OnceCell<Retries>,
    pub(crate) polls: OnceCell<Vec<Poll>>,
    pub(crate) in_poll: OnceCell<Vec<bool>>,
    pub(crate) timer_driven: OnceCell<Vec<bool>>,
    pub(crate) nplus1: OnceCell<Vec<NPlus1>>,
}

impl Prep {
    pub fn build(sessions: &[Session], ops: &[Operation]) -> Prep {
        let n = sessions.len();
        let mut op = vec![NONE; n];
        for (k, o) in ops.iter().enumerate().filter(|(_, o)| !o.background) {
            for &m in &o.members {
                if m < n {
                    op[m] = k as u32;
                }
            }
        }
        let (mut methods, mut keys, mut tmpls, mut eps, mut hosts, mut mimes) =
            (Interner::default(), Interner::default(), Interner::default(), Interner::default(), Interner::default(), Interner::default());
        let mut requests: FxHashMap<(u32, u32), u32> = FxHashMap::default();
        let mut canons: FxHashMap<(u32, u32, Option<u64>), u32> = FxHashMap::default();
        let mut canon_parts = vec![];
        let mut p = Prep {
            http: vec![],
            op,
            method: vec![NONE; n],
            method_strs: vec![],
            url_key: vec![NONE; n],
            url_key_strs: vec![],
            request: vec![NONE; n],
            canon: vec![NONE; n],
            canon_parts: vec![],
            tmpl: vec![NONE; n],
            tmpl_strs: vec![],
            vars: vec![vec![]; n],
            endpoint: vec![NONE; n],
            endpoint_strs: vec![],
            host: vec![NONE; n],
            host_strs: vec![],
            mime: vec![NONE; n],
            mime_strs: vec![],
            is_static: vec![false; n],
            odata: vec![false; n],
            rtt: net::RttEstimate { ms: net::DEFAULT_RTT_MS, source: net::RttSource::Assumed },
            retries: OnceCell::new(),
            polls: OnceCell::new(),
            in_poll: OnceCell::new(),
            timer_driven: OnceCell::new(),
            nplus1: OnceCell::new(),
        };
        for (i, s) in sessions.iter().enumerate() {
            let mime = s.content_type.split(';').next().unwrap_or("").trim();
            p.mime[i] = mimes.id(&lower(mime));
            if !s.is_http() {
                p.host[i] = if s.host.is_empty() { hosts.owned(canon::parse(&s.url).host) } else { hosts.id(&lower(&s.host)) };
                continue;
            }
            p.http.push(i);
            let d = canon::derive(&s.method, &s.url, Some(s.started));
            p.host[i] = if s.host.is_empty() { hosts.id(&d.url.host) } else { hosts.id(&lower(&s.host)) };
            let m = methods.id(&upper(&s.method));
            let k = keys.owned(d.url_key);
            p.method[i] = m;
            p.url_key[i] = k;
            let next = requests.len() as u32;
            p.request[i] = *requests.entry((m, k)).or_insert(next);
            let next = canons.len() as u32;
            p.canon[i] = *canons.entry((m, k, s.request_body_hash)).or_insert_with(|| {
                canon_parts.push((m, k, s.request_body_hash));
                next
            });
            p.tmpl[i] = tmpls.owned(d.template.key);
            p.vars[i] = d.template.vars;
            p.endpoint[i] = eps.owned(d.endpoint);
            p.is_static[i] = canon::is_static(&mimes.strs[p.mime[i] as usize], &d.url.path);
            p.odata[i] = canon::is_odata(&d.url);
        }
        p.method_strs = methods.strs;
        p.url_key_strs = keys.strs;
        p.canon_parts = canon_parts;
        p.tmpl_strs = tmpls.strs;
        p.endpoint_strs = eps.strs;
        p.host_strs = hosts.strs;
        p.mime_strs = mimes.strs;
        p.rtt = net::observed_rtt(sessions, &p.http);
        p
    }

    pub fn endpoint_of(&self, i: usize) -> &str {
        self.endpoint.get(i).and_then(|&e| self.endpoint_strs.get(e as usize)).map(String::as_str).unwrap_or("")
    }
    pub fn host_of(&self, i: usize) -> &str {
        self.host.get(i).and_then(|&h| self.host_strs.get(h as usize)).map(String::as_str).unwrap_or("")
    }
    pub fn mime_of(&self, i: usize) -> &str {
        self.mime.get(i).and_then(|&m| self.mime_strs.get(m as usize)).map(String::as_str).unwrap_or("")
    }
    pub fn url_key_of(&self, i: usize) -> &str {
        self.url_key.get(i).and_then(|&k| self.url_key_strs.get(k as usize)).map(String::as_str).unwrap_or("")
    }
    /// The canonical request string of a `canon` id (`canon::canonical_at` with body hash).
    pub fn canon_str(&self, c: u32) -> String {
        let Some(&(m, k, h)) = self.canon_parts.get(c as usize) else { return String::new() };
        let mut s = format!("{} {}", self.method_strs[m as usize], self.url_key_strs[k as usize]);
        if let Some(h) = h {
            s.push_str(&format!(" #{h:016x}"));
        }
        s
    }
}
