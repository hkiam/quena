//! Operations: sessions that belong to one user/application action (see REPORT.md).
//!
//! [`segment`] groups the HTTP sessions of a capture (tunnels and WebSockets are left out):
//!
//! 1. **Idle gaps, per process.** The sessions of each process form a separate stream
//!    (interleaving processes never merge operations). Within a stream a new operation
//!    starts when no request was in flight for at least `opts.operation_gap_ms`. A very
//!    long request (long polling, downloads) keeps the stream "in flight" for at most
//!    [`LONG_REQUEST_FACTOR`] × the gap, so that one hanging request does not glue the
//!    whole capture together.
//! 2. **Correlation.** Segments whose sessions share a W3C `traceparent` trace id or an
//!    identical `x-correlation-id` are merged (also across processes). An id that appears
//!    in more than [`MAX_ID_SEGMENTS`] segments is treated as a session-wide id (not an
//!    operation id) and ignored.
//!
//! Operations are numbered `op-1`, `op-2` … by start time; `members` are indexes into the
//! (start-sorted) sessions, sorted. The label is the operation's main request (see
//! [`main_request`]) as `METHOD path`, shortened, plus ` (+n)` for the other requests.
//! Metrics (labels in the report language): requests, duration, bytes, sequential levels
//! (critical path, see `net.rs`), new connections, errors, exact duplicates.
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use crate::canon;
use crate::model::{Lang, Metric, Operation, Options, Session, Unit};
use crate::net;
use crate::util;

/// A request keeps its stream in flight for at most this many operation gaps.
pub const LONG_REQUEST_FACTOR: f64 = 10.0;
/// Correlation ids seen in more segments than this are session-wide and not merged.
pub const MAX_ID_SEGMENTS: usize = 8;
/// Maximum length of the path part of an operation label.
pub const LABEL_LEN: usize = 60;

/// Trace id of a W3C `traceparent` (`00-<32 hex>-<16 hex>-<2 hex>`), not all zero.
pub fn trace_id(traceparent: &str) -> Option<&str> {
    let mut p = traceparent.trim().split('-');
    let _version = p.next()?;
    let t = p.next()?;
    p.next()?;
    (t.len() == 32 && t.bytes().all(|b| b.is_ascii_hexdigit()) && t.bytes().any(|b| b != b'0')).then_some(t)
}

/// The main request of an operation: the first HTML document, else the first request
/// that is not a static resource, else the first request. Index into `sessions`.
pub fn main_request(sessions: &[Session], members: &[usize]) -> Option<usize> {
    let doc = |s: &Session| matches!(s.mime().as_str(), "text/html" | "application/xhtml+xml");
    members
        .iter()
        .copied()
        .find(|&i| doc(&sessions[i]))
        .or_else(|| members.iter().copied().find(|&i| !canon::is_static(&sessions[i].mime(), &sessions[i].url)))
        .or_else(|| members.first().copied())
}

/// `METHOD path` of a session for labels (path shortened).
pub fn short_label(s: &Session) -> String {
    let u = canon::parse(&s.url);
    format!("{} {}", s.method.to_ascii_uppercase(), util::short(&u.path, LABEL_LEN))
}

fn find(parent: &mut [usize], mut x: usize) -> usize {
    while parent[x] != x {
        parent[x] = parent[parent[x]];
        x = parent[x];
    }
    x
}

/// Split the capture into operations (see module docs). `sessions` must be sorted by start.
pub fn segment(sessions: &[Session], opts: &Options) -> Vec<Operation> {
    // Analyzer caches refer to the previous segmentation.
    crate::analyzers::patterns::invalidate_cache();
    let gap_us = (opts.operation_gap_ms * 1000.0) as u64;
    let cap_us = (opts.operation_gap_ms * LONG_REQUEST_FACTOR * 1000.0) as u64;

    // 1. Idle gaps per process.
    let mut segs: Vec<Vec<usize>> = vec![];
    let mut streams: HashMap<&str, (usize, u64)> = HashMap::new(); // process → (segment, in flight until)
    for (i, s) in sessions.iter().enumerate() {
        if !s.is_http() {
            continue;
        }
        let until = s.end().min(s.started.saturating_add(cap_us));
        match streams.get_mut(s.process.as_str()) {
            Some((seg, busy)) if s.started < busy.saturating_add(gap_us) => {
                segs[*seg].push(i);
                *busy = (*busy).max(until);
            }
            _ => {
                streams.insert(s.process.as_str(), (segs.len(), until));
                segs.push(vec![i]);
            }
        }
    }

    // 2. Merge segments that share a trace or correlation id.
    let mut ids: HashMap<(bool, &str), Vec<usize>> = HashMap::new();
    for (k, seg) in segs.iter().enumerate() {
        for &i in seg {
            let s = &sessions[i];
            let t = s.req_header("traceparent").and_then(trace_id).map(|t| (true, t));
            let c = s.req_header("x-correlation-id").map(str::trim).filter(|c| !c.is_empty()).map(|c| (false, c));
            for key in [t, c].into_iter().flatten() {
                let v = ids.entry(key).or_default();
                if v.last() != Some(&k) {
                    v.push(k);
                }
            }
        }
    }
    let mut parent: Vec<usize> = (0..segs.len()).collect();
    let mut keys: Vec<&(bool, &str)> = ids.keys().collect();
    keys.sort(); // deterministic
    for key in keys {
        let v = &ids[key];
        if v.len() < 2 || v.len() > MAX_ID_SEGMENTS {
            continue;
        }
        for &k in &v[1..] {
            let (a, b) = (find(&mut parent, v[0]), find(&mut parent, k));
            if a != b {
                parent[a.max(b)] = a.min(b);
            }
        }
    }
    let mut groups: Vec<Vec<usize>> = vec![vec![]; segs.len()];
    for (k, seg) in segs.into_iter().enumerate() {
        let r = find(&mut parent, k);
        groups[r].extend(seg);
    }
    let mut groups: Vec<Vec<usize>> = groups.into_iter().filter(|g| !g.is_empty()).collect();
    for g in &mut groups {
        g.sort_unstable();
    }
    // 3. Background traffic: single requests of one endpoint that recur on their own (timers,
    //    polling, keep-alives) form one background operation instead of many tiny ones.
    let single_key = |g: &Vec<usize>| (g.len() == 1).then(|| crate::canon::endpoint(&sessions[g[0]].method, &sessions[g[0]].url));
    let mut singles: HashMap<String, usize> = HashMap::new();
    for g in &groups {
        if let Some(k) = single_key(g) {
            *singles.entry(k).or_default() += 1;
        }
    }
    let mut background: HashMap<String, Vec<usize>> = HashMap::new();
    groups.retain(|g| match single_key(g) {
        Some(k) if singles[&k] >= MIN_BACKGROUND => {
            background.entry(k).or_default().push(g[0]);
            false
        }
        _ => true,
    });
    let mut bg: Vec<Vec<usize>> = background.into_values().collect();
    for g in &mut bg {
        g.sort_unstable();
    }
    let bg_starts: Vec<usize> = bg.iter().map(|g| g[0]).collect();
    groups.extend(bg);

    // Members are indexes into start-sorted sessions: the first member starts first.
    groups.sort_by_key(|g| g[0]);

    groups
        .into_iter()
        .enumerate()
        .map(|(n, members)| {
            let is_bg = bg_starts.contains(&members[0]) && members.len() >= MIN_BACKGROUND;
            let mut op = operation(sessions, opts.lang, n + 1, members);
            if is_bg {
                op.background = true;
                let s = &sessions[op.members[0]];
                op.label = match opts.lang {
                    Lang::De => format!("Hintergrund: {} ({}×)", short_label(s), op.members.len()),
                    Lang::En => format!("Background: {} ({}×)", short_label(s), op.members.len()),
                };
            }
            op
        })
        .collect()
}

/// Single recurring requests of one endpoint from this count on form a background operation.
const MIN_BACKGROUND: usize = 3;

fn operation(sessions: &[Session], lang: Lang, n: usize, members: Vec<usize>) -> Operation {
    let l = |en: &str, de: &str| if lang == Lang::De { de.to_string() } else { en.to_string() };
    let start = sessions[members[0]].started;
    let end = members.iter().map(|&i| sessions[i].end()).max().unwrap_or(start);
    let main = main_request(sessions, &members).unwrap_or(members[0]);
    let mut label = short_label(&sessions[main]);
    if members.len() > 1 {
        label.push_str(&format!(" (+{})", members.len() - 1));
    }
    let mut seen = HashSet::new();
    let mut dups = 0;
    let (mut bytes, mut new_conns, mut errors) = (0u64, 0usize, 0usize);
    for &i in &members {
        let s = &sessions[i];
        bytes += s.request_bytes + s.response_bytes;
        new_conns += s.new_connection() as usize;
        errors += (s.status >= 400 || s.failed()) as usize;
        let mut h = std::hash::DefaultHasher::new();
        (s.method.as_str(), s.url.as_str(), s.request_body_hash).hash(&mut h);
        if !seen.insert(h.finish()) {
            dups += 1;
        }
    }
    let levels = net::critical_path(sessions, &members).len();
    let m = |key: &str, label: String, value: f64, unit: Unit| Metric { label, ..Metric::new(key, "", value, unit) };
    let metrics = vec![
        m("requests", l("Requests", "Requests"), members.len() as f64, Unit::Count),
        m("duration", l("Duration", "Dauer"), (end - start) as f64 / 1000.0, Unit::Ms),
        m("bytes", l("Transferred", "Übertragen"), bytes as f64, Unit::Bytes),
        m("sequentialLevels", l("Sequential levels", "Sequenzielle Stufen"), levels as f64, Unit::Count),
        m("newConnections", l("New connections", "Neue Verbindungen"), new_conns as f64, Unit::Count),
        m("errors", l("Errors and failures", "Fehler und Abbrüche"), errors as f64, Unit::Count),
        m("duplicates", l("Exact duplicates", "Exakte Duplikate"), dups as f64, Unit::Count),
    ];
    Operation { id: format!("op-{n}"), label, start, end, members, metrics, background: false }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::*;

    fn seg(mut s: Vec<Session>) -> (Vec<Session>, Vec<Operation>) {
        s.sort_by_key(|x| (x.started, x.id));
        let o = segment(&s, &Options::default());
        (s, o)
    }

    #[test]
    fn idle_gaps_split_operations() {
        let (_, o) = seg(vec![
            get(1, "https://h/a").at(0).took(100),
            get(2, "https://h/b").at(500).took(100),
            get(3, "https://h/c").at(3000).took(100), // 2.4 s idle → new operation
            tunnel(4, 3050),
        ]);
        assert_eq!(o.len(), 2);
        assert_eq!((o[0].id.as_str(), o[0].members.clone()), ("op-1", vec![0, 1]));
        assert_eq!(o[1].members, vec![2]);
        assert_eq!(o[0].label, "GET /a (+1)");
        assert_eq!(o[1].label, "GET /c");
    }

    fn tunnel(id: u64, at: u64) -> Session {
        let mut t = req(id, "CONNECT", "https://h:443").at(at);
        t.kind = crate::model::Kind::Tunnel;
        t
    }

    #[test]
    fn a_long_request_keeps_the_operation_open() {
        let (_, o) = seg(vec![get(1, "https://h/slow").at(0).took(5000), get(2, "https://h/b").at(4000).took(10)]);
        assert_eq!(o.len(), 1);
        // … but only for 10 × the gap (15 s).
        let (_, o) = seg(vec![get(1, "https://h/longpoll").at(0).took(60_000), get(2, "https://h/b").at(30_000).took(10)]);
        assert_eq!(o.len(), 2);
    }

    #[test]
    fn processes_are_separate_streams() {
        let mut a = get(1, "https://h/a").at(0).took(1000);
        a.process = "chrome".into();
        let mut b = get(2, "https://h/b").at(900).took(1000);
        b.process = "outlook".into();
        let mut c = get(3, "https://h/c").at(1100).took(100);
        c.process = "chrome".into();
        let (_, o) = seg(vec![a, b, c]);
        assert_eq!(o.len(), 2);
        assert_eq!(o[0].members, vec![0, 2]);
        assert_eq!(o[1].members, vec![1]);
    }

    #[test]
    fn trace_ids_merge_segments() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let (_, o) = seg(vec![
            get(1, "https://h/start").at(0).took(100).req_h("traceparent", tp),
            get(2, "https://h/other").at(3000).took(100),
            get(3, "https://h/cont").at(6000).took(100).req_h("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-b7ad6b7169203331-01"),
        ]);
        assert_eq!(o.len(), 2);
        assert_eq!(o[0].members, vec![0, 2]);
        assert_eq!(o[1].id, "op-2");
        // correlation id
        let (_, o) = seg(vec![get(1, "https://h/a").at(0).req_h("x-correlation-id", "abc"), get(2, "https://h/b").at(5000).req_h("x-correlation-id", "abc")]);
        assert_eq!(o.len(), 1);
        // an id on every request of the capture is session-wide and ignored
        let s: Vec<Session> = (0..20).map(|i| get(i, &format!("https://h/page{}", ["a", "b", "c", "d"][i as usize % 4]).replace("page", &format!("p{i}x"))).at(i * 5000).req_h("x-correlation-id", "session")).collect();
        assert_eq!(seg(s).1.len(), 20);
        assert_eq!(trace_id("00-00000000000000000000000000000000-00f067aa0ba902b7-01"), None);
        assert_eq!(trace_id("garbage"), None);
    }

    #[test]
    fn recurring_single_requests_form_one_background_operation() {
        let mut v: Vec<Session> = (0..6).map(|i| get(i, "https://h/api/notifications").at(i * 5000).took(20)).collect();
        v.push(get(10, "https://h/case/1").at(2000).took(20));
        v.push(get(11, "https://h/api/case/1").at(2050).took(20));
        let (_, o) = seg(v);
        assert_eq!(o.len(), 2, "{o:?}");
        let bg = o.iter().find(|x| x.members.len() == 6).expect("background operation");
        assert!(bg.label.starts_with("Background: GET /api/notifications (6×)"), "{}", bg.label);
        // Two of a kind are not background yet.
        let (_, o) = seg((0..2).map(|i| get(i, "https://h/api/x").at(i * 5000)).collect());
        assert_eq!(o.len(), 2);
    }

    #[test]
    fn label_prefers_document_then_api() {
        let (_, o) = seg(vec![
            get(1, "https://h/app.js").at(0).body(100, "application/javascript"),
            get(2, "https://h/api/cases").at(10).body(100, "application/json"),
            get(3, "https://h/index.html").at(20).body(100, "text/html"),
        ]);
        assert_eq!(o[0].label, "GET /index.html (+2)");
        let (_, o) = seg(vec![get(1, "https://h/app.js").at(0).body(100, "application/javascript"), get(2, "https://h/api/cases").at(10).body(100, "application/json")]);
        assert_eq!(o[0].label, "GET /api/cases (+1)");
    }

    #[test]
    fn metrics() {
        let (_, o) = seg(vec![
            get(1, "https://h/a").at(0).took(100).body(1000, "application/json").new_conn(0, 5, 5),
            get(2, "https://h/a").at(100).took(100).body(1000, "application/json"),
            get(3, "https://h/b").at(200).took(100).status(500),
        ]);
        let v = |k: &str| o[0].metrics.iter().find(|m| m.key == k).unwrap().value;
        assert_eq!((v("requests"), v("duration"), v("bytes")), (3.0, 300.0, 2000.0));
        assert_eq!((v("sequentialLevels"), v("newConnections"), v("errors"), v("duplicates")), (3.0, 1.0, 1.0, 1.0));
    }
}
