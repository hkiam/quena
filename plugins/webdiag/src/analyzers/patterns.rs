//! Analyzers across sessions: duplicates, N+1, polling, retries, chattiness, OData
//! queries and the network sensitivity of operations.
//!
//! | Rule | Looks for | Threshold |
//! |---|---|---|
//! | `DUP-EXACT` | identical GET/HEAD (method, raw URL, body hash) | ≥ 2; warning ≥ 5, critical: one URL ≥ 20× or ≥ 25 % of all requests |
//! | `DUP-SUBMIT` | identical POST/PATCH within 5 s | ≥ 2 warning, ≥ 3 critical |
//! | `DUP-SEMANTIC` | same `canon::canonical`, different raw URL | ≥ 2 variants; warning ≥ 5 requests |
//! | `DUP-REFRESH` | same GET reloaded within 30 s, response unchanged | ≥ 3 unchanged reloads; warning ≥ 10 |
//! | `PAT-NPLUS1` | one `canon::template` varying in one position | ≥ 10 in an operation; critical ≥ 50 or ≥ 20 sequential |
//! | `PAT-POLLING` | one template at a regular interval | ≥ 5, CV < 0.3, ≥ 1 s; warning < 5 s or ≥ 60 polls |
//! | `PAT-RETRY` | same request again after a failure | within 30 s; critical: storm or non-idempotent |
//! | `PAT-CHATTY` | operations with many requests | ≥ 50 or ≥ 20/s; critical ≥ 150 |
//! | `ODATA-QUERY` / `ODATA-PAGING` | large unbounded/unselected OData queries; overlapping pages | ≥ 1 MiB |
//! | `NET-LATENCY` | long sequential chains | ≥ 10 levels |
//! | `NET-BANDWIDTH` | large transfers, heavy operations | `large*Bytes` options, ≥ 10 MiB per operation |
//! | `NET-RESILIENCE` | operations combining several risk factors | ≥ 2 factors; critical ≥ 3 |
//!
//! Members of a polling series (PAT-POLLING) are timer-driven: DUP-EXACT, DUP-REFRESH and
//! PAT-CHATTY leave them out so that one poll loop is reported once, as polling.
//!
//! Style as in `request.rs`. Findings about operations that repeat (the same main
//! request) are merged into one finding per main request (key = rule + main endpoint),
//! describing the worst occurrence.
//!
//! The expensive per-session preparation (canonical form, template, operation index) is
//! shared by all analyzers of one run through a per-thread cache ([`Prep`]), which
//! `ops::segment` invalidates at the start of each run. Everything is O(n log n).
use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use crate::canon;
use crate::model::{Analyzer, Confidence, Ctx, Finding, Network, Session, Severity};
use crate::net;
use crate::ops;
use crate::util::{self, MAX_PER_RULE};

pub fn all() -> Vec<Box<dyn Analyzer>> {
    vec![
        Box::new(DupExact),
        Box::new(DupSubmit),
        Box::new(DupSemantic),
        Box::new(DupRefresh),
        Box::new(NPlusOne),
        Box::new(Polling),
        Box::new(Retry),
        Box::new(Chatty),
        Box::new(ODataQuery),
        Box::new(NetLatency),
        Box::new(NetBandwidth),
        Box::new(NetResilience),
    ]
}

// ------------------------------------------------------------------ thresholds

/// DUP-EXACT: one URL repeated this often is critical.
pub const EXACT_CRITICAL_REPEATS: usize = 20;
/// DUP-EXACT: this share of exact duplicates in the capture is critical.
pub const EXACT_CRITICAL_SHARE: f64 = 0.25;
/// DUP-SUBMIT: identical non-idempotent requests within this window (ms).
pub const SUBMIT_WINDOW_MS: f64 = 5_000.0;
/// DUP-REFRESH: reloads within this window (ms) …
pub const REFRESH_WINDOW_MS: f64 = 30_000.0;
/// … at least this many times with an unchanged response.
pub const REFRESH_MIN_RELOADS: usize = 3;
/// PAT-NPLUS1: requests of one template in an operation.
pub const NPLUS1_MIN: usize = 10;
pub const NPLUS1_CRITICAL: usize = 50;
pub const NPLUS1_SEQ_CRITICAL: usize = 20;
/// PAT-NPLUS1: a pause longer than this (ms) ends a cluster within an operation.
pub const NPLUS1_GAP_MS: f64 = 5_000.0;
/// PAT-POLLING.
pub const POLL_MIN: usize = 5;
pub const POLL_MAX_CV: f64 = 0.3;
pub const POLL_MIN_INTERVAL_MS: f64 = 1_000.0;
pub const POLL_FAST_MS: f64 = 5_000.0;
pub const POLL_MANY: usize = 60;
/// PAT-RETRY.
pub const RETRY_WINDOW_MS: f64 = 30_000.0;
pub const RETRY_STORM_SEQ: usize = 5;
pub const RETRY_STORM_BURST: usize = 20;
pub const RETRY_STORM_WINDOW_MS: f64 = 10_000.0;
/// PAT-CHATTY.
pub const CHATTY_MIN: usize = 50;
pub const CHATTY_RATE: f64 = 20.0;
pub const CHATTY_RATE_MIN: usize = 20;
pub const CHATTY_CRITICAL: usize = 150;
/// ODATA-QUERY: decoded response size of a "large" collection query.
pub const ODATA_LARGE_BYTES: u64 = 1 << 20;
pub const ODATA_EXPAND_DEPTH: usize = 3;
pub const ODATA_EXPAND_ITEMS: usize = 5;
/// NET-LATENCY / NET-RESILIENCE: sequential levels.
pub const LATENCY_MIN_LEVELS: usize = 10;
/// NET-BANDWIDTH / NET-RESILIENCE: bytes of a heavy operation or transfer.
pub const HEAVY_BYTES: u64 = 10 << 20;

// ------------------------------------------------------------------ shared preparation

const NONE: u32 = u32::MAX;

/// Per-session data shared by the analyzers of one run (see module docs).
pub(crate) struct Prep {
    key: (usize, usize, usize, usize),
    /// Indexes of HTTP sessions, in start order.
    http: Vec<usize>,
    /// Operation index per session (`NONE` for non-HTTP).
    op: Vec<u32>,
    /// Interned `canon::canonical` (with request body hash) per session.
    canon: Vec<u32>,
    canon_str: Vec<String>,
    /// Interned `canon::template` key and its variables per session.
    tmpl: Vec<u32>,
    tmpl_str: Vec<String>,
    vars: Vec<Vec<(String, String)>>,
    rtt: net::RttEstimate,
    chains: OnceCell<Vec<Vec<usize>>>,
    retries: OnceCell<Retries>,
    polls: OnceCell<Vec<Poll>>,
    in_poll: OnceCell<Vec<bool>>,
    nplus1: OnceCell<Vec<NPlus1>>,
}

thread_local! {
    static CACHE: RefCell<Option<Rc<Prep>>> = const { RefCell::new(None) };
}

/// Drop the shared preparation (called by `ops::segment` for every new run).
pub(crate) fn invalidate_cache() {
    CACHE.with(|c| *c.borrow_mut() = None);
}

fn intern(map: &mut HashMap<String, u32>, strs: &mut Vec<String>, s: String) -> u32 {
    if let Some(&id) = map.get(&s) {
        return id;
    }
    let id = strs.len() as u32;
    strs.push(s.clone());
    map.insert(s, id);
    id
}

fn prep(ctx: &Ctx) -> Rc<Prep> {
    let key = (ctx.sessions.as_ptr() as usize, ctx.sessions.len(), ctx.ops.as_ptr() as usize, ctx.ops.len());
    if let Some(p) = CACHE.with(|c| c.borrow().as_ref().filter(|p| p.key == key).cloned()) {
        return p;
    }
    let p = Rc::new(Prep::build(ctx, key));
    CACHE.with(|c| *c.borrow_mut() = Some(p.clone()));
    p
}

impl Prep {
    fn build(ctx: &Ctx, key: (usize, usize, usize, usize)) -> Prep {
        let n = ctx.sessions.len();
        let mut op = vec![NONE; n];
        for (k, o) in ctx.ops.iter().enumerate().filter(|(_, o)| !o.background) {
            for &m in &o.members {
                if m < n {
                    op[m] = k as u32;
                }
            }
        }
        let (mut cmap, mut tmap) = (HashMap::new(), HashMap::new());
        let (mut canon_str, mut tmpl_str) = (vec![], vec![]);
        let (mut canon, mut tmpl, mut vars) = (vec![NONE; n], vec![NONE; n], vec![vec![]; n]);
        let mut http = vec![];
        for (i, s) in ctx.sessions.iter().enumerate() {
            if !s.is_http() {
                continue;
            }
            http.push(i);
            canon[i] = intern(&mut cmap, &mut canon_str, canon::canonical(&s.method, &s.url, s.request_body_hash));
            let t = canon::template(&s.method, &s.url);
            tmpl[i] = intern(&mut tmap, &mut tmpl_str, t.key);
            vars[i] = t.vars;
        }
        let rtt = net::observed_rtt(ctx.sessions, &http);
        Prep { key, http, op, canon, canon_str, tmpl, tmpl_str, vars, rtt, chains: OnceCell::new(), retries: OnceCell::new(), polls: OnceCell::new(), in_poll: OnceCell::new(), nplus1: OnceCell::new() }
    }

    /// Critical path per operation.
    fn chains(&self, ctx: &Ctx) -> &Vec<Vec<usize>> {
        self.chains.get_or_init(|| ctx.ops.iter().map(|o| net::critical_path(ctx.sessions, &o.members)).collect())
    }
    fn retries(&self, ctx: &Ctx) -> &Retries {
        self.retries.get_or_init(|| find_retries(ctx, self))
    }
    fn polls(&self, ctx: &Ctx) -> &Vec<Poll> {
        self.polls.get_or_init(|| find_polls(ctx, self))
    }
    /// Per session: member of a polling series (timer-driven, reported by PAT-POLLING).
    fn in_poll(&self, ctx: &Ctx) -> &Vec<bool> {
        self.in_poll.get_or_init(|| {
            let mut v = vec![false; ctx.sessions.len()];
            for poll in self.polls(ctx) {
                for &i in &poll.members {
                    v[i] = true;
                }
            }
            v
        })
    }
    fn nplus1(&self, ctx: &Ctx) -> &Vec<NPlus1> {
        self.nplus1.get_or_init(|| find_nplus1(ctx, self))
    }
}

// ------------------------------------------------------------------ small helpers

fn ms(s: &Session) -> f64 {
    s.duration_us() as f64 / 1000.0
}
fn bytes(s: &Session) -> u64 {
    s.request_bytes + s.response_bytes
}
fn since_ms(a: u64, b: u64) -> f64 {
    (b as f64 - a as f64) / 1000.0
}
fn upper(m: &str) -> String {
    m.to_ascii_uppercase()
}
fn ids<'a>(ctx: &'a Ctx, idx: &'a [usize]) -> impl Iterator<Item = u64> + 'a {
    idx.iter().map(move |&i| ctx.sessions[i].id)
}
fn is_get(s: &Session) -> bool {
    s.method.eq_ignore_ascii_case("GET") || s.method.eq_ignore_ascii_case("HEAD")
}
fn non_idempotent(s: &Session) -> bool {
    s.method.eq_ignore_ascii_case("POST") || s.method.eq_ignore_ascii_case("PATCH")
}
/// A response that suggests retrying: 5xx, 429, 408, or no response at all.
fn is_failure(s: &Session) -> bool {
    s.failed() || s.status >= 500 || s.status == 429 || s.status == 408
}
fn is_timeout(s: &Session) -> bool {
    s.status == 408
        || s.status == 504
        || s.error.as_deref().is_some_and(|e| {
            let e = e.to_ascii_lowercase();
            e.contains("timeout") || e.contains("timed out")
        })
}
fn failure_text(s: &Session) -> String {
    if s.status > 0 { s.status.to_string() } else { util::short(s.error.as_deref().unwrap_or("no response"), 40) }
}
fn display(s: &Session) -> String {
    format!("{} {}", upper(&s.method), util::short(&s.url, 100))
}
fn op_id<'a>(ctx: &'a Ctx, k: u32) -> Option<&'a str> {
    ctx.ops.get(k as usize).map(|o| o.id.as_str())
}
fn set_op(f: Finding, ctx: &Ctx, k: u32) -> Finding {
    match op_id(ctx, k) {
        Some(id) => f.operation(id),
        None => f,
    }
}
/// Stable subject of an operation: the endpoint of its main request.
fn op_subject(ctx: &Ctx, k: usize) -> String {
    let o = &ctx.ops[k];
    let main = ops::main_request(ctx.sessions, &o.members).unwrap_or(o.members[0]);
    let s = &ctx.sessions[main];
    canon::endpoint(&s.method, &s.url)
}
/// The network profile with the highest RTT (for "worst case" texts).
fn worst_rtt_net<'a>(ctx: &Ctx<'a>) -> Option<&'a Network> {
    ctx.opts.networks.iter().max_by(|a, b| a.rtt_ms.total_cmp(&b.rtt_ms))
}
/// The network profile with the lowest effective throughput.
fn slowest_net<'a>(ctx: &Ctx<'a>) -> Option<&'a Network> {
    ctx.opts.networks.iter().min_by(|a, b| net::throughput_bps(a).total_cmp(&net::throughput_bps(b)))
}
fn fmt_mbps(ctx: &Ctx, bps: f64) -> String {
    let m = bps / 1e6;
    format!("{} Mbit/s", crate::fmt::num(m, if m < 10.0 { 1 } else { 0 }, ctx.opts.lang))
}
fn rtt_text(ctx: &Ctx, r: &net::RttEstimate) -> String {
    match r.source {
        net::RttSource::Measured(n) => {
            if ctx.de() {
                format!("{} (Median des TCP-Verbindungsaufbaus von {} neuen Verbindungen)", ctx.fmt_ms(r.ms), ctx.fmt_count(n))
            } else {
                format!("{} (median TCP connect of {} new connections)", ctx.fmt_ms(r.ms), ctx.fmt_count(n))
            }
        }
        net::RttSource::AssumedLocal => format!("{} ({})", ctx.fmt_ms(r.ms), ctx.l("assumed: local or very fast capture", "angenommen: lokale oder sehr schnelle Aufzeichnung")),
        net::RttSource::Assumed => format!("{} ({})", ctx.fmt_ms(r.ms), ctx.l("assumed, no handshake measured", "angenommen, kein Handshake gemessen")),
    }
}
/// Human name of a template variable (`path[3]`, `key[2]`, `$filter`, `q:id`).
fn var_name(ctx: &Ctx, v: &str) -> String {
    if let Some(p) = v.strip_prefix("path[") {
        format!("{} {}", ctx.l("path segment", "Pfadsegment"), p.trim_end_matches(']'))
    } else if v.starts_with("key[") {
        ctx.l("OData key", "OData-Schlüssel").to_string()
    } else if v == "$filter" {
        ctx.l("literal in $filter", "Literal in $filter").to_string()
    } else if let Some(q) = v.strip_prefix("q:") {
        format!("{} {q}", ctx.l("query parameter", "Query-Parameter"))
    } else {
        v.to_string()
    }
}
fn is_paging_var(v: &str) -> bool {
    matches!(v, "q:$skip" | "q:$skiptoken" | "q:page" | "q:offset" | "q:start" | "q:cursor" | "q:pagetoken" | "q:skip")
}
/// The Quena bandwidth/latency simulation, as a next step.
fn simulate_step(ctx: &Ctx) -> String {
    ctx.l(
        "Verify with Quena's bandwidth/latency simulation (Settings → Connections → Bandwidth simulation), e.g. at 100–200 ms added latency.",
        "Mit der Bandbreiten-/Latenzsimulation von Quena prüfen (Einstellungen → Verbindungen → Bandbreitensimulation), z. B. mit 100–200 ms zusätzlicher Latenz.",
    )
    .to_string()
}

/// Sort worst first and keep at most `MAX_PER_RULE` findings; the rest is summarised in
/// the last one (`<ID>|more`).
fn emit(ctx: &Ctx, out: &mut Vec<Finding>, id: &'static str, what: (&str, &str), mut fs: Vec<Finding>) {
    fs.sort_by(|a, b| a.severity.cmp(&b.severity).then(b.score.cmp(&a.score)).then(a.key.cmp(&b.key)));
    if fs.len() <= MAX_PER_RULE {
        out.extend(fs);
        return;
    }
    let rest = fs.split_off(MAX_PER_RULE - 1);
    out.extend(fs);
    let n = rest.len();
    let sev = rest.iter().map(|f| f.severity).min().unwrap_or(Severity::Info);
    let mut f = Finding::new(
        id,
        "more",
        sev,
        if ctx.de() { format!("{}: {} weitere Fälle", what.1, ctx.fmt_count(n)) } else { format!("{}: {} more cases", what.0, ctx.fmt_count(n)) },
        if ctx.de() {
            format!("{} weitere Befunde dieser Regel sind hier zusammengefasst; die wichtigsten sind oben einzeln aufgeführt.", ctx.fmt_count(n))
        } else {
            format!("{} further findings of this rule are summarised here; the most important ones are listed individually above.", ctx.fmt_count(n))
        },
    )
    .categories(&rest[0].categories)
    .confidence(rest[0].confidence)
    .score(rest[0].score as f64)
    .tags(&rest[0].tags)
    .sessions(rest.iter().flat_map(|f| f.sessions.iter().copied()));
    for r in rest.iter().take(15) {
        f = f.fact(ctx.l("Also", "Außerdem"), r.title.clone());
    }
    if rest.iter().any(|r| r.estimate) {
        f = f.estimate();
    }
    f.threshold = rest[0].threshold.clone();
    out.push(f);
}

/// Group candidate operations `(op index, badness)` by their subject (main endpoint):
/// `(subject, worst op, all ops)`, worst first.
fn by_subject(ctx: &Ctx, cands: Vec<(usize, f64)>) -> Vec<(String, usize, Vec<usize>)> {
    let groups = util::group_by(cands, |(k, _)| op_subject(ctx, *k));
    let mut out: Vec<(String, usize, Vec<usize>, f64)> = groups
        .into_iter()
        .map(|(subj, v)| {
            let worst = v.iter().cloned().max_by(|a, b| a.1.total_cmp(&b.1).then(b.0.cmp(&a.0))).unwrap();
            (subj, worst.0, v.iter().map(|x| x.0).collect(), worst.1)
        })
        .collect();
    out.sort_by(|a, b| b.3.total_cmp(&a.3).then(a.1.cmp(&b.1)));
    out.into_iter().map(|(s, w, all, _)| (s, w, all)).collect()
}
fn ops_sessions<'a>(ctx: &'a Ctx, ops: &'a [usize]) -> impl Iterator<Item = u64> + 'a {
    ops.iter().flat_map(move |&k| ctx.ops[k].members.iter().map(move |&i| ctx.sessions[i].id))
}
fn similar_fact(ctx: &Ctx, f: Finding, ops: &[usize]) -> Finding {
    if ops.len() > 1 {
        f.fact(ctx.l("Similar operations", "Ähnliche Vorgänge"), ctx.fmt_count(ops.len()))
    } else {
        f
    }
}

// ================================================================== DUP-EXACT

/// DUP-EXACT: identical GET/HEAD requests (method, raw URL, request body hash).
struct DupExact;

impl Analyzer for DupExact {
    fn id(&self) -> &'static str {
        "DUP-EXACT"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "modernization"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let p = prep(ctx);
        // Polling series are reported by PAT-POLLING; authentication challenges and failures
        // that are repeated are reported by AUTH-FAIL and PAT-RETRY.
        let in_poll = p.in_poll(ctx);
        let reported_elsewhere = |s: &Session| s.failed() || matches!(s.status, 401 | 407 | 408 | 429) || s.status >= 500;
        let cand = p.http.iter().copied().filter(|&i| is_get(&ctx.sessions[i]) && !in_poll[i] && !reported_elsewhere(&ctx.sessions[i]));
        let exact = util::group_by(cand, |&i| {
            let s = &ctx.sessions[i];
            (upper(&s.method), s.url.as_str(), s.request_body_hash)
        });
        // Aggregate the exact groups by canonical request.
        let dups = exact.into_iter().filter(|(_, v)| v.len() >= 2).map(|(_, v)| v);
        let by_canon = util::group_by(dups, |v| p.canon[v[0]]);
        let total_http = p.http.len();
        let mut all_repeats: Vec<usize> = vec![];
        let mut fs = vec![];
        for (c, groups) in by_canon {
            let repeats: Vec<usize> = groups.iter().flat_map(|g| g[1..].iter().copied()).collect();
            let all: Vec<usize> = groups.iter().flatten().copied().collect();
            all_repeats.extend(&repeats);
            let n_rep = repeats.len();
            let max_single = groups.iter().map(|g| g.len()).max().unwrap_or(0);
            let revalidated = repeats.iter().filter(|&&i| ctx.sessions[i].status == 304).count();
            let wasted_bytes: u64 = repeats.iter().map(|&i| bytes(&ctx.sessions[i])).sum();
            let wasted_ms: f64 = repeats.iter().map(|&i| ms(&ctx.sessions[i])).sum();
            let mut opsv: Vec<u32> = all.iter().map(|&i| p.op[i]).collect();
            opsv.sort_unstable();
            opsv.dedup();
            let first = &ctx.sessions[groups[0][0]];
            let severity = if max_single >= EXACT_CRITICAL_REPEATS {
                Severity::Critical
            } else if n_rep + 1 >= 5 {
                Severity::Warning
            } else {
                Severity::Info
            };
            let occurrences = n_rep + groups.len();
            let mut f = Finding::new(
                "DUP-EXACT",
                &p.canon_str[c as usize],
                severity,
                format!("{} {}", ctx.l("Repeated identical requests:", "Wiederholte identische Requests:"), util::short(&canon::endpoint(&first.method, &first.url), 80)),
                if ctx.de() {
                    format!("{} wurde {}-mal identisch angefordert ({} Wiederholungen); {} der Wiederholungen waren 304-Revalidierungen.", display(first), ctx.fmt_count(occurrences), ctx.fmt_count(n_rep), ctx.fmt_count(revalidated))
                } else {
                    format!("{} was requested {} times identically ({} repeats); {} of the repeats were 304 revalidations.", display(first), ctx.fmt_count(occurrences), ctx.fmt_count(n_rep), ctx.fmt_count(revalidated))
                },
            )
            .categories(&["performance", "duplicates"])
            .score(util::scale(wasted_ms, 0.0, 30_000.0) * 0.6 + util::scale(n_rep as f64, 1.0, 100.0) * 0.4)
            .threshold(ctx.l(
                "≥ 2 identical GET/HEAD requests; warning from 5, critical when one URL is requested ≥ 20 times",
                "≥ 2 identische GET/HEAD-Requests; Warnung ab 5, kritisch, wenn eine URL ≥ 20-mal angefordert wird",
            ))
            .fact(ctx.l("Requests", "Requests"), ctx.fmt_count(occurrences))
            .fact(ctx.l("Repeats", "Wiederholungen"), ctx.fmt_count(n_rep))
            .fact(ctx.l("Of which 304 revalidations", "Davon 304-Revalidierungen"), ctx.fmt_count(revalidated))
            .fact(ctx.l("Most repeats of one URL", "Meiste Wiederholungen einer URL"), ctx.fmt_count(max_single))
            .fact(ctx.l("Transferred by repeats", "Durch Wiederholungen übertragen"), ctx.fmt_bytes(wasted_bytes as f64))
            .fact(ctx.l("Time of repeats (sum)", "Zeit der Wiederholungen (Summe)"), ctx.fmt_ms(wasted_ms))
            .fact(ctx.l("Operations", "Vorgänge"), ctx.fmt_count(opsv.len()))
            .impact(if ctx.de() {
                format!("Die Wiederholungen übertrugen {} und dauerten zusammen {}, die ein Cache oder eine Deduplizierung im Client vermeiden würde.", ctx.fmt_bytes(wasted_bytes as f64), ctx.fmt_ms(wasted_ms))
            } else {
                format!("The repeats transferred {} and took {} in total, which a cache or deduplication in the client would avoid.", ctx.fmt_bytes(wasted_bytes as f64), ctx.fmt_ms(wasted_ms))
            })
            .hypothesis(ctx.l(
                "Several components load the same resource independently (no shared client-side cache or request deduplication).",
                "Mehrere Komponenten laden dieselbe Ressource unabhängig voneinander (kein gemeinsamer Client-Cache, keine Deduplizierung).",
            ))
            .recommend(ctx.l(
                "Load the resource once and share the result (or the in-flight request) between the callers.",
                "Die Ressource einmal laden und das Ergebnis (oder den laufenden Request) zwischen den Aufrufern teilen.",
            ))
            .recommend(ctx.l(
                "Allow HTTP caching: Cache-Control with max-age for stable data, ETag/Last-Modified for revalidation.",
                "HTTP-Caching ermöglichen: Cache-Control mit max-age für stabile Daten, ETag/Last-Modified für Revalidierung.",
            ))
            .next_step(ctx.l("Select the sessions and compare their initiators (Referer, process, timing).", "Die Sessions auswählen und ihre Auslöser vergleichen (Referer, Prozess, Zeitpunkt)."))
            .tags(&["duplicate", "caching"])
            .sessions(ids(ctx, &all));
            if revalidated > 0 {
                f = f.hypothesis(ctx.l(
                    "The client revalidates on every use (304): cheaper than a full download, but still one round trip each; a max-age would avoid it.",
                    "Der Client revalidiert bei jeder Verwendung (304): günstiger als ein voller Download, aber jeweils ein Roundtrip; ein max-age würde ihn vermeiden.",
                ));
            }
            if first.resp_header("cache-control").is_none() && first.resp_header("etag").is_none() && first.resp_header("expires").is_none() {
                f = f.hypothesis(ctx.l(
                    "The response carries no caching headers (Cache-Control, ETag, Expires), so it cannot be reused.",
                    "Die Response enthält keine Caching-Header (Cache-Control, ETag, Expires) und kann daher nicht wiederverwendet werden.",
                ));
            }
            if opsv.len() == 1 && opsv[0] != NONE {
                f = set_op(f, ctx, opsv[0]);
            }
            fs.push(f);
        }
        let share = if total_http > 0 { all_repeats.len() as f64 / total_http as f64 } else { 0.0 };
        if share >= EXACT_CRITICAL_SHARE && all_repeats.len() >= 10 {
            let wasted: u64 = all_repeats.iter().map(|&i| bytes(&ctx.sessions[i])).sum();
            out.push(
                Finding::new(
                    "DUP-EXACT",
                    "share",
                    Severity::Critical,
                    if ctx.de() { format!("{} aller Requests sind exakte Duplikate", ctx.fmt_pct(share)) } else { format!("{} of all requests are exact duplicates", ctx.fmt_pct(share)) },
                    if ctx.de() {
                        format!("{} von {} Requests wiederholten einen vorherigen GET/HEAD-Request unverändert.", ctx.fmt_count(all_repeats.len()), ctx.fmt_count(total_http))
                    } else {
                        format!("{} of {} requests repeated an earlier GET/HEAD request unchanged.", ctx.fmt_count(all_repeats.len()), ctx.fmt_count(total_http))
                    },
                )
                .categories(&["performance", "duplicates"])
                .score(util::scale(share, EXACT_CRITICAL_SHARE, 0.8))
                .threshold(ctx.l("≥ 25 % exact duplicates in the capture", "≥ 25 % exakte Duplikate in der Aufzeichnung"))
                .fact(ctx.l("Duplicate share", "Anteil Duplikate"), ctx.fmt_pct(share))
                .fact(ctx.l("Transferred by repeats", "Durch Wiederholungen übertragen"), ctx.fmt_bytes(wasted as f64))
                .impact(ctx.l(
                    "A large part of the traffic is redundant; removing it reduces load on client, network and server alike.",
                    "Ein großer Teil des Verkehrs ist überflüssig; ihn zu vermeiden entlastet Client, Netz und Server gleichermaßen.",
                ))
                .recommend(ctx.l(
                    "Introduce a shared client-side cache / request deduplication layer and HTTP caching headers.",
                    "Eine gemeinsame Cache-/Deduplizierungsschicht im Client und HTTP-Caching-Header einführen.",
                ))
                .tags(&["duplicate", "caching"])
                .sessions(ids(ctx, &all_repeats)),
            );
        }
        emit(ctx, out, "DUP-EXACT", ("Repeated identical requests", "Wiederholte identische Requests"), fs);
    }
}

// ================================================================== DUP-SUBMIT

/// DUP-SUBMIT: identical POST/PATCH requests within 5 s.
struct DupSubmit;

impl Analyzer for DupSubmit {
    fn id(&self) -> &'static str {
        "DUP-SUBMIT"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["troubleshooting", "resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let p = prep(ctx);
        // The body must be known: hashed, or empty.
        let cand = p.http.iter().copied().filter(|&i| {
            let s = &ctx.sessions[i];
            non_idempotent(s) && (s.request_body_hash.is_some() || s.request_bytes == 0)
        });
        let groups = util::group_by(cand, |&i| {
            let s = &ctx.sessions[i];
            (upper(&s.method), s.url.as_str(), s.request_body_hash)
        });
        let mut clusters: Vec<Vec<usize>> = vec![];
        for (_, list) in groups {
            let mut cur: Vec<usize> = vec![];
            for &i in &list {
                let s = &ctx.sessions[i];
                let joins = cur.last().is_some_and(|&j| {
                    let prev = &ctx.sessions[j];
                    // After a failure it is a retry (PAT-RETRY), not a double submission.
                    since_ms(prev.started, s.started) <= SUBMIT_WINDOW_MS && !is_failure(prev)
                });
                if !joins {
                    if cur.len() >= 2 {
                        clusters.push(std::mem::take(&mut cur));
                    }
                    cur.clear();
                }
                cur.push(i);
            }
            if cur.len() >= 2 {
                clusters.push(cur);
            }
        }
        let by_ep = util::group_by(clusters, |c| {
            let s = &ctx.sessions[c[0]];
            canon::endpoint(&s.method, &s.url)
        });
        let mut fs = vec![];
        for (ep, cl) in by_ep {
            let all: Vec<usize> = cl.iter().flatten().copied().collect();
            let largest = cl.iter().map(|c| c.len()).max().unwrap_or(0);
            let extra: usize = cl.iter().map(|c| c.len() - 1).sum();
            let first = &ctx.sessions[cl[0][0]];
            let min_gap = cl
                .iter()
                .flat_map(|c| c.windows(2).map(|w| since_ms(ctx.sessions[w[0]].started, ctx.sessions[w[1]].started)))
                .fold(f64::INFINITY, f64::min);
            let path = canon::parse(&first.url).path.to_ascii_lowercase();
            let query_like = ["graphql", "search", "query", "find", "$batch"].iter().any(|k| path.contains(k));
            let mut f = Finding::new(
                "DUP-SUBMIT",
                &ep,
                if largest >= 3 { Severity::Critical } else { Severity::Warning },
                format!("{} {}", ctx.l("Possible double submission:", "Mögliches doppeltes Absenden:"), util::short(&ep, 80)),
                if ctx.de() {
                    format!(
                        "{} identische {}-Requests (gleiche URL und gleicher Body) wurden innerhalb von {} gesendet, in {} Gruppe(n); größte Gruppe: {}, kürzester Abstand {}.",
                        ctx.fmt_count(all.len()),
                        upper(&first.method),
                        ctx.fmt_ms(SUBMIT_WINDOW_MS),
                        ctx.fmt_count(cl.len()),
                        ctx.fmt_count(largest),
                        ctx.fmt_ms(min_gap)
                    )
                } else {
                    format!(
                        "{} identical {} requests (same URL and body) were sent within {}, in {} group(s); largest group: {}, shortest interval {}.",
                        ctx.fmt_count(all.len()),
                        upper(&first.method),
                        ctx.fmt_ms(SUBMIT_WINDOW_MS),
                        ctx.fmt_count(cl.len()),
                        ctx.fmt_count(largest),
                        ctx.fmt_ms(min_gap)
                    )
                },
            )
            .confidence(Confidence::Medium)
            .categories(&["troubleshooting", "duplicates"])
            .score(util::scale(extra as f64, 1.0, 20.0))
            .threshold(ctx.l("≥ 2 identical POST/PATCH within 5 s (critical ≥ 3)", "≥ 2 identische POST/PATCH innerhalb von 5 s (kritisch ≥ 3)"))
            .fact(ctx.l("Requests", "Requests"), ctx.fmt_count(all.len()))
            .fact(ctx.l("Groups", "Gruppen"), ctx.fmt_count(cl.len()))
            .fact(ctx.l("Largest group", "Größte Gruppe"), ctx.fmt_count(largest))
            .fact(ctx.l("Shortest interval", "Kürzester Abstand"), ctx.fmt_ms(min_gap))
            .impact(ctx.l(
                "Non-idempotent requests may have been executed more than once: duplicate records, double bookings or conflicting updates.",
                "Nicht idempotente Requests wurden möglicherweise mehrfach ausgeführt: doppelte Datensätze, Doppelbuchungen oder widersprüchliche Änderungen.",
            ))
            .hypothesis(ctx.l(
                "A double click, a submit button that stays enabled while the request is pending, or an event handler registered twice.",
                "Ein Doppelklick, ein Absenden-Button, der während des Requests aktiv bleibt, oder ein doppelt registrierter Event-Handler.",
            ))
            .hypothesis(ctx.l("A client-side retry without a preceding failure (e.g. a too short timeout).", "Eine clientseitige Wiederholung ohne vorherigen Fehler (z. B. ein zu kurzer Timeout)."))
            .recommend(ctx.l("Disable the action while the request is pending; debounce repeated triggers.", "Die Aktion während des laufenden Requests sperren; wiederholte Auslöser entprellen."))
            .recommend(ctx.l(
                "Make the operation idempotent on the server: an idempotency key (e.g. an Idempotency-Key header) and server-side deduplication.",
                "Die Operation serverseitig idempotent machen: ein Idempotenzschlüssel (z. B. Header Idempotency-Key) und Deduplizierung auf dem Server.",
            ))
            .next_step(ctx.l("Check on the server whether the requests created duplicate data.", "Auf dem Server prüfen, ob die Requests doppelte Daten erzeugt haben."))
            .tags(&["duplicate", "idempotency"])
            .sessions(ids(ctx, &all));
            if query_like {
                f = f.hypothesis(ctx.l(
                    "The endpoint looks like a query sent via POST (search, GraphQL, batch): then this is a redundant query rather than a double submission.",
                    "Der Endpunkt sieht nach einer per POST gesendeten Abfrage aus (Suche, GraphQL, Batch): Dann ist es eher eine überflüssige Abfrage als ein doppeltes Absenden.",
                ));
            }
            let op = p.op[cl[0][0]];
            if cl.iter().all(|c| p.op[c[0]] == op) {
                f = set_op(f, ctx, op);
            }
            fs.push(f);
        }
        emit(ctx, out, "DUP-SUBMIT", ("Possible double submissions", "Mögliches doppeltes Absenden"), fs);
    }
}

// ================================================================== DUP-SEMANTIC

/// DUP-SEMANTIC: the same canonical request under different raw URLs.
struct DupSemantic;

#[derive(Default)]
struct Diffs {
    order: usize,
    format: usize,
    cache_buster: usize,
}

fn classify_variant(base: &str, other: &str, d: &mut Diffs) {
    let (a, b) = (canon::parse(base), canon::parse(other));
    let busted = |u: &canon::Url| u.query.iter().any(|(k, v)| canon::is_cache_buster(k, v));
    if busted(&a) || busted(&b) {
        d.cache_buster += 1;
        return;
    }
    let raw = |u: &str| {
        let q = u.split('#').next().unwrap_or("").split_once('?').map(|x| x.1).unwrap_or("");
        let mut v: Vec<&str> = q.split('&').filter(|x| !x.is_empty()).collect();
        v.sort_unstable();
        (u.split('?').next().unwrap_or("").to_string(), v.join("&"))
    };
    if raw(base) == raw(other) {
        d.order += 1;
    } else {
        d.format += 1;
    }
}

impl Analyzer for DupSemantic {
    fn id(&self) -> &'static str {
        "DUP-SEMANTIC"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "modernization"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let p = prep(ctx);
        let cand = p.http.iter().copied().filter(|&i| is_get(&ctx.sessions[i]));
        let groups = util::group_by(cand, |&i| p.canon[i]);
        let mut fs = vec![];
        for (c, list) in groups {
            if list.len() < 2 {
                continue;
            }
            let variants = util::group_by(list.iter().copied(), |&i| ctx.sessions[i].url.as_str());
            if variants.len() < 2 {
                continue;
            }
            let base = variants[0].0;
            let mut d = Diffs::default();
            for (v, _) in &variants[1..] {
                classify_variant(base, v, &mut d);
            }
            let first = &ctx.sessions[list[0]];
            let n = list.len();
            let mut kinds = vec![];
            if d.order > 0 {
                kinds.push(if ctx.de() { format!("Reihenfolge der Parameter ({})", d.order) } else { format!("parameter order ({})", d.order) });
            }
            if d.format > 0 {
                kinds.push(if ctx.de() { format!("Formatierung/Kodierung ({})", d.format) } else { format!("formatting/encoding ({})", d.format) });
            }
            if d.cache_buster > 0 {
                kinds.push(if ctx.de() { format!("Cache-Buster ({})", d.cache_buster) } else { format!("cache busters ({})", d.cache_buster) });
            }
            let odata = canon::is_odata(&canon::parse(&first.url));
            let wasted_ms: f64 = list[1..].iter().map(|&i| ms(&ctx.sessions[i])).sum();
            let rows: Vec<Vec<String>> = variants.iter().take(8).map(|(u, v)| vec![util::short(u, 140), ctx.fmt_count(v.len())]).collect();
            let mut f = Finding::new(
                "DUP-SEMANTIC",
                &p.canon_str[c as usize],
                if n >= 5 { Severity::Warning } else { Severity::Info },
                format!("{} {}", ctx.l("Same request under different URLs:", "Gleicher Request unter verschiedenen URLs:"), util::short(&canon::endpoint(&first.method, &first.url), 80)),
                if ctx.de() {
                    format!("{} Requests auf dieselbe Ressource verwendeten {} verschiedene URLs. Unterschiede: {}.", ctx.fmt_count(n), ctx.fmt_count(variants.len()), kinds.join(", "))
                } else {
                    format!("{} requests for the same resource used {} different URLs. Differences: {}.", ctx.fmt_count(n), ctx.fmt_count(variants.len()), kinds.join(", "))
                },
            )
            .categories(&["performance", "duplicates"])
            .score(util::scale(n as f64, 2.0, 100.0))
            .threshold(ctx.l("≥ 2 URL variants of one canonical request (warning from 5 requests)", "≥ 2 URL-Varianten eines kanonischen Requests (Warnung ab 5 Requests)"))
            .fact(ctx.l("Requests", "Requests"), ctx.fmt_count(n))
            .fact(ctx.l("URL variants", "URL-Varianten"), ctx.fmt_count(variants.len()))
            .fact(ctx.l("Canonical form", "Kanonische Form"), util::short(&p.canon_str[c as usize], 160))
            .fact(ctx.l("Time of redundant requests (sum)", "Zeit der überflüssigen Requests (Summe)"), ctx.fmt_ms(wasted_ms))
            .table(vec![ctx.l("URL variant", "URL-Variante").into(), ctx.l("Requests", "Requests").into()], rows)
            .impact(ctx.l(
                "Caches treat each variant as a different resource, so the same data is loaded again instead of being reused.",
                "Caches behandeln jede Variante als eigene Ressource; dieselben Daten werden erneut geladen statt wiederverwendet.",
            ))
            .recommend(ctx.l(
                "Build these URLs in one place (one query builder with fixed parameter order and formatting).",
                "Diese URLs an einer Stelle bauen (ein Query-Builder mit fester Parameterreihenfolge und Formatierung).",
            ))
            .tags(&["duplicate"])
            .sessions(ids(ctx, &list));
            if d.order + d.format > 0 {
                f = f.hypothesis(ctx.l(
                    "The URL is assembled in several places of the code, each with its own order or formatting.",
                    "Die URL wird an mehreren Stellen im Code zusammengesetzt, jeweils mit eigener Reihenfolge oder Formatierung.",
                ));
            }
            if d.cache_buster > 0 {
                f = f
                    .hypothesis(ctx.l(
                        "A cache-buster parameter makes every URL unique, so no cache (browser, proxy, CDN) can serve it.",
                        "Ein Cache-Buster-Parameter macht jede URL einzigartig, sodass kein Cache (Browser, Proxy, CDN) sie bedienen kann.",
                    ))
                    .recommend(ctx.l(
                        "Replace the cache buster by proper Cache-Control/ETag headers (or a content hash in the file name for static files).",
                        "Den Cache-Buster durch passende Cache-Control-/ETag-Header ersetzen (bei statischen Dateien durch einen Inhalts-Hash im Dateinamen).",
                    ));
            }
            if odata {
                f = f.tags(&["odata"]).recommend(ctx.l(
                    "Normalise the OData system query options ($filter spacing, $select/$expand order) in the client library.",
                    "Die OData-Systemoptionen ($filter-Leerzeichen, Reihenfolge von $select/$expand) in der Client-Bibliothek vereinheitlichen.",
                ));
            }
            fs.push(f);
        }
        emit(ctx, out, "DUP-SEMANTIC", ("Same request under different URLs", "Gleicher Request unter verschiedenen URLs"), fs);
    }
}

// ================================================================== DUP-REFRESH

/// DUP-REFRESH: the same GET reloaded within 30 s with an unchanged response.
struct DupRefresh;

fn unchanged(prev: &Session, cur: &Session) -> bool {
    cur.status == 304 || ((200..300).contains(&cur.status) && cur.response_body_hash.is_some() && cur.response_body_hash == prev.response_body_hash)
}

impl Analyzer for DupRefresh {
    fn id(&self) -> &'static str {
        "DUP-REFRESH"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let p = prep(ctx);
        let in_poll = p.in_poll(ctx);
        let cand = p.http.iter().copied().filter(|&i| ctx.sessions[i].method.eq_ignore_ascii_case("GET"));
        let groups = util::group_by(cand, |&i| p.canon[i]);
        let mut fs = vec![];
        for (c, list) in groups {
            if list.len() <= REFRESH_MIN_RELOADS {
                continue;
            }
            // Runs of unchanged reloads, each within 30 s of the previous load.
            let mut runs: Vec<Vec<usize>> = vec![];
            let mut cur: Vec<usize> = vec![list[0]];
            for w in list.windows(2) {
                let (a, b) = (&ctx.sessions[w[0]], &ctx.sessions[w[1]]);
                if since_ms(a.started, b.started) <= REFRESH_WINDOW_MS && unchanged(a, b) {
                    cur.push(w[1]);
                } else {
                    runs.push(std::mem::replace(&mut cur, vec![w[1]]));
                }
            }
            runs.push(cur);
            let runs: Vec<Vec<usize>> = runs
                .into_iter()
                .filter(|r| r.len() > REFRESH_MIN_RELOADS && r.iter().filter(|&&i| in_poll[i]).count() * 2 <= r.len())
                // Reloads of one and the same URL are exact duplicates (DUP-EXACT); this rule
                // adds the reloads that differ only in form (cache busters, parameter order).
                .filter(|r| r.iter().any(|&i| ctx.sessions[i].url != ctx.sessions[r[0]].url))
                .collect();
            if runs.is_empty() {
                continue;
            }
            let reloads: Vec<usize> = runs.iter().flat_map(|r| r[1..].iter().copied()).collect();
            let all: Vec<usize> = runs.iter().flatten().copied().collect();
            let n304 = reloads.iter().filter(|&&i| ctx.sessions[i].status == 304).count();
            let wasted: u64 = reloads.iter().map(|&i| bytes(&ctx.sessions[i])).sum();
            let wasted_ms: f64 = reloads.iter().map(|&i| ms(&ctx.sessions[i])).sum();
            let first = &ctx.sessions[all[0]];
            let span = since_ms(first.started, ctx.sessions[*all.last().unwrap()].started);
            let mut f = Finding::new(
                "DUP-REFRESH",
                &p.canon_str[c as usize],
                if reloads.len() >= 10 { Severity::Warning } else { Severity::Info },
                format!("{} {}", ctx.l("Redundant refresh:", "Überflüssiges Neuladen:"), util::short(&canon::endpoint(&first.method, &first.url), 80)),
                if ctx.de() {
                    format!("{} wurde innerhalb von {} {}-mal neu geladen, ohne dass sich die Response änderte ({} davon 304).", display(first), ctx.fmt_ms(span), ctx.fmt_count(reloads.len()), ctx.fmt_count(n304))
                } else {
                    format!("{} was reloaded {} times within {} without the response changing ({} of them 304).", display(first), ctx.fmt_count(reloads.len()), ctx.fmt_ms(span), ctx.fmt_count(n304))
                },
            )
            .categories(&["performance", "caching"])
            .score(util::scale(reloads.len() as f64, 3.0, 100.0))
            .threshold(ctx.l("≥ 3 unchanged reloads, each within 30 s (warning ≥ 10)", "≥ 3 unveränderte Neuladungen, jeweils innerhalb von 30 s (Warnung ≥ 10)"))
            .fact(ctx.l("Unchanged reloads", "Unveränderte Neuladungen"), ctx.fmt_count(reloads.len()))
            .fact(ctx.l("Of which 304", "Davon 304"), ctx.fmt_count(n304))
            .fact(ctx.l("Transferred by reloads", "Durch Neuladen übertragen"), ctx.fmt_bytes(wasted as f64))
            .fact(ctx.l("Time of reloads (sum)", "Zeit des Neuladens (Summe)"), ctx.fmt_ms(wasted_ms))
            .impact(ctx.l(
                "Each reload costs at least one round trip and server work for data the client already has.",
                "Jedes Neuladen kostet mindestens einen Roundtrip und Serverarbeit für Daten, die der Client schon hat.",
            ))
            .hypothesis(ctx.l(
                "The data is reloaded on every view change or component mount instead of being kept in client state.",
                "Die Daten werden bei jedem Ansichtswechsel oder Einblenden einer Komponente neu geladen, statt im Client-Zustand gehalten zu werden.",
            ))
            .recommend(ctx.l("Keep the data in client state and reload it only when it can have changed.", "Die Daten im Client-Zustand halten und nur neu laden, wenn sie sich geändert haben können."))
            .recommend(ctx.l(
                "Cache-Control: max-age (for data that may be slightly stale) lets the browser answer without a request.",
                "Cache-Control: max-age (für Daten, die leicht veraltet sein dürfen) lässt den Browser ohne Request antworten.",
            ))
            .tags(&["refresh", "caching"])
            .sessions(ids(ctx, &all));
            f = if n304 * 2 >= reloads.len() {
                f.hypothesis(ctx.l(
                    "The requests are already conditional (ETag/Last-Modified → 304); the remaining cost is the round trip.",
                    "Die Requests sind bereits bedingt (ETag/Last-Modified → 304); es bleibt der Roundtrip.",
                ))
            } else {
                f.recommend(ctx.l(
                    "Send ETag/Last-Modified so that reloads become cheap conditional requests (304).",
                    "ETag/Last-Modified senden, damit Neuladungen zu günstigen bedingten Requests (304) werden.",
                ))
            };
            let op = p.op[all[0]];
            if all.iter().all(|&i| p.op[i] == op) {
                f = set_op(f, ctx, op);
            }
            fs.push(f);
        }
        emit(ctx, out, "DUP-REFRESH", ("Redundant refresh", "Überflüssiges Neuladen"), fs);
    }
}

// ================================================================== PAT-NPLUS1

/// One N+1 cluster: requests of one template in one operation, varying in one position.
struct NPlus1 {
    tmpl: u32,
    op: u32,
    members: Vec<usize>,
    var: String,
    distinct: usize,
    levels: usize,
}

fn find_nplus1(ctx: &Ctx, p: &Prep) -> Vec<NPlus1> {
    let cand = p.http.iter().copied().filter(|&i| {
        let s = &ctx.sessions[i];
        p.op[i] != NONE && !p.vars[i].is_empty() && !canon::is_static(&s.mime(), &s.url)
    });
    let groups = util::group_by(cand, |&i| (p.op[i], p.tmpl[i]));
    let mut out = vec![];
    for ((op, tmpl), list) in groups {
        if list.len() < NPLUS1_MIN {
            continue;
        }
        // Split at pauses > 5 s (within long operations).
        let mut clusters: Vec<Vec<usize>> = vec![];
        let mut busy = 0u64;
        for &i in &list {
            let s = &ctx.sessions[i];
            if clusters.is_empty() || since_ms(busy, s.started) > NPLUS1_GAP_MS {
                clusters.push(vec![]);
            }
            busy = busy.max(s.end());
            clusters.last_mut().unwrap().push(i);
        }
        for members in clusters {
            if members.len() < NPLUS1_MIN {
                continue;
            }
            let len = p.vars[members[0]].len();
            if members.iter().any(|&i| p.vars[i].len() != len) {
                continue;
            }
            let mut varying: Option<(usize, usize)> = None;
            let mut ok = true;
            for pos in 0..len {
                let mut vals: Vec<&str> = members.iter().map(|&i| p.vars[i][pos].1.as_str()).collect();
                vals.sort_unstable();
                vals.dedup();
                if vals.len() > 1 {
                    if varying.is_some() {
                        ok = false;
                        break;
                    }
                    varying = Some((pos, vals.len()));
                }
            }
            let Some((pos, distinct)) = varying.filter(|_| ok) else { continue };
            let var = p.vars[members[0]][pos].0.clone();
            if is_paging_var(&var) || distinct < (members.len() / 2).max(5) {
                continue;
            }
            let levels = net::critical_path(ctx.sessions, &members).len();
            out.push(NPlus1 { tmpl, op, members, var, distinct, levels });
        }
    }
    out
}

/// PAT-NPLUS1: many requests of one shape that differ only in one id.
struct NPlusOne;

impl Analyzer for NPlusOne {
    fn id(&self) -> &'static str {
        "PAT-NPLUS1"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "modernization", "resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let p = prep(ctx);
        let by_tmpl = util::group_by(p.nplus1(ctx).iter(), |c| c.tmpl);
        let mut fs = vec![];
        for (t, clusters) in by_tmpl {
            let worst = clusters.iter().max_by_key(|c| (c.members.len().max(c.levels * 2), std::cmp::Reverse(c.members[0]))).unwrap();
            let all: Vec<usize> = clusters.iter().flat_map(|c| c.members.iter().copied()).collect();
            let n = worst.members.len();
            let sessions: Vec<&Session> = worst.members.iter().map(|&i| &ctx.sessions[i]).collect();
            let total_ms: f64 = sessions.iter().map(|s| ms(s)).sum();
            let total_bytes: u64 = sessions.iter().map(|s| bytes(s)).sum();
            let wall = since_ms(sessions[0].started, sessions.iter().map(|s| s.end()).max().unwrap_or(0));
            let sequential = worst.levels * 2 >= n;
            let first = sessions[0];
            let odata = canon::is_odata(&canon::parse(&first.url));
            let severity = if n >= NPLUS1_CRITICAL || worst.levels >= NPLUS1_SEQ_CRITICAL { Severity::Critical } else { Severity::Warning };
            let var = var_name(ctx, &worst.var);
            let template = &p.tmpl_str[t as usize];
            let mode = match (sequential, ctx.de()) {
                (true, true) => "überwiegend nacheinander",
                (true, false) => "mostly one after another",
                (false, true) => "überwiegend parallel",
                (false, false) => "mostly in parallel",
            };
            let mut f = Finding::new(
                "PAT-NPLUS1",
                template,
                severity,
                format!("{} {}", ctx.l("N+1 request pattern:", "N+1-Request-Muster:"), util::short(&canon::endpoint(&first.method, &first.url), 80)),
                if ctx.de() {
                    format!(
                        "{} Requests gleicher Form unterschieden sich nur in einem Wert ({}; {} verschiedene Werte) und liefen {} ({} sequenzielle Stufen, {} insgesamt).",
                        ctx.fmt_count(n),
                        var,
                        ctx.fmt_count(worst.distinct),
                        mode,
                        ctx.fmt_count(worst.levels),
                        ctx.fmt_ms(wall)
                    )
                } else {
                    format!(
                        "{} requests of the same shape differed only in {} ({} distinct values) and ran {} ({} sequential levels, {} in total).",
                        ctx.fmt_count(n),
                        var,
                        ctx.fmt_count(worst.distinct),
                        mode,
                        ctx.fmt_count(worst.levels),
                        ctx.fmt_ms(wall)
                    )
                },
            )
            .categories(&["performance", "chattiness"])
            .score(util::scale(n as f64 + worst.levels as f64 * 2.0, NPLUS1_MIN as f64, 300.0))
            .threshold(ctx.l(
                "≥ 10 requests of one template in one operation, varying in one position (critical ≥ 50 or ≥ 20 sequential)",
                "≥ 10 Requests einer Vorlage in einem Vorgang, variabel an einer Stelle (kritisch ≥ 50 oder ≥ 20 sequenziell)",
            ))
            .fact(ctx.l("Template", "Vorlage"), util::short(template, 160))
            .fact(ctx.l("Varying part", "Variabler Teil"), var)
            .fact(ctx.l("Requests", "Requests"), ctx.fmt_count(n))
            .fact(ctx.l("Distinct values", "Verschiedene Werte"), ctx.fmt_count(worst.distinct))
            .fact(ctx.l("Sequential levels", "Sequenzielle Stufen"), ctx.fmt_count(worst.levels))
            .fact(ctx.l("Time of the requests (sum)", "Zeit der Requests (Summe)"), ctx.fmt_ms(total_ms))
            .fact(ctx.l("Wall time", "Gesamtdauer"), ctx.fmt_ms(wall))
            .fact(ctx.l("Transferred", "Übertragen"), ctx.fmt_bytes(total_bytes as f64))
            .hypothesis(ctx.l(
                "The client loads a list and then fetches the details of every item one by one.",
                "Der Client lädt eine Liste und holt danach die Details jedes Eintrags einzeln.",
            ))
            .tags(&["n+1"])
            .sessions(ids(ctx, &all));
            if clusters.len() > 1 {
                f = f.fact(ctx.l("Occurrences (operations/bursts)", "Vorkommen (Vorgänge/Schübe)"), ctx.fmt_count(clusters.len()));
            }
            if let (true, Some(w)) = (sequential, worst_rtt_net(ctx)) {
                let extra = worst.levels as f64 * (w.rtt_ms - p.rtt.ms).max(0.0);
                f = f.estimate().impact(if ctx.de() {
                    format!("Jeder sequenzielle Request kostet mindestens einen Roundtrip: Bei {} RTT ({}) kämen allein dadurch etwa {} hinzu.", ctx.fmt_ms(w.rtt_ms), w.name, ctx.fmt_ms(extra))
                } else {
                    format!("Every sequential request costs at least one round trip: at {} RTT ({}) this alone adds about {}.", ctx.fmt_ms(w.rtt_ms), w.name, ctx.fmt_ms(extra))
                });
            } else {
                f = f.impact(ctx.l(
                    "Many small requests cost round trips, connection slots and server overhead; they scale with the number of items.",
                    "Viele kleine Requests kosten Roundtrips, Verbindungsplätze und Serverlast; sie wachsen mit der Anzahl der Einträge.",
                ));
            }
            f = if odata {
                f.tags(&["odata"])
                    .recommend(ctx.l(
                        "Load the items with one query: $filter=Id in (1,2,3) (OData 4.01) or $filter=Id eq 1 or Id eq 2 ….",
                        "Die Einträge mit einer Abfrage laden: $filter=Id in (1,2,3) (OData 4.01) oder $filter=Id eq 1 or Id eq 2 ….",
                    ))
                    .recommend(ctx.l("Load the related entities together with the parent query ($expand).", "Die zugehörigen Entitäten mit der übergeordneten Abfrage laden ($expand)."))
                    .recommend(ctx.l("If separate requests are unavoidable, group them in one $batch request.", "Wenn getrennte Requests unvermeidbar sind, sie in einem $batch-Request bündeln."))
            } else {
                f.recommend(ctx.l(
                    "Offer a bulk endpoint (e.g. ?ids=1,2,3) or include the data in the parent response.",
                    "Einen Sammel-Endpunkt anbieten (z. B. ?ids=1,2,3) oder die Daten in die übergeordnete Response aufnehmen.",
                ))
                .recommend(ctx.l(
                    "Resolve the relation on the server (aggregation layer / backend for frontend, GraphQL).",
                    "Die Beziehung auf dem Server auflösen (Aggregationsschicht / Backend for Frontend, GraphQL).",
                ))
            };
            if sequential {
                f = f.recommend(ctx.l("At least run independent requests in parallel.", "Unabhängige Requests zumindest parallel ausführen."));
            }
            f = set_op(f, ctx, worst.op).next_step(ctx.l("Select the sessions and look for the list request that precedes them.", "Die Sessions auswählen und den vorausgehenden Listen-Request suchen."));
            fs.push(f);
        }
        emit(ctx, out, "PAT-NPLUS1", ("N+1 request patterns", "N+1-Request-Muster"), fs);
    }
}

// ================================================================== PAT-POLLING

/// One polling series: a template requested at a regular interval.
struct Poll {
    tmpl: u32,
    members: Vec<usize>,
    interval_ms: f64,
    cv: f64,
    unchanged: usize,
    conditional: usize,
    long_poll: bool,
}

fn find_polls(ctx: &Ctx, p: &Prep) -> Vec<Poll> {
    let groups = util::group_by(p.http.iter().copied(), |&i| (ctx.sessions[i].process.as_str(), p.tmpl[i]));
    let mut out = vec![];
    for ((_, tmpl), list) in groups {
        if list.len() < POLL_MIN {
            continue;
        }
        let iv: Vec<f64> = list.windows(2).map(|w| since_ms(ctx.sessions[w[0]].started, ctx.sessions[w[1]].started)).collect();
        let med = util::percentile(&iv, 50.0);
        if med < POLL_MIN_INTERVAL_MS / 2.0 {
            continue;
        }
        // Runs of intervals close to the median.
        let mut runs: Vec<Vec<usize>> = vec![vec![list[0]]];
        for (k, &d) in iv.iter().enumerate() {
            if d > med * 2.0 || d < med / 2.0 {
                runs.push(vec![]);
            }
            runs.last_mut().unwrap().push(list[k + 1]);
        }
        for members in runs {
            if members.len() < POLL_MIN {
                continue;
            }
            let iv: Vec<f64> = members.windows(2).map(|w| since_ms(ctx.sessions[w[0]].started, ctx.sessions[w[1]].started)).collect();
            let (mean, cv) = util::mean_cv(&iv);
            if cv >= POLL_MAX_CV || mean < POLL_MIN_INTERVAL_MS {
                continue;
            }
            let unchanged_n = members.windows(2).filter(|w| unchanged(&ctx.sessions[w[0]], &ctx.sessions[w[1]])).count();
            let conditional = members.iter().filter(|&&i| ctx.sessions[i].req_header("if-none-match").is_some() || ctx.sessions[i].req_header("if-modified-since").is_some()).count();
            let durs: Vec<f64> = members.iter().map(|&i| ms(&ctx.sessions[i])).collect();
            let long_poll = util::percentile(&durs, 50.0) >= mean * 0.8;
            out.push(Poll { tmpl, members, interval_ms: mean, cv, unchanged: unchanged_n, conditional, long_poll });
        }
    }
    out
}

/// PAT-POLLING: the same template at a near-regular interval.
struct Polling;

impl Analyzer for Polling {
    fn id(&self) -> &'static str {
        "PAT-POLLING"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "modernization", "resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let p = prep(ctx);
        let by_tmpl = util::group_by(p.polls(ctx).iter(), |x| x.tmpl);
        let mut fs = vec![];
        for (t, series) in by_tmpl {
            let all: Vec<usize> = series.iter().flat_map(|x| x.members.iter().copied()).collect();
            let n = all.len();
            let main = series.iter().max_by_key(|x| x.members.len()).unwrap();
            let period = main.interval_ms;
            let pairs: usize = series.iter().map(|x| x.members.len() - 1).sum();
            let unchanged_share = if pairs > 0 { series.iter().map(|x| x.unchanged).sum::<usize>() as f64 / pairs as f64 } else { 0.0 };
            let conditional: usize = series.iter().map(|x| x.conditional).sum();
            let span: f64 = series.iter().map(|x| since_ms(ctx.sessions[x.members[0]].started, ctx.sessions[*x.members.last().unwrap()].end())).sum();
            let total_bytes: u64 = all.iter().map(|&i| bytes(&ctx.sessions[i])).sum();
            let long_poll = main.long_poll;
            let first = &ctx.sessions[all[0]];
            let severity = if long_poll {
                Severity::Info
            } else if period < POLL_FAST_MS || n >= POLL_MANY {
                Severity::Warning
            } else {
                Severity::Info
            };
            let per_hour = 3_600_000.0 / period.max(1.0);
            let mut f = Finding::new(
                "PAT-POLLING",
                &p.tmpl_str[t as usize],
                severity,
                if ctx.de() {
                    format!("Polling alle {}: {}", ctx.fmt_ms(period), util::short(&canon::endpoint(&first.method, &first.url), 80))
                } else {
                    format!("Polling every {}: {}", ctx.fmt_ms(period), util::short(&canon::endpoint(&first.method, &first.url), 80))
                },
                if ctx.de() {
                    format!(
                        "{} Requests in regelmäßigem Abstand von {} (Schwankung {}) über {}; {} der Responses waren unverändert.",
                        ctx.fmt_count(n),
                        ctx.fmt_ms(period),
                        ctx.fmt_pct(main.cv),
                        ctx.fmt_ms(span),
                        ctx.fmt_pct(unchanged_share)
                    )
                } else {
                    format!(
                        "{} requests at a regular interval of {} (variation {}) over {}; {} of the responses were unchanged.",
                        ctx.fmt_count(n),
                        ctx.fmt_ms(period),
                        ctx.fmt_pct(main.cv),
                        ctx.fmt_ms(span),
                        ctx.fmt_pct(unchanged_share)
                    )
                },
            )
            .categories(&["performance", "polling"])
            .score(util::scale(per_hour, 60.0, 3600.0) * 0.5 + util::scale(unchanged_share, 0.0, 1.0) * 0.5)
            .threshold(ctx.l(
                "≥ 5 requests at a regular interval ≥ 1 s (variation < 30 %); warning below 5 s or from 60 polls",
                "≥ 5 Requests in regelmäßigem Abstand ≥ 1 s (Schwankung < 30 %); Warnung unter 5 s oder ab 60 Abfragen",
            ))
            .fact(ctx.l("Polls", "Abfragen"), ctx.fmt_count(n))
            .fact(ctx.l("Period", "Intervall"), ctx.fmt_ms(period))
            .fact(ctx.l("Variation (CV)", "Schwankung (VK)"), ctx.fmt_pct(main.cv))
            .fact(ctx.l("Unchanged responses", "Unveränderte Responses"), ctx.fmt_pct(unchanged_share))
            .fact(ctx.l("Conditional requests", "Bedingte Requests"), ctx.fmt_count(conditional))
            .fact(ctx.l("Transferred", "Übertragen"), ctx.fmt_bytes(total_bytes as f64))
            .fact(ctx.l("Requests per hour and client", "Requests pro Stunde und Client"), ctx.fmt_count(per_hour.round() as usize))
            .impact(if ctx.de() {
                format!("Pro Client etwa {} Requests pro Stunde; die Last wächst mit der Zahl der Clients, auch wenn sich nichts ändert.", ctx.fmt_count(per_hour.round() as usize))
            } else {
                format!("About {} requests per hour per client; the load grows with the number of clients even when nothing changes.", ctx.fmt_count(per_hour.round() as usize))
            })
            .tags(&["polling"])
            .sessions(ids(ctx, &all));
            if long_poll {
                f = f.hypothesis(ctx.l(
                    "Each request is held open by the server for most of the interval: this is long polling, already a form of push.",
                    "Jeder Request wird vom Server fast das ganze Intervall offen gehalten: Das ist Long Polling, bereits eine Form von Push.",
                ));
            } else {
                f = f
                    .recommend(ctx.l(
                        "Replace polling by push (WebSocket or Server-Sent Events) where the server knows about changes.",
                        "Polling durch Push ersetzen (WebSocket oder Server-Sent Events), wo der Server Änderungen kennt.",
                    ))
                    .recommend(ctx.l(
                        "Otherwise poll less often, back off while nothing changes and pause while the view is hidden.",
                        "Andernfalls seltener abfragen, bei unveränderten Daten das Intervall verlängern und bei verdeckter Ansicht pausieren.",
                    ));
            }
            if conditional * 2 < n {
                f = f.recommend(ctx.l(
                    "Use conditional requests (ETag + If-None-Match → 304) so that unchanged polls transfer no body.",
                    "Bedingte Requests verwenden (ETag + If-None-Match → 304), damit unveränderte Abfragen keinen Body übertragen.",
                ));
            }
            f = f.hypothesis(ctx.l(
                "On unstable networks, fixed-interval polling without backoff keeps load high and piles up requests after outages.",
                "In instabilen Netzen hält Polling mit festem Intervall ohne Backoff die Last hoch und staut nach Ausfällen Requests auf.",
            ));
            fs.push(f);
        }
        emit(ctx, out, "PAT-POLLING", ("Polling", "Polling"), fs);
    }
}

// ================================================================== PAT-RETRY

/// One retry sequence: a failed request and its repetitions.
struct RetrySeq {
    /// Session indexes: the first failure, then every retry.
    attempts: Vec<usize>,
    recovered: bool,
    /// Retries that came sooner than the preceding `Retry-After`.
    ra_violations: usize,
    /// Failures that carried a `Retry-After`.
    ra_seen: usize,
}

struct Retries {
    seqs: Vec<RetrySeq>,
    /// The densest 10 s window of retries, if it holds ≥ `RETRY_STORM_BURST`.
    storm: Option<Vec<usize>>,
}

fn find_retries(ctx: &Ctx, p: &Prep) -> Retries {
    let groups = util::group_by(p.http.iter().copied(), |&i| p.canon[i]);
    let mut seqs = vec![];
    for (_, list) in groups {
        if list.len() < 2 {
            continue;
        }
        let mut cur: Option<RetrySeq> = None;
        let mut prev: Option<usize> = None;
        for &j in &list {
            let s = &ctx.sessions[j];
            if let Some(pi) = prev {
                let ps = &ctx.sessions[pi];
                let after = s.started + net::TOLERANCE_US >= ps.end();
                if is_failure(ps) && after && since_ms(ps.end(), s.started) <= RETRY_WINDOW_MS {
                    let seq = cur.get_or_insert_with(|| RetrySeq { attempts: vec![pi], recovered: false, ra_violations: 0, ra_seen: 0 });
                    seq.attempts.push(j);
                    if let Some(ra) = ps.resp_header("retry-after").and_then(|v| util::retry_after_ms(v, ps.end())) {
                        seq.ra_seen += 1;
                        if since_ms(ps.end(), s.started) + 1.0 < ra {
                            seq.ra_violations += 1;
                        }
                    }
                    if !is_failure(s) {
                        let mut done = cur.take().unwrap();
                        done.recovered = true;
                        seqs.push(done);
                    }
                    prev = Some(j);
                    continue;
                }
            }
            if let Some(done) = cur.take() {
                seqs.push(done);
            }
            prev = Some(j);
        }
        if let Some(done) = cur.take() {
            seqs.push(done);
        }
    }
    seqs.sort_by_key(|s| s.attempts[0]);
    // Densest window of retries (all sequences together).
    let mut retries: Vec<usize> = seqs.iter().flat_map(|s| s.attempts[1..].iter().copied()).collect();
    retries.sort_unstable();
    let (mut best, mut lo) = ((0, 0), 0);
    for hi in 0..retries.len() {
        while since_ms(ctx.sessions[retries[lo]].started, ctx.sessions[retries[hi]].started) > RETRY_STORM_WINDOW_MS {
            lo += 1;
        }
        if hi + 1 - lo > best.1 - best.0 {
            best = (lo, hi + 1);
        }
    }
    let storm = (best.1 - best.0 >= RETRY_STORM_BURST).then(|| retries[best.0..best.1].to_vec());
    Retries { seqs, storm }
}

/// PAT-RETRY: the same request repeated after a failure.
struct Retry;

impl Analyzer for Retry {
    fn id(&self) -> &'static str {
        "PAT-RETRY"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["troubleshooting", "resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let p = prep(ctx);
        let r = p.retries(ctx);
        let by_ep = util::group_by(r.seqs.iter(), |s| {
            let x = &ctx.sessions[s.attempts[0]];
            canon::endpoint(&x.method, &x.url)
        });
        let mut fs = vec![];
        for (ep, seqs) in by_ep {
            let all: Vec<usize> = seqs.iter().flat_map(|s| s.attempts.iter().copied()).collect();
            let retries: usize = seqs.iter().map(|s| s.attempts.len() - 1).sum();
            let max_retries = seqs.iter().map(|s| s.attempts.len() - 1).max().unwrap_or(0);
            let recovered = seqs.iter().filter(|s| s.recovered).count();
            let violations: usize = seqs.iter().map(|s| s.ra_violations).sum();
            let ra_seen: usize = seqs.iter().map(|s| s.ra_seen).sum();
            let first = &ctx.sessions[seqs[0].attempts[0]];
            let unsafe_method = non_idempotent(first);
            let mut causes: Vec<String> = all.iter().map(|&i| &ctx.sessions[i]).filter(|s| is_failure(s)).map(failure_text).collect();
            causes.sort();
            causes.dedup();
            let storm = max_retries >= RETRY_STORM_SEQ;
            let severity = if unsafe_method || storm {
                Severity::Critical
            } else if violations > 0 || recovered < seqs.len() {
                Severity::Warning
            } else {
                Severity::Info
            };
            let gaps: Vec<f64> = seqs.iter().flat_map(|s| s.attempts.windows(2).map(|w| since_ms(ctx.sessions[w[0]].end(), ctx.sessions[w[1]].started))).collect();
            let median_gap = util::percentile(&gaps, 50.0);
            let mut f = Finding::new(
                "PAT-RETRY",
                &ep,
                severity,
                if storm {
                    format!("{} {}", ctx.l("Retry storm:", "Wiederholungssturm:"), util::short(&ep, 80))
                } else {
                    format!("{} {}", ctx.l("Retries after failures:", "Wiederholungen nach Fehlern:"), util::short(&ep, 80))
                },
                if ctx.de() {
                    format!(
                        "{} Wiederholung(en) in {} Folge(n) nach Fehlern ({}); {} Folge(n) endeten erfolgreich, {} weiterhin fehlerhaft. Meiste Wiederholungen eines Requests: {}, typischer Abstand {}.",
                        ctx.fmt_count(retries),
                        ctx.fmt_count(seqs.len()),
                        causes.join(", "),
                        ctx.fmt_count(recovered),
                        ctx.fmt_count(seqs.len() - recovered),
                        ctx.fmt_count(max_retries),
                        ctx.fmt_ms(median_gap)
                    )
                } else {
                    format!(
                        "{} retr(ies) in {} sequence(s) after failures ({}); {} sequence(s) recovered, {} still failing. Most retries of one request: {}, typical gap {}.",
                        ctx.fmt_count(retries),
                        ctx.fmt_count(seqs.len()),
                        causes.join(", "),
                        ctx.fmt_count(recovered),
                        ctx.fmt_count(seqs.len() - recovered),
                        ctx.fmt_count(max_retries),
                        ctx.fmt_ms(median_gap)
                    )
                },
            )
            .categories(&["troubleshooting", "resilience"])
            .score(util::scale(retries as f64, 1.0, 50.0))
            .threshold(ctx.l(
                "Same request within 30 s after a 5xx/429/408 or failed response; storm: ≥ 5 retries of one request",
                "Gleicher Request innerhalb von 30 s nach 5xx/429/408 oder ohne Response; Sturm: ≥ 5 Wiederholungen eines Requests",
            ))
            .fact(ctx.l("Retries", "Wiederholungen"), ctx.fmt_count(retries))
            .fact(ctx.l("Sequences", "Folgen"), ctx.fmt_count(seqs.len()))
            .fact(ctx.l("Recovered", "Erfolgreich beendet"), ctx.fmt_count(recovered))
            .fact(ctx.l("Most retries of one request", "Meiste Wiederholungen eines Requests"), ctx.fmt_count(max_retries))
            .fact(ctx.l("Typical gap before retry", "Typischer Abstand vor Wiederholung"), ctx.fmt_ms(median_gap))
            .fact(ctx.l("Failures", "Fehler"), causes.join(", "))
            .impact(ctx.l(
                "Retries hide failures from the user but add load exactly when the server or network is struggling.",
                "Wiederholungen verbergen Fehler vor dem Benutzer, erzeugen aber zusätzliche Last genau dann, wenn Server oder Netz ohnehin kämpfen.",
            ))
            .recommend(ctx.l(
                "Retry with exponential backoff and jitter, limit the number of attempts and stop early (circuit breaker).",
                "Mit exponentiellem Backoff und Zufallsanteil wiederholen, die Zahl der Versuche begrenzen und früh abbrechen (Circuit Breaker).",
            ))
            .next_step(ctx.l("Open the first failure of a sequence and check its cause (status, error, timing).", "Den ersten Fehler einer Folge öffnen und seine Ursache prüfen (Status, Fehler, Zeitverlauf)."))
            .tags(&["retry"])
            .sessions(ids(ctx, &all));
            if ra_seen > 0 {
                f = f.fact(ctx.l("Retry-After ignored", "Retry-After missachtet"), format!("{} / {}", ctx.fmt_count(violations), ctx.fmt_count(ra_seen)));
            }
            if violations > 0 {
                f = f.recommend(ctx.l(
                    "Respect Retry-After: the server asked the client to wait longer than it did.",
                    "Retry-After beachten: Der Server hat den Client gebeten, länger zu warten, als er es tat.",
                ));
            } else if causes.iter().any(|c| c == "429" || c == "503") {
                f = f.recommend(ctx.l(
                    "For 429/503, the server should send Retry-After and the client should honour it.",
                    "Bei 429/503 sollte der Server Retry-After senden und der Client es beachten.",
                ));
            }
            if unsafe_method {
                f = f
                    .hypothesis(ctx.l(
                        "A non-idempotent request was repeated: if the first attempt reached the server, the action may have been executed twice.",
                        "Ein nicht idempotenter Request wurde wiederholt: Hat der erste Versuch den Server erreicht, wurde die Aktion möglicherweise doppelt ausgeführt.",
                    ))
                    .recommend(ctx.l(
                        "Retry writes only with an idempotency key (e.g. Idempotency-Key header) that the server deduplicates.",
                        "Schreibende Requests nur mit Idempotenzschlüssel wiederholen (z. B. Header Idempotency-Key), den der Server dedupliziert.",
                    ))
                    .tags(&["idempotency"]);
            }
            if median_gap < 1000.0 {
                f = f.hypothesis(ctx.l("Retries follow almost immediately; there is no noticeable backoff.", "Die Wiederholungen folgen fast sofort; ein spürbarer Backoff fehlt."));
            }
            let op = p.op[all[0]];
            if all.iter().all(|&i| p.op[i] == op) {
                f = set_op(f, ctx, op);
            }
            fs.push(f);
        }
        if let Some(storm) = &r.storm {
            let span = since_ms(ctx.sessions[storm[0]].started, ctx.sessions[*storm.last().unwrap()].started);
            let mut eps: Vec<String> = storm.iter().map(|&i| canon::endpoint(&ctx.sessions[i].method, &ctx.sessions[i].url)).collect();
            eps.sort();
            eps.dedup();
            out.push(
                Finding::new(
                    "PAT-RETRY",
                    "storm",
                    Severity::Critical,
                    if ctx.de() { format!("Wiederholungssturm: {} Wiederholungen innerhalb von {}", ctx.fmt_count(storm.len()), ctx.fmt_ms(span.max(1.0))) } else { format!("Retry storm: {} retries within {}", ctx.fmt_count(storm.len()), ctx.fmt_ms(span.max(1.0))) },
                    if ctx.de() {
                        format!("{} Wiederholungen nach Fehlern fielen in ein Zeitfenster von {} ({} Endpunkte).", ctx.fmt_count(storm.len()), ctx.fmt_ms(RETRY_STORM_WINDOW_MS), ctx.fmt_count(eps.len()))
                    } else {
                        format!("{} retries after failures fell into a window of {} ({} endpoints).", ctx.fmt_count(storm.len()), ctx.fmt_ms(RETRY_STORM_WINDOW_MS), ctx.fmt_count(eps.len()))
                    },
                )
                .categories(&["troubleshooting", "resilience"])
                .score(util::scale(storm.len() as f64, RETRY_STORM_BURST as f64, 200.0))
                .threshold(ctx.l("≥ 20 retries within 10 s", "≥ 20 Wiederholungen innerhalb von 10 s"))
                .fact(ctx.l("Endpoints", "Endpunkte"), eps.iter().take(5).map(|e| util::short(e, 60)).collect::<Vec<_>>().join(", "))
                .impact(ctx.l(
                    "Synchronised retries can overload a recovering server and prolong the outage.",
                    "Gleichzeitige Wiederholungen können einen sich erholenden Server überlasten und den Ausfall verlängern.",
                ))
                .recommend(ctx.l("Use exponential backoff with jitter and a shared retry budget / circuit breaker.", "Exponentiellen Backoff mit Zufallsanteil und ein gemeinsames Wiederholungsbudget / Circuit Breaker verwenden."))
                .tags(&["retry"])
                .sessions(ids(ctx, storm)),
            );
        }
        emit(ctx, out, "PAT-RETRY", ("Retries after failures", "Wiederholungen nach Fehlern"), fs);
    }
}

// ================================================================== PAT-CHATTY

/// PAT-CHATTY: operations with very many requests.
struct Chatty;

impl Analyzer for Chatty {
    fn id(&self) -> &'static str {
        "PAT-CHATTY"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "modernization", "resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let p = prep(ctx);
        // Polling series are timer-driven, not part of the operation's chattiness.
        let in_poll = p.in_poll(ctx);
        let members: Vec<Vec<usize>> = ctx.ops.iter().map(|o| o.members.iter().copied().filter(|&i| !in_poll[i]).collect()).collect();
        let rate = |k: usize| {
            let o = &ctx.ops[k];
            members[k].len() as f64 / ((o.end - o.start) as f64 / 1e6).max(0.001)
        };
        let cands: Vec<(usize, f64)> = (0..ctx.ops.len()).filter(|&k| !ctx.ops[k].background)
            .filter(|&k| {
                let n = members[k].len();
                n >= CHATTY_MIN || (n >= CHATTY_RATE_MIN && rate(k) >= CHATTY_RATE)
            })
            .map(|k| (k, members[k].len() as f64))
            .collect();
        if cands.is_empty() {
            return;
        }
        let mut n1_per_op: HashMap<u32, usize> = HashMap::new();
        for c in p.nplus1(ctx) {
            *n1_per_op.entry(c.op).or_default() += c.members.len();
        }
        let chains = p.chains(ctx);
        let mut fs = vec![];
        for (subj, k, all_ops) in by_subject(ctx, cands) {
            let o = &ctx.ops[k];
            let m = &members[k];
            let n = m.len();
            let mut canon_ids: Vec<u32> = m.iter().map(|&i| p.canon[i]).collect();
            canon_ids.sort_unstable();
            canon_ids.dedup();
            let unique = canon_ids.len();
            let total_bytes: u64 = m.iter().map(|&i| bytes(&ctx.sessions[i])).sum();
            let rts: u32 = m.iter().map(|&i| net::round_trips(&ctx.sessions[i])).sum();
            let levels = chains[k].len();
            let dur = (o.end - o.start) as f64 / 1000.0;
            let n1 = n1_per_op.get(&(k as u32)).copied().unwrap_or(0);
            let row = |a: &str, b: &str, v: String| vec![ctx.l(a, b).to_string(), v];
            let rows = vec![
                row("Requests", "Requests", ctx.fmt_count(n)),
                row("Unique resources", "Eindeutige Ressourcen", ctx.fmt_count(unique)),
                row("Duplicates", "Duplikate", ctx.fmt_count(n - unique)),
                row("N+1 candidates", "N+1-Kandidaten", ctx.fmt_count(n1)),
                row("Transferred", "Übertragen", ctx.fmt_bytes(total_bytes as f64)),
                row("Network round trips", "Netz-Roundtrips", ctx.fmt_count(rts as usize)),
                row("Sequential levels", "Sequenzielle Stufen", ctx.fmt_count(levels)),
                row("Duration", "Dauer", ctx.fmt_ms(dur)),
                row("Requests per second", "Requests pro Sekunde", crate::fmt::num(rate(k), 1, ctx.opts.lang)),
            ];
            let mut f = Finding::new(
                "PAT-CHATTY",
                &subj,
                if n >= CHATTY_CRITICAL { Severity::Critical } else { Severity::Warning },
                format!("{} {}", ctx.l("Chatty operation:", "Gesprächiger Vorgang:"), o.label),
                if ctx.de() {
                    format!("Der Vorgang „{}“ benötigte {} Requests in {} ({} eindeutige Ressourcen, {} Duplikate, {} N+1-Kandidaten).", o.label, ctx.fmt_count(n), ctx.fmt_ms(dur), ctx.fmt_count(unique), ctx.fmt_count(n - unique), ctx.fmt_count(n1))
                } else {
                    format!("Operation “{}” needed {} requests in {} ({} unique resources, {} duplicates, {} N+1 candidates).", o.label, ctx.fmt_count(n), ctx.fmt_ms(dur), ctx.fmt_count(unique), ctx.fmt_count(n - unique), ctx.fmt_count(n1))
                },
            )
            .categories(&["performance", "chattiness"])
            .score(util::scale(n as f64, CHATTY_MIN as f64, 1000.0))
            .threshold(ctx.l("≥ 50 requests per operation or ≥ 20 requests/s (critical ≥ 150)", "≥ 50 Requests pro Vorgang oder ≥ 20 Requests/s (kritisch ≥ 150)"))
            .table(vec![ctx.l("Chattiness", "Gesprächigkeit").into(), ctx.l("Value", "Wert").into()], rows)
            .impact(ctx.l(
                "Every request costs at least one round trip plus client and server overhead; on slower networks chatty operations degrade first.",
                "Jeder Request kostet mindestens einen Roundtrip plus Aufwand auf Client und Server; in langsameren Netzen leiden gesprächige Vorgänge zuerst.",
            ))
            .hypothesis(ctx.l(
                "The client composes the view from many fine-grained API calls instead of a few coarse-grained ones.",
                "Der Client setzt die Ansicht aus vielen feingranularen API-Aufrufen zusammen statt aus wenigen grobgranularen.",
            ))
            .recommend(ctx.l(
                "Provide coarse-grained endpoints for the view (backend for frontend) or batch requests ($batch, bulk APIs).",
                "Grobgranulare Endpunkte für die Ansicht bereitstellen (Backend for Frontend) oder Requests bündeln ($batch, Sammel-APIs).",
            ))
            .recommend(ctx.l("Cache reference data and remove duplicate requests.", "Stammdaten cachen und doppelte Requests entfernen."))
            .recommend(ctx.l("Load secondary data lazily, when it is shown.", "Nachrangige Daten erst laden, wenn sie angezeigt werden."))
            .operation(&o.id)
            .tags(&["chatty"])
            .sessions(all_ops.iter().flat_map(|&j| members[j].iter().map(|&i| ctx.sessions[i].id)));
            f = similar_fact(ctx, f, &all_ops);
            if n1 > 0 {
                f = f.tags(&["n+1"]);
            }
            fs.push(f);
        }
        emit(ctx, out, "PAT-CHATTY", ("Chatty operations", "Gesprächige Vorgänge"), fs);
    }
}

// ================================================================== ODATA-QUERY / ODATA-PAGING

/// ODATA-QUERY: large OData collection queries (unbounded, no `$select`, deep `$expand`);
/// ODATA-PAGING: overlapping or repeated pages of one query.
struct ODataQuery;

fn is_collection_get(u: &canon::Url) -> bool {
    let last = u.path.rsplit('/').find(|s| !s.is_empty()).unwrap_or("");
    let last = canon::decode(last);
    !(last.ends_with(')') || last.starts_with('$') || last.eq_ignore_ascii_case("$metadata"))
}

impl Analyzer for ODataQuery {
    fn id(&self) -> &'static str {
        "ODATA-QUERY"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "modernization"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let p = prep(ctx);
        self.queries(ctx, &p, out);
        self.paging(ctx, &p, out);
    }
}

impl ODataQuery {
    fn queries(&self, ctx: &Ctx, p: &Prep, out: &mut Vec<Finding>) {
        struct Q {
            i: usize,
            unbounded: bool,
            no_select: bool,
            expand: (usize, usize),
            size: u64,
        }
        let mut qs = vec![];
        for &i in &p.http {
            let s = &ctx.sessions[i];
            if !s.method.eq_ignore_ascii_case("GET") || s.status >= 400 || s.failed() {
                continue;
            }
            let size = if s.response_decoded_bytes > 0 { s.response_decoded_bytes } else { s.response_bytes };
            if size < ODATA_LARGE_BYTES {
                continue;
            }
            let u = canon::parse(&s.url);
            if !canon::is_odata(&u) || !is_collection_get(&u) {
                continue;
            }
            let o = canon::odata_options(&u);
            let has = |k: &str| o.iter().any(|(n, _)| n == k);
            let max_page = s.req_header("prefer").is_some_and(|v| v.to_ascii_lowercase().contains("maxpagesize"));
            let expand = o.iter().find(|(n, _)| n == "$expand").map(|(_, v)| canon::odata_expand_shape(v)).unwrap_or((0, 0));
            qs.push(Q { i, unbounded: !has("$top") && !has("$skiptoken") && !max_page, no_select: !has("$select"), expand, size });
        }
        let groups = util::group_by(qs, |q| canon::endpoint(&ctx.sessions[q.i].method, &ctx.sessions[q.i].url));
        let mut fs = vec![];
        for (ep, list) in groups {
            let unbounded = list.iter().filter(|q| q.unbounded).count();
            let no_select = list.iter().filter(|q| q.no_select).count();
            let deep = list.iter().filter(|q| q.expand.0 >= ODATA_EXPAND_DEPTH || q.expand.1 >= ODATA_EXPAND_ITEMS).count();
            if unbounded + no_select + deep == 0 {
                continue;
            }
            let largest = list.iter().map(|q| q.size).max().unwrap_or(0);
            let total: u64 = list.iter().map(|q| q.size).sum();
            let (max_depth, max_items) = list.iter().fold((0, 0), |a, q| (a.0.max(q.expand.0), a.1.max(q.expand.1)));
            let severity = if unbounded > 0 && largest >= ctx.opts.large_response_bytes.saturating_mul(2) {
                Severity::Critical
            } else if unbounded > 0 {
                Severity::Warning
            } else {
                Severity::Info
            };
            let mut issues = vec![];
            if unbounded > 0 {
                issues.push(if ctx.de() { format!("{} ohne $top/Paging", unbounded) } else { format!("{} without $top/paging", unbounded) });
            }
            if no_select > 0 {
                issues.push(if ctx.de() { format!("{} ohne $select", no_select) } else { format!("{} without $select", no_select) });
            }
            if deep > 0 {
                issues.push(if ctx.de() { format!("{} mit tiefem $expand", deep) } else { format!("{} with deep $expand", deep) });
            }
            let idx: Vec<usize> = list.iter().map(|q| q.i).collect();
            let mut f = Finding::new(
                "ODATA-QUERY",
                &ep,
                severity,
                format!("{} {}", ctx.l("Large OData query:", "Große OData-Abfrage:"), util::short(&ep, 80)),
                if ctx.de() {
                    format!("{} Abfrage(n) lieferten große Ergebnisse (bis {}, zusammen {}): {}.", ctx.fmt_count(list.len()), ctx.fmt_bytes(largest as f64), ctx.fmt_bytes(total as f64), issues.join(", "))
                } else {
                    format!("{} quer(ies) returned large results (up to {}, {} in total): {}.", ctx.fmt_count(list.len()), ctx.fmt_bytes(largest as f64), ctx.fmt_bytes(total as f64), issues.join(", "))
                },
            )
            .categories(&["performance", "odata"])
            .score(util::scale(total as f64, ODATA_LARGE_BYTES as f64, 200.0 * ODATA_LARGE_BYTES as f64))
            .threshold(ctx.l("OData collection GET ≥ 1 MiB (decoded)", "OData-Collection-GET ≥ 1 MiB (dekodiert)"))
            .fact(ctx.l("Queries", "Abfragen"), ctx.fmt_count(list.len()))
            .fact(ctx.l("Largest response", "Größte Response"), ctx.fmt_bytes(largest as f64))
            .fact(ctx.l("Without $top/paging", "Ohne $top/Paging"), ctx.fmt_count(unbounded))
            .fact(ctx.l("Without $select", "Ohne $select"), ctx.fmt_count(no_select))
            .impact(ctx.l(
                "Large result sets cost server time, transfer time and client memory; unbounded queries grow with the data.",
                "Große Ergebnismengen kosten Serverzeit, Übertragungszeit und Client-Speicher; unbegrenzte Abfragen wachsen mit dem Datenbestand.",
            ))
            .next_step(ctx.l("Open the largest session and check which properties and entities the client actually uses.", "Die größte Session öffnen und prüfen, welche Eigenschaften und Entitäten der Client tatsächlich verwendet."))
            .tags(&["odata"])
            .sessions(ids(ctx, &idx));
            if unbounded > 0 {
                f = f
                    .hypothesis(ctx.l(
                        "The query has no $top: it returns the whole (filtered) collection, unless the server pages on its own (@odata.nextLink).",
                        "Die Abfrage hat kein $top: Sie liefert die ganze (gefilterte) Menge, sofern der Server nicht selbst paginiert (@odata.nextLink).",
                    ))
                    .recommend(ctx.l(
                        "Page the query ($top/$skip or server-driven paging with Prefer: odata.maxpagesize) and load further pages on demand.",
                        "Die Abfrage paginieren ($top/$skip oder serverseitiges Paging mit Prefer: odata.maxpagesize) und weitere Seiten bei Bedarf laden.",
                    ));
            }
            if no_select > 0 {
                f = f
                    .hypothesis(ctx.l("Without $select all properties are returned: possible overfetching.", "Ohne $select werden alle Eigenschaften geliefert: mögliches Overfetching."))
                    .recommend(ctx.l("Request only the needed properties with $select.", "Nur die benötigten Eigenschaften per $select anfordern."));
            }
            if deep > 0 {
                f = f
                    .fact(ctx.l("$expand depth / items", "$expand-Tiefe / -Einträge"), format!("{} / {}", max_depth, max_items))
                    .hypothesis(ctx.l(
                        "The deep $expand multiplies the result: every expanded level repeats data for each parent entity.",
                        "Das tiefe $expand vervielfacht das Ergebnis: Jede expandierte Ebene wiederholt Daten für jede übergeordnete Entität.",
                    ))
                    .recommend(ctx.l(
                        "Limit $expand to what is shown, with nested $select/$top, or load details on demand.",
                        "$expand auf das Angezeigte beschränken, mit verschachteltem $select/$top, oder Details bei Bedarf laden.",
                    ));
            }
            let op = p.op[idx[0]];
            if idx.iter().all(|&i| p.op[i] == op) {
                f = set_op(f, ctx, op);
            }
            fs.push(f);
        }
        emit(ctx, out, "ODATA-QUERY", ("Large OData queries", "Große OData-Abfragen"), fs);
    }

    fn paging(&self, ctx: &Ctx, p: &Prep, out: &mut Vec<Finding>) {
        // (session, skip, top) of paged OData GETs, grouped by operation + query without paging.
        let mut pages = vec![];
        for &i in &p.http {
            let s = &ctx.sessions[i];
            if !s.method.eq_ignore_ascii_case("GET") {
                continue;
            }
            let u = canon::parse(&s.url);
            let o = canon::odata_options(&u);
            let get = |k: &str| o.iter().find(|(n, _)| n == k).and_then(|(_, v)| v.trim().parse::<u64>().ok());
            let (Some(top), skip) = (get("$top"), get("$skip").unwrap_or(0)) else { continue };
            if o.iter().any(|(n, _)| n == "$skiptoken") {
                continue;
            }
            let rest: Vec<(String, String)> = u.query.iter().filter(|(k, _)| !matches!(k.to_ascii_lowercase().as_str(), "$skip" | "$top")).cloned().collect();
            let mut q = rest.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>();
            q.sort();
            let key = format!("{} {}{}?{}", upper(&s.method), u.host, u.path, q.join("&"));
            pages.push((p.op[i], key, i, skip, top));
        }
        let groups = util::group_by(pages, |x| (x.0, x.1.clone()));
        struct Hit {
            op: u32,
            sessions: Vec<usize>,
            repeated: usize,
            overlapping: usize,
            pages: usize,
        }
        let mut hits: Vec<(String, Hit)> = vec![];
        for ((op, _), list) in groups {
            if list.len() < 2 {
                continue;
            }
            let mut ranges: Vec<(u64, u64, usize)> = list.iter().map(|x| (x.3, x.3.saturating_add(x.4), x.2)).collect();
            ranges.sort();
            let (mut repeated, mut overlapping) = (0, 0);
            let mut affected = vec![];
            let mut max_end = 0u64;
            for (k, r) in ranges.iter().enumerate() {
                if k > 0 {
                    let prev = ranges[k - 1];
                    if (prev.0, prev.1) == (r.0, r.1) {
                        repeated += 1;
                        affected.extend([prev.2, r.2]);
                    } else if r.0 < max_end {
                        overlapping += 1;
                        affected.extend([prev.2, r.2]);
                    }
                }
                max_end = max_end.max(r.1);
            }
            if repeated + overlapping == 0 {
                continue;
            }
            affected.sort_unstable();
            affected.dedup();
            let s = &ctx.sessions[list[0].2];
            hits.push((canon::endpoint(&s.method, &s.url), Hit { op, sessions: affected, repeated, overlapping, pages: list.len() }));
        }
        let by_ep = util::group_by(hits, |h| h.0.clone());
        let mut fs = vec![];
        for (ep, hs) in by_ep {
            let repeated: usize = hs.iter().map(|h| h.1.repeated).sum();
            let overlapping: usize = hs.iter().map(|h| h.1.overlapping).sum();
            let pages: usize = hs.iter().map(|h| h.1.pages).sum();
            let all: Vec<usize> = hs.iter().flat_map(|h| h.1.sessions.iter().copied()).collect();
            let wasted: u64 = all.iter().map(|&i| bytes(&ctx.sessions[i])).sum();
            let mut f = Finding::new(
                "ODATA-PAGING",
                &ep,
                if repeated + overlapping >= 3 { Severity::Warning } else { Severity::Info },
                format!("{} {}", ctx.l("Redundant paging:", "Überflüssiges Paging:"), util::short(&ep, 80)),
                if ctx.de() {
                    format!("Beim Blättern derselben Abfrage ({} Seiten) wurden {} Seite(n) erneut und {} überlappend geladen.", ctx.fmt_count(pages), ctx.fmt_count(repeated), ctx.fmt_count(overlapping))
                } else {
                    format!("While paging through the same query ({} pages), {} page(s) were loaded again and {} overlapping.", ctx.fmt_count(pages), ctx.fmt_count(repeated), ctx.fmt_count(overlapping))
                },
            )
            .categories(&["performance", "odata"])
            .score(util::scale((repeated + overlapping) as f64, 1.0, 30.0))
            .threshold(ctx.l("Repeated or overlapping $skip/$top ranges of one query within an operation (warning ≥ 3)", "Wiederholte oder überlappende $skip/$top-Bereiche einer Abfrage in einem Vorgang (Warnung ≥ 3)"))
            .fact(ctx.l("Pages", "Seiten"), ctx.fmt_count(pages))
            .fact(ctx.l("Repeated pages", "Wiederholte Seiten"), ctx.fmt_count(repeated))
            .fact(ctx.l("Overlapping pages", "Überlappende Seiten"), ctx.fmt_count(overlapping))
            .fact(ctx.l("Transferred by affected pages", "Durch betroffene Seiten übertragen"), ctx.fmt_bytes(wasted as f64))
            .impact(ctx.l("The same records are transferred and processed more than once.", "Dieselben Datensätze werden mehrfach übertragen und verarbeitet."))
            .hypothesis(ctx.l(
                "The client recomputes the page offsets (e.g. after a resize or scroll) or several components page independently.",
                "Der Client berechnet die Seiten-Offsets neu (z. B. nach Größenänderung oder Scrollen) oder mehrere Komponenten blättern unabhängig.",
            ))
            .recommend(ctx.l("Keep already loaded pages in client state and request only missing ranges.", "Bereits geladene Seiten im Client-Zustand halten und nur fehlende Bereiche anfordern."))
            .recommend(ctx.l("Prefer server-driven paging ($skiptoken / @odata.nextLink) over computed offsets.", "Serverseitiges Paging ($skiptoken / @odata.nextLink) statt berechneter Offsets bevorzugen."))
            .tags(&["odata", "paging"])
            .sessions(ids(ctx, &all));
            if hs.len() == 1 {
                f = set_op(f, ctx, hs[0].1.op);
            }
            fs.push(f);
        }
        emit(ctx, out, "ODATA-PAGING", ("Redundant paging", "Überflüssiges Paging"), fs);
    }
}

// ================================================================== NET-LATENCY

/// NET-LATENCY: long sequential chains and their extra time per network profile.
struct NetLatency;

impl Analyzer for NetLatency {
    fn id(&self) -> &'static str {
        "NET-LATENCY"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "resilience", "modernization"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let p = prep(ctx);
        let chains = p.chains(ctx);
        let cands: Vec<(usize, f64)> = (0..ctx.ops.len()).filter(|&k| !ctx.ops[k].background).filter(|&k| chains[k].len() >= LATENCY_MIN_LEVELS).map(|k| (k, chains[k].len() as f64)).collect();
        let mut fs = vec![];
        for (subj, k, all_ops) in by_subject(ctx, cands) {
            let o = &ctx.ops[k];
            let chain = &chains[k];
            let levels = chain.len();
            let rts = net::chain_round_trips(ctx.sessions, chain);
            let chain_ms: f64 = chain.iter().map(|&i| ms(&ctx.sessions[i])).sum();
            let dur = (o.end - o.start) as f64 / 1000.0;
            let new_conns = chain.iter().filter(|&&i| ctx.sessions[i].new_connection()).count();
            let extras: Vec<(&Network, f64)> = ctx.opts.networks.iter().map(|n| (n, net::extra_latency_ms(rts, &p.rtt, n))).collect();
            let (wnet, worst) = extras.iter().cloned().max_by(|a, b| a.1.total_cmp(&b.1)).map(|(n, e)| (Some(n), e)).unwrap_or((None, 0.0));
            let rows: Vec<Vec<String>> = extras
                .iter()
                .map(|(n, e)| vec![n.name.clone(), ctx.fmt_ms(n.rtt_ms), ctx.fmt_count(rts as usize), format!("+{}", ctx.fmt_ms(*e)), ctx.fmt_ms(dur + e)])
                .collect();
            // All chain steps on one client connection: the order is enforced, not incidental.
            let conn = ctx.sessions[chain[0]].client_connection;
            let same_conn = conn.is_some() && chain.iter().filter(|&&i| ctx.sessions[i].client_connection == conn).count() * 10 >= levels * 9;
            let severity = if worst >= 10_000.0 {
                Severity::Critical
            } else if worst >= 2_000.0 {
                Severity::Warning
            } else {
                Severity::Info
            };
            let path: Vec<String> = chain.iter().take(6).map(|&i| ops::short_label(&ctx.sessions[i])).collect();
            let mut path = path.join(" → ");
            if levels > 6 {
                path.push_str(" → …");
            }
            let mut f = Finding::new(
                "NET-LATENCY",
                &subj,
                severity,
                format!("{} {}", ctx.l("Latency-sensitive request chain:", "Latenzempfindliche Request-Kette:"), o.label),
                if ctx.de() {
                    format!("Im Vorgang „{}“ liefen {} Requests nacheinander (kritischer Pfad {} von {}); zusammen {} Netz-Roundtrips.", o.label, ctx.fmt_count(levels), ctx.fmt_ms(chain_ms), ctx.fmt_ms(dur), ctx.fmt_count(rts as usize))
                } else {
                    format!("In operation “{}”, {} requests ran one after another (critical path {} of {}); {} network round trips in total.", o.label, ctx.fmt_count(levels), ctx.fmt_ms(chain_ms), ctx.fmt_ms(dur), ctx.fmt_count(rts as usize))
                },
            )
            .categories(&["performance", "latency"])
            .confidence(if same_conn { Confidence::High } else { Confidence::Medium })
            .estimate()
            .score(util::scale(worst, 500.0, 30_000.0))
            .threshold(ctx.l("≥ 10 sequential levels in an operation", "≥ 10 sequenzielle Stufen in einem Vorgang"))
            .fact(ctx.l("Sequential levels", "Sequenzielle Stufen"), ctx.fmt_count(levels))
            .fact(ctx.l("Round trips on the chain", "Roundtrips auf der Kette"), ctx.fmt_count(rts as usize))
            .fact(ctx.l("New connections on the chain", "Neue Verbindungen auf der Kette"), ctx.fmt_count(new_conns))
            .fact(ctx.l("Observed RTT (estimate)", "Beobachtete RTT (Schätzung)"), rtt_text(ctx, &p.rtt))
            .fact(ctx.l("Critical path", "Kritischer Pfad"), path)
            .table(
                vec![
                    ctx.l("Network", "Netz").into(),
                    ctx.l("RTT", "RTT").into(),
                    ctx.l("Round trips", "Roundtrips").into(),
                    ctx.l("Estimated extra time", "Geschätzte Mehrzeit").into(),
                    ctx.l("Estimated duration", "Geschätzte Dauer").into(),
                ],
                rows,
            )
            .hypothesis(ctx.l(
                "The chain is an upper bound: requests that merely started after others had finished count as dependent; the real dependencies may be fewer.",
                "Die Kette ist eine Obergrenze: Requests, die nur zufällig nach anderen begannen, zählen als abhängig; die echten Abhängigkeiten können weniger sein.",
            ))
            .recommend(ctx.l("Check which requests really need the result of the previous one.", "Prüfen, welche Requests wirklich das Ergebnis des vorherigen benötigen."))
            .recommend(ctx.l("Run independent requests in parallel.", "Unabhängige Requests parallel ausführen."))
            .recommend(ctx.l("Batch dependent lookups ($batch, bulk endpoints) or aggregate them on the server.", "Abhängige Abfragen bündeln ($batch, Sammel-Endpunkte) oder auf dem Server zusammenfassen."))
            .next_step(simulate_step(ctx))
            .operation(&o.id)
            .tags(&["latency"])
            .sessions(ops_sessions(ctx, &all_ops));
            if let Some(w) = wnet {
                f = f.impact(if ctx.de() {
                    format!("Bei {} RTT ({}) würde der Vorgang schätzungsweise {} länger dauern.", ctx.fmt_ms(w.rtt_ms), w.name, ctx.fmt_ms(worst))
                } else {
                    format!("At {} RTT ({}) the operation would take an estimated {} longer.", ctx.fmt_ms(w.rtt_ms), w.name, ctx.fmt_ms(worst))
                });
            }
            if chain.iter().any(|&i| ctx.sessions[i].version.starts_with("HTTP/1")) {
                f = f.hypothesis(ctx.l(
                    "With HTTP/1.x, the connection limit per host (often 6) can serialise independent requests; HTTP/2 multiplexing avoids that.",
                    "Mit HTTP/1.x kann das Verbindungslimit pro Host (oft 6) unabhängige Requests serialisieren; HTTP/2-Multiplexing vermeidet das.",
                ));
            }
            if new_conns > 0 {
                f = f.recommend(ctx.l(
                    "Reuse connections (keep-alive, HTTP/2): new connections on the chain add handshake round trips.",
                    "Verbindungen wiederverwenden (Keep-Alive, HTTP/2): Neue Verbindungen auf der Kette kosten zusätzliche Handshake-Roundtrips.",
                ));
            }
            fs.push(similar_fact(ctx, f, &all_ops));
        }
        emit(ctx, out, "NET-LATENCY", ("Latency-sensitive request chains", "Latenzempfindliche Request-Ketten"), fs);
    }
}

// ================================================================== NET-BANDWIDTH

/// NET-BANDWIDTH: large transfers and heavy operations, transfer time per network profile.
struct NetBandwidth;

fn transfer_table(ctx: &Ctx, largest: u64, total: u64) -> (Vec<String>, Vec<Vec<String>>, f64) {
    let cols = vec![
        ctx.l("Network", "Netz").into(),
        ctx.l("Bandwidth", "Bandbreite").into(),
        ctx.l("Loss", "Verlust").into(),
        ctx.l("Effective throughput", "Effektiver Durchsatz").into(),
        ctx.l("Largest transfer", "Größte Übertragung").into(),
        ctx.l("All transfers", "Alle Übertragungen").into(),
    ];
    let mut worst: f64 = 0.0;
    let rows = ctx
        .opts
        .networks
        .iter()
        .map(|n| {
            let t = net::transfer_ms(largest, n);
            worst = worst.max(t);
            vec![
                n.name.clone(),
                fmt_mbps(ctx, n.mbps * 1e6),
                format!("{} %", crate::fmt::num(n.loss_pct, 1, ctx.opts.lang)),
                fmt_mbps(ctx, net::throughput_bps(n)),
                ctx.fmt_ms(t),
                ctx.fmt_ms(net::transfer_ms(total, n)),
            ]
        })
        .collect();
    (cols, rows, worst)
}

fn transfer_severity(worst_ms: f64) -> Severity {
    if worst_ms >= 60_000.0 {
        Severity::Critical
    } else if worst_ms >= 10_000.0 {
        Severity::Warning
    } else {
        Severity::Info
    }
}

impl NetBandwidth {
    fn common(ctx: &Ctx, f: Finding, compressible_plain: bool) -> Finding {
        let mut f = f
            .categories(&["performance", "bandwidth"])
            .estimate()
            .impact(match slowest_net(ctx) {
                Some(n) if ctx.de() => format!("Auf „{}“ begrenzt der effektive Durchsatz von {} die Übertragung (Schätzung nach Bandbreite und Mathis-Formel).", n.name, fmt_mbps(ctx, net::throughput_bps(n))),
                Some(n) => format!("On “{}” the effective throughput of {} limits the transfer (estimate from bandwidth and the Mathis formula).", n.name, fmt_mbps(ctx, net::throughput_bps(n))),
                None => String::new(),
            })
            .recommend(ctx.l("Page large result sets and load further data on demand.", "Große Ergebnismengen paginieren und weitere Daten bei Bedarf laden."))
            .recommend(ctx.l("Transfer only needed fields ($select / field selection).", "Nur benötigte Felder übertragen ($select / Feldauswahl)."))
            .recommend(ctx.l("Load only changes (delta loading, ETag) instead of complete data sets.", "Nur Änderungen laden (Delta-Laden, ETag) statt vollständiger Datenbestände."))
            .recommend(ctx.l("Stream or chunk large transfers so that the client can work with partial data.", "Große Übertragungen streamen oder aufteilen, damit der Client mit Teildaten arbeiten kann."))
            .next_step(simulate_step(ctx))
            .tags(&["large"]);
        if compressible_plain {
            f = f.recommend(ctx.l(
                "Compress the text responses (gzip/br); they were transferred uncompressed.",
                "Die Text-Responses komprimieren (gzip/br); sie wurden unkomprimiert übertragen.",
            ));
        }
        f
    }
}

impl Analyzer for NetBandwidth {
    fn id(&self) -> &'static str {
        "NET-BANDWIDTH"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let p = prep(ctx);
        let plain = |s: &Session| canon::is_compressible(&s.mime()) && s.resp_header("content-encoding").is_none_or(|v| v.trim().eq_ignore_ascii_case("identity"));
        // 1. Large single transfers, per endpoint.
        let large = p.http.iter().copied().filter(|&i| {
            let s = &ctx.sessions[i];
            s.response_bytes >= ctx.opts.large_response_bytes || s.request_bytes >= ctx.opts.large_request_bytes
        });
        let groups = util::group_by(large, |&i| canon::endpoint(&ctx.sessions[i].method, &ctx.sessions[i].url));
        let mut fs = vec![];
        for (ep, list) in groups {
            let largest = list.iter().map(|&i| bytes(&ctx.sessions[i])).max().unwrap_or(0);
            let total: u64 = list.iter().map(|&i| bytes(&ctx.sessions[i])).sum();
            let observed = list.iter().map(|&i| ms(&ctx.sessions[i])).fold(0.0, f64::max);
            let (cols, rows, worst) = transfer_table(ctx, largest, total);
            let upload = list.iter().any(|&i| ctx.sessions[i].request_bytes >= ctx.opts.large_request_bytes);
            let f = Finding::new(
                "NET-BANDWIDTH",
                &ep,
                transfer_severity(worst),
                format!("{} {}", ctx.l("Bandwidth-sensitive transfer:", "Bandbreitenempfindliche Übertragung:"), util::short(&ep, 80)),
                if ctx.de() {
                    format!("{} {} übertrugen bis zu {} (zusammen {}); gemessen dauerte der längste {}.", ctx.fmt_count(list.len()), if upload { "Requests (auch Uploads)" } else { "Requests" }, ctx.fmt_bytes(largest as f64), ctx.fmt_bytes(total as f64), ctx.fmt_ms(observed))
                } else {
                    format!("{} request(s){} transferred up to {} ({} in total); the longest took {} as captured.", ctx.fmt_count(list.len()), if upload { " (including uploads)" } else { "" }, ctx.fmt_bytes(largest as f64), ctx.fmt_bytes(total as f64), ctx.fmt_ms(observed))
                },
            )
            .score(util::scale(worst, 1_000.0, 120_000.0))
            .threshold(if ctx.de() {
                format!("Response ≥ {} oder Request ≥ {}", ctx.fmt_bytes(ctx.opts.large_response_bytes as f64), ctx.fmt_bytes(ctx.opts.large_request_bytes as f64))
            } else {
                format!("response ≥ {} or request ≥ {}", ctx.fmt_bytes(ctx.opts.large_response_bytes as f64), ctx.fmt_bytes(ctx.opts.large_request_bytes as f64))
            })
            .fact(ctx.l("Requests", "Requests"), ctx.fmt_count(list.len()))
            .fact(ctx.l("Largest transfer", "Größte Übertragung"), ctx.fmt_bytes(largest as f64))
            .fact(ctx.l("Longest as captured", "Längste gemessen"), ctx.fmt_ms(observed))
            .table(cols, rows)
            .sessions(ids(ctx, &list));
            let mut f = Self::common(ctx, f, list.iter().any(|&i| plain(&ctx.sessions[i])));
            let op = p.op[list[0]];
            if list.iter().all(|&i| p.op[i] == op) {
                f = set_op(f, ctx, op);
            }
            fs.push(f);
        }
        emit(ctx, out, "NET-BANDWIDTH", ("Bandwidth-sensitive transfers", "Bandbreitenempfindliche Übertragungen"), fs);

        // 2. Heavy operations.
        let op_bytes = |k: usize| ctx.ops[k].members.iter().map(|&i| bytes(&ctx.sessions[i])).sum::<u64>();
        let cands: Vec<(usize, f64)> = (0..ctx.ops.len()).filter(|&k| !ctx.ops[k].background).map(|k| (k, op_bytes(k) as f64)).filter(|x| x.1 >= HEAVY_BYTES as f64).collect();
        let mut fs = vec![];
        for (subj, k, all_ops) in by_subject(ctx, cands) {
            let o = &ctx.ops[k];
            let total = op_bytes(k);
            let largest = o.members.iter().map(|&i| bytes(&ctx.sessions[i])).max().unwrap_or(0);
            let (cols, rows, _) = transfer_table(ctx, largest, total);
            let worst = ctx.opts.networks.iter().map(|n| net::transfer_ms(total, n)).fold(0.0, f64::max);
            let f = Finding::new(
                "NET-BANDWIDTH",
                &format!("op:{subj}"),
                transfer_severity(worst),
                format!("{} {}", ctx.l("Heavy operation:", "Datenintensiver Vorgang:"), o.label),
                if ctx.de() {
                    format!("Der Vorgang „{}“ übertrug {} in {} Requests (größte Übertragung {}).", o.label, ctx.fmt_bytes(total as f64), ctx.fmt_count(o.members.len()), ctx.fmt_bytes(largest as f64))
                } else {
                    format!("Operation “{}” transferred {} in {} requests (largest transfer {}).", o.label, ctx.fmt_bytes(total as f64), ctx.fmt_count(o.members.len()), ctx.fmt_bytes(largest as f64))
                },
            )
            .score(util::scale(worst, 1_000.0, 120_000.0))
            .threshold(ctx.l("≥ 10 MiB per operation", "≥ 10 MiB pro Vorgang"))
            .fact(ctx.l("Transferred", "Übertragen"), ctx.fmt_bytes(total as f64))
            .fact(ctx.l("Requests", "Requests"), ctx.fmt_count(o.members.len()))
            .table(cols, rows)
            .operation(&o.id)
            .sessions(ops_sessions(ctx, &all_ops));
            let f = Self::common(ctx, f, o.members.iter().any(|&i| plain(&ctx.sessions[i]) && ctx.sessions[i].response_bytes >= 100 * 1024));
            fs.push(similar_fact(ctx, f, &all_ops));
        }
        // Distinct "more" key from the per-endpoint findings.
        let before = out.len();
        emit(ctx, out, "NET-BANDWIDTH", ("Heavy operations", "Datenintensive Vorgänge"), fs);
        for f in &mut out[before..] {
            if f.key == "NET-BANDWIDTH|more" {
                f.key = "NET-BANDWIDTH|op:more".into();
            }
        }
    }
}

// ================================================================== NET-RESILIENCE

/// NET-RESILIENCE: operations that combine several factors that make them sensitive to
/// slow or unstable networks (sequential chains, large transfers, retries, timeouts,
/// polling).
struct NetResilience;

impl Analyzer for NetResilience {
    fn id(&self) -> &'static str {
        "NET-RESILIENCE"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let p = prep(ctx);
        let chains = p.chains(ctx);
        let nops = ctx.ops.len();
        let mut retries = vec![0usize; nops];
        for s in &p.retries(ctx).seqs {
            for &i in &s.attempts[1..] {
                if p.op[i] != NONE {
                    retries[p.op[i] as usize] += 1;
                }
            }
        }
        let mut polls = vec![0usize; nops];
        for x in p.polls(ctx) {
            for &i in &x.members {
                if p.op[i] != NONE {
                    polls[p.op[i] as usize] += 1;
                }
            }
        }
        let worst_rtt = worst_rtt_net(ctx);
        let slow = slowest_net(ctx);
        let mut factors_of: Vec<Vec<(String, String)>> = vec![vec![]; nops];
        let mut cands = vec![];
        for k in (0..nops).filter(|&k| !ctx.ops[k].background) {
            let o = &ctx.ops[k];
            let mut fx: Vec<(String, String)> = vec![];
            let levels = chains[k].len();
            if levels >= LATENCY_MIN_LEVELS {
                let extra = worst_rtt.map(|n| net::extra_latency_ms(net::chain_round_trips(ctx.sessions, &chains[k]), &p.rtt, n)).unwrap_or(0.0);
                fx.push((
                    ctx.l("Sequential chain", "Sequenzielle Kette").into(),
                    if ctx.de() {
                        format!("{} Stufen; ca. +{} bei {}", ctx.fmt_count(levels), ctx.fmt_ms(extra), worst_rtt.map(|n| n.name.as_str()).unwrap_or("–"))
                    } else {
                        format!("{} levels; about +{} on {}", ctx.fmt_count(levels), ctx.fmt_ms(extra), worst_rtt.map(|n| n.name.as_str()).unwrap_or("–"))
                    },
                ));
            }
            let total: u64 = o.members.iter().map(|&i| bytes(&ctx.sessions[i])).sum();
            if total >= HEAVY_BYTES {
                let t = slow.map(|n| net::transfer_ms(total, n)).unwrap_or(0.0);
                fx.push((
                    ctx.l("Large transfers", "Große Übertragungen").into(),
                    if ctx.de() {
                        format!("{}; ca. {} bei {}", ctx.fmt_bytes(total as f64), ctx.fmt_ms(t), slow.map(|n| n.name.as_str()).unwrap_or("–"))
                    } else {
                        format!("{}; about {} on {}", ctx.fmt_bytes(total as f64), ctx.fmt_ms(t), slow.map(|n| n.name.as_str()).unwrap_or("–"))
                    },
                ));
            }
            if retries[k] > 0 {
                fx.push((ctx.l("Retries", "Wiederholungen").into(), if ctx.de() { format!("{} nach Fehlern", ctx.fmt_count(retries[k])) } else { format!("{} after failures", ctx.fmt_count(retries[k])) }));
            }
            let timeouts = o.members.iter().filter(|&&i| is_timeout(&ctx.sessions[i])).count();
            if timeouts > 0 {
                fx.push((ctx.l("Timeouts", "Timeouts").into(), ctx.fmt_count(timeouts)));
            }
            if polls[k] >= POLL_MIN {
                fx.push((ctx.l("Polling", "Polling").into(), if ctx.de() { format!("{} Abfragen", ctx.fmt_count(polls[k])) } else { format!("{} polls", ctx.fmt_count(polls[k])) }));
            }
            if fx.len() >= 2 {
                cands.push((k, fx.len() as f64 * 1000.0 + o.members.len() as f64));
            }
            factors_of[k] = fx;
        }
        let mut fs = vec![];
        for (subj, k, all_ops) in by_subject(ctx, cands) {
            let o = &ctx.ops[k];
            let fx = &factors_of[k];
            let rows: Vec<Vec<String>> = fx.iter().map(|(a, b)| vec![a.clone(), b.clone()]).collect();
            let names: Vec<&str> = fx.iter().map(|x| x.0.as_str()).collect();
            let mut f = Finding::new(
                "NET-RESILIENCE",
                &subj,
                if fx.len() >= 3 { Severity::Critical } else { Severity::Warning },
                format!("{} {}", ctx.l("Operation sensitive to unstable networks:", "Vorgang empfindlich für instabile Netze:"), o.label),
                if ctx.de() {
                    format!("Der Vorgang „{}“ vereint {} Faktoren, die ihn in langsamen oder instabilen Netzen anfällig machen können: {}.", o.label, fx.len(), names.join(", "))
                } else {
                    format!("Operation “{}” combines {} factors that may make it fragile on slow or unstable networks: {}.", o.label, fx.len(), names.join(", "))
                },
            )
            .categories(&["resilience", "network"])
            .confidence(Confidence::Medium)
            .estimate()
            .score(util::scale(fx.len() as f64, 2.0, 5.0))
            .threshold(ctx.l(
                "≥ 2 of: ≥ 10 sequential levels, ≥ 10 MiB, retries, timeouts, polling (critical ≥ 3)",
                "≥ 2 von: ≥ 10 sequenzielle Stufen, ≥ 10 MiB, Wiederholungen, Timeouts, Polling (kritisch ≥ 3)",
            ))
            .table(vec![ctx.l("Factor", "Faktor").into(), ctx.l("Observation", "Beobachtung").into()], rows)
            .impact(ctx.l(
                "With higher latency or packet loss these factors reinforce each other: longer chains hit timeouts, timeouts cause retries, retries add load.",
                "Bei höherer Latenz oder Paketverlust verstärken sich diese Faktoren gegenseitig: Längere Ketten laufen in Timeouts, Timeouts lösen Wiederholungen aus, Wiederholungen erhöhen die Last.",
            ))
            .hypothesis(ctx.l(
                "The operation was probably designed and tested on a fast network; its behaviour under poor conditions is unverified.",
                "Der Vorgang wurde vermutlich in einem schnellen Netz entwickelt und getestet; sein Verhalten unter schlechten Bedingungen ist ungeprüft.",
            ))
            .recommend(ctx.l("Measure the operation under simulated latency and loss.", "Den Vorgang unter simulierter Latenz und Paketverlust messen."))
            .recommend(ctx.l("Check the timeouts: are they sized for high-latency networks, and what does the user see when they expire?", "Die Timeouts prüfen: Sind sie für Netze mit hoher Latenz bemessen, und was sieht der Benutzer, wenn sie ablaufen?"))
            .recommend(ctx.l("Check the retry policy: backoff with jitter, Retry-After, idempotency of retried writes.", "Die Wiederholungsstrategie prüfen: Backoff mit Zufallsanteil, Retry-After, Idempotenz wiederholter Schreibzugriffe."))
            .recommend(ctx.l("Reduce sequential dependencies and round trips (parallelise, batch).", "Sequenzielle Abhängigkeiten und Roundtrips reduzieren (parallelisieren, bündeln)."))
            .recommend(ctx.l("Make large transfers resumable or split them (paging, range requests) and compress them.", "Große Übertragungen fortsetzbar machen oder aufteilen (Paging, Range-Requests) und komprimieren."))
            .recommend(ctx.l("Replace polling by push and make reconnects robust (backoff, resynchronisation).", "Polling durch Push ersetzen und Wiederverbindungen robust gestalten (Backoff, Neusynchronisation)."))
            .recommend(ctx.l("Check the user feedback during long waits and partial failures (progress, cancel, retry).", "Die Rückmeldung an den Benutzer bei langen Wartezeiten und Teilausfällen prüfen (Fortschritt, Abbrechen, Wiederholen)."))
            .next_step(simulate_step(ctx))
            .operation(&o.id)
            .tags(&["resilience"])
            .sessions(ops_sessions(ctx, &all_ops));
            f = f.fact(ctx.l("Observed RTT (estimate)", "Beobachtete RTT (Schätzung)"), rtt_text(ctx, &p.rtt));
            fs.push(similar_fact(ctx, f, &all_ops));
        }
        emit(ctx, out, "NET-RESILIENCE", ("Operations sensitive to unstable networks", "Vorgänge empfindlich für instabile Netze"), fs);
    }
}
