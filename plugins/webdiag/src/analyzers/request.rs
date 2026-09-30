//! Analyzers of single sessions and their simple aggregates.
//!
//! Style (all analyzers): aggregate by endpoint (`canon::endpoint`) instead of one finding
//! per session; at most `util::MAX_PER_RULE` findings per rule, worst first; every finding
//! names its threshold and lists all affected sessions; texts in both languages via
//! `ctx.l(en, de)`; numbers via `ctx.fmt_*`.
use std::collections::{HashMap, HashSet};

use crate::canon;
use crate::model::{Analyzer, Confidence, Ctx, Finding, Kind, Session, Severity};
use crate::util::{self, MAX_PER_RULE};

pub fn all() -> Vec<Box<dyn Analyzer>> {
    vec![
        Box::new(SlowRequests),
        Box::new(ServerTime),
        Box::new(LargeRequests),
        Box::new(LargeResponses),
        Box::new(Compression),
        Box::new(HttpErrors),
        Box::new(NetFailures),
        Box::new(AuthFailures),
        Box::new(AuthRepeat),
        Box::new(Redirects),
        Box::new(Cookies),
        Box::new(Caching),
        Box::new(ConnReuse),
        Box::new(TlsOld),
        Box::new(CorsPreflight),
    ]
}

/// PERF-SLOW: requests slower than `opts.slow_ms`, per endpoint.
struct SlowRequests;

impl Analyzer for SlowRequests {
    fn id(&self) -> &'static str {
        "PERF-SLOW"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "troubleshooting", "resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let limit = ctx.opts.slow_ms;
        let slow = ctx.http().filter(|s| !s.failed() && s.duration_us() as f64 / 1000.0 > limit);
        let mut groups = util::group_by(slow, |s| canon::endpoint(&s.method, &s.url));
        // Worst total time first.
        let total = |v: &[&crate::model::Session]| v.iter().map(|s| s.duration_us() as f64 / 1000.0).sum::<f64>();
        groups.sort_by(|a, b| total(&b.1).total_cmp(&total(&a.1)));
        for (endpoint, list) in groups.into_iter().take(MAX_PER_RULE) {
            let times: Vec<f64> = list.iter().map(|s| s.duration_us() as f64 / 1000.0).collect();
            let worst = times.iter().cloned().fold(0.0, f64::max);
            let median = util::percentile(&times, 50.0);
            // Where the time went: server (TTFB) or transfer (download).
            let ttfb: Vec<f64> = list.iter().filter_map(|s| s.ttfb_ms()).collect();
            let server_share = if ttfb.is_empty() { None } else { Some(util::percentile(&ttfb, 50.0) / median.max(1.0)) };
            let severity = if worst > limit * 5.0 { Severity::Critical } else { Severity::Warning };
            let n = list.len();
            let mut f = Finding::new(
                "PERF-SLOW",
                &endpoint,
                severity,
                format!("{} {}", ctx.l("Slow requests:", "Langsame Requests:"), util::short(&endpoint, 80)),
                if ctx.de() {
                    format!("{} Request(s) dauerten länger als {} (Median {}, max. {}).", ctx.fmt_count(n), ctx.fmt_ms(limit), ctx.fmt_ms(median), ctx.fmt_ms(worst))
                } else {
                    format!("{} request(s) took longer than {} (median {}, max {}).", ctx.fmt_count(n), ctx.fmt_ms(limit), ctx.fmt_ms(median), ctx.fmt_ms(worst))
                },
            )
            .categories(&["performance", "timing"])
            .score(util::scale(total(&list), limit, limit * 50.0))
            .threshold(format!("> {}", ctx.fmt_ms(limit)))
            .fact(ctx.l("Requests", "Requests"), ctx.fmt_count(n))
            .fact(ctx.l("Median", "Median"), ctx.fmt_ms(median))
            .fact(ctx.l("Slowest", "Langsamster"), ctx.fmt_ms(worst))
            .impact(ctx.l("Users wait for these requests; slow endpoints often dominate the duration of an operation.", "Benutzer warten auf diese Requests; langsame Endpunkte bestimmen oft die Dauer eines Vorgangs."))
            .sessions(list.iter().map(|s| s.id));
            match server_share {
                Some(r) if r > 0.7 => {
                    f = f
                        .fact(ctx.l("Server time (TTFB) share", "Anteil Serverzeit (TTFB)"), ctx.fmt_pct(r))
                        .hypothesis(ctx.l("Most of the time is spent on the server before the first byte.", "Der Großteil der Zeit vergeht auf dem Server bis zum ersten Byte."))
                        .recommend(ctx.l("Profile the server side of this endpoint (database, downstream calls).", "Die Serverseite dieses Endpunkts profilieren (Datenbank, nachgelagerte Aufrufe)."))
                }
                Some(r) => {
                    f = f
                        .fact(ctx.l("Server time (TTFB) share", "Anteil Serverzeit (TTFB)"), ctx.fmt_pct(r))
                        .hypothesis(ctx.l("A large part of the time is spent transferring the response.", "Ein großer Teil der Zeit entfällt auf die Übertragung der Response."))
                        .recommend(ctx.l("Reduce the response size (filtering, paging, compression).", "Die Response verkleinern (Filtern, Paging, Kompression)."))
                }
                None => f = f.confidence(Confidence::Medium).recommend(ctx.l("Check the server and the network for this endpoint.", "Server und Netz für diesen Endpunkt prüfen.")),
            }
            out.push(f.next_step(ctx.l("Open the slowest session and compare its timeline phases.", "Die langsamste Session öffnen und ihre Zeitachsen-Phasen vergleichen.")));
        }
    }
}

// ------------------------------------------------------------------ shared helpers

fn ms(s: &Session) -> f64 {
    s.duration_us() as f64 / 1000.0
}

fn ratio(a: usize, b: usize) -> f64 {
    if b == 0 { 0.0 } else { a as f64 / b as f64 }
}

/// Host of a session, lower-case (from the URL when the host field is empty).
fn host(s: &Session) -> String {
    if s.host.is_empty() { canon::parse(&s.url).host } else { s.host.to_ascii_lowercase() }
}

fn endpoint(s: &Session) -> String {
    canon::endpoint(&s.method, &s.url)
}

/// Decoded response size (wire size when the decoded size is unknown).
fn decoded(s: &Session) -> u64 {
    if s.response_decoded_bytes > 0 { s.response_decoded_bytes } else { s.response_bytes }
}

/// Values with their counts, most frequent first (ties by value).
fn top(values: impl IntoIterator<Item = String>) -> Vec<(String, usize)> {
    let mut m: HashMap<String, usize> = HashMap::new();
    for v in values {
        *m.entry(v).or_default() += 1;
    }
    let mut v: Vec<_> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v
}

/// `a (3), b (1), …`
fn list_top(ctx: &Ctx, v: &[(String, usize)], n: usize) -> String {
    let mut s: Vec<String> = v.iter().take(n).map(|(k, c)| format!("{} ({})", util::short(k, 60), ctx.fmt_count(*c))).collect();
    if v.len() > n {
        s.push("…".into());
    }
    s.join(", ")
}

/// Sorted distinct names, at most `n`: `a, b, c, …`
fn list_names<'a>(names: impl IntoIterator<Item = &'a str>, n: usize) -> String {
    let mut v: Vec<&str> = names.into_iter().filter(|x| !x.is_empty()).collect();
    v.sort_unstable();
    v.dedup();
    let more = v.len() > n;
    let mut s: Vec<String> = v.into_iter().take(n).map(|x| util::short(x, 40)).collect();
    if more {
        s.push("…".into());
    }
    s.join(", ")
}

fn sev_label<'a>(ctx: &Ctx, s: Severity) -> &'a str {
    match s {
        Severity::Critical => ctx.l("critical", "kritisch"),
        Severity::Warning => ctx.l("warning", "Warnung"),
        Severity::Info => ctx.l("info", "Hinweis"),
    }
}

/// Keep the worst `MAX_PER_RULE` findings of one rule; summarise the rest in the last one.
fn emit(ctx: &Ctx, out: &mut Vec<Finding>, mut list: Vec<Finding>) {
    list.sort_by(|a, b| a.severity.cmp(&b.severity).then(b.score.cmp(&a.score)).then(a.key.cmp(&b.key)));
    if list.len() > MAX_PER_RULE {
        let rest = list.split_off(MAX_PER_RULE);
        let sessions: HashSet<u64> = rest.iter().flat_map(|f| f.sessions.iter().copied()).collect();
        let worst = rest.iter().map(|f| f.severity).min().unwrap_or(Severity::Info);
        let text = if ctx.de() {
            format!("{} weitere (höchste Stufe: {}; {} Sessions)", ctx.fmt_count(rest.len()), sev_label(ctx, worst), ctx.fmt_count(sessions.len()))
        } else {
            format!("{} more (highest severity: {}; {} sessions)", ctx.fmt_count(rest.len()), sev_label(ctx, worst), ctx.fmt_count(sessions.len()))
        };
        if let Some(last) = list.last_mut() {
            last.facts.push((ctx.l("Further findings of this rule (not listed)", "Weitere Befunde dieser Regel (nicht aufgeführt)").to_string(), text));
        }
    }
    out.extend(list);
}

fn mbit(ctx: &Ctx, mbps: f64) -> String {
    format!("{} Mbit/s", crate::fmt::num(mbps, if mbps < 10.0 { 1 } else { 0 }, ctx.opts.lang))
}

/// Modelled time to transfer `bytes` once per network profile (one round trip plus bandwidth).
fn transfer_table(ctx: &Ctx, bytes: f64) -> (Vec<String>, Vec<Vec<String>>) {
    let cols = vec![ctx.l("Network", "Netz").to_string(), "RTT".into(), ctx.l("Bandwidth", "Bandbreite").to_string(), ctx.l("Estimated transfer time", "Geschätzte Übertragungszeit").to_string()];
    let rows = ctx
        .opts
        .networks
        .iter()
        .map(|n| {
            let t = n.rtt_ms + bytes * 8.0 / (n.mbps * 1_000_000.0) * 1000.0;
            vec![n.name.clone(), ctx.fmt_ms(n.rtt_ms), mbit(ctx, n.mbps), ctx.fmt_ms(t)]
        })
        .collect();
    (cols, rows)
}

/// Modelled cost of `round_trips` additional round trips per network profile.
fn rtt_table(ctx: &Ctx, round_trips: f64) -> (Vec<String>, Vec<Vec<String>>) {
    let cols = vec![ctx.l("Network", "Netz").to_string(), "RTT".into(), ctx.l("Estimated extra time", "Geschätzte Mehrzeit").to_string()];
    let rows = ctx.opts.networks.iter().map(|n| vec![n.name.clone(), ctx.fmt_ms(n.rtt_ms), format!("+{}", ctx.fmt_ms(round_trips * n.rtt_ms))]).collect();
    (cols, rows)
}

fn header_has(v: Option<&str>, token: &str) -> bool {
    v.is_some_and(|v| v.to_ascii_lowercase().contains(token))
}

// ------------------------------------------------------------------ PERF-TTFB

/// Median server time at or above this multiple of the threshold is critical.
const TTFB_CRITICAL_FACTOR: f64 = 5.0;
/// Server time share of the total duration above which the transfer is negligible.
const TTFB_SERVER_DOMINANT: f64 = 0.7;

/// PERF-TTFB: server time to first byte above `opts.ttfb_ms`, per endpoint.
struct ServerTime;

impl Analyzer for ServerTime {
    fn id(&self) -> &'static str {
        "PERF-TTFB"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "troubleshooting"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let limit = ctx.opts.ttfb_ms;
        // All requests per endpoint and those with timers, for the share of slow ones.
        let mut per_endpoint: HashMap<String, (usize, usize)> = HashMap::new();
        for s in ctx.http().filter(|s| !s.failed()) {
            let e = per_endpoint.entry(endpoint(s)).or_default();
            e.0 += 1;
            e.1 += s.ttfb_ms().is_some() as usize;
        }
        let slow = ctx.http().filter(|s| !s.failed() && s.ttfb_ms().is_some_and(|t| t > limit));
        let mut list = vec![];
        for (ep, v) in util::group_by(slow, |s| endpoint(s)) {
            let ttfb: Vec<f64> = v.iter().filter_map(|s| s.ttfb_ms()).collect();
            let median = util::percentile(&ttfb, 50.0);
            let worst = ttfb.iter().cloned().fold(0.0, f64::max);
            let sum_ttfb: f64 = ttfb.iter().sum();
            let sum_total = v.iter().map(|s| ms(s)).sum::<f64>().max(sum_ttfb);
            let share = if sum_total > 0.0 { sum_ttfb / sum_total } else { 1.0 };
            let downloads: Vec<f64> = v.iter().filter_map(|s| s.download_ms()).collect();
            let n = v.len();
            let (all, timed) = per_endpoint.get(&ep).copied().unwrap_or((n, n));
            let severity = if median >= limit * TTFB_CRITICAL_FACTOR { Severity::Critical } else { Severity::Warning };
            let mut f = Finding::new(
                "PERF-TTFB",
                &ep,
                severity,
                format!("{} {}", ctx.l("High server time (TTFB):", "Hohe Serverzeit (TTFB):"), util::short(&ep, 80)),
                if ctx.de() {
                    format!(
                        "{} von {} Request(s) warteten länger als {} auf das erste Byte der Response (Median {}, max. {}).",
                        ctx.fmt_count(n),
                        ctx.fmt_count(all),
                        ctx.fmt_ms(limit),
                        ctx.fmt_ms(median),
                        ctx.fmt_ms(worst)
                    )
                } else {
                    format!(
                        "{} of {} request(s) waited longer than {} for the first response byte (median {}, max {}).",
                        ctx.fmt_count(n),
                        ctx.fmt_count(all),
                        ctx.fmt_ms(limit),
                        ctx.fmt_ms(median),
                        ctx.fmt_ms(worst)
                    )
                },
            )
            .categories(&["performance", "server"])
            .score(util::scale(sum_ttfb, limit, limit * 50.0))
            .threshold(format!("TTFB > {}", ctx.fmt_ms(limit)))
            .fact(ctx.l("Requests above the threshold", "Requests über der Schwelle"), format!("{} / {}", ctx.fmt_count(n), ctx.fmt_count(all)))
            .fact(ctx.l("Median TTFB", "Median TTFB"), ctx.fmt_ms(median))
            .fact(ctx.l("Maximum TTFB", "Maximale TTFB"), ctx.fmt_ms(worst))
            .fact(ctx.l("Server time share of the total time", "Anteil Serverzeit an der Gesamtzeit"), ctx.fmt_pct(share))
            .impact(ctx.l(
                "The server needs this long before it sends the first byte; a faster network does not shorten this wait.",
                "So lange braucht der Server, bis er das erste Byte sendet; ein schnelleres Netz verkürzt diese Wartezeit nicht.",
            ))
            .sessions(v.iter().map(|s| s.id));
            if !downloads.is_empty() {
                f = f.fact(ctx.l("Median download time", "Median Downloadzeit"), ctx.fmt_ms(util::percentile(&downloads, 50.0)));
            }
            f = if share >= TTFB_SERVER_DOMINANT {
                f.hypothesis(ctx.l(
                    "The time is spent on the server (processing, database, downstream calls, queueing), not in the transfer.",
                    "Die Zeit vergeht auf dem Server (Verarbeitung, Datenbank, nachgelagerte Aufrufe, Warteschlangen), nicht bei der Übertragung.",
                ))
            } else {
                f.hypothesis(ctx.l(
                    "Besides the server time, a notable part is spent transferring the response (see PERF-SLOW and PERF-LARGE-RESP).",
                    "Neben der Serverzeit entfällt ein nennenswerter Teil auf die Übertragung der Response (siehe PERF-SLOW und PERF-LARGE-RESP).",
                ))
            };
            if n * 2 < timed {
                f = f.hypothesis(ctx.l(
                    "Only some requests to this endpoint are slow: this points to load-dependent effects (locks, cold caches, garbage collection, exhausted thread or connection pools).",
                    "Nur ein Teil der Requests an diesen Endpunkt ist langsam: Das deutet auf lastabhängige Effekte hin (Sperren, kalte Caches, Garbage Collection, erschöpfte Thread- oder Verbindungspools).",
                ));
            }
            if timed < all {
                f = f.confidence(Confidence::Medium);
            }
            list.push(
                f.recommend(ctx.l("Profile the server side of this endpoint: database queries, downstream calls, locking.", "Die Serverseite dieses Endpunkts profilieren: Datenbankabfragen, nachgelagerte Aufrufe, Sperren."))
                    .recommend(ctx.l("Cache results on the server or move long-running work to asynchronous processing.", "Ergebnisse serverseitig cachen oder lang laufende Arbeit in asynchrone Verarbeitung auslagern."))
                    .next_step(ctx.l("Look up the slowest requests in the server logs (timestamps, request ids).", "Die langsamsten Requests in den Serverlogs nachschlagen (Zeitstempel, Request-IDs).")),
            );
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ PERF-LARGE-REQ / PERF-LARGE-RESP

/// Sizes at or above this multiple of the threshold are critical (responses) or warnings (requests).
const LARGE_CRITICAL_FACTOR: f64 = 5.0;
/// So many large uploads to one endpoint are a warning even below the critical size.
const LARGE_REQ_WARN_COUNT: usize = 10;

/// PERF-LARGE-REQ: request bodies of at least `opts.large_request_bytes`, per endpoint.
struct LargeRequests;

impl Analyzer for LargeRequests {
    fn id(&self) -> &'static str {
        "PERF-LARGE-REQ"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let limit = ctx.opts.large_request_bytes;
        let large = ctx.http().filter(|s| s.request_bytes >= limit);
        let mut list = vec![];
        for (ep, v) in util::group_by(large, |s| endpoint(s)) {
            let sizes: Vec<f64> = v.iter().map(|s| s.request_bytes as f64).collect();
            let median = util::percentile(&sizes, 50.0);
            let worst = sizes.iter().cloned().fold(0.0, f64::max);
            let total: f64 = sizes.iter().sum();
            let failed = v.iter().filter(|s| s.failed()).count();
            let resumable = v.iter().any(|s| s.req_header("content-range").is_some());
            let types = top(v.iter().filter_map(|s| s.req_header("content-type")).map(|c| c.split(';').next().unwrap_or("").trim().to_ascii_lowercase()));
            let n = v.len();
            let severity = if worst >= limit as f64 * LARGE_CRITICAL_FACTOR || n >= LARGE_REQ_WARN_COUNT || failed > 0 { Severity::Warning } else { Severity::Info };
            let (cols, rows) = transfer_table(ctx, median);
            let mut f = Finding::new(
                "PERF-LARGE-REQ",
                &ep,
                severity,
                format!("{} {}", ctx.l("Large request bodies:", "Große Request-Bodys:"), util::short(&ep, 80)),
                if ctx.de() {
                    format!("{} Request(s) sendeten mindestens {} (Median {}, max. {}, insgesamt {}).", ctx.fmt_count(n), ctx.fmt_bytes(limit as f64), ctx.fmt_bytes(median), ctx.fmt_bytes(worst), ctx.fmt_bytes(total))
                } else {
                    format!("{} request(s) sent at least {} (median {}, max {}, total {}).", ctx.fmt_count(n), ctx.fmt_bytes(limit as f64), ctx.fmt_bytes(median), ctx.fmt_bytes(worst), ctx.fmt_bytes(total))
                },
            )
            .categories(&["performance", "payload"])
            .score(util::scale(total, limit as f64, limit as f64 * 100.0))
            .threshold(format!("≥ {}", ctx.fmt_bytes(limit as f64)))
            .fact(ctx.l("Requests", "Requests"), ctx.fmt_count(n))
            .fact(ctx.l("Median size", "Median Größe"), ctx.fmt_bytes(median))
            .fact(ctx.l("Largest", "Größter"), ctx.fmt_bytes(worst))
            .fact(ctx.l("Total uploaded", "Insgesamt hochgeladen"), ctx.fmt_bytes(total))
            .impact(ctx.l(
                "Uploads of this size take seconds on slow or asymmetric links and are the first to break on unstable networks.",
                "Uploads dieser Größe dauern bei langsamen oder asymmetrischen Leitungen Sekunden und brechen in instabilen Netzen als Erstes ab.",
            ))
            .estimate()
            .table(cols, rows)
            .sessions(v.iter().map(|s| s.id));
            if !types.is_empty() {
                f = f.fact(ctx.l("Content type", "Inhaltstyp"), list_top(ctx, &types, 3));
            }
            if failed > 0 {
                f = f.fact(ctx.l("Failed", "Fehlgeschlagen"), ctx.fmt_count(failed)).hypothesis(if ctx.de() {
                    format!("{} dieser Uploads schlugen fehl – bei großen Bodys sind Timeouts und abgebrochene Verbindungen wahrscheinlicher.", ctx.fmt_count(failed))
                } else {
                    format!("{} of these uploads failed – timeouts and dropped connections are more likely with large bodies.", ctx.fmt_count(failed))
                });
            }
            if !resumable {
                f = f
                    .hypothesis(ctx.l(
                        "No Content-Range was seen: the upload is neither chunked nor resumable, so an interruption restarts it from the beginning.",
                        "Kein Content-Range gesehen: Der Upload ist weder in Teile zerlegt noch fortsetzbar; nach einer Unterbrechung beginnt er von vorn.",
                    ))
                    .recommend(ctx.l(
                        "Upload large payloads in chunks with resume support (Content-Range chunks, tus or a multipart upload API).",
                        "Große Nutzlasten in Teilen mit Fortsetzungsmöglichkeit hochladen (Content-Range-Teile, tus oder eine Multipart-Upload-API).",
                    ));
            }
            list.push(
                f.recommend(ctx.l(
                    "Check whether the whole payload is needed: send only changes, compress text payloads, upload files directly to storage.",
                    "Prüfen, ob die ganze Nutzlast nötig ist: nur Änderungen senden, Text-Nutzlasten komprimieren, Dateien direkt in den Speicher hochladen.",
                ))
                .next_step(ctx.l("Repeat the upload with bandwidth simulation (Settings → Connections).", "Den Upload mit Bandbreitensimulation wiederholen (Einstellungen → Verbindungen).")),
            );
        }
        emit(ctx, out, list);
    }
}

/// PERF-LARGE-RESP: responses of at least `opts.large_response_bytes` (decoded), per endpoint.
struct LargeResponses;

impl Analyzer for LargeResponses {
    fn id(&self) -> &'static str {
        "PERF-LARGE-RESP"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "resilience", "modernization"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let limit = ctx.opts.large_response_bytes;
        let large = ctx.http().filter(|s| decoded(s) >= limit);
        let mut list = vec![];
        for (ep, v) in util::group_by(large, |s| endpoint(s)) {
            let sizes: Vec<f64> = v.iter().map(|s| decoded(s) as f64).collect();
            let median = util::percentile(&sizes, 50.0);
            let worst = sizes.iter().cloned().fold(0.0, f64::max);
            let total: f64 = sizes.iter().sum();
            let wire: Vec<f64> = v.iter().map(|s| if s.response_bytes > 0 { s.response_bytes as f64 } else { decoded(s) as f64 }).collect();
            let wire_total: f64 = wire.iter().sum();
            let types = top(v.iter().map(|s| s.mime()).filter(|m| !m.is_empty()));
            let odata = v.iter().any(|s| canon::is_odata(&canon::parse(&s.url)));
            let uncompressed = v.iter().any(|s| canon::is_compressible(&s.mime()) && s.resp_header("content-encoding").is_none());
            let n = v.len();
            let severity = if worst >= limit as f64 * LARGE_CRITICAL_FACTOR { Severity::Critical } else { Severity::Warning };
            let (cols, rows) = transfer_table(ctx, util::percentile(&wire, 50.0));
            let mut f = Finding::new(
                "PERF-LARGE-RESP",
                &ep,
                severity,
                format!("{} {}", ctx.l("Large responses:", "Große Responses:"), util::short(&ep, 80)),
                if ctx.de() {
                    format!("{} Response(s) waren mindestens {} groß (Median {}, max. {}, insgesamt {}).", ctx.fmt_count(n), ctx.fmt_bytes(limit as f64), ctx.fmt_bytes(median), ctx.fmt_bytes(worst), ctx.fmt_bytes(total))
                } else {
                    format!("{} response(s) of at least {} (median {}, max {}, total {}).", ctx.fmt_count(n), ctx.fmt_bytes(limit as f64), ctx.fmt_bytes(median), ctx.fmt_bytes(worst), ctx.fmt_bytes(total))
                },
            )
            .categories(&["performance", "payload"])
            .score(util::scale(total, limit as f64, limit as f64 * 50.0))
            .threshold(format!("≥ {} ({} ≥ {})", ctx.fmt_bytes(limit as f64), sev_label(ctx, Severity::Critical), ctx.fmt_bytes(limit as f64 * LARGE_CRITICAL_FACTOR)))
            .fact(ctx.l("Responses", "Responses"), ctx.fmt_count(n))
            .fact(ctx.l("Median size (decoded)", "Median Größe (dekodiert)"), ctx.fmt_bytes(median))
            .fact(ctx.l("Largest (decoded)", "Größte (dekodiert)"), ctx.fmt_bytes(worst))
            .fact(ctx.l("Transferred on the wire", "Übertragen (Leitung)"), ctx.fmt_bytes(wire_total))
            .impact(ctx.l(
                "Large responses dominate the load time on slow links and cost memory and parsing time in the client.",
                "Große Responses bestimmen bei langsamen Leitungen die Ladezeit und kosten im Client Speicher und Parse-Zeit.",
            ))
            .estimate()
            .table(cols, rows)
            .tags(&["payload"])
            .sessions(v.iter().map(|s| s.id));
            if !types.is_empty() {
                f = f.fact(ctx.l("Content type", "Inhaltstyp"), list_top(ctx, &types, 3));
            }
            if odata {
                f = f.recommend(ctx.l(
                    "Request only the needed properties with $select and page with $top/$skip or server-driven paging.",
                    "Nur die benötigten Eigenschaften mit $select anfordern und mit $top/$skip oder serverseitigem Paging blättern.",
                ));
            } else {
                f = f.recommend(ctx.l("Page or filter the data on the server instead of loading it completely.", "Die Daten auf dem Server blättern oder filtern, statt sie vollständig zu laden."));
            }
            if uncompressed {
                f = f.recommend(ctx.l("Compress the responses (see PERF-COMPRESS).", "Die Responses komprimieren (siehe PERF-COMPRESS)."));
            }
            list.push(
                f.recommend(ctx.l("Load details lazily when they are shown.", "Details erst laden, wenn sie angezeigt werden (Lazy Loading)."))
                    .recommend(ctx.l(
                        "Stream the response (e.g. chunked or NDJSON) so the client can start processing before the download ends.",
                        "Die Response streamen (z. B. chunked oder NDJSON), damit der Client vor dem Ende des Downloads mit der Verarbeitung beginnen kann.",
                    ))
                    .next_step(ctx.l("Check which parts of the response the client actually uses.", "Prüfen, welche Teile der Response der Client tatsächlich verwendet.")),
            );
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ PERF-COMPRESS

/// Smallest response worth compressing.
const COMPRESS_MIN_BYTES: u64 = 1024;
/// Wire size at least this share of the decoded size: not compressed.
const COMPRESS_WIRE_RATIO: f64 = 0.9;
/// Estimated saving per host from which the finding is a warning.
const COMPRESS_WARN_SAVING: f64 = 256.0 * 1024.0;
/// Request bodies from this size are worth compressing (info).
const COMPRESS_REQ_MIN_BYTES: u64 = 64 * 1024;

/// Typical gzip/Brotli saving for a content type.
fn saving_ratio(mime: &str) -> f64 {
    if mime.contains("javascript") || mime.contains("ecmascript") || mime == "text/css" {
        0.6
    } else if mime.starts_with("font/") || mime == "application/wasm" || mime == "application/vnd.ms-fontobject" {
        0.5
    } else {
        0.7
    }
}

fn no_encoding(v: Option<&str>) -> bool {
    v.is_none_or(|v| v.trim().is_empty() || v.trim().eq_ignore_ascii_case("identity"))
}

/// PERF-COMPRESS: compressible content sent without compression, per host.
struct Compression;

impl Analyzer for Compression {
    fn id(&self) -> &'static str {
        "PERF-COMPRESS"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let mut list = vec![];
        let plain = ctx.http().filter(|s| {
            let d = decoded(s);
            !s.failed()
                && s.status != 304
                && !s.method.eq_ignore_ascii_case("HEAD")
                && d >= COMPRESS_MIN_BYTES
                && canon::is_compressible(&s.mime())
                && no_encoding(s.resp_header("content-encoding"))
                && (s.response_bytes == 0 || s.response_bytes as f64 >= d as f64 * COMPRESS_WIRE_RATIO)
        });
        for (h, v) in util::group_by(plain, |s| host(s)) {
            let n = v.len();
            let size: f64 = v.iter().map(|s| decoded(s) as f64).sum();
            let saving: f64 = v.iter().map(|s| decoded(s) as f64 * saving_ratio(&s.mime())).sum();
            let no_ae = v.iter().filter(|s| no_encoding(s.req_header("accept-encoding"))).count();
            let wire_unknown = v.iter().any(|s| s.response_bytes == 0);
            let mut eps: Vec<(String, Vec<&Session>)> = util::group_by(v.iter().copied(), |s| endpoint(s));
            let ep_saving = |l: &[&Session]| l.iter().map(|s| decoded(s) as f64 * saving_ratio(&s.mime())).sum::<f64>();
            eps.sort_by(|a, b| ep_saving(&b.1).total_cmp(&ep_saving(&a.1)).then(a.0.cmp(&b.0)));
            let rows: Vec<Vec<String>> = eps
                .iter()
                .take(8)
                .map(|(e, l)| vec![util::short(e, 80), ctx.fmt_count(l.len()), ctx.fmt_bytes(l.iter().map(|s| decoded(s) as f64).sum()), ctx.fmt_bytes(ep_saving(l))])
                .collect();
            let types = top(v.iter().map(|s| s.mime()));
            let severity = if saving >= COMPRESS_WARN_SAVING { Severity::Warning } else { Severity::Info };
            let mut f = Finding::new(
                "PERF-COMPRESS",
                &h,
                severity,
                format!("{} {}", ctx.l("Uncompressed responses:", "Unkomprimierte Responses:"), util::short(&h, 80)),
                if ctx.de() {
                    format!("{} komprimierbare Response(s) von {} ({}) wurden ohne Content-Encoding übertragen.", ctx.fmt_count(n), h, ctx.fmt_bytes(size))
                } else {
                    format!("{} compressible response(s) from {} ({}) were sent without Content-Encoding.", ctx.fmt_count(n), h, ctx.fmt_bytes(size))
                },
            )
            .categories(&["performance", "payload"])
            .score(util::scale(saving, 10.0 * 1024.0, 50.0 * 1024.0 * 1024.0))
            .threshold(if ctx.de() {
                format!("≥ {}, komprimierbarer Typ, ohne Content-Encoding (Warnung ab {} Ersparnis)", ctx.fmt_bytes(COMPRESS_MIN_BYTES as f64), ctx.fmt_bytes(COMPRESS_WARN_SAVING))
            } else {
                format!("≥ {}, compressible type, no Content-Encoding (warning from {} saving)", ctx.fmt_bytes(COMPRESS_MIN_BYTES as f64), ctx.fmt_bytes(COMPRESS_WARN_SAVING))
            })
            .impact(if ctx.de() {
                format!("Kompression würde etwa {} ({}) einsparen – spürbar vor allem bei langsamen Leitungen.", ctx.fmt_bytes(saving), ctx.fmt_pct(saving / size.max(1.0)))
            } else {
                format!("Compression would save about {} ({}) – noticeable especially on slow links.", ctx.fmt_bytes(saving), ctx.fmt_pct(saving / size.max(1.0)))
            })
            .estimate()
            .fact(ctx.l("Responses", "Responses"), ctx.fmt_count(n))
            .fact(ctx.l("Uncompressed size", "Unkomprimierte Größe"), ctx.fmt_bytes(size))
            .fact(ctx.l("Estimated saving", "Geschätzte Ersparnis"), ctx.fmt_bytes(saving))
            .fact(ctx.l("Content types", "Inhaltstypen"), list_top(ctx, &types, 4))
            .table(
                vec![ctx.l("Endpoint", "Endpunkt").into(), ctx.l("Responses", "Responses").into(), ctx.l("Size", "Größe").into(), ctx.l("Estimated saving", "Geschätzte Ersparnis").into()],
                rows,
            )
            .sessions(v.iter().map(|s| s.id));
            if no_ae > 0 {
                f = f.fact(ctx.l("Requests without Accept-Encoding", "Requests ohne Accept-Encoding"), format!("{} / {}", ctx.fmt_count(no_ae), ctx.fmt_count(n))).hypothesis(if ctx.de() {
                    format!("{} der Requests enthielten kein Accept-Encoding – für sie darf der Server nicht komprimieren; der Client muss gzip/br anbieten.", ctx.fmt_count(no_ae))
                } else {
                    format!("{} of the requests carried no Accept-Encoding – the server may not compress for them; the client has to offer gzip/br.", ctx.fmt_count(no_ae))
                });
                f = f.recommend(ctx.l("Let the client send Accept-Encoding: gzip, br (enable automatic decompression in the HTTP client).", "Den Client Accept-Encoding: gzip, br senden lassen (automatische Dekompression im HTTP-Client aktivieren)."));
            }
            if no_ae < n {
                f = f.hypothesis(ctx.l(
                    "The client accepts compression, but the server or a proxy does not compress these content types.",
                    "Der Client akzeptiert Kompression, aber Server oder Proxy komprimieren diese Inhaltstypen nicht.",
                ));
            }
            if wire_unknown {
                f = f.confidence(Confidence::Medium);
            }
            list.push(
                f.recommend(ctx.l("Enable gzip or Brotli for these content types on the server or reverse proxy.", "Auf dem Server oder Reverse Proxy gzip oder Brotli für diese Inhaltstypen aktivieren."))
                    .next_step(ctx.l("Check the response headers of the largest responses for Content-Encoding.", "Die Response-Header der größten Responses auf Content-Encoding prüfen.")),
            );
        }
        // Request side: large compressible bodies sent as they are.
        let plain_req = ctx.http().filter(|s| {
            s.request_bytes >= COMPRESS_REQ_MIN_BYTES
                && s.req_header("content-type").is_some_and(|c| canon::is_compressible(c.split(';').next().unwrap_or("").trim().to_ascii_lowercase().as_str()))
                && no_encoding(s.req_header("content-encoding"))
        });
        for (h, v) in util::group_by(plain_req, |s| host(s)) {
            let size: f64 = v.iter().map(|s| s.request_bytes as f64).sum();
            let eps = top(v.iter().map(|s| endpoint(s)));
            list.push(
                Finding::new(
                    "PERF-COMPRESS",
                    &format!("request|{h}"),
                    Severity::Info,
                    format!("{} {}", ctx.l("Uncompressed request bodies:", "Unkomprimierte Request-Bodys:"), util::short(&h, 80)),
                    if ctx.de() {
                        format!("{} Request(s) an {} sendeten zusammen {} komprimierbaren Inhalt ohne Content-Encoding.", ctx.fmt_count(v.len()), h, ctx.fmt_bytes(size))
                    } else {
                        format!("{} request(s) to {} sent {} of compressible content without Content-Encoding.", ctx.fmt_count(v.len()), h, ctx.fmt_bytes(size))
                    },
                )
                .categories(&["performance", "payload"])
                .score(util::scale(size, COMPRESS_REQ_MIN_BYTES as f64, 100.0 * 1024.0 * 1024.0))
                .threshold(format!("≥ {}", ctx.fmt_bytes(COMPRESS_REQ_MIN_BYTES as f64)))
                .estimate()
                .impact(if ctx.de() {
                    format!("Kompression würde beim Upload etwa {} einsparen.", ctx.fmt_bytes(size * 0.7))
                } else {
                    format!("Compression would save about {} of upload.", ctx.fmt_bytes(size * 0.7))
                })
                .fact(ctx.l("Endpoints", "Endpunkte"), list_top(ctx, &eps, 3))
                .hypothesis(ctx.l("Request compression must be supported by the server; many servers accept gzip request bodies only when configured.", "Request-Kompression muss der Server unterstützen; viele Server nehmen gzip-Request-Bodys nur nach Konfiguration an."))
                .recommend(ctx.l("Compress large text uploads (Content-Encoding: gzip) where the server accepts it, or send less data.", "Große Text-Uploads komprimieren (Content-Encoding: gzip), sofern der Server das annimmt, oder weniger Daten senden."))
                .sessions(v.iter().map(|s| s.id)),
            );
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ ERR-HTTP

/// 5xx responses of one endpoint and status from this count are critical …
const ERR5XX_CRIT_COUNT: usize = 10;
/// … or from this share of the endpoint's requests (with at least `ERR5XX_CRIT_MIN`).
const ERR5XX_CRIT_SHARE: f64 = 0.25;
const ERR5XX_CRIT_MIN: usize = 3;
/// Response/request headers that carry ids for the server logs.
const REQUEST_ID_HEADERS: [&str; 5] = ["x-request-id", "request-id", "x-ms-request-id", "x-correlation-id", "traceparent"];

/// Likely cause and remedy of an HTTP status.
fn status_hint<'a>(ctx: &Ctx, code: u16) -> (&'a str, &'a str) {
    match code {
        400 => (
            ctx.l("The server rejects the request as malformed (parameters, body format, validation).", "Der Server weist den Request als fehlerhaft ab (Parameter, Body-Format, Validierung)."),
            ctx.l("Compare a failing request with a successful one; read the error body of the response.", "Einen fehlerhaften mit einem erfolgreichen Request vergleichen; den Fehler-Body der Response lesen."),
        ),
        404 => (
            ctx.l("The resource does not exist (wrong URL, deleted object, wrong base path or routing).", "Die Ressource existiert nicht (falsche URL, gelöschtes Objekt, falscher Basispfad oder Routing)."),
            ctx.l("Check the URL construction in the client and the routing on the server.", "Den URL-Aufbau im Client und das Routing auf dem Server prüfen."),
        ),
        405 => (
            ctx.l("The method is not allowed for this resource.", "Die Methode ist für diese Ressource nicht erlaubt."),
            ctx.l("Check the HTTP method and any X-HTTP-Method-Override.", "HTTP-Methode und gegebenenfalls X-HTTP-Method-Override prüfen."),
        ),
        408 | 504 => (
            ctx.l("A timeout on the server or a gateway: the backend did not answer in time.", "Ein Timeout auf dem Server oder einem Gateway: Das Backend hat nicht rechtzeitig geantwortet."),
            ctx.l("Check the timeouts along the chain and the server time of this endpoint (PERF-TTFB).", "Die Timeouts entlang der Kette und die Serverzeit dieses Endpunkts prüfen (PERF-TTFB)."),
        ),
        409 | 412 | 428 => (
            ctx.l("A conflict or failed precondition: concurrent changes or a stale ETag (If-Match).", "Ein Konflikt oder eine verletzte Vorbedingung: gleichzeitige Änderungen oder ein veraltetes ETag (If-Match)."),
            ctx.l("Reload the resource before changing it and handle conflicts in the client.", "Die Ressource vor dem Ändern neu laden und Konflikte im Client behandeln."),
        ),
        413 | 414 | 431 => (
            ctx.l("The request is too large for the server (body, URL or headers).", "Der Request ist für den Server zu groß (Body, URL oder Header)."),
            ctx.l("Reduce the request size (fewer parameters in the URL, smaller cookies, chunked uploads).", "Den Request verkleinern (weniger Parameter in der URL, kleinere Cookies, Uploads in Teilen)."),
        ),
        415 => (
            ctx.l("The server does not accept the content type of the request body.", "Der Server akzeptiert den Inhaltstyp des Request-Bodys nicht."),
            ctx.l("Check Content-Type and the body format.", "Content-Type und Body-Format prüfen."),
        ),
        422 => (
            ctx.l("The request is well-formed but fails validation.", "Der Request ist formal korrekt, besteht aber die Validierung nicht."),
            ctx.l("Read the validation errors in the response body.", "Die Validierungsfehler im Response-Body lesen."),
        ),
        429 => (
            ctx.l("Rate limiting: the client sends more requests than allowed.", "Ratenbegrenzung: Der Client sendet mehr Requests als erlaubt."),
            ctx.l("Reduce the request rate (caching, batching) and honour Retry-After with back-off.", "Die Request-Rate senken (Caching, Batching) und Retry-After mit Back-off beachten."),
        ),
        500 => (
            ctx.l("An unhandled error on the server (exception).", "Ein unbehandelter Fehler auf dem Server (Exception)."),
            ctx.l("Look up the exception in the server logs for these requests.", "Die Exception zu diesen Requests in den Serverlogs nachschlagen."),
        ),
        501 => (
            ctx.l("The server does not implement this function.", "Der Server implementiert diese Funktion nicht."),
            ctx.l("Check the API version the client expects.", "Die API-Version prüfen, die der Client erwartet."),
        ),
        502 => (
            ctx.l("A gateway or proxy got no valid response from the backend (crashed, restarted or unreachable).", "Ein Gateway oder Proxy bekam keine gültige Antwort vom Backend (abgestürzt, neu gestartet oder nicht erreichbar)."),
            ctx.l("Check the backend behind the gateway and its health at the time of the errors.", "Das Backend hinter dem Gateway und seinen Zustand zum Zeitpunkt der Fehler prüfen."),
        ),
        503 => (
            ctx.l("The service is unavailable or overloaded (maintenance, throttling, scaling).", "Der Dienst ist nicht verfügbar oder überlastet (Wartung, Drosselung, Skalierung)."),
            ctx.l("Check the load and availability of the service; honour Retry-After.", "Last und Verfügbarkeit des Dienstes prüfen; Retry-After beachten."),
        ),
        c if c >= 500 => (
            ctx.l("A server-side error.", "Ein serverseitiger Fehler."),
            ctx.l("Look up these requests in the server logs.", "Diese Requests in den Serverlogs nachschlagen."),
        ),
        _ => (
            ctx.l("The server rejects the request (client error).", "Der Server weist den Request ab (Client-Fehler)."),
            ctx.l("Read the error body of the response and compare with a successful request.", "Den Fehler-Body der Response lesen und mit einem erfolgreichen Request vergleichen."),
        ),
    }
}

/// ERR-HTTP: HTTP error responses per endpoint and status (401/403/407: AUTH-FAIL).
struct HttpErrors;

impl Analyzer for HttpErrors {
    fn id(&self) -> &'static str {
        "ERR-HTTP"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["troubleshooting"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let mut statuses: HashMap<String, HashMap<u16, usize>> = HashMap::new();
        for s in ctx.http().filter(|s| s.status > 0) {
            *statuses.entry(endpoint(s)).or_default().entry(s.status).or_default() += 1;
        }
        let errors = ctx.http().filter(|s| {
            s.status >= 400 && !matches!(s.status, 401 | 403 | 407) && !(s.status == 404 && canon::parse(&s.url).path.to_ascii_lowercase().ends_with("/favicon.ico"))
        });
        let mut list = vec![];
        for ((ep, code), v) in util::group_by(errors, |s| (endpoint(s), s.status)) {
            let n = v.len();
            let dist = statuses.get(&ep).cloned().unwrap_or_default();
            let all: usize = dist.values().sum::<usize>().max(n);
            let share = ratio(n, all);
            let static404 = code == 404 && v.iter().all(|s| canon::is_static("", &canon::parse(&s.url).path));
            let severity = if code >= 500 {
                if n >= ERR5XX_CRIT_COUNT || (share >= ERR5XX_CRIT_SHARE && n >= ERR5XX_CRIT_MIN) { Severity::Critical } else { Severity::Warning }
            } else if static404 {
                Severity::Info
            } else {
                Severity::Warning
            };
            let mut dist: Vec<(u16, usize)> = dist.into_iter().collect();
            dist.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let rows: Vec<Vec<String>> = dist.iter().take(8).map(|(c, k)| vec![c.to_string(), ctx.fmt_count(*k), ctx.fmt_pct(ratio(*k, all))]).collect();
            let ids: Vec<&str> = v.iter().filter_map(|s| REQUEST_ID_HEADERS.iter().find_map(|h| s.resp_header(h).or_else(|| s.req_header(h)))).take(3).collect();
            let retry_after = v.iter().filter(|s| s.resp_header("retry-after").is_some()).count();
            let (hyp, rec) = status_hint(ctx, code);
            let mut f = Finding::new(
                "ERR-HTTP",
                &format!("{ep}|{code}"),
                severity,
                format!("HTTP {code}: {}", util::short(&ep, 80)),
                if ctx.de() {
                    format!("{} von {} Request(s) an {} endeten mit HTTP {} ({}).", ctx.fmt_count(n), ctx.fmt_count(all), ep, code, ctx.fmt_pct(share))
                } else {
                    format!("{} of {} request(s) to {} returned HTTP {} ({}).", ctx.fmt_count(n), ctx.fmt_count(all), ep, code, ctx.fmt_pct(share))
                },
            )
            .categories(&["errors"])
            .score(util::scale(n as f64, 0.0, 50.0) * 0.5 + share * 50.0 + if code >= 500 { 10.0 } else { 0.0 })
            .threshold(if code >= 500 {
                if ctx.de() {
                    format!("5xx: kritisch ab {} Requests oder ab {} Anteil", ctx.fmt_count(ERR5XX_CRIT_COUNT), ctx.fmt_pct(ERR5XX_CRIT_SHARE))
                } else {
                    format!("5xx: critical from {} requests or {} share", ctx.fmt_count(ERR5XX_CRIT_COUNT), ctx.fmt_pct(ERR5XX_CRIT_SHARE))
                }
            } else {
                "≥ 400".to_string()
            })
            .fact(ctx.l("Status", "Status"), code.to_string())
            .fact(ctx.l("Requests with this status", "Requests mit diesem Status"), ctx.fmt_count(n))
            .fact(ctx.l("Share of the endpoint's requests", "Anteil an den Requests des Endpunkts"), ctx.fmt_pct(share))
            .table(vec![ctx.l("Status", "Status").into(), ctx.l("Requests", "Requests").into(), ctx.l("Share", "Anteil").into()], rows)
            .impact(if code >= 500 {
                ctx.l("Server errors break the user's action or trigger retries.", "Serverfehler brechen die Aktion des Benutzers ab oder lösen Wiederholungen aus.")
            } else if static404 {
                ctx.l("Missing static resources cost a round trip each and may break the page layout.", "Fehlende statische Ressourcen kosten je einen Roundtrip und können das Seitenlayout stören.")
            } else {
                ctx.l("The client sends requests the server rejects; the action fails or is repeated needlessly.", "Der Client sendet Requests, die der Server abweist; die Aktion schlägt fehl oder wird unnötig wiederholt.")
            })
            .hypothesis(hyp)
            .recommend(rec)
            .sessions(v.iter().map(|s| s.id));
            if !ids.is_empty() {
                f = f.fact(ctx.l("Request ids (examples)", "Request-IDs (Beispiele)"), ids.iter().map(|x| util::short(x, 60)).collect::<Vec<_>>().join(", "));
            }
            if retry_after > 0 {
                f = f.fact(ctx.l("Responses with Retry-After", "Responses mit Retry-After"), ctx.fmt_count(retry_after));
            }
            if static404 {
                f = f.recommend(ctx.l("Remove the reference or deploy the missing file.", "Den Verweis entfernen oder die fehlende Datei ausliefern."));
            }
            list.push(f.next_step(ctx.l("Open a failing session and read the response body.", "Eine fehlerhafte Session öffnen und den Response-Body lesen.")));
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ NET-FAIL

/// Failures of a host from this share of its requests are critical …
const NETFAIL_CRIT_SHARE: f64 = 0.05;
/// … if there are at least this many.
const NETFAIL_CRIT_MIN: usize = 3;

/// Error class of a failed session from its error text (case-insensitive).
fn error_class(s: &Session) -> &'static str {
    let Some(e) = s.error.as_deref() else { return "other" };
    let e = e.to_ascii_lowercase();
    let has = |w: &[&str]| w.iter().any(|x| e.contains(x));
    if has(&["dns", "could not resolve", "resolve host", "no such host", "nodename", "getaddrinfo", "enotfound", "name or service not known", "host not found", "unknown host", "name_not_resolved"]) {
        "dns"
    } else if has(&["tls", "ssl", "certificate", "handshake", "x509", "schannel"]) {
        "tls"
    } else if has(&["refused", "econnrefused"]) {
        "refused"
    } else if has(&["timeout", "timed out", "time-out", "time out", "etimedout", "deadline"]) {
        "timeout"
    } else if has(&["reset", "broken pipe", "epipe", "forcibly closed", "connection closed", "closed by", "unexpected eof"]) {
        "reset"
    } else if has(&["abort", "cancel"]) {
        "aborted"
    } else {
        "other"
    }
}

fn class_label<'a>(ctx: &Ctx, c: &str) -> &'a str {
    match c {
        "timeout" => ctx.l("timeout", "Timeout"),
        "reset" => ctx.l("connection reset", "Verbindung zurückgesetzt"),
        "refused" => ctx.l("connection refused", "Verbindung abgelehnt"),
        "dns" => ctx.l("name resolution (DNS)", "Namensauflösung (DNS)"),
        "tls" => ctx.l("TLS/certificate", "TLS/Zertifikat"),
        "aborted" => ctx.l("aborted", "abgebrochen"),
        _ => ctx.l("other / no response", "sonstige / keine Antwort"),
    }
}

fn class_hint<'a>(ctx: &Ctx, c: &str) -> (&'a str, &'a str) {
    match c {
        "timeout" => (
            ctx.l("The server or the network did not answer within the client's or proxy's timeout (overload, packet loss, blocked port).", "Server oder Netz haben nicht innerhalb des Timeouts von Client oder Proxy geantwortet (Überlast, Paketverlust, gesperrter Port)."),
            ctx.l("Compare the time until failure with the configured timeouts; check server load and the network path.", "Die Zeit bis zum Abbruch mit den konfigurierten Timeouts vergleichen; Serverlast und Netzpfad prüfen."),
        ),
        "reset" => (
            ctx.l("The connection was closed by the other side or a middlebox (idle timeout of a firewall/load balancer, server restart).", "Die Verbindung wurde von der Gegenseite oder einem Zwischensystem geschlossen (Leerlauf-Timeout von Firewall/Load Balancer, Neustart des Servers)."),
            ctx.l("Check idle timeouts along the path and retry idempotent requests on a fresh connection.", "Leerlauf-Timeouts entlang des Pfads prüfen und idempotente Requests auf einer neuen Verbindung wiederholen."),
        ),
        "refused" => (
            ctx.l("Nothing listens on the target port, or a firewall actively rejects the connection.", "Auf dem Zielport lauscht nichts, oder eine Firewall weist die Verbindung aktiv ab."),
            ctx.l("Check that the service is running and reachable on this host and port.", "Prüfen, ob der Dienst läuft und auf diesem Host und Port erreichbar ist."),
        ),
        "dns" => (
            ctx.l("The host name could not be resolved (typo, missing DNS entry, VPN or split DNS).", "Der Hostname konnte nicht aufgelöst werden (Tippfehler, fehlender DNS-Eintrag, VPN oder Split-DNS)."),
            ctx.l("Check the host name and the DNS configuration of the client.", "Hostnamen und DNS-Konfiguration des Clients prüfen."),
        ),
        "tls" => (
            ctx.l("The TLS handshake failed (untrusted or expired certificate, name mismatch, no common protocol version).", "Der TLS-Handshake ist fehlgeschlagen (nicht vertrauenswürdiges oder abgelaufenes Zertifikat, Namenskonflikt, keine gemeinsame Protokollversion)."),
            ctx.l("Check the server certificate chain and the supported TLS versions on both sides.", "Die Zertifikatskette des Servers und die unterstützten TLS-Versionen auf beiden Seiten prüfen."),
        ),
        "aborted" => (
            ctx.l("The client aborted the requests (navigation, cancellation, superseded request).", "Der Client hat die Requests abgebrochen (Navigation, Abbruch, überholter Request)."),
            ctx.l("Harmless if intended; otherwise check why the client cancels (timeouts in the client code).", "Unkritisch, wenn beabsichtigt; sonst prüfen, warum der Client abbricht (Timeouts im Client-Code)."),
        ),
        _ => (
            ctx.l("The requests got no usable response.", "Die Requests erhielten keine verwertbare Antwort."),
            ctx.l("Open a failing session and read the error message.", "Eine fehlgeschlagene Session öffnen und die Fehlermeldung lesen."),
        ),
    }
}

/// NET-FAIL: sessions without a usable response, per host and error class.
struct NetFailures;

impl Analyzer for NetFailures {
    fn id(&self) -> &'static str {
        "NET-FAIL"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["troubleshooting", "resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let relevant = || ctx.sessions.iter().filter(|s| s.kind != Kind::WebSocket);
        let mut per_host: HashMap<String, (usize, usize)> = HashMap::new();
        for s in relevant() {
            let e = per_host.entry(host(s)).or_default();
            e.0 += 1;
            e.1 += s.failed() as usize;
        }
        let mut list = vec![];
        for ((h, class), v) in util::group_by(relevant().filter(|s| s.failed()), |s| (host(s), error_class(s))) {
            let n = v.len();
            let (all, failed) = per_host.get(&h).copied().unwrap_or((n, n));
            let share = ratio(failed, all);
            let severity = if share >= NETFAIL_CRIT_SHARE && failed >= NETFAIL_CRIT_MIN && class != "aborted" {
                Severity::Critical
            } else if class == "aborted" {
                Severity::Info
            } else {
                Severity::Warning
            };
            let durations: Vec<f64> = v.iter().filter(|s| s.duration_ms.is_some() || s.timers.client_done_response.is_some()).map(|s| ms(s)).collect();
            let messages = top(v.iter().filter_map(|s| s.error.as_deref()).map(|e| util::short(e.trim(), 80)));
            let tunnels = v.iter().filter(|s| s.kind == Kind::Tunnel).count();
            let (hyp, rec) = class_hint(ctx, class);
            let label = class_label(ctx, class);
            let mut f = Finding::new(
                "NET-FAIL",
                &format!("{h}|{class}"),
                severity,
                format!("{} ({}): {}", ctx.l("Connection failures", "Verbindungsfehler"), label, util::short(&h, 80)),
                if ctx.de() {
                    format!("{} Request(s) an {} erhielten keine Antwort ({}); insgesamt scheiterten {} von {} Requests an diesen Host ({}).", ctx.fmt_count(n), h, label, ctx.fmt_count(failed), ctx.fmt_count(all), ctx.fmt_pct(share))
                } else {
                    format!("{} request(s) to {} got no response ({}); in total {} of {} requests to this host failed ({}).", ctx.fmt_count(n), h, label, ctx.fmt_count(failed), ctx.fmt_count(all), ctx.fmt_pct(share))
                },
            )
            .categories(&["errors", "network"])
            .score(util::scale(n as f64, 0.0, 50.0) * 0.5 + share.min(1.0) * 50.0)
            .threshold(if ctx.de() {
                format!("kritisch ab {} der Requests eines Hosts (mind. {})", ctx.fmt_pct(NETFAIL_CRIT_SHARE), ctx.fmt_count(NETFAIL_CRIT_MIN))
            } else {
                format!("critical from {} of a host's requests (at least {})", ctx.fmt_pct(NETFAIL_CRIT_SHARE), ctx.fmt_count(NETFAIL_CRIT_MIN))
            })
            .fact(ctx.l("Error class", "Fehlerklasse"), label)
            .fact(ctx.l("Failed (this class)", "Fehlgeschlagen (diese Klasse)"), ctx.fmt_count(n))
            .fact(ctx.l("Requests to the host", "Requests an den Host"), ctx.fmt_count(all))
            .fact(ctx.l("Failed share of the host (all classes)", "Fehleranteil des Hosts (alle Klassen)"), ctx.fmt_pct(share))
            .impact(ctx.l("The affected actions fail or wait for retries; on unstable networks this gets worse.", "Die betroffenen Aktionen scheitern oder warten auf Wiederholungen; in instabilen Netzen verschärft sich das."))
            .hypothesis(hyp)
            .recommend(rec)
            .sessions(v.iter().map(|s| s.id));
            if !durations.is_empty() {
                f = f.fact(ctx.l("Median time until failure", "Median Zeit bis zum Abbruch"), ctx.fmt_ms(util::percentile(&durations, 50.0)));
            }
            if !messages.is_empty() {
                f = f.fact(ctx.l("Error messages", "Fehlermeldungen"), list_top(ctx, &messages, 3));
            } else {
                f = f.confidence(Confidence::Medium);
            }
            if tunnels > 0 {
                f = f.fact(ctx.l("Of which tunnels (CONNECT)", "Davon Tunnel (CONNECT)"), ctx.fmt_count(tunnels));
            }
            list.push(f.next_step(ctx.l("Check whether the failures cluster in time (outage) or are spread (instability).", "Prüfen, ob sich die Fehler zeitlich häufen (Ausfall) oder verteilt auftreten (Instabilität).")));
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ AUTH-FAIL

/// A 401/407 answered by a success on the same request within this time is a normal challenge.
const AUTH_RETRY_WINDOW_US: u64 = 5_000_000;
/// Answered challenges per host from this count are reported (info).
const AUTH_CHALLENGE_INFO_MIN: usize = 10;
/// Unanswered 401/407 per endpoint from this count are an authentication loop (critical).
const AUTH_LOOP_MIN: usize = 3;

/// Schemes offered by the server (WWW-/Proxy-Authenticate).
fn offered_schemes(s: &Session) -> Vec<String> {
    s.resp_headers("www-authenticate").chain(s.resp_headers("proxy-authenticate")).map(util::auth_scheme).filter(|x| !x.is_empty()).collect()
}

/// Scheme the client sent (Authorization / Proxy-Authorization).
fn sent_scheme(s: &Session) -> Option<String> {
    s.req_header("authorization").or_else(|| s.req_header("proxy-authorization")).map(util::auth_scheme).filter(|x| !x.is_empty())
}

fn is_challenge(s: &Session) -> bool {
    matches!(s.status, 401 | 407)
}

/// AUTH-FAIL: 401/407/403 per endpoint; challenges answered successfully are normal.
struct AuthFailures;

impl Analyzer for AuthFailures {
    fn id(&self) -> &'static str {
        "AUTH-FAIL"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["auth", "troubleshooting"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let ss = ctx.sessions;
        let mut by_request: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, s) in ss.iter().enumerate().filter(|(_, s)| s.is_http()) {
            by_request.entry(canon::canonical(&s.method, &s.url, None)).or_default().push(i);
        }
        let mut requests_per_host: HashMap<String, usize> = HashMap::new();
        for s in ctx.http() {
            *requests_per_host.entry(host(s)).or_default() += 1;
        }
        // Classify every 401/407: answered (a success follows within the window, possibly
        // after further challenge legs as in NTLM) or not.
        let mut answered = vec![];
        let mut unanswered = vec![];
        for (i, s) in ss.iter().enumerate().filter(|(_, s)| s.is_http() && is_challenge(s)) {
            let list = &by_request[&canon::canonical(&s.method, &s.url, None)];
            let pos = list.binary_search(&i).unwrap_or(0);
            let mut prev_end = s.end();
            let mut ok = false;
            for &j in &list[pos + 1..] {
                let t = &ss[j];
                if t.started > prev_end + AUTH_RETRY_WINDOW_US {
                    break;
                }
                if (200..400).contains(&t.status) {
                    ok = true;
                    break;
                }
                prev_end = prev_end.max(t.end());
            }
            if ok { answered.push(s) } else { unanswered.push(s) }
        }
        let mut list = vec![];
        let schemes_fact = |f: Finding, v: &[&Session]| {
            let offered = top(v.iter().flat_map(|s| offered_schemes(s)));
            let sent = top(v.iter().map(|s| sent_scheme(s).unwrap_or_else(|| ctx.l("none", "keine").to_string())));
            let mut f = f.fact(ctx.l("Client sent", "Client sendete"), list_top(ctx, &sent, 4));
            if !offered.is_empty() {
                f = f.fact(ctx.l("Schemes offered by the server", "Vom Server angebotene Verfahren"), list_top(ctx, &offered, 4));
            }
            f
        };
        // Normal challenges: only when frequent.
        for (h, v) in util::group_by(answered, |s| host(s)) {
            if v.len() < AUTH_CHALLENGE_INFO_MIN {
                continue;
            }
            let all = requests_per_host.get(&h).copied().unwrap_or(v.len());
            let (cols, rows) = rtt_table(ctx, v.len() as f64);
            let f = Finding::new(
                "AUTH-FAIL",
                &format!("challenge|{h}"),
                Severity::Info,
                format!("{} {}", ctx.l("Frequent authentication challenges:", "Häufige Anmelde-Challenges:"), util::short(&h, 80)),
                if ctx.de() {
                    format!("{} Request(s) an {} wurden zunächst mit 401/407 beantwortet und danach erfolgreich wiederholt ({} aller Requests).", ctx.fmt_count(v.len()), h, ctx.fmt_pct(ratio(v.len(), all)))
                } else {
                    format!("{} request(s) to {} were first answered with 401/407 and then repeated successfully ({} of all requests).", ctx.fmt_count(v.len()), h, ctx.fmt_pct(ratio(v.len(), all)))
                },
            )
            .categories(&["auth", "latency"])
            .score(util::scale(v.len() as f64, AUTH_CHALLENGE_INFO_MIN as f64, 500.0))
            .threshold(format!("≥ {}", ctx.fmt_count(AUTH_CHALLENGE_INFO_MIN)))
            .impact(ctx.l("Each challenge is a normal handshake, but costs an extra round trip.", "Jede Challenge ist ein normaler Handshake, kostet aber einen zusätzlichen Roundtrip."))
            .hypothesis(ctx.l("The client sends credentials only after being challenged (no pre-authentication), or authentication is not kept per connection.", "Der Client sendet Anmeldedaten erst nach der Aufforderung (keine Vorab-Anmeldung), oder die Anmeldung wird nicht pro Verbindung gehalten."))
            .recommend(ctx.l("Send credentials pre-emptively where possible and reuse authenticated connections (see AUTH-REPEAT).", "Anmeldedaten nach Möglichkeit vorab senden und angemeldete Verbindungen wiederverwenden (siehe AUTH-REPEAT)."))
            .estimate()
            .table(cols, rows)
            .sessions(v.iter().map(|s| s.id));
            list.push(schemes_fact(f, &v));
        }
        // Challenges never followed by success.
        for (ep, v) in util::group_by(unanswered, |s| endpoint(s)) {
            let n = v.len();
            let severity = if n >= AUTH_LOOP_MIN { Severity::Critical } else { Severity::Warning };
            let proxy = v.iter().all(|s| s.status == 407);
            let sent: Vec<String> = v.iter().filter_map(|s| sent_scheme(s)).collect();
            let has = |x: &str| sent.iter().any(|s| s.eq_ignore_ascii_case(x));
            let mut f = Finding::new(
                "AUTH-FAIL",
                &format!("unauthorized|{ep}"),
                severity,
                if n >= AUTH_LOOP_MIN {
                    format!("{} {}", ctx.l("Authentication loop/failure:", "Anmeldeschleife/-fehler:"), util::short(&ep, 80))
                } else {
                    format!("{} {}", ctx.l("Authentication failed:", "Anmeldung fehlgeschlagen:"), util::short(&ep, 80))
                },
                if ctx.de() {
                    format!("{} Request(s) an {} wurden mit {} abgewiesen, ohne dass innerhalb von {} ein erfolgreicher Versuch folgte.", ctx.fmt_count(n), ep, if proxy { "407" } else { "401" }, ctx.fmt_ms(AUTH_RETRY_WINDOW_US as f64 / 1000.0))
                } else {
                    format!("{} request(s) to {} were rejected with {} and no successful attempt followed within {}.", ctx.fmt_count(n), ep, if proxy { "407" } else { "401" }, ctx.fmt_ms(AUTH_RETRY_WINDOW_US as f64 / 1000.0))
                },
            )
            .categories(&["auth", "errors"])
            .score(util::scale(n as f64, 0.0, 30.0))
            .threshold(if ctx.de() { format!("kritisch ab {} ohne späteren Erfolg", ctx.fmt_count(AUTH_LOOP_MIN)) } else { format!("critical from {} without later success", ctx.fmt_count(AUTH_LOOP_MIN)) })
            .impact(ctx.l("The user's action fails; repeated failed logins can lock the account.", "Die Aktion des Benutzers scheitert; wiederholte fehlgeschlagene Anmeldungen können das Konto sperren."))
            .sessions(v.iter().map(|s| s.id));
            if proxy {
                f = f.hypothesis(ctx.l("The proxy requires authentication the client does not provide.", "Der Proxy verlangt eine Anmeldung, die der Client nicht liefert."));
            }
            if sent.is_empty() {
                f = f.hypothesis(ctx.l("The client sent no credentials at all (not configured, or stripped by a proxy).", "Der Client sendete überhaupt keine Anmeldedaten (nicht konfiguriert oder von einem Proxy entfernt)."));
            }
            if has("Bearer") {
                f = f.hypothesis(ctx.l("The token is rejected: expired, wrong audience or scope, or clock skew.", "Das Token wird abgelehnt: abgelaufen, falsche Audience oder Scope, oder Uhrzeitabweichung."));
                if v.iter().any(|s| s.resp_headers("www-authenticate").any(|w| w.to_ascii_lowercase().contains("error"))) {
                    f = f.hypothesis(ctx.l("The server names an error in WWW-Authenticate (value redacted in the capture).", "Der Server nennt in WWW-Authenticate einen Fehler (Wert in der Aufzeichnung geschwärzt)."));
                }
            }
            if has("NTLM") || has("Negotiate") {
                f = f.hypothesis(ctx.l(
                    "The Windows authentication handshake does not complete: Kerberos (SPN, delegation), NTLM blocked by policy, or a proxy/load balancer that does not keep the connection (NTLM is bound to the connection).",
                    "Der Windows-Anmelde-Handshake wird nicht abgeschlossen: Kerberos (SPN, Delegierung), NTLM per Richtlinie gesperrt, oder ein Proxy/Load Balancer hält die Verbindung nicht (NTLM ist an die Verbindung gebunden).",
                ));
            }
            if has("Basic") {
                f = f.hypothesis(ctx.l("The user name or password is wrong.", "Benutzername oder Passwort sind falsch."));
            }
            f = schemes_fact(f, &v);
            if n >= AUTH_LOOP_MIN {
                f = f.recommend(ctx.l("Stop the client from retrying rejected credentials in a loop.", "Verhindern, dass der Client abgewiesene Anmeldedaten in einer Schleife erneut sendet."));
            }
            list.push(
                f.recommend(ctx.l("Check the credentials or token (lifetime, audience, scope) and the authentication configuration of the server.", "Anmeldedaten bzw. Token (Laufzeit, Audience, Scope) und die Anmeldekonfiguration des Servers prüfen."))
                    .next_step(ctx.l("Look up the rejected requests in the server's security log.", "Die abgewiesenen Requests im Sicherheitsprotokoll des Servers nachschlagen.")),
            );
        }
        // 403: authenticated but not allowed.
        for (ep, v) in util::group_by(ctx.http().filter(|s| s.status == 403), |s| endpoint(s)) {
            let n = v.len();
            let f = Finding::new(
                "AUTH-FAIL",
                &format!("forbidden|{ep}"),
                Severity::Warning,
                format!("{} {}", ctx.l("Access denied (403):", "Zugriff verweigert (403):"), util::short(&ep, 80)),
                if ctx.de() { format!("{} Request(s) an {} wurden mit 403 Forbidden abgewiesen.", ctx.fmt_count(n), ep) } else { format!("{} request(s) to {} were rejected with 403 Forbidden.", ctx.fmt_count(n), ep) },
            )
            .categories(&["auth", "errors"])
            .score(util::scale(n as f64, 0.0, 30.0))
            .threshold("403")
            .impact(ctx.l("The action fails although the client is (possibly) signed in.", "Die Aktion scheitert, obwohl der Client (möglicherweise) angemeldet ist."))
            .hypothesis(ctx.l("The identity is known but lacks the permission (role, scope, group membership).", "Die Identität ist bekannt, hat aber nicht die Berechtigung (Rolle, Scope, Gruppenmitgliedschaft)."))
            .hypothesis(ctx.l("A firewall, WAF or CSRF protection blocks the request.", "Eine Firewall, WAF oder ein CSRF-Schutz blockiert den Request."))
            .recommend(ctx.l("Check the permissions of the identity and the token scopes; read the error body.", "Berechtigungen der Identität und die Scopes des Tokens prüfen; den Fehler-Body lesen."))
            .sessions(v.iter().map(|s| s.id));
            list.push(schemes_fact(f, &v));
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ AUTH-REPEAT

/// Windows handshakes per host from this count are reported …
const HANDSHAKE_MIN: usize = 5;
/// … when they are at least this share of the host's requests.
const HANDSHAKE_SHARE_INFO: f64 = 0.2;
/// Warning from this count and share.
const HANDSHAKE_WARN_MIN: usize = 10;
const HANDSHAKE_SHARE_WARN: f64 = 0.5;
/// Negotiate tokens at most this large are unlikely to be Kerberos tickets.
const NEGOTIATE_NTLM_MAX_BYTES: u64 = 1000;
/// Token requests of one endpoint within this window …
const TOKEN_WINDOW_US: u64 = 300_000_000;
/// … from this count: the token is not cached.
const TOKEN_MIN: usize = 3;

fn windows_scheme(s: &Session) -> Option<String> {
    sent_scheme(s).filter(|x| x.eq_ignore_ascii_case("NTLM") || x.eq_ignore_ascii_case("Negotiate"))
}

fn is_token_request(s: &Session) -> bool {
    let p = canon::parse(&s.url).path.to_ascii_lowercase();
    s.method.eq_ignore_ascii_case("POST") && (p.contains("/token") || p.contains("/oauth2") || p.contains("/connect/token"))
}

/// AUTH-REPEAT: repeated authentication (Windows handshakes, token acquisition).
struct AuthRepeat;

impl Analyzer for AuthRepeat {
    fn id(&self) -> &'static str {
        "AUTH-REPEAT"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["auth", "performance", "resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let mut list = vec![];
        for (h, v) in util::group_by(ctx.http(), |s| host(s)) {
            let legs: Vec<&Session> = v.iter().copied().filter(|s| windows_scheme(s).is_some()).collect();
            // A completed handshake: the leg that is not answered with another challenge.
            let done: Vec<&Session> = legs.iter().copied().filter(|s| !is_challenge(s)).collect();
            let n = v.len();
            let share = ratio(done.len(), n);
            if done.len() < HANDSHAKE_MIN || share < HANDSHAKE_SHARE_INFO {
                continue;
            }
            let challenges = v.iter().filter(|s| is_challenge(s) && offered_schemes(s).iter().any(|x| x.eq_ignore_ascii_case("NTLM") || x.eq_ignore_ascii_case("Negotiate"))).count();
            let on_new = done.iter().filter(|s| s.new_connection()).count();
            let conn_known = v.iter().any(|s| s.server_connection_reused || s.timers.server_connect_start.is_some());
            let close = v.iter().filter(|s| header_has(s.resp_header("connection"), "close") || header_has(s.req_header("connection"), "close")).count();
            let schemes = top(legs.iter().filter_map(|s| windows_scheme(s)));
            let ntlm = schemes.iter().any(|(x, _)| x.eq_ignore_ascii_case("NTLM"));
            let neg_sizes: Vec<u64> =
                legs.iter().filter(|s| windows_scheme(s).is_some_and(|x| x.eq_ignore_ascii_case("Negotiate"))).filter_map(|s| s.req_header("authorization").and_then(util::redacted_bytes)).collect();
            let severity = if done.len() >= HANDSHAKE_WARN_MIN && share >= HANDSHAKE_SHARE_WARN { Severity::Warning } else { Severity::Info };
            let (cols, rows) = rtt_table(ctx, challenges as f64);
            let mut f = Finding::new(
                "AUTH-REPEAT",
                &format!("handshake|{h}"),
                severity,
                format!("{} {}", ctx.l("Repeated Windows authentication:", "Wiederholte Windows-Anmeldung:"), util::short(&h, 80)),
                if ctx.de() {
                    format!("{} von {} Requests an {} führten eine NTLM-/Negotiate-Anmeldung durch ({}); dazu kamen {} Challenge-Antworten (401/407).", ctx.fmt_count(done.len()), ctx.fmt_count(n), h, ctx.fmt_pct(share), ctx.fmt_count(challenges))
                } else {
                    format!("{} of {} requests to {} performed an NTLM/Negotiate authentication ({}), plus {} challenge responses (401/407).", ctx.fmt_count(done.len()), ctx.fmt_count(n), h, ctx.fmt_pct(share), ctx.fmt_count(challenges))
                },
            )
            .categories(&["auth", "latency"])
            .score(util::scale(done.len() as f64, HANDSHAKE_MIN as f64, 500.0) * 0.5 + share * 50.0)
            .threshold(if ctx.de() {
                format!("≥ {} Handshakes und ≥ {} der Requests (Warnung ab {} und {})", HANDSHAKE_MIN, ctx.fmt_pct(HANDSHAKE_SHARE_INFO), HANDSHAKE_WARN_MIN, ctx.fmt_pct(HANDSHAKE_SHARE_WARN))
            } else {
                format!("≥ {} handshakes and ≥ {} of requests (warning from {} and {})", HANDSHAKE_MIN, ctx.fmt_pct(HANDSHAKE_SHARE_INFO), HANDSHAKE_WARN_MIN, ctx.fmt_pct(HANDSHAKE_SHARE_WARN))
            })
            .fact(ctx.l("Requests", "Requests"), ctx.fmt_count(n))
            .fact(ctx.l("Handshakes", "Handshakes"), ctx.fmt_count(done.len()))
            .fact(ctx.l("Challenges (401/407)", "Challenges (401/407)"), ctx.fmt_count(challenges))
            .fact(ctx.l("Schemes", "Verfahren"), list_top(ctx, &schemes, 3))
            .impact(ctx.l(
                "Every handshake costs one or two extra round trips and load on the domain controller; on high-latency links this adds up.",
                "Jeder Handshake kostet ein bis zwei zusätzliche Roundtrips und belastet den Domänencontroller; bei hoher Latenz summiert sich das.",
            ))
            .estimate()
            .table(cols, rows)
            .sessions(legs.iter().map(|s| s.id))
            .sessions(v.iter().filter(|s| is_challenge(s)).map(|s| s.id));
            if conn_known {
                f = f.fact(ctx.l("Handshakes on new connections", "Handshakes auf neuen Verbindungen"), format!("{} / {}", ctx.fmt_count(on_new), ctx.fmt_count(done.len())));
                if on_new * 2 >= done.len() {
                    f = f.hypothesis(ctx.l(
                        "Connections are not reused, so the client has to authenticate again on every new connection.",
                        "Verbindungen werden nicht wiederverwendet, daher muss sich der Client auf jeder neuen Verbindung erneut anmelden.",
                    ));
                } else {
                    f = f.hypothesis(ctx.l(
                        "The client authenticates again although the connection is reused (authentication not kept per connection, or per-request authentication on the server).",
                        "Der Client meldet sich erneut an, obwohl die Verbindung wiederverwendet wird (Anmeldung nicht pro Verbindung gehalten oder Anmeldung pro Request auf dem Server).",
                    ));
                }
            } else {
                f = f.confidence(Confidence::Medium);
            }
            if close > 0 {
                f = f.fact(ctx.l("Connection: close", "Connection: close"), ctx.fmt_count(close));
            }
            if ntlm {
                f = f.recommend(ctx.l("Prefer Kerberos over NTLM (correct SPN, Negotiate without NTLM fallback).", "Kerberos statt NTLM verwenden (korrekter SPN, Negotiate ohne NTLM-Fallback)."));
            } else if !neg_sizes.is_empty() && neg_sizes.iter().all(|&b| b <= NEGOTIATE_NTLM_MAX_BYTES) {
                f = f.hypothesis(if ctx.de() {
                    format!("Die Negotiate-Tokens sind höchstens {} groß – vermutlich steckt NTLM darin (Kerberos-Fallback).", ctx.fmt_bytes(NEGOTIATE_NTLM_MAX_BYTES as f64))
                } else {
                    format!("The Negotiate tokens are at most {} – probably NTLM inside (Kerberos fallback).", ctx.fmt_bytes(NEGOTIATE_NTLM_MAX_BYTES as f64))
                });
            }
            list.push(
                f.recommend(ctx.l("Keep authenticated connections open and reuse them (keep-alive, connection pooling).", "Angemeldete Verbindungen offen halten und wiederverwenden (Keep-alive, Connection-Pooling)."))
                    .recommend(ctx.l("For APIs, consider token-based authentication that does not need a handshake per connection.", "Für APIs eine tokenbasierte Anmeldung erwägen, die keinen Handshake pro Verbindung braucht."))
                    .next_step(ctx.l("Filter the sessions by the Authorization header and compare the connection ids.", "Die Sessions nach dem Authorization-Header filtern und die Verbindungs-IDs vergleichen.")),
            );
        }
        // Token acquisition that is not cached.
        for (ep, v) in util::group_by(ctx.http().filter(|s| is_token_request(s)), |s| endpoint(s)) {
            let times: Vec<u64> = v.iter().map(|s| s.started).collect();
            let peak = util::max_in_window(&times, TOKEN_WINDOW_US);
            if peak < TOKEN_MIN {
                continue;
            }
            let hashes = top(v.iter().filter_map(|s| s.request_body_hash).map(|h| format!("{h:016x}")));
            let identical = hashes.first().map(|x| x.1).unwrap_or(0);
            let span_ms = (times.last().unwrap_or(&0) - times.first().unwrap_or(&0)) as f64 / 1000.0;
            let severity = if identical >= TOKEN_MIN || hashes.is_empty() { Severity::Warning } else { Severity::Info };
            let mut f = Finding::new(
                "AUTH-REPEAT",
                &format!("token|{ep}"),
                severity,
                format!("{} {}", ctx.l("Token requested repeatedly:", "Token wiederholt angefordert:"), util::short(&ep, 80)),
                if ctx.de() {
                    format!("{} Token-Anforderung(en) an {}, davon bis zu {} innerhalb von 5 Minuten.", ctx.fmt_count(v.len()), ep, ctx.fmt_count(peak))
                } else {
                    format!("{} token request(s) to {}, up to {} within 5 minutes.", ctx.fmt_count(v.len()), ep, ctx.fmt_count(peak))
                },
            )
            .categories(&["auth", "performance"])
            .score(util::scale(peak as f64, TOKEN_MIN as f64, 100.0))
            .threshold(format!("≥ {} in 5 min", TOKEN_MIN))
            .fact(ctx.l("Token requests", "Token-Anforderungen"), ctx.fmt_count(v.len()))
            .fact(ctx.l("Most within 5 minutes", "Höchstens innerhalb von 5 Minuten"), ctx.fmt_count(peak))
            .fact(ctx.l("Time span", "Zeitraum"), ctx.fmt_ms(span_ms))
            .impact(ctx.l("Every token request adds latency (often several round trips to the identity provider) and load there.", "Jede Token-Anforderung kostet Latenz (oft mehrere Roundtrips zum Identity Provider) und erzeugt dort Last."))
            .recommend(ctx.l("Cache the token until shortly before it expires (expires_in) and share the cache between components.", "Das Token bis kurz vor Ablauf (expires_in) cachen und den Cache zwischen Komponenten teilen."))
            .next_step(ctx.l("Compare the token lifetime with the interval between the requests.", "Die Laufzeit des Tokens mit dem Abstand zwischen den Anforderungen vergleichen."))
            .sessions(v.iter().map(|s| s.id));
            if identical >= 2 {
                f = f.fact(ctx.l("Identical requests (same body)", "Identische Anforderungen (gleicher Body)"), ctx.fmt_count(identical)).hypothesis(ctx.l(
                    "The same token request is repeated: the token is not cached (a new client instance per call, or the cache is bypassed).",
                    "Dieselbe Token-Anforderung wird wiederholt: Das Token wird nicht gecacht (neue Client-Instanz pro Aufruf oder der Cache wird umgangen).",
                ));
            } else if !hashes.is_empty() {
                f = f.hypothesis(ctx.l(
                    "The token requests differ (different scopes or refresh tokens); one token per resource may be expected, repeated refreshes are not.",
                    "Die Token-Anforderungen unterscheiden sich (verschiedene Scopes oder Refresh-Tokens); ein Token pro Ressource ist erwartbar, wiederholte Erneuerungen nicht.",
                ));
            } else {
                f = f.confidence(Confidence::Medium);
            }
            list.push(f);
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ REDIRECT

/// The next hop of a redirect must start within this time after it ended.
const REDIRECT_FOLLOW_US: u64 = 10_000_000;
/// Chains with at least this many redirects are a warning.
const REDIRECT_CHAIN_MIN: usize = 3;
/// HTTP→HTTPS redirects per host from this count are reported.
const REDIRECT_HTTPS_MIN: usize = 3;
/// Safety bound when following chains.
const REDIRECT_MAX_HOPS: usize = 30;

fn redirect_target(s: &Session) -> Option<String> {
    if !s.is_http() || !(300..400).contains(&s.status) || s.status == 304 {
        return None;
    }
    let loc = s.resp_header("location")?.trim();
    (!loc.is_empty()).then(|| canon::resolve(&s.url, loc))
}

fn url_key(url: &str) -> String {
    canon::canonical("GET", url, None)
}

fn bare_host(h: &str) -> &str {
    h.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map(|(h, _)| h).unwrap_or(h)
}

/// REDIRECT: redirect chains, loops and HTTP→HTTPS redirects.
struct Redirects;

impl Analyzer for Redirects {
    fn id(&self) -> &'static str {
        "REDIRECT"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["troubleshooting", "performance"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let ss = ctx.sessions;
        let targets: Vec<Option<String>> = ss.iter().map(redirect_target).collect();
        if targets.iter().all(|t| t.is_none()) {
            return;
        }
        let mut by_url: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, s) in ss.iter().enumerate().filter(|(_, s)| s.is_http()) {
            by_url.entry(url_key(&s.url)).or_default().push(i);
        }
        // Next hop: the first later session requesting the resolved Location in time.
        let mut next: Vec<Option<usize>> = vec![None; ss.len()];
        let mut has_pred = vec![false; ss.len()];
        for (i, t) in targets.iter().enumerate() {
            let Some(t) = t else { continue };
            let Some(cands) = by_url.get(&url_key(t)) else { continue };
            let deadline = ss[i].end() + REDIRECT_FOLLOW_US;
            let start = cands.partition_point(|&j| j <= i);
            if let Some(&j) = cands[start..].iter().find(|&&j| ss[j].started >= ss[i].started)
                && ss[j].started <= deadline
            {
                next[i] = Some(j);
                has_pred[j] = true;
            }
        }
        struct Chain {
            hops: Vec<usize>,
            redirects: usize,
            looped: bool,
        }
        let mut chains = vec![];
        for i in (0..ss.len()).filter(|&i| targets[i].is_some() && !has_pred[i]) {
            let mut hops = vec![i];
            let mut seen: HashSet<String> = HashSet::from([url_key(&ss[i].url)]);
            let mut looped = false;
            let mut cur = i;
            while let Some(j) = next[cur] {
                hops.push(j);
                if !seen.insert(url_key(&ss[j].url)) {
                    looped = true;
                    break;
                }
                if targets[j].is_none() || hops.len() > REDIRECT_MAX_HOPS {
                    break;
                }
                cur = j;
            }
            let redirects = hops.iter().filter(|&&k| targets[k].is_some()).count();
            chains.push(Chain { hops, redirects, looped });
        }
        let mut list = vec![];
        let long = chains.into_iter().filter(|c| c.looped || c.redirects >= REDIRECT_CHAIN_MIN);
        for ((looped, first), v) in util::group_by(long, |c| (c.looped, endpoint(&ss[c.hops[0]]))) {
            let example = &v[0];
            let hops = v.iter().map(|c| c.redirects).max().unwrap_or(0);
            let total: Vec<f64> = v.iter().map(|c| (ss[*c.hops.last().unwrap_or(&c.hops[0])].end().saturating_sub(ss[c.hops[0]].started)) as f64 / 1000.0).collect();
            let rows: Vec<Vec<String>> = example.hops.iter().enumerate().map(|(k, &j)| vec![(k + 1).to_string(), ss[j].status.to_string(), util::short(&ss[j].url, 100)]).collect();
            let (severity, title, subject) = if looped {
                (Severity::Critical, ctx.l("Redirect loop:", "Weiterleitungsschleife:"), format!("loop|{first}"))
            } else {
                (Severity::Warning, ctx.l("Long redirect chain:", "Lange Weiterleitungskette:"), format!("chain|{first}"))
            };
            let mut f = Finding::new(
                "REDIRECT",
                &subject,
                severity,
                format!("{title} {}", util::short(&first, 80)),
                if looped {
                    if ctx.de() {
                        format!("{} Weiterleitungskette(n) ab {} führten zu einer bereits besuchten URL zurück.", ctx.fmt_count(v.len()), first)
                    } else {
                        format!("{} redirect chain(s) starting at {} led back to a URL already visited.", ctx.fmt_count(v.len()), first)
                    }
                } else if ctx.de() {
                    format!("{} Weiterleitungskette(n) ab {} mit bis zu {} Weiterleitungen (Median Gesamtdauer {}).", ctx.fmt_count(v.len()), first, hops, ctx.fmt_ms(util::percentile(&total, 50.0)))
                } else {
                    format!("{} redirect chain(s) starting at {} with up to {} redirects (median total time {}).", ctx.fmt_count(v.len()), first, hops, ctx.fmt_ms(util::percentile(&total, 50.0)))
                },
            )
            .categories(&["latency", "redirects"])
            .score(util::scale((hops * v.len()) as f64, REDIRECT_CHAIN_MIN as f64, 100.0) + if looped { 30.0 } else { 0.0 })
            .threshold(if ctx.de() { format!("≥ {} Weiterleitungen; Schleife: kritisch", REDIRECT_CHAIN_MIN) } else { format!("≥ {} redirects; loop: critical", REDIRECT_CHAIN_MIN) })
            .fact(ctx.l("Chains", "Ketten"), ctx.fmt_count(v.len()))
            .fact(ctx.l("Redirects (longest chain)", "Weiterleitungen (längste Kette)"), ctx.fmt_count(hops))
            .table(vec![ctx.l("Hop", "Schritt").into(), ctx.l("Status", "Status").into(), "URL".into()], rows)
            .sessions(v.iter().flat_map(|c| c.hops.iter().map(|&j| ss[j].id)));
            f = if looped {
                f.impact(ctx.l("The client never reaches the content; browsers abort after about 20 redirects.", "Der Client erreicht den Inhalt nie; Browser brechen nach etwa 20 Weiterleitungen ab."))
                    .hypothesis(ctx.l(
                        "Typical causes: a login that does not set its cookie (blocked, wrong domain or path), or conflicting rewrite rules (HTTP/HTTPS, trailing slash, host name).",
                        "Typische Ursachen: eine Anmeldung, die ihr Cookie nicht setzt (blockiert, falsche Domain oder falscher Pfad), oder widersprüchliche Umschreiberegeln (HTTP/HTTPS, abschließender Schrägstrich, Hostname).",
                    ))
                    .recommend(ctx.l("Follow the example chain and fix the rule or the missing cookie that sends the client back.", "Der Beispielkette folgen und die Regel oder das fehlende Cookie beheben, das den Client zurückschickt."))
            } else {
                let (cols, rows) = rtt_table(ctx, hops as f64);
                f.impact(ctx.l("Every redirect costs a full round trip (often a new connection) before the content loads.", "Jede Weiterleitung kostet einen vollen Roundtrip (oft eine neue Verbindung), bevor der Inhalt lädt."))
                    .hypothesis(ctx.l("Configured URLs are outdated, or several layers (proxy, application, login) redirect one after another.", "Konfigurierte URLs sind veraltet, oder mehrere Schichten (Proxy, Anwendung, Anmeldung) leiten nacheinander weiter."))
                    .recommend(ctx.l("Link directly to the final URL and merge redirect rules into a single hop.", "Direkt auf die endgültige URL verweisen und Weiterleitungsregeln zu einem einzigen Schritt zusammenfassen."))
                    .estimate()
                    .table(cols, rows)
            };
            if ss[example.hops[0]].timers.client_done_response.is_none() {
                f = f.confidence(Confidence::Medium);
            }
            list.push(f);
        }
        // HTTP → HTTPS on the same host, repeatedly.
        let upgrades = (0..ss.len()).filter(|&i| {
            targets[i].as_ref().is_some_and(|t| {
                let (a, b) = (canon::parse(&ss[i].url), canon::parse(t));
                a.scheme == "http" && b.scheme == "https" && bare_host(&a.host) == bare_host(&b.host)
            })
        });
        for (h, v) in util::group_by(upgrades, |&i| bare_host(&host(&ss[i])).to_string()) {
            if v.len() < REDIRECT_HTTPS_MIN {
                continue;
            }
            let hsts = ctx.http().any(|s| s.is_https() && bare_host(&host(s)) == h && s.resp_header("strict-transport-security").is_some());
            let (cols, rows) = rtt_table(ctx, v.len() as f64);
            let mut f = Finding::new(
                "REDIRECT",
                &format!("https|{h}"),
                Severity::Info,
                format!("{} {}", ctx.l("Repeated HTTP→HTTPS redirects:", "Wiederholte HTTP→HTTPS-Weiterleitungen:"), util::short(&h, 80)),
                if ctx.de() {
                    format!("{} Request(s) an http://{} wurden auf HTTPS umgeleitet.", ctx.fmt_count(v.len()), h)
                } else {
                    format!("{} request(s) to http://{} were redirected to HTTPS.", ctx.fmt_count(v.len()), h)
                },
            )
            .categories(&["latency", "redirects", "security"])
            .score(util::scale(v.len() as f64, REDIRECT_HTTPS_MIN as f64, 200.0))
            .threshold(format!("≥ {}", REDIRECT_HTTPS_MIN))
            .impact(ctx.l("Each detour costs a round trip and sends the first request unencrypted.", "Jeder Umweg kostet einen Roundtrip und sendet den ersten Request unverschlüsselt."))
            .fact(ctx.l("HSTS header seen", "HSTS-Header gesehen"), if hsts { ctx.l("yes", "ja") } else { ctx.l("no", "nein") })
            .recommend(ctx.l("Use https:// URLs in the client configuration and links.", "In der Client-Konfiguration und in Links https://-URLs verwenden."))
            .estimate()
            .table(cols, rows)
            .sessions(v.iter().map(|&i| ss[i].id));
            f = if hsts {
                f.hypothesis(ctx.l("The server sends HSTS, but the client ignores it (non-browser clients usually do).", "Der Server sendet HSTS, aber der Client beachtet es nicht (Nicht-Browser-Clients meist nicht)."))
            } else {
                f.hypothesis(ctx.l("HSTS is missing, so clients keep trying HTTP first.", "HSTS fehlt, daher versuchen Clients es weiterhin zuerst mit HTTP."))
                    .recommend(ctx.l("Send Strict-Transport-Security on HTTPS responses.", "Strict-Transport-Security in HTTPS-Responses senden."))
            };
            list.push(f);
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ COOKIE

/// A Cookie header with at least this many names is very large.
const COOKIE_NAMES_MAX: usize = 30;
/// Sum of the (latest) cookie value sizes per host from which cookies are very large.
const COOKIE_BYTES_MAX: u64 = 4096;
/// The same cookie set this often per host is repeated.
const COOKIE_REPEAT_MIN: usize = 10;

fn session_like(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("sid") || n.contains("session") || n.contains("auth") || n.contains("token") || n.contains("jwt")
}

fn cookie_names(s: &Session) -> Vec<String> {
    s.req_header("cookie").map(|c| c.split(';').map(|x| x.split('=').next().unwrap_or("").trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default()
}

/// COOKIE: cookie attributes, size and churn from `Set-Cookie` (redacted).
struct Cookies;

impl Analyzer for Cookies {
    fn id(&self) -> &'static str {
        "COOKIE"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["troubleshooting", "auth"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let mut list = vec![];
        for (h, v) in util::group_by(ctx.http(), |s| host(s)) {
            let sets: Vec<(&Session, util::SetCookie)> = v.iter().flat_map(|s| s.resp_headers("set-cookie").map(move |c| (*s, util::set_cookie(c)))).filter(|(_, c)| !c.name.is_empty()).collect();
            let finding = |kind: &str, severity: Severity, title: &str, obs: String, items: &[&(&Session, util::SetCookie)]| {
                Finding::new("COOKIE", &format!("{kind}|{h}"), severity, format!("{title} {}", util::short(&h, 80)), obs)
                    .categories(&["cookies"])
                    .fact(ctx.l("Cookies", "Cookies"), list_names(items.iter().map(|(_, c)| c.name.as_str()), 10))
                    .fact(ctx.l("Responses", "Responses"), ctx.fmt_count(items.iter().map(|(s, _)| s.id).collect::<HashSet<_>>().len()))
                    .sessions(items.iter().map(|(s, _)| s.id))
            };
            // SameSite=None without Secure: rejected by browsers.
            let none_insecure: Vec<_> = sets.iter().filter(|(_, c)| !c.deletes && c.same_site.as_deref() == Some("none") && !c.secure).collect();
            if !none_insecure.is_empty() {
                list.push(
                    finding(
                        "samesite",
                        Severity::Critical,
                        ctx.l("SameSite=None cookies without Secure:", "SameSite=None-Cookies ohne Secure:"),
                        if ctx.de() {
                            format!("{} Set-Cookie mit SameSite=None, aber ohne Secure – aktuelle Browser verwerfen diese Cookies.", ctx.fmt_count(none_insecure.len()))
                        } else {
                            format!("{} Set-Cookie with SameSite=None but without Secure – current browsers reject these cookies.", ctx.fmt_count(none_insecure.len()))
                        },
                        &none_insecure,
                    )
                    .score(80.0)
                    .threshold("SameSite=None ⇒ Secure")
                    .impact(ctx.l("The cookie is not stored; sign-in or session state breaks, often only in cross-site scenarios (embedded, SSO).", "Das Cookie wird nicht gespeichert; Anmeldung oder Sitzung gehen verloren, oft nur in Cross-Site-Szenarien (eingebettet, SSO)."))
                    .recommend(ctx.l("Add Secure to cookies with SameSite=None (requires HTTPS).", "Cookies mit SameSite=None zusätzlich mit Secure setzen (erfordert HTTPS).")),
                );
            }
            // Cookies on HTTPS without Secure.
            let insecure: Vec<_> = sets.iter().filter(|(s, c)| s.is_https() && !c.deletes && !c.secure && c.same_site.as_deref() != Some("none")).collect();
            if !insecure.is_empty() {
                let sensitive = insecure.iter().any(|(_, c)| session_like(&c.name));
                list.push(
                    finding(
                        "insecure",
                        Severity::Warning,
                        ctx.l("Cookies without Secure on HTTPS:", "Cookies ohne Secure über HTTPS:"),
                        if ctx.de() {
                            format!("{} Set-Cookie über HTTPS ohne das Attribut Secure.", ctx.fmt_count(insecure.len()))
                        } else {
                            format!("{} Set-Cookie over HTTPS without the Secure attribute.", ctx.fmt_count(insecure.len()))
                        },
                        &insecure,
                    )
                    .categories(&["cookies", "security"])
                    .score(if sensitive { 70.0 } else { 40.0 })
                    .threshold("HTTPS ⇒ Secure")
                    .impact(ctx.l("The browser would also send these cookies over plain HTTP, where they can be read.", "Der Browser würde diese Cookies auch über unverschlüsseltes HTTP senden, wo sie mitgelesen werden können."))
                    .recommend(ctx.l("Set Secure on all cookies of HTTPS sites.", "Alle Cookies von HTTPS-Sites mit Secure setzen.")),
                );
            }
            // Session cookies readable by scripts.
            let readable: Vec<_> = sets.iter().filter(|(_, c)| !c.deletes && !c.http_only && session_like(&c.name)).collect();
            if !readable.is_empty() {
                list.push(
                    finding(
                        "httponly",
                        Severity::Info,
                        ctx.l("Session cookies without HttpOnly:", "Sitzungs-Cookies ohne HttpOnly:"),
                        if ctx.de() {
                            format!("{} Set-Cookie für sitzungsähnliche Cookies ohne HttpOnly.", ctx.fmt_count(readable.len()))
                        } else {
                            format!("{} Set-Cookie for session-like cookies without HttpOnly.", ctx.fmt_count(readable.len()))
                        },
                        &readable,
                    )
                    .categories(&["cookies", "security"])
                    .score(30.0)
                    .confidence(Confidence::Medium)
                    .threshold(ctx.l("names like sid, session, auth, token", "Namen wie sid, session, auth, token"))
                    .impact(ctx.l("Scripts (including injected ones) can read these cookies.", "Skripte (auch eingeschleuste) können diese Cookies lesen."))
                    .hypothesis(ctx.l("The name suggests a session or authentication cookie; this is a heuristic.", "Der Name deutet auf ein Sitzungs- oder Anmelde-Cookie hin; das ist eine Heuristik."))
                    .recommend(ctx.l("Set HttpOnly on cookies that scripts do not need.", "Cookies, die Skripte nicht brauchen, mit HttpOnly setzen.")),
                );
            }
            // Very large cookies.
            let mut latest: HashMap<&str, u64> = HashMap::new();
            for (_, c) in sets.iter().filter(|(_, c)| !c.deletes) {
                latest.insert(c.name.as_str(), c.bytes.unwrap_or(0) + c.name.len() as u64);
            }
            let set_bytes: u64 = latest.values().sum();
            let (max_names, max_sess) = v.iter().map(|s| (cookie_names(s).len(), s.id)).max_by_key(|x| x.0).unwrap_or((0, 0));
            if set_bytes >= COOKIE_BYTES_MAX || max_names >= COOKIE_NAMES_MAX {
                let mut big: Vec<u64> = v.iter().filter(|s| cookie_names(s).len() >= COOKIE_NAMES_MAX).map(|s| s.id).collect();
                if max_names >= COOKIE_NAMES_MAX {
                    big.push(max_sess);
                }
                big.extend(sets.iter().map(|(s, _)| s.id));
                list.push(
                    Finding::new(
                        "COOKIE",
                        &format!("size|{h}"),
                        Severity::Warning,
                        format!("{} {}", ctx.l("Very large cookies:", "Sehr große Cookies:"), util::short(&h, 80)),
                        if ctx.de() {
                            format!("Der Host setzt {} Cookies mit zusammen etwa {}; Requests enthielten bis zu {} Cookie-Namen.", ctx.fmt_count(latest.len()), ctx.fmt_bytes(set_bytes as f64), ctx.fmt_count(max_names))
                        } else {
                            format!("The host sets {} cookies of about {} in total; requests carried up to {} cookie names.", ctx.fmt_count(latest.len()), ctx.fmt_bytes(set_bytes as f64), ctx.fmt_count(max_names))
                        },
                    )
                    .categories(&["cookies", "performance"])
                    .score(util::scale(set_bytes as f64, COOKIE_BYTES_MAX as f64, 8.0 * COOKIE_BYTES_MAX as f64).max(util::scale(max_names as f64, COOKIE_NAMES_MAX as f64, 100.0)))
                    .threshold(if ctx.de() {
                        format!("≥ {} Set-Cookie-Werte pro Host oder ≥ {} Cookie-Namen", ctx.fmt_bytes(COOKIE_BYTES_MAX as f64), COOKIE_NAMES_MAX)
                    } else {
                        format!("≥ {} of Set-Cookie values per host or ≥ {} cookie names", ctx.fmt_bytes(COOKIE_BYTES_MAX as f64), COOKIE_NAMES_MAX)
                    })
                    .fact(ctx.l("Cookies set", "Gesetzte Cookies"), ctx.fmt_count(latest.len()))
                    .fact(ctx.l("Size of the set values", "Größe der gesetzten Werte"), ctx.fmt_bytes(set_bytes as f64))
                    .fact(ctx.l("Most cookie names in one request", "Meiste Cookie-Namen in einem Request"), ctx.fmt_count(max_names))
                    .impact(ctx.l(
                        "The cookies travel with every request to the host; large Cookie headers slow down uploads and can exceed server limits (400/431).",
                        "Die Cookies gehen mit jedem Request an den Host; große Cookie-Header bremsen Uploads und können Serverlimits überschreiten (400/431).",
                    ))
                    .hypothesis(ctx.l("Large chunked authentication cookies or many tracking cookies on a shared domain.", "Große, aufgeteilte Anmelde-Cookies oder viele Tracking-Cookies auf einer gemeinsamen Domain."))
                    .recommend(ctx.l("Keep session state on the server, limit cookie paths and domains, serve static content from a cookie-free host.", "Sitzungsdaten auf dem Server halten, Pfade und Domains der Cookies begrenzen, statische Inhalte von einem cookiefreien Host ausliefern."))
                    .sessions(big),
                );
            }
            // The same cookie set again and again.
            for (name, items) in util::group_by(sets.iter().filter(|(_, c)| !c.deletes), |(_, c)| c.name.clone()) {
                if items.len() < COOKIE_REPEAT_MIN {
                    continue;
                }
                let first = items[0].0.started;
                let later: Vec<&&Session> = v.iter().filter(|s| s.started > first).collect();
                let returned = later.iter().any(|s| cookie_names(s).iter().any(|x| x == &name));
                let known = later.iter().any(|s| s.req_header("cookie").is_some()) || returned;
                let severity = if !returned && !later.is_empty() { Severity::Warning } else { Severity::Info };
                let mut f = Finding::new(
                    "COOKIE",
                    &format!("repeat|{h}|{name}"),
                    severity,
                    format!("{} {} ({})", ctx.l("Cookie set repeatedly:", "Cookie wiederholt gesetzt:"), util::short(&name, 40), util::short(&h, 60)),
                    if ctx.de() {
                        format!("Das Cookie {} wurde von {} {}-mal gesetzt.", name, h, ctx.fmt_count(items.len()))
                    } else {
                        format!("The cookie {} was set {} times by {}.", name, ctx.fmt_count(items.len()), h)
                    },
                )
                .categories(&["cookies"])
                .score(util::scale(items.len() as f64, COOKIE_REPEAT_MIN as f64, 500.0))
                .threshold(format!("≥ {}", COOKIE_REPEAT_MIN))
                .fact(ctx.l("Times set", "Anzahl gesetzt"), ctx.fmt_count(items.len()))
                .fact(ctx.l("Sent back by the client", "Vom Client zurückgesendet"), if returned { ctx.l("yes", "ja") } else { ctx.l("no", "nein") })
                .sessions(items.iter().map(|(s, _)| s.id));
                f = if !returned && !later.is_empty() {
                    f.impact(ctx.l("The client does not send the cookie back, so the server starts a new session (or login) on every request.", "Der Client sendet das Cookie nicht zurück, daher beginnt der Server bei jedem Request eine neue Sitzung (oder Anmeldung)."))
                        .hypothesis(ctx.l(
                            "The client has no cookie store, or rejects the cookie (Secure/SameSite/Domain/Path attributes).",
                            "Der Client hat keinen Cookie-Speicher oder verwirft das Cookie (Attribute Secure/SameSite/Domain/Path).",
                        ))
                        .recommend(ctx.l("Enable a cookie container in the HTTP client and check the cookie attributes.", "Im HTTP-Client einen Cookie-Container aktivieren und die Cookie-Attribute prüfen."))
                } else {
                    f.impact(ctx.l("Each renewal adds header bytes; with sliding expiration this is often expected.", "Jede Erneuerung kostet Header-Bytes; bei gleitendem Ablauf ist das oft erwartet."))
                        .hypothesis(ctx.l("The server renews the cookie on every response (sliding expiration, token refresh).", "Der Server erneuert das Cookie bei jeder Response (gleitender Ablauf, Token-Erneuerung)."))
                        .recommend(ctx.l("Renew the cookie only when needed (e.g. after half of its lifetime).", "Das Cookie nur bei Bedarf erneuern (z. B. nach der Hälfte seiner Laufzeit)."))
                };
                if !known {
                    f = f.confidence(Confidence::Low);
                }
                list.push(f);
            }
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ CACHE

/// Full reloads of the same static URL from this count are a warning.
const CACHE_RELOAD_MIN: usize = 3;
/// 304 revalidations of the same resource from this count are reported (info).
const CACHE_304_MIN: usize = 10;
/// API GETs of the same URL with an ETag but never revalidated, from this count (info).
const CACHE_ETAG_API_MIN: usize = 3;

fn max_age(cc: &str) -> Option<u64> {
    cc.split(',').find_map(|d| {
        let (k, v) = d.trim().split_once('=')?;
        matches!(k.trim().to_ascii_lowercase().as_str(), "max-age" | "s-maxage").then(|| v.trim().trim_matches('"').parse().ok())?
    })
}

/// The response tells caches how long it is fresh or how to revalidate it.
fn cacheable(s: &Session) -> bool {
    let cc = s.resp_header("cache-control").unwrap_or("").to_ascii_lowercase();
    max_age(&cc).is_some_and(|a| a > 0) || cc.contains("immutable") || s.resp_header("expires").is_some() || s.resp_header("etag").is_some() || s.resp_header("last-modified").is_some()
}

fn conditional(s: &Session) -> bool {
    s.req_header("if-none-match").is_some() || s.req_header("if-modified-since").is_some()
}

/// Groups with the most sessions first.
fn by_count(mut g: Vec<(String, Vec<&Session>)>) -> Vec<(String, Vec<&Session>)> {
    g.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    g
}

fn is_static(s: &Session) -> bool {
    canon::is_static(&s.mime(), &canon::parse(&s.url).path)
}

/// CACHE: static resources without caching, full reloads, revalidation instead of freshness.
struct Caching;

impl Analyzer for Caching {
    fn id(&self) -> &'static str {
        "CACHE"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "modernization"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let mut list = vec![];
        let gets = ctx.http().filter(|s| s.method.eq_ignore_ascii_case("GET") && !s.failed());
        for (h, v) in util::group_by(gets, |s| host(s)) {
            let url_rows = |groups: &[(String, Vec<&Session>)]| -> Vec<Vec<String>> { groups.iter().take(8).map(|(u, l)| vec![util::short(u, 100), ctx.fmt_count(l.len()), ctx.fmt_bytes(l.iter().map(|s| s.response_bytes as f64).sum())]).collect() };
            let cols = || vec!["URL".to_string(), ctx.l("Requests", "Requests").to_string(), ctx.l("Transferred", "Übertragen").to_string()];
            let statics: Vec<&Session> = v.iter().copied().filter(|s| is_static(s)).collect();
            // Static resources without any freshness or validator.
            let explicit = |s: &Session| {
                s.resp_header("cache-control").is_some_and(|c| {
                    let c = c.to_ascii_lowercase();
                    c.contains("no-store") || c.contains("no-cache")
                })
            };
            let bare: Vec<&Session> = statics.iter().copied().filter(|s| s.status == 200 && !cacheable(s) && !explicit(s)).collect();
            if !bare.is_empty() {
                let g = by_count(util::group_by(bare.iter().copied(), |s| endpoint(s)));
                list.push(
                    Finding::new(
                        "CACHE",
                        &format!("uncacheable|{h}"),
                        Severity::Warning,
                        format!("{} {}", ctx.l("Static resources without caching headers:", "Statische Ressourcen ohne Cache-Header:"), util::short(&h, 80)),
                        if ctx.de() {
                            format!("{} statische Response(s) von {} ({} verschiedene) hatten weder Cache-Control max-age noch Expires, ETag oder Last-Modified.", ctx.fmt_count(bare.len()), h, ctx.fmt_count(g.len()))
                        } else {
                            format!("{} static response(s) from {} ({} distinct) had neither Cache-Control max-age nor Expires, ETag or Last-Modified.", ctx.fmt_count(bare.len()), h, ctx.fmt_count(g.len()))
                        },
                    )
                    .categories(&["performance", "caching"])
                    .score(util::scale(bare.len() as f64, 1.0, 200.0))
                    .threshold(ctx.l("no max-age, Expires, ETag or Last-Modified", "kein max-age, Expires, ETag oder Last-Modified"))
                    .impact(ctx.l("Clients cannot cache or revalidate these files and download them completely every time.", "Clients können diese Dateien weder cachen noch revalidieren und laden sie jedes Mal vollständig."))
                    .recommend(ctx.l(
                        "Serve versioned static files with Cache-Control: max-age=31536000, immutable; others at least with an ETag or Last-Modified.",
                        "Versionierte statische Dateien mit Cache-Control: max-age=31536000, immutable ausliefern, andere mindestens mit ETag oder Last-Modified.",
                    ))
                    .table(vec![ctx.l("Endpoint", "Endpunkt").into(), ctx.l("Requests", "Requests").into(), ctx.l("Transferred", "Übertragen").into()], url_rows(&g))
                    .sessions(bare.iter().map(|s| s.id)),
                );
            }
            // Static resources explicitly not cached.
            let nostore: Vec<&Session> = statics.iter().copied().filter(|s| s.status == 200 && explicit(s)).collect();
            if !nostore.is_empty() {
                let g = by_count(util::group_by(nostore.iter().copied(), |s| endpoint(s)));
                list.push(
                    Finding::new(
                        "CACHE",
                        &format!("nostore|{h}"),
                        Severity::Info,
                        format!("{} {}", ctx.l("Static resources marked no-store/no-cache:", "Statische Ressourcen mit no-store/no-cache:"), util::short(&h, 80)),
                        if ctx.de() {
                            format!("{} statische Response(s) von {} verbieten das Cachen oder erzwingen eine Revalidierung.", ctx.fmt_count(nostore.len()), h)
                        } else {
                            format!("{} static response(s) from {} forbid caching or force revalidation.", ctx.fmt_count(nostore.len()), h)
                        },
                    )
                    .categories(&["performance", "caching"])
                    .score(util::scale(nostore.len() as f64, 1.0, 200.0))
                    .threshold("Cache-Control: no-store / no-cache")
                    .impact(ctx.l("Every use costs at least a round trip, with no-store the full download.", "Jede Verwendung kostet mindestens einen Roundtrip, bei no-store den vollständigen Download."))
                    .hypothesis(ctx.l("A global server or proxy rule applies no-cache to all responses, including static files.", "Eine globale Server- oder Proxy-Regel setzt no-cache für alle Responses, auch für statische Dateien."))
                    .recommend(ctx.l("Limit no-store/no-cache to dynamic, sensitive responses.", "no-store/no-cache auf dynamische, vertrauliche Responses beschränken."))
                    .table(vec![ctx.l("Endpoint", "Endpunkt").into(), ctx.l("Requests", "Requests").into(), ctx.l("Transferred", "Übertragen").into()], url_rows(&g))
                    .sessions(nostore.iter().map(|s| s.id)),
                );
            }
            // Full reloads of the same static URL.
            let reloads: Vec<(String, Vec<&Session>)> =
                by_count(util::group_by(statics.iter().copied().filter(|s| s.status == 200 && !conditional(s)), |s| url_key(&s.url)).into_iter().filter(|(_, l)| l.len() >= CACHE_RELOAD_MIN).collect());
            if !reloads.is_empty() {
                let n: usize = reloads.iter().map(|(_, l)| l.len()).sum();
                let wasted: f64 = reloads.iter().map(|(_, l)| l.iter().skip(1).map(|s| s.response_bytes as f64).sum::<f64>()).sum();
                let fresh = reloads.iter().any(|(_, l)| l.iter().any(|s| cacheable(s)));
                let mut f = Finding::new(
                    "CACHE",
                    &format!("reload|{h}"),
                    Severity::Warning,
                    format!("{} {}", ctx.l("Static resources downloaded again and again:", "Statische Ressourcen immer wieder geladen:"), util::short(&h, 80)),
                    if ctx.de() {
                        format!("{} statische URL(s) von {} wurden jeweils mindestens {}-mal vollständig ohne If-None-Match/If-Modified-Since geladen ({} Requests).", ctx.fmt_count(reloads.len()), h, CACHE_RELOAD_MIN, ctx.fmt_count(n))
                    } else {
                        format!("{} static URL(s) from {} were fully downloaded at least {} times each without If-None-Match/If-Modified-Since ({} requests).", ctx.fmt_count(reloads.len()), h, CACHE_RELOAD_MIN, ctx.fmt_count(n))
                    },
                )
                .categories(&["performance", "caching"])
                .score(util::scale(wasted, 10.0 * 1024.0, 20.0 * 1024.0 * 1024.0).max(util::scale(n as f64, CACHE_RELOAD_MIN as f64, 300.0)))
                .threshold(format!("≥ {}", CACHE_RELOAD_MIN))
                .fact(ctx.l("Repeated transfer", "Wiederholt übertragen"), ctx.fmt_bytes(wasted))
                .impact(ctx.l("The same bytes are transferred repeatedly; every reload waits for the network.", "Dieselben Bytes werden mehrfach übertragen; jedes erneute Laden wartet auf das Netz."))
                .table(cols(), url_rows(&reloads))
                .sessions(reloads.iter().flat_map(|(_, l)| l.iter().map(|s| s.id)));
                f = if fresh {
                    f.hypothesis(ctx.l(
                        "The responses are cacheable, but the client does not cache them (no HTTP cache in the client, cache disabled, e.g. developer tools).",
                        "Die Responses sind cachebar, aber der Client cacht sie nicht (kein HTTP-Cache im Client, Cache deaktiviert, z. B. in den Entwicklertools).",
                    ))
                    .recommend(ctx.l("Enable an HTTP cache in the client or keep loaded resources in memory.", "Im Client einen HTTP-Cache aktivieren oder geladene Ressourcen im Speicher halten."))
                } else {
                    f.hypothesis(ctx.l("Without caching headers the client cannot cache the resources.", "Ohne Cache-Header kann der Client die Ressourcen nicht cachen."))
                        .recommend(ctx.l("Add Cache-Control max-age (and an ETag) to these resources.", "Diesen Ressourcen Cache-Control max-age (und ein ETag) mitgeben."))
                };
                list.push(f);
            }
            // Many 304 for the same resource: revalidation instead of freshness.
            let revalidated: Vec<(String, Vec<&Session>)> =
                by_count(util::group_by(statics.iter().copied().filter(|s| s.status == 304), |s| url_key(&s.url)).into_iter().filter(|(_, l)| l.len() >= CACHE_304_MIN).collect());
            if !revalidated.is_empty() {
                let n: usize = revalidated.iter().map(|(_, l)| l.len()).sum();
                let (tcols, trows) = rtt_table(ctx, n as f64);
                list.push(
                    Finding::new(
                        "CACHE",
                        &format!("revalidate|{h}"),
                        Severity::Info,
                        format!("{} {}", ctx.l("Frequent revalidation (304):", "Häufige Revalidierung (304):"), util::short(&h, 80)),
                        if ctx.de() {
                            format!("{} statische Ressource(n) von {} wurden je mindestens {}-mal mit 304 revalidiert ({} Requests).", ctx.fmt_count(revalidated.len()), h, CACHE_304_MIN, ctx.fmt_count(n))
                        } else {
                            format!("{} static resource(s) from {} were revalidated with 304 at least {} times each ({} requests).", ctx.fmt_count(revalidated.len()), h, CACHE_304_MIN, ctx.fmt_count(n))
                        },
                    )
                    .categories(&["performance", "caching"])
                    .score(util::scale(n as f64, CACHE_304_MIN as f64, 1000.0))
                    .threshold(format!("≥ {} × 304", CACHE_304_MIN))
                    .impact(ctx.l("Each revalidation is small but costs a full round trip.", "Jede Revalidierung ist klein, kostet aber einen vollen Roundtrip."))
                    .hypothesis(ctx.l("The resources have validators but no (or a very short) freshness lifetime.", "Die Ressourcen haben Validatoren, aber keine (oder eine sehr kurze) Frische-Dauer."))
                    .recommend(ctx.l("Give versioned static files a long max-age (immutable) so no revalidation is needed.", "Versionierten statischen Dateien ein langes max-age (immutable) geben, damit keine Revalidierung nötig ist."))
                    .estimate()
                    .table(tcols, trows)
                    .fact(ctx.l("Resources", "Ressourcen"), revalidated.iter().take(5).map(|(u, _)| util::short(u, 60)).collect::<Vec<_>>().join(", "))
                    .sessions(revalidated.iter().flat_map(|(_, l)| l.iter().map(|s| s.id))),
                );
            }
            // API responses with ETag the client never uses.
            let api: Vec<(String, Vec<&Session>)> = by_count(
                util::group_by(v.iter().copied().filter(|s| !is_static(s) && (s.status == 200 || s.status == 304)), |s| url_key(&s.url))
                    .into_iter()
                    .filter(|(_, l)| l.len() >= CACHE_ETAG_API_MIN && l.iter().any(|s| s.resp_header("etag").is_some()) && !l.iter().any(|s| conditional(s)))
                    .collect(),
            );
            if !api.is_empty() {
                let n: usize = api.iter().map(|(_, l)| l.len()).sum();
                list.push(
                    Finding::new(
                        "CACHE",
                        &format!("etag|{h}"),
                        Severity::Info,
                        format!("{} {}", ctx.l("ETags not used by the client:", "ETags vom Client nicht genutzt:"), util::short(&h, 80)),
                        if ctx.de() {
                            format!("{} API-URL(s) von {} liefern ein ETag, wurden aber {}-mal ohne If-None-Match erneut geladen.", ctx.fmt_count(api.len()), h, ctx.fmt_count(n))
                        } else {
                            format!("{} API URL(s) from {} return an ETag but were requested {} times without If-None-Match.", ctx.fmt_count(api.len()), h, ctx.fmt_count(n))
                        },
                    )
                    .categories(&["performance", "caching"])
                    .score(util::scale(n as f64, CACHE_ETAG_API_MIN as f64, 500.0))
                    .threshold(format!("≥ {}", CACHE_ETAG_API_MIN))
                    .impact(ctx.l("A conditional request would return 304 without a body when nothing changed.", "Ein bedingter Request würde ohne Änderung 304 ohne Body liefern."))
                    .recommend(ctx.l("Send If-None-Match with the last ETag (or use an HTTP cache in the client).", "If-None-Match mit dem letzten ETag senden (oder im Client einen HTTP-Cache verwenden)."))
                    .table(cols(), url_rows(&api))
                    .sessions(api.iter().flat_map(|(_, l)| l.iter().map(|s| s.id))),
                );
            }
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ CONN-REUSE

/// New connections for at least this share of a host's requests …
const CONN_NEW_SHARE_WARN: f64 = 0.3;
/// … and at least this many are a warning.
const CONN_NEW_MIN: usize = 10;
/// `Connection: close` or HTTP/1.0 from this count per host are reported (info).
const CONN_CLOSE_MIN: usize = 5;
/// So many parallel HTTP/1.x requests to one host suggest HTTP/2 (info).
const H2_PARALLEL_MIN: usize = 6;

fn handshake_ms(s: &Session) -> f64 {
    let t = &s.timers;
    (t.dns_ms.unwrap_or(0) + t.tcp_connect_ms.unwrap_or(0) + t.tls_handshake_ms.unwrap_or(0)) as f64
}

/// Round trips of a connection setup: TCP plus TLS (1 for TLS 1.3, 2 before).
fn setup_round_trips(s: &Session) -> f64 {
    if !s.is_https() {
        1.0
    } else if s.tls_version.as_deref().and_then(util::tls_version).is_some_and(|v| v >= (1, 3)) {
        2.0
    } else {
        3.0
    }
}

/// CONN-REUSE: new upstream connections, handshake time, Connection: close, HTTP/1.x.
struct ConnReuse;

impl Analyzer for ConnReuse {
    fn id(&self) -> &'static str {
        "CONN-REUSE"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let mut list = vec![];
        for (h, v) in util::group_by(ctx.http(), |s| host(s)) {
            let n = v.len();
            let known = v.iter().filter(|s| s.server_connection_reused || s.timers.server_connect_start.is_some()).count();
            let fresh: Vec<&Session> = v.iter().copied().filter(|s| s.new_connection()).collect();
            let close = v.iter().filter(|s| header_has(s.resp_header("connection"), "close") || header_has(s.req_header("connection"), "close")).count();
            let http10 = v.iter().filter(|s| s.version.eq_ignore_ascii_case("HTTP/1.0")).count();
            let share = ratio(fresh.len(), n);
            let warn = known > 0 && fresh.len() >= CONN_NEW_MIN && share >= CONN_NEW_SHARE_WARN;
            if warn || close >= CONN_CLOSE_MIN || http10 >= CONN_CLOSE_MIN {
                let hs: f64 = fresh.iter().map(|s| handshake_ms(s)).sum();
                let total: f64 = v.iter().map(|s| ms(s)).sum();
                let trips: f64 = fresh.iter().map(|s| setup_round_trips(s)).sum();
                let (cols, rows) = rtt_table(ctx, trips);
                let mut f = Finding::new(
                    "CONN-REUSE",
                    &h,
                    if warn { Severity::Warning } else { Severity::Info },
                    format!("{} {}", ctx.l("Connections not reused:", "Verbindungen nicht wiederverwendet:"), util::short(&h, 80)),
                    if ctx.de() {
                        format!("{} von {} Requests an {} öffneten eine neue Verbindung ({}); {} mit Connection: close, {} über HTTP/1.0.", ctx.fmt_count(fresh.len()), ctx.fmt_count(n), h, ctx.fmt_pct(share), ctx.fmt_count(close), ctx.fmt_count(http10))
                    } else {
                        format!("{} of {} requests to {} opened a new connection ({}); {} with Connection: close, {} over HTTP/1.0.", ctx.fmt_count(fresh.len()), ctx.fmt_count(n), h, ctx.fmt_pct(share), ctx.fmt_count(close), ctx.fmt_count(http10))
                    },
                )
                .categories(&["performance", "network"])
                .score(util::scale(fresh.len() as f64, CONN_NEW_MIN as f64, 500.0) * 0.5 + share * 50.0)
                .threshold(if ctx.de() {
                    format!("Warnung ab {} neuen Verbindungen und ≥ {} der Requests", CONN_NEW_MIN, ctx.fmt_pct(CONN_NEW_SHARE_WARN))
                } else {
                    format!("warning from {} new connections and ≥ {} of requests", CONN_NEW_MIN, ctx.fmt_pct(CONN_NEW_SHARE_WARN))
                })
                .fact(ctx.l("Requests", "Requests"), ctx.fmt_count(n))
                .fact(ctx.l("New connections", "Neue Verbindungen"), ctx.fmt_count(fresh.len()))
                .fact(ctx.l("Handshake time (DNS+TCP+TLS)", "Handshake-Zeit (DNS+TCP+TLS)"), ctx.fmt_ms(hs))
                .fact(ctx.l("Handshake share of the total time", "Anteil Handshake an der Gesamtzeit"), ctx.fmt_pct(if total > 0.0 { (hs / total).min(1.0) } else { 0.0 }))
                .impact(ctx.l(
                    "Every new connection costs TCP and TLS round trips before the request can be sent; on high-latency links this dominates short requests.",
                    "Jede neue Verbindung kostet TCP- und TLS-Roundtrips, bevor der Request gesendet werden kann; bei hoher Latenz überwiegt das bei kurzen Requests.",
                ))
                .estimate()
                .table(cols, rows)
                .sessions(fresh.iter().map(|s| s.id))
                .sessions(v.iter().filter(|s| header_has(s.resp_header("connection"), "close") || header_has(s.req_header("connection"), "close") || s.version.eq_ignore_ascii_case("HTTP/1.0")).map(|s| s.id));
                if close > 0 {
                    f = f.fact("Connection: close", ctx.fmt_count(close)).hypothesis(ctx.l("Connection: close ends the connection after the response (client, server or proxy setting).", "Connection: close beendet die Verbindung nach der Response (Einstellung von Client, Server oder Proxy)."));
                }
                if http10 > 0 {
                    f = f.fact("HTTP/1.0", ctx.fmt_count(http10)).hypothesis(ctx.l("HTTP/1.0 has no persistent connections by default; an old client or proxy is involved.", "HTTP/1.0 hat standardmäßig keine dauerhaften Verbindungen; ein alter Client oder Proxy ist beteiligt."));
                }
                if warn && close == 0 && http10 == 0 {
                    f = f.hypothesis(ctx.l(
                        "The client creates a new HTTP client or connection per request, or idle connections are closed too early (pool size, idle timeout of a load balancer).",
                        "Der Client erzeugt pro Request einen neuen HTTP-Client oder eine neue Verbindung, oder Leerlaufverbindungen werden zu früh geschlossen (Poolgröße, Leerlauf-Timeout eines Load Balancers).",
                    ));
                }
                f = match ratio(known, n) {
                    r if r < 0.5 => f.confidence(Confidence::Low),
                    r if r < 0.9 => f.confidence(Confidence::Medium),
                    _ => f,
                };
                list.push(
                    f.recommend(ctx.l("Reuse one HTTP client with a connection pool and keep-alive.", "Einen HTTP-Client mit Connection-Pool und Keep-alive wiederverwenden."))
                        .recommend(ctx.l("Align idle timeouts of client, proxy and server; prefer HTTP/2.", "Leerlauf-Timeouts von Client, Proxy und Server abstimmen; HTTP/2 bevorzugen."))
                        .next_step(ctx.l("Compare the connection ids of consecutive requests to this host.", "Die Verbindungs-IDs aufeinanderfolgender Requests an diesen Host vergleichen.")),
                );
            }
            // Many parallel requests but only HTTP/1.x.
            let h1 = v.iter().all(|s| s.version.to_ascii_uppercase().starts_with("HTTP/1"));
            if h1 {
                let spans: Vec<(u64, u64)> = v.iter().map(|s| (s.started, s.end())).collect();
                let peak = util::max_concurrency(&spans);
                if peak >= H2_PARALLEL_MIN {
                    list.push(
                        Finding::new(
                            "CONN-REUSE",
                            &format!("h2|{h}"),
                            Severity::Info,
                            format!("{} {}", ctx.l("Many parallel HTTP/1.1 requests:", "Viele parallele HTTP/1.1-Requests:"), util::short(&h, 80)),
                            if ctx.de() {
                                format!("Bis zu {} Requests an {} liefen gleichzeitig, alle über HTTP/1.x.", ctx.fmt_count(peak), h)
                            } else {
                                format!("Up to {} requests to {} ran at the same time, all over HTTP/1.x.", ctx.fmt_count(peak), h)
                            },
                        )
                        .categories(&["performance", "network"])
                        .score(util::scale(peak as f64, H2_PARALLEL_MIN as f64, 50.0))
                        .threshold(format!("≥ {}", H2_PARALLEL_MIN))
                        .fact(ctx.l("Most parallel requests", "Meiste parallele Requests"), ctx.fmt_count(peak))
                        .impact(ctx.l("HTTP/1.1 needs one connection per parallel request (browsers allow about 6 per host); further requests queue.", "HTTP/1.1 braucht eine Verbindung pro parallelem Request (Browser erlauben etwa 6 pro Host); weitere Requests warten."))
                        .hypothesis(ctx.l("The server, a proxy or the client does not offer HTTP/2.", "Server, Proxy oder Client bieten kein HTTP/2 an."))
                        .recommend(ctx.l("Enable HTTP/2 so parallel requests share one connection.", "HTTP/2 aktivieren, damit sich parallele Requests eine Verbindung teilen."))
                        .confidence(Confidence::Medium)
                        .sessions(v.iter().map(|s| s.id)),
                    );
                }
            }
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ TLS-OLD

/// Lowest acceptable protocol version.
const TLS_MIN: (u8, u8) = (1, 2);

/// TLS-OLD: upstream TLS below 1.2, per host.
struct TlsOld;

impl Analyzer for TlsOld {
    fn id(&self) -> &'static str {
        "TLS-OLD"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["troubleshooting", "security"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let old = ctx.sessions.iter().filter(|s| s.kind != Kind::WebSocket && s.tls_version.as_deref().and_then(util::tls_version).is_some_and(|v| v < TLS_MIN));
        let mut list = vec![];
        for (h, v) in util::group_by(old, |s| host(s)) {
            let versions = top(v.iter().filter_map(|s| s.tls_version.clone()));
            list.push(
                Finding::new(
                    "TLS-OLD",
                    &h,
                    Severity::Warning,
                    format!("{} {}", ctx.l("Outdated TLS version:", "Veraltete TLS-Version:"), util::short(&h, 80)),
                    if ctx.de() {
                        format!("{} Verbindung(en) zu {} nutzten ein Protokoll unter TLS 1.2 ({}).", ctx.fmt_count(v.len()), h, list_top(ctx, &versions, 3))
                    } else {
                        format!("{} connection(s) to {} used a protocol below TLS 1.2 ({}).", ctx.fmt_count(v.len()), h, list_top(ctx, &versions, 3))
                    },
                )
                .categories(&["security", "tls"])
                .score(util::scale(v.len() as f64, 1.0, 100.0))
                .threshold("< TLS 1.2")
                .fact(ctx.l("Versions", "Versionen"), list_top(ctx, &versions, 4))
                .impact(ctx.l(
                    "TLS 1.0/1.1 are deprecated and insecure; current clients and servers refuse them, so connections will start to fail.",
                    "TLS 1.0/1.1 sind veraltet und unsicher; aktuelle Clients und Server lehnen sie ab, Verbindungen werden daher scheitern.",
                ))
                .hypothesis(ctx.l("An old server, appliance or client framework (e.g. an old .NET Framework default) negotiates the old protocol.", "Ein alter Server, eine Appliance oder ein altes Client-Framework (z. B. alte .NET-Framework-Voreinstellung) handelt das alte Protokoll aus."))
                .recommend(ctx.l("Enable TLS 1.2/1.3 on the server and let the client use the operating system defaults.", "TLS 1.2/1.3 auf dem Server aktivieren und den Client die Voreinstellungen des Betriebssystems nutzen lassen."))
                .sessions(v.iter().map(|s| s.id)),
            );
        }
        emit(ctx, out, list);
    }
}

// ------------------------------------------------------------------ CORS-PREFLIGHT

/// Preflights per host from this count are reported.
const PREFLIGHT_MIN: usize = 5;
/// Preflights per cross-origin request at or above this ratio: a preflight per request (warning).
const PREFLIGHT_PER_REQUEST: f64 = 0.8;

fn is_preflight(s: &Session) -> bool {
    s.method.eq_ignore_ascii_case("OPTIONS") && s.req_header("access-control-request-method").is_some()
}

/// CORS-PREFLIGHT: OPTIONS preflights per host, missing Max-Age, failing preflights.
struct CorsPreflight;

impl Analyzer for CorsPreflight {
    fn id(&self) -> &'static str {
        "CORS-PREFLIGHT"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "troubleshooting"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let mut list = vec![];
        for (h, v) in util::group_by(ctx.http(), |s| host(s)) {
            let pre: Vec<&Session> = v.iter().copied().filter(|s| is_preflight(s)).collect();
            if pre.is_empty() {
                continue;
            }
            let others: Vec<&Session> = v.iter().copied().filter(|s| !s.method.eq_ignore_ascii_case("OPTIONS")).collect();
            let with_origin = others.iter().filter(|s| s.req_header("origin").is_some()).count();
            let actual = if with_origin > 0 { with_origin } else { others.len() };
            // Failing preflights block the actual request.
            let failed: Vec<&Session> = pre.iter().copied().filter(|s| s.failed() || s.status >= 400 || ((200..300).contains(&s.status) && s.resp_header("access-control-allow-origin").is_none())).collect();
            if !failed.is_empty() {
                let statuses = top(failed.iter().map(|s| if s.status == 0 { "–".to_string() } else { s.status.to_string() }));
                list.push(
                    Finding::new(
                        "CORS-PREFLIGHT",
                        &format!("fail|{h}"),
                        Severity::Warning,
                        format!("{} {}", ctx.l("Failing CORS preflights:", "Fehlschlagende CORS-Preflights:"), util::short(&h, 80)),
                        if ctx.de() {
                            format!("{} Preflight(s) an {} schlugen fehl oder enthielten kein Access-Control-Allow-Origin.", ctx.fmt_count(failed.len()), h)
                        } else {
                            format!("{} preflight(s) to {} failed or carried no Access-Control-Allow-Origin.", ctx.fmt_count(failed.len()), h)
                        },
                    )
                    .categories(&["cors", "errors"])
                    .score(util::scale(failed.len() as f64, 0.0, 50.0))
                    .threshold(ctx.l("status ≥ 400 or no Access-Control-Allow-Origin", "Status ≥ 400 oder kein Access-Control-Allow-Origin"))
                    .fact(ctx.l("Status", "Status"), list_top(ctx, &statuses, 4))
                    .impact(ctx.l("The browser blocks the actual request; the application sees a network error.", "Der Browser blockiert den eigentlichen Request; die Anwendung sieht einen Netzwerkfehler."))
                    .hypothesis(ctx.l(
                        "The server does not handle OPTIONS (or requires authentication for it), or the origin is not allowed.",
                        "Der Server behandelt OPTIONS nicht (oder verlangt dafür eine Anmeldung), oder der Origin ist nicht erlaubt.",
                    ))
                    .recommend(ctx.l("Answer OPTIONS without authentication and with the CORS headers for the allowed origins.", "OPTIONS ohne Anmeldung und mit den CORS-Headern für die erlaubten Origins beantworten."))
                    .sessions(failed.iter().map(|s| s.id)),
                );
            }
            if pre.len() < PREFLIGHT_MIN {
                continue;
            }
            let per_request = ratio(pre.len(), actual.max(1));
            let time: f64 = pre.iter().map(|s| ms(s)).sum();
            let total: f64 = v.iter().map(|s| ms(s)).sum();
            let ok: Vec<&&Session> = pre.iter().filter(|s| (200..300).contains(&s.status)).collect();
            let no_max_age = ok.iter().filter(|s| s.resp_header("access-control-max-age").is_none()).count();
            let max_ages = top(ok.iter().filter_map(|s| s.resp_header("access-control-max-age")).map(|x| x.trim().to_string()));
            let distinct_urls = pre.iter().map(|s| url_key(&s.url)).collect::<HashSet<_>>().len();
            let eps = top(pre.iter().map(|s| format!("{} {}", s.req_header("access-control-request-method").unwrap_or("?").trim().to_ascii_uppercase(), canon::endpoint("", &s.url).trim_start())));
            let severity = if per_request >= PREFLIGHT_PER_REQUEST { Severity::Warning } else { Severity::Info };
            let (cols, rows) = rtt_table(ctx, pre.len() as f64);
            let mut f = Finding::new(
                "CORS-PREFLIGHT",
                &h,
                severity,
                format!("{} {}", ctx.l("CORS preflights:", "CORS-Preflights:"), util::short(&h, 80)),
                if ctx.de() {
                    format!("{} Preflight-Request(s) an {} für {} eigentliche Requests ({} pro Request), zusammen {}.", ctx.fmt_count(pre.len()), h, ctx.fmt_count(actual), crate::fmt::num(per_request, 2, ctx.opts.lang), ctx.fmt_ms(time))
                } else {
                    format!("{} preflight request(s) to {} for {} actual requests ({} per request), {} in total.", ctx.fmt_count(pre.len()), h, ctx.fmt_count(actual), crate::fmt::num(per_request, 2, ctx.opts.lang), ctx.fmt_ms(time))
                },
            )
            .categories(&["cors", "latency"])
            .score(util::scale(pre.len() as f64, PREFLIGHT_MIN as f64, 500.0) * 0.5 + per_request.min(1.0) * 50.0)
            .threshold(if ctx.de() {
                format!("≥ {} Preflights; Warnung ab {} Preflights pro Request", PREFLIGHT_MIN, crate::fmt::num(PREFLIGHT_PER_REQUEST, 1, ctx.opts.lang))
            } else {
                format!("≥ {} preflights; warning from {} preflights per request", PREFLIGHT_MIN, crate::fmt::num(PREFLIGHT_PER_REQUEST, 1, ctx.opts.lang))
            })
            .fact(ctx.l("Preflights", "Preflights"), ctx.fmt_count(pre.len()))
            .fact(ctx.l("Share of the host's requests", "Anteil an den Requests des Hosts"), ctx.fmt_pct(ratio(pre.len(), v.len())))
            .fact(ctx.l("Time in preflights", "Zeit in Preflights"), format!("{} ({})", ctx.fmt_ms(time), ctx.fmt_pct(if total > 0.0 { time / total } else { 0.0 })))
            .fact(ctx.l("Without Access-Control-Max-Age", "Ohne Access-Control-Max-Age"), format!("{} / {}", ctx.fmt_count(no_max_age), ctx.fmt_count(ok.len())))
            .fact(ctx.l("Endpoints", "Endpunkte"), list_top(ctx, &eps, 4))
            .impact(ctx.l("Each preflight is an extra round trip before the actual request.", "Jeder Preflight ist ein zusätzlicher Roundtrip vor dem eigentlichen Request."))
            .estimate()
            .table(cols, rows)
            .sessions(pre.iter().map(|s| s.id));
            if !max_ages.is_empty() {
                f = f.fact("Access-Control-Max-Age", list_top(ctx, &max_ages, 3));
            }
            if no_max_age > 0 {
                f = f.recommend(ctx.l("Send Access-Control-Max-Age (e.g. 7200; browsers cap it) so preflights are cached.", "Access-Control-Max-Age senden (z. B. 7200; Browser begrenzen den Wert), damit Preflights gecacht werden."));
            }
            if distinct_urls * 10 >= pre.len() * 8 {
                f = f.hypothesis(ctx.l(
                    "Almost every preflight is for a different URL (ids in the path): the preflight cache works per URL and cannot help.",
                    "Fast jeder Preflight gilt einer anderen URL (IDs im Pfad): Der Preflight-Cache arbeitet pro URL und kann nicht helfen.",
                ));
            }
            list.push(
                f.hypothesis(ctx.l(
                    "Preflights are triggered by custom headers (e.g. Authorization), JSON content types or methods other than GET/POST.",
                    "Preflights werden durch eigene Header (z. B. Authorization), JSON-Inhaltstypen oder andere Methoden als GET/POST ausgelöst.",
                ))
                .recommend(ctx.l("Serve the API from the same origin (reverse proxy) to avoid CORS altogether.", "Die API über denselben Origin ausliefern (Reverse Proxy), um CORS ganz zu vermeiden."))
                .next_step(ctx.l("Filter the capture by OPTIONS and compare with the following requests.", "Die Aufzeichnung nach OPTIONS filtern und mit den folgenden Requests vergleichen.")),
            );
        }
        emit(ctx, out, list);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::get;

    #[test]
    fn error_classes() {
        let c = |e: &str| error_class(&get(1, "https://h/").failed_with(e));
        assert_eq!(c("The operation Timed Out"), "timeout");
        assert_eq!(c("ECONNRESET"), "reset");
        assert_eq!(c("Connection refused"), "refused");
        assert_eq!(c("DNS lookup failed: no such host"), "dns");
        assert_eq!(c("TLS handshake failed: certificate expired"), "tls");
        assert_eq!(c("request aborted by client"), "aborted");
        assert_eq!(c("weird"), "other");
        assert_eq!(error_class(&get(1, "https://h/").status(0)), "other");
    }

    #[test]
    fn helpers() {
        assert_eq!(max_age("public, max-age=600"), Some(600));
        assert_eq!(max_age("no-cache"), None);
        assert_eq!(bare_host("h.test:8080"), "h.test");
        assert!(session_like("ASP.NET_SessionId") && session_like("sid") && !session_like("theme"));
    }
}
