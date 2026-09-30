//! Analyzers of single sessions and their simple aggregates.
//!
//! Style (all analyzers): aggregate by endpoint (`canon::endpoint`) instead of one finding
//! per session; at most `util::MAX_PER_RULE` findings per rule, worst first; every finding
//! names its threshold and lists all affected sessions; texts in both languages via
//! `ctx.l(en, de)`; numbers via `ctx.fmt_*`.
use crate::canon;
use crate::model::{Analyzer, Confidence, Ctx, Finding, Severity};
use crate::util::{self, MAX_PER_RULE};

pub fn all() -> Vec<Box<dyn Analyzer>> {
    vec![Box::new(SlowRequests)]
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
