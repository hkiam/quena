//! Clock differences between the servers and this computer, from the `Date` response header.
//!
//! * CLOCK-SKEW: a host's clock differs from this computer's by ≥ 30 s (warning ≥ 60 s,
//!   critical ≥ 5 min — Kerberos' default tolerance; token libraries often allow only 60 s).
//! * CLOCK-LOCAL: several unrelated sites differ by about the same amount in the same
//!   direction — then this computer's clock is the likely culprit (reported once instead of
//!   per host).
//! * CLOCK-DRIFT: the responses of one host carry times that disagree with each other by
//!   ≥ 30 s — servers behind one name (load balancer) with unsynchronised clocks.
//!
//! The offset of a response is `Date + Age − local time of the first response byte`, plus
//! 0.5 s because `Date` is truncated to whole seconds. Network delay and the time the server
//! took before writing the header make it slightly negative; the thresholds are far above that.
use crate::model::{Analyzer, Confidence, Ctx, Finding, Session, Severity};
use crate::util;
use std::collections::HashMap;

pub fn all() -> Vec<Box<dyn Analyzer>> {
    vec![Box::new(Clocks)]
}

const SKEW_INFO_S: f64 = 30.0;
const SKEW_WARN_S: f64 = 60.0;
const SKEW_CRIT_S: f64 = 300.0;
/// Several sites agree within this (or 10 % of the offset) → this computer's clock.
const LOCAL_AGREE_S: f64 = 10.0;
const LOCAL_MIN_SITES: usize = 3;
const DRIFT_MIN_SAMPLES: usize = 5;
const DRIFT_SPREAD_S: f64 = 30.0;

/// Offset of the server clock against this computer for one response, in seconds.
pub fn offset_s(s: &Session) -> Option<(f64, bool)> {
    if !s.is_http() || s.status == 0 {
        return None;
    }
    let date = util::parse_http_date(s.resp_header("date")?)? as f64;
    let age = s.resp_header("age").and_then(|a| a.trim().parse::<f64>().ok()).filter(|a| a.is_finite() && *a >= 0.0).unwrap_or(0.0).min(1e8);
    let local_us = s.timers.server_got_first_byte.or(s.timers.client_done_response).unwrap_or_else(|| s.end());
    Some((date + age + 0.5 - local_us as f64 / 1e6, age > 0.0))
}

/// `a.b.example.com:443` → `example.com` (groups hosts of one site).
fn site(host: &str) -> String {
    let h = host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map(|(h, _)| h).unwrap_or(host);
    if h.parse::<std::net::IpAddr>().is_ok() || h.starts_with('[') {
        return h.to_string();
    }
    let labels: Vec<&str> = h.split('.').filter(|l| !l.is_empty()).collect();
    labels[labels.len().saturating_sub(2)..].join(".").to_ascii_lowercase()
}

struct HostClock<'a> {
    host: &'a str,
    offsets: Vec<f64>,
    fresh: Vec<f64>,
    ids: Vec<u64>,
}

impl HostClock<'_> {
    fn median(&self) -> f64 {
        util::percentile(&self.offsets, 50.0)
    }
}

fn severity_for(abs_s: f64) -> Severity {
    if abs_s >= SKEW_CRIT_S {
        Severity::Critical
    } else if abs_s >= SKEW_WARN_S {
        Severity::Warning
    } else {
        Severity::Info
    }
}

/// "+2 min 5 s (server ahead)" / "−45 s (server behind)".
fn describe(ctx: &Ctx, offset: f64) -> String {
    let t = ctx.fmt_ms(offset.abs() * 1000.0);
    match (offset >= 0.0, ctx.de()) {
        (true, true) => format!("+{t} (Server geht vor)"),
        (true, false) => format!("+{t} (server ahead)"),
        (false, true) => format!("−{t} (Server geht nach)"),
        (false, false) => format!("−{t} (server behind)"),
    }
}

fn impact(ctx: &Ctx) -> &'static str {
    ctx.l(
        "Time-based checks fail although everything else is right: Kerberos rejects tickets beyond 5 minutes (KRB_AP_ERR_SKEW), JWT/OIDC and SAML libraries reject tokens as “not yet valid” or “expired” (nbf/exp/iat, often only 60 s leeway), signed URLs (e.g. X-Amz-Date) and one-time codes (TOTP) stop working, cookies and cache lifetimes expire too early or too late, and logs of client and server no longer line up.",
        "Zeitbasierte Prüfungen schlagen fehl, obwohl sonst alles stimmt: Kerberos lehnt Tickets ab 5 Minuten Abweichung ab (KRB_AP_ERR_SKEW), JWT-/OIDC- und SAML-Bibliotheken weisen Tokens als „noch nicht gültig“ oder „abgelaufen“ zurück (nbf/exp/iat, oft nur 60 s Toleranz), signierte URLs (z. B. X-Amz-Date) und Einmalcodes (TOTP) funktionieren nicht mehr, Cookies und Cache-Lebensdauern laufen zu früh oder zu spät ab, und die Protokolle von Client und Server passen zeitlich nicht mehr zusammen.",
    )
}

struct Clocks;

impl Analyzer for Clocks {
    fn id(&self) -> &'static str {
        "CLOCK-SKEW"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["troubleshooting", "auth", "resilience"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let mut hosts: Vec<HostClock> = vec![];
        let mut index: HashMap<&str, usize> = HashMap::new();
        for s in ctx.http() {
            let Some((off, cached)) = offset_s(s) else { continue };
            let i = *index.entry(s.host.as_str()).or_insert_with(|| {
                hosts.push(HostClock { host: s.host.as_str(), offsets: vec![], fresh: vec![], ids: vec![] });
                hosts.len() - 1
            });
            let h = &mut hosts[i];
            h.offsets.push(off);
            if !cached {
                h.fresh.push(off);
            }
            h.ids.push(s.id);
        }
        if hosts.is_empty() {
            return;
        }

        // 1. This computer's clock: most sites with a sample are off by about the same amount.
        let skewed: Vec<&HostClock> = hosts.iter().filter(|h| h.median().abs() >= SKEW_INFO_S).collect();
        let mut by_site: HashMap<String, Vec<f64>> = HashMap::new();
        for h in &skewed {
            by_site.entry(site(h.host)).or_default().push(h.median());
        }
        let all_sites: std::collections::HashSet<String> = hosts.iter().map(|h| site(h.host)).collect();
        let site_medians: Vec<f64> = by_site.values().map(|v| util::percentile(v, 50.0)).collect();
        let overall = util::percentile(&site_medians, 50.0);
        let agree = site_medians.iter().all(|m| m.signum() == overall.signum() && (m - overall).abs() <= LOCAL_AGREE_S.max(overall.abs() * 0.1));
        let local = by_site.len() >= LOCAL_MIN_SITES && agree && by_site.len() * 10 >= all_sites.len() * 6;
        let mut findings = vec![];
        if local {
            let ids: Vec<u64> = skewed.iter().flat_map(|h| h.ids.iter().copied()).collect();
            let n_sites = by_site.len();
            let mut f = Finding::new(
                "CLOCK-LOCAL",
                "",
                severity_for(overall.abs()),
                ctx.l("This computer's clock is probably wrong", "Die Uhr dieses Computers geht vermutlich falsch"),
                if ctx.de() {
                    format!("{} voneinander unabhängige Sites melden übereinstimmend eine um {} abweichende Zeit – dass sie sich alle gleich irren, ist unwahrscheinlich.", ctx.fmt_count(n_sites), describe(ctx, overall))
                } else {
                    format!("{} unrelated sites agree on a time that differs by {} — it is unlikely that they are all wrong in the same way.", ctx.fmt_count(n_sites), describe(ctx, overall))
                },
            )
            .categories(&["clock", "troubleshooting"])
            .score(util::scale(overall.abs(), SKEW_INFO_S, SKEW_CRIT_S * 2.0))
            .threshold(if ctx.de() {
                format!("≥ {LOCAL_MIN_SITES} Sites mit ≥ {} Abweichung in dieselbe Richtung (auf ±{} einig)", ctx.fmt_ms(SKEW_INFO_S * 1000.0), ctx.fmt_ms(LOCAL_AGREE_S * 1000.0))
            } else {
                format!("≥ {LOCAL_MIN_SITES} sites off by ≥ {} in the same direction (agreeing within ±{})", ctx.fmt_ms(SKEW_INFO_S * 1000.0), ctx.fmt_ms(LOCAL_AGREE_S * 1000.0))
            })
            .fact(ctx.l("Servers vs. this computer", "Server gegenüber diesem Computer"), describe(ctx, overall))
            .fact(ctx.l("Sites", "Sites"), ctx.fmt_count(n_sites))
            .impact(impact(ctx))
            .hypothesis(ctx.l(
                "The computer (or VM) that recorded the traffic has no working time synchronisation (NTP / Windows Time), or its time zone setting is wrong while its clock is set to local time.",
                "Der Computer (oder die VM), auf dem aufgezeichnet wurde, hat keine funktionierende Zeitsynchronisation (NTP / Windows-Zeitdienst), oder die Zeitzone ist falsch eingestellt, während die Uhr auf Ortszeit steht.",
            ))
            .recommend(ctx.l("Synchronise the clock (NTP; on Windows: w32tm /resync) and check the time zone.", "Die Uhr synchronisieren (NTP; unter Windows: w32tm /resync) und die Zeitzone prüfen."))
            .recommend(ctx.l("If the capture was imported, the offset belongs to the computer it was recorded on.", "Stammt die Aufnahme aus einem Import, gehört die Abweichung zu dem Computer, auf dem aufgezeichnet wurde."))
            .sessions(ids)
            .tags(&["clock"]);
            if site_medians.len() < 5 {
                f = f.confidence(Confidence::Medium);
            }
            findings.push(f);
        }

        // 2. Per host (unless explained by this computer's clock).
        for h in &hosts {
            let m = h.median();
            if local || m.abs() < SKEW_INFO_S {
                continue;
            }
            let (lo, hi) = (h.offsets.iter().cloned().fold(f64::MAX, f64::min), h.offsets.iter().cloned().fold(f64::MIN, f64::max));
            let n = h.offsets.len();
            let mut f = Finding::new(
                "CLOCK-SKEW",
                h.host,
                severity_for(m.abs()),
                format!("{} {}", ctx.l("Server clock differs:", "Serveruhr weicht ab:"), h.host),
                if ctx.de() {
                    format!("Die Uhr von {} weicht um {} von diesem Computer ab (aus dem Date-Header von {} Responses).", h.host, describe(ctx, m), ctx.fmt_count(n))
                } else {
                    format!("The clock of {} differs from this computer by {} (from the Date header of {} responses).", h.host, describe(ctx, m), ctx.fmt_count(n))
                },
            )
            .categories(&["clock", "troubleshooting"])
            .score(util::scale(m.abs(), SKEW_INFO_S, SKEW_CRIT_S * 2.0))
            .threshold(if ctx.de() {
                format!("≥ {}; Warnung ab {}, kritisch ab {} (Kerberos-Standardtoleranz)", ctx.fmt_ms(SKEW_INFO_S * 1000.0), ctx.fmt_ms(SKEW_WARN_S * 1000.0), ctx.fmt_ms(SKEW_CRIT_S * 1000.0))
            } else {
                format!("≥ {}; warning from {}, critical from {} (Kerberos' default tolerance)", ctx.fmt_ms(SKEW_INFO_S * 1000.0), ctx.fmt_ms(SKEW_WARN_S * 1000.0), ctx.fmt_ms(SKEW_CRIT_S * 1000.0))
            })
            .fact(ctx.l("Offset (median)", "Abweichung (Median)"), describe(ctx, m))
            .fact(ctx.l("Range", "Spanne"), format!("{} … {}", describe(ctx, lo), describe(ctx, hi)))
            .fact(ctx.l("Responses with a Date header", "Responses mit Date-Header"), ctx.fmt_count(n))
            .impact(impact(ctx))
            .hypothesis(ctx.l(
                "The server (or the proxy/CDN that sets the Date header) has no working time synchronisation.",
                "Der Server (oder der Proxy/das CDN, der bzw. das den Date-Header setzt) hat keine funktionierende Zeitsynchronisation.",
            ))
            .recommend(ctx.l("Check NTP on the server and on the proxies in front of it.", "NTP auf dem Server und den vorgeschalteten Proxys prüfen."))
            .next_step(ctx.l("Compare with other hosts in this report: if all show the same offset, the local clock is wrong instead.", "Mit anderen Hosts in diesem Bericht vergleichen: zeigen alle dieselbe Abweichung, geht stattdessen die lokale Uhr falsch."))
            .sessions(h.ids.iter().copied())
            .tags(&["clock"]);
            if n < 3 {
                f = f.confidence(Confidence::Medium);
            }
            findings.push(f);
        }
        crate::analyzers::request::emit(ctx, out, findings);

        // 3. Servers behind one name disagree with each other.
        let mut drift = vec![];
        for h in &hosts {
            if h.fresh.len() < DRIFT_MIN_SAMPLES {
                continue;
            }
            let (p10, p90) = (util::percentile(&h.fresh, 10.0), util::percentile(&h.fresh, 90.0));
            let spread = p90 - p10;
            if spread < DRIFT_SPREAD_S {
                continue;
            }
            drift.push(
                Finding::new(
                    "CLOCK-DRIFT",
                    h.host,
                    if spread >= SKEW_CRIT_S { Severity::Critical } else { Severity::Warning },
                    format!("{} {}", ctx.l("Server clocks disagree behind", "Serveruhren uneinig hinter"), h.host),
                    if ctx.de() {
                        format!("Die Responses von {} tragen Zeiten, die um {} auseinanderliegen (10.–90. Perzentil) – wahrscheinlich mehrere Server hinter einem Namen mit unterschiedlich gehenden Uhren.", h.host, ctx.fmt_ms(spread * 1000.0))
                    } else {
                        format!("The responses of {} carry times that are {} apart (10th–90th percentile) — probably several servers behind one name whose clocks differ.", h.host, ctx.fmt_ms(spread * 1000.0))
                    },
                )
                .categories(&["clock", "troubleshooting"])
                .score(util::scale(spread, DRIFT_SPREAD_S, SKEW_CRIT_S * 2.0))
                .threshold(if ctx.de() {
                    format!("≥ {} Streuung bei ≥ {DRIFT_MIN_SAMPLES} ungecachten Responses", ctx.fmt_ms(DRIFT_SPREAD_S * 1000.0))
                } else {
                    format!("≥ {} spread over ≥ {DRIFT_MIN_SAMPLES} uncached responses", ctx.fmt_ms(DRIFT_SPREAD_S * 1000.0))
                })
                .fact(ctx.l("Earliest / latest offset", "Kleinste / größte Abweichung"), format!("{} / {}", describe(ctx, p10), describe(ctx, p90)))
                .fact(ctx.l("Responses", "Responses"), ctx.fmt_count(h.fresh.len()))
                .impact(ctx.l(
                    "Whether a token, ticket or signed URL is accepted depends on which server answers: errors come and go without a pattern (“works on retry”).",
                    "Ob ein Token, Ticket oder eine signierte URL akzeptiert wird, hängt davon ab, welcher Server antwortet: Fehler kommen und gehen ohne erkennbares Muster („klappt beim zweiten Versuch“).",
                ))
                .hypothesis(ctx.l("Nodes behind a load balancer synchronise their time differently (or not at all).", "Knoten hinter einem Load Balancer synchronisieren ihre Zeit unterschiedlich (oder gar nicht)."))
                .recommend(ctx.l("Synchronise all nodes against the same time source.", "Alle Knoten gegen dieselbe Zeitquelle synchronisieren."))
                .next_step(ctx.l("Look for a response header that names the node (e.g. X-Served-By, Server) to find the one that is off.", "Nach einem Response-Header suchen, der den Knoten nennt (z. B. X-Served-By, Server), um den abweichenden zu finden."))
                .sessions(h.ids.iter().copied())
                .tags(&["clock"])
                .confidence(if h.fresh.len() >= 10 { Confidence::High } else { Confidence::Medium }),
            );
        }
        crate::analyzers::request::emit(ctx, out, drift);
    }
}
