//! SCOPE-MIXED: the analysed traffic mixes several applications.
//!
//! Captures are system-wide: a browser, a chat client and an updater end up in one list.
//! Mixed traffic dilutes the findings (duplicates, chattiness, capture metrics describe the
//! mix, not the application under test), so the report says so and recommends narrowing the
//! scope to one process or target host.
use crate::model::{Analyzer, Confidence, Ctx, Finding, Severity};
use crate::util;

pub fn all() -> Vec<Box<dyn Analyzer>> {
    vec![Box::new(MixedScope)]
}

/// A process counts from this share of the HTTP requests on.
const SIGNIFICANT_SHARE: f64 = 0.10;
/// Unrelated site groups (registrable-ish domains) from this count on.
const MANY_SITES: usize = 8;

/// `a.b.example.com:443` → `example.com` (last two labels; good enough to group sites).
fn site(host: &str) -> String {
    let h = host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map(|(h, _)| h).unwrap_or(host);
    if h.parse::<std::net::IpAddr>().is_ok() || h.starts_with('[') {
        return h.to_string();
    }
    let labels: Vec<&str> = h.split('.').filter(|l| !l.is_empty()).collect();
    labels[labels.len().saturating_sub(2)..].join(".").to_ascii_lowercase()
}

struct MixedScope;

impl Analyzer for MixedScope {
    fn id(&self) -> &'static str {
        "SCOPE-MIXED"
    }
    fn profiles(&self) -> &'static [&'static str] {
        &["performance", "troubleshooting", "auth", "resilience", "modernization"]
    }
    fn run(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let http: Vec<_> = ctx.http().collect();
        let n = http.len();
        if n < 20 {
            return;
        }
        let mut procs = util::group_by(http.iter().copied(), |s| if s.process.is_empty() { "?".to_string() } else { s.process.clone() });
        procs.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
        let significant: Vec<_> = procs.iter().filter(|(_, v)| v.len() as f64 / n as f64 >= SIGNIFICANT_SHARE).collect();
        let mut sites = util::group_by(http.iter().copied(), |s| site(&s.host));
        sites.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
        let many_sites = sites.len() >= MANY_SITES && sites.iter().filter(|(_, v)| v.len() as f64 / n as f64 >= 0.02).count() >= MANY_SITES;
        if significant.len() < 2 && !many_sites {
            return;
        }
        let severity = if significant.len() >= 3 { Severity::Warning } else { Severity::Info };
        let top = |v: &Vec<(String, Vec<&crate::model::Session>)>| -> Vec<Vec<String>> {
            v.iter().take(8).map(|(k, list)| vec![k.clone(), ctx.fmt_count(list.len()), ctx.fmt_pct(list.len() as f64 / n as f64)]).collect()
        };
        let obs = if ctx.de() {
            format!(
                "Der analysierte Verkehr stammt von {} Prozessen ({} davon mit ≥ {} der Requests) und {} Sites.",
                ctx.fmt_count(procs.len()),
                ctx.fmt_count(significant.len()),
                ctx.fmt_pct(SIGNIFICANT_SHARE),
                ctx.fmt_count(sites.len())
            )
        } else {
            format!(
                "The analysed traffic comes from {} processes ({} of them with ≥ {} of the requests) and {} sites.",
                ctx.fmt_count(procs.len()),
                ctx.fmt_count(significant.len()),
                ctx.fmt_pct(SIGNIFICANT_SHARE),
                ctx.fmt_count(sites.len())
            )
        };
        let mut rows = top(&procs);
        rows.extend(top(&sites).into_iter().map(|mut r| {
            r[0] = format!("{} {}", ctx.l("site", "Site"), r[0]);
            r
        }));
        out.push(
            Finding::new("SCOPE-MIXED", "", severity, ctx.l("Mixed traffic: results may be diluted", "Gemischter Verkehr: Ergebnisse können verwässert sein"), obs)
                .categories(&["scope"])
                .confidence(Confidence::High)
                .score(util::scale(significant.len() as f64, 1.0, 5.0))
                .threshold(if ctx.de() {
                    format!("≥ 2 Prozesse mit je ≥ {} der Requests oder ≥ {MANY_SITES} Sites", ctx.fmt_pct(SIGNIFICANT_SHARE))
                } else {
                    format!("≥ 2 processes with ≥ {} of the requests each, or ≥ {MANY_SITES} sites", ctx.fmt_pct(SIGNIFICANT_SHARE))
                })
                .impact(ctx.l(
                    "Duplicates, chattiness, operations and the capture metrics describe the mix of applications, not the application under test; unrelated traffic can hide or fake patterns.",
                    "Duplikate, Gesprächigkeit, Vorgänge und die Kennzahlen beschreiben die Mischung der Anwendungen, nicht die untersuchte Anwendung; fremder Verkehr kann Muster verdecken oder vortäuschen.",
                ))
                .recommend(ctx.l(
                    "Narrow the scope to the process or target host under test (Diagnostics → Scope), or filter the list first.",
                    "Den Umfang auf den untersuchten Prozess oder Zielhost einschränken (Diagnose → Umfang) oder die Liste vorher filtern.",
                ))
                .recommend(ctx.l(
                    "For a single user action, select its sessions and analyse the selection.",
                    "Für eine einzelne Benutzeraktion deren Sessions auswählen und die Auswahl analysieren.",
                ))
                .table(vec![ctx.l("Process / site", "Prozess / Site").into(), ctx.l("Requests", "Requests").into(), ctx.l("Share", "Anteil").into()], rows)
                .tags(&["scope"]),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::testkit::*;

    fn mix(procs: &[(&str, u64)]) -> Vec<crate::model::Session> {
        let mut v = vec![];
        let mut id = 0;
        for (p, n) in procs {
            for _ in 0..*n {
                let mut s = get(id, &format!("https://{p}.test/x{}", id % 3)).at(id * 700);
                s.process = p.to_string();
                v.push(s);
                id += 1;
            }
        }
        v
    }

    #[test]
    fn mixed_processes_are_reported() {
        let f = analyse(mix(&[("chrome", 40), ("teams", 30), ("updater", 20)]), "{}");
        let m = of(&f, "SCOPE-MIXED");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].severity, crate::model::Severity::Warning);
        assert!(m[0].table.as_ref().unwrap().rows[0][0] == "chrome");
    }

    #[test]
    fn one_application_is_fine() {
        assert!(of(&analyse(mix(&[("app", 60), ("other", 3)]), "{}"), "SCOPE-MIXED").is_empty());
        assert!(of(&analyse(mix(&[("a", 5), ("b", 5)]), "{}"), "SCOPE-MIXED").is_empty(), "too small to judge");
        assert_eq!(super::site("a.b.example.com:443"), "example.com");
        assert_eq!(super::site("127.0.0.1:8080"), "127.0.0.1");
    }
}
