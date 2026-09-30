//! Diagnostic profiles: which question the report answers.
use crate::model::Lang;

pub struct Profile {
    pub id: &'static str,
    pub name: (&'static str, &'static str),
    pub description: (&'static str, &'static str),
}

pub const PROFILES: &[Profile] = &[
    Profile {
        id: "full",
        name: ("Full diagnostic", "Vollständige Diagnose"),
        description: ("All checks.", "Alle Prüfungen."),
    },
    Profile {
        id: "performance",
        name: ("Performance", "Performance"),
        description: (
            "Latency, slow and large requests, sequential chains, duplicates, polling, compression, caching.",
            "Latenz, langsame und große Requests, sequenzielle Ketten, Duplikate, Polling, Kompression, Caching.",
        ),
    },
    Profile {
        id: "troubleshooting",
        name: ("Troubleshooting", "Fehlersuche"),
        description: (
            "HTTP errors, connection failures, timeouts, retries, redirects, authentication, TLS, cookies, CORS.",
            "HTTP-Fehler, Verbindungsabbrüche, Timeouts, Wiederholungen, Weiterleitungen, Anmeldung, TLS, Cookies, CORS.",
        ),
    },
    Profile {
        id: "auth",
        name: ("Authentication", "Anmeldung"),
        description: (
            "401/403, repeated authentication, NTLM/Kerberos handshakes, token and cookie problems.",
            "401/403, wiederholte Anmeldung, NTLM-/Kerberos-Handshakes, Token- und Cookie-Probleme.",
        ),
    },
    Profile {
        id: "resilience",
        name: ("Network resilience", "Netzrobustheit"),
        description: (
            "How the traffic behaves on slow, high-latency or unstable networks.",
            "Wie sich der Verkehr bei langsamen, latenzreichen oder instabilen Netzen verhält.",
        ),
    },
    Profile {
        id: "modernization",
        name: ("Modernization", "Modernisierung"),
        description: (
            "Communication patterns not to carry over: chatty APIs, polling, large payloads, sequential calls, missing caching.",
            "Kommunikationsmuster, die nicht übernommen werden sollten: gesprächige APIs, Polling, große Payloads, sequenzielle Aufrufe, fehlendes Caching.",
        ),
    },
];

pub fn get(id: &str) -> &'static Profile {
    PROFILES.iter().find(|p| p.id == id).unwrap_or(&PROFILES[0])
}

pub fn pick(pair: (&'static str, &'static str), lang: Lang) -> &'static str {
    if lang == Lang::De { pair.1 } else { pair.0 }
}
