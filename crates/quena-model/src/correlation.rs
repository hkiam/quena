//! Keys that tie requests together beyond the connection: the trace or correlation id a
//! client sends, and the session cookie. Used to group the session list.

use crate::Headers;

/// Longest key kept (ids are short; anything longer is cut).
const MAX_KEY: usize = 64;

fn cut(s: &str) -> String {
    let s = s.trim();
    let mut end = s.len().min(MAX_KEY);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// The trace id of a request: W3C `traceparent`, B3, Jaeger, AWS X-Ray, Google Cloud, or a
/// correlation id header. Empty when there is none.
pub fn trace_id(h: &Headers) -> String {
    if let Some(v) = h.get("traceparent") {
        // version-traceid-spanid-flags
        if let Some(t) = v.split('-').nth(1).filter(|t| t.len() == 32) {
            return cut(t);
        }
    }
    if let Some(v) = h.get("x-b3-traceid") {
        return cut(v);
    }
    if let Some(v) = h.get("b3") {
        return cut(v.split('-').next().unwrap_or(""));
    }
    if let Some(v) = h.get("uber-trace-id") {
        return cut(v.split(':').next().unwrap_or(""));
    }
    if let Some(root) = h
        .get("x-amzn-trace-id")
        .and_then(|v| v.split(';').find_map(|p| p.trim().strip_prefix("Root=")))
    {
        return cut(root);
    }
    if let Some(v) = h.get("x-cloud-trace-context") {
        return cut(v.split(['/', ';']).next().unwrap_or(""));
    }
    for name in [
        "x-correlation-id",
        "x-correlationid",
        "correlation-id",
        "x-request-correlation-id",
    ] {
        if let Some(v) = h.get(name) {
            return cut(v);
        }
    }
    String::new()
}

/// Cookie names of common server sessions (case-insensitive; `ASPSESSIONID…` as a prefix).
const SESSION_COOKIES: &[&str] = &[
    "jsessionid",
    "phpsessid",
    "asp.net_sessionid",
    "connect.sid",
    "sessionid",
    "session",
    "session_id",
    "_session_id",
    "sid",
    "laravel_session",
    "ci_session",
    "cfid",
    "jwt_session",
];

/// The session cookie of a request as `NAME #hash` (the value itself never leaves the
/// detail: equal values give equal keys, and the list shows no secret). Empty when none.
pub fn session_key(h: &Headers) -> String {
    for line in h.get_all("cookie") {
        for pair in line.split(';') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            let (name, value) = (name.trim(), value.trim());
            let lower = name.to_ascii_lowercase();
            if value.is_empty()
                || !(SESSION_COOKIES.contains(&lower.as_str()) || lower.starts_with("aspsessionid"))
            {
                continue;
            }
            return format!("{} #{:08x}", cut(name), fnv1a(value.as_bytes()) as u32);
        }
    }
    String::new()
}

fn fnv1a(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &x| {
        (h ^ x as u64).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Headers {
        Headers(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn trace_ids() {
        assert_eq!(
            trace_id(&h(&[(
                "traceparent",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
            )])),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(
            trace_id(&h(&[(
                "b3",
                "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1"
            )])),
            "80f198ee56343ba864fe8b2a57d3eff7"
        );
        assert_eq!(trace_id(&h(&[("uber-trace-id", "abc:def:0:1")])), "abc");
        assert_eq!(
            trace_id(&h(&[(
                "X-Amzn-Trace-Id",
                "Self=1-x;Root=1-5759e988-bd862e3fe1be46a994272793;Sampled=1"
            )])),
            "1-5759e988-bd862e3fe1be46a994272793"
        );
        assert_eq!(trace_id(&h(&[("X-Correlation-ID", " c-42 ")])), "c-42");
        assert_eq!(trace_id(&h(&[("traceparent", "garbage")])), "");
        assert_eq!(trace_id(&h(&[])), "");
        assert_eq!(
            trace_id(&h(&[("x-correlation-id", &"x".repeat(200))])).len(),
            MAX_KEY
        );
    }

    #[test]
    fn session_cookies() {
        let a = session_key(&h(&[("Cookie", "theme=dark; JSESSIONID=ABC123; x=1")]));
        assert!(
            a.starts_with("JSESSIONID #") && !a.contains("ABC123"),
            "{a}"
        );
        assert_eq!(a, session_key(&h(&[("cookie", "JSESSIONID=ABC123")])));
        assert_ne!(a, session_key(&h(&[("cookie", "JSESSIONID=ABC124")])));
        assert!(
            session_key(&h(&[("cookie", "ASPSESSIONIDQQGRTDTA=XYZ")]))
                .starts_with("ASPSESSIONIDQQGRTDTA #")
        );
        assert_eq!(session_key(&h(&[("cookie", "theme=dark; sessionid=")])), "");
        assert_eq!(session_key(&h(&[])), "");
    }
}
