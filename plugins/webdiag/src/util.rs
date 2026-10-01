//! Small helpers shared by the analyzers.
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hash, Hasher};

/// A fast, non-cryptographic hasher (the "Fx" hash of rustc) for internal maps whose keys
/// do not come from an adversary that could force collisions (session-derived strings and
/// ids of one capture). Results never depend on hash order: maps that are iterated are
/// sorted or keep insertion order.
#[derive(Default, Clone, Copy)]
pub struct FxHasher(u64);

const FX_SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

impl FxHasher {
    #[inline]
    fn add(&mut self, w: u64) {
        self.0 = (self.0.rotate_left(5) ^ w).wrapping_mul(FX_SEED);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut c = bytes.chunks_exact(8);
        for w in &mut c {
            self.add(u64::from_le_bytes(w.try_into().unwrap_or([0; 8])));
        }
        let r = c.remainder();
        if !r.is_empty() {
            let mut b = [0u8; 8];
            b[..r.len()].copy_from_slice(r);
            self.add(u64::from_le_bytes(b));
        }
    }
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

/// `HashMap` with [`FxHasher`].
pub type FxHashMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;
/// `HashSet` with [`FxHasher`].
pub type FxHashSet<K> = std::collections::HashSet<K, BuildHasherDefault<FxHasher>>;

/// Group items by key, keeping the order in which keys first appear.
pub fn group_by<T, K: Hash + Eq + Clone>(items: impl IntoIterator<Item = T>, key: impl Fn(&T) -> K) -> Vec<(K, Vec<T>)> {
    let mut idx: FxHashMap<K, usize> = FxHashMap::default();
    let mut out: Vec<(K, Vec<T>)> = vec![];
    for it in items {
        let k = key(&it);
        match idx.get(&k) {
            Some(&i) => out[i].1.push(it),
            None => {
                idx.insert(k.clone(), out.len());
                out.push((k, vec![it]));
            }
        }
    }
    out
}

/// Percentile (0–100) of unsorted values; 0 for none.
pub fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    let rank = (p / 100.0 * (v.len() - 1) as f64).round() as usize;
    v[rank.min(v.len() - 1)]
}

/// Mean and coefficient of variation (stddev / mean).
pub fn mean_cv(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let var = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    (mean, if mean > 0.0 { var.sqrt() / mean } else { 0.0 })
}

/// Shorten a URL/endpoint for titles.
pub fn short(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Map a value between `lo` and `hi` linearly to 0–100 (clamped): impact scores.
pub fn scale(v: f64, lo: f64, hi: f64) -> f64 {
    if hi <= lo {
        return 50.0;
    }
    ((v - lo) / (hi - lo) * 100.0).clamp(0.0, 100.0)
}

/// At most this many findings per rule; the rest is summarised in the last one.
pub const MAX_PER_RULE: usize = 10;

// ------------------------------------------------------------------ header and time helpers

/// Byte count of a redacted value such as `Bearer <812 bytes>` or `<40 bytes>`.
pub fn redacted_bytes(v: &str) -> Option<u64> {
    let rest = &v[v.find('<')? + 1..];
    let (n, tail) = rest.split_once(' ')?;
    (tail.starts_with("bytes>") || tail.starts_with("byte>")).then(|| n.trim().parse().ok())?
}

/// Scheme of a (redacted) authentication header: `Bearer <812 bytes>` → `Bearer`.
pub fn auth_scheme(v: &str) -> String {
    v.split(|c: char| c.is_whitespace() || c == ',').find(|t| !t.is_empty()).unwrap_or("").to_string()
}

/// Largest number of timestamps (sorted ascending) inside any window of length `window`.
pub fn max_in_window(sorted: &[u64], window: u64) -> usize {
    let mut best = 0;
    let mut lo = 0;
    for hi in 0..sorted.len() {
        while sorted[hi].saturating_sub(sorted[lo]) > window {
            lo += 1;
        }
        best = best.max(hi - lo + 1);
    }
    best
}

/// Largest number of overlapping `(start, end)` intervals (an interval ending when another
/// starts does not overlap it).
pub fn max_concurrency(intervals: &[(u64, u64)]) -> usize {
    let mut ev: Vec<(u64, i32)> = Vec::with_capacity(intervals.len() * 2);
    for &(s, e) in intervals {
        ev.push((s, 1));
        ev.push((e.max(s), -1));
    }
    ev.sort_unstable();
    let (mut cur, mut best) = (0i32, 0i32);
    for (_, d) in ev {
        cur += d;
        best = best.max(cur);
    }
    best.max(0) as usize
}

/// Protocol version of a TLS/SSL name (`TLSv1.2`, `Tls12`, `TLS 1.0`, `SSLv3`):
/// TLS 1.x → `(1, x)`, SSL n → `(0, n)`; `None` if not recognised.
pub fn tls_version(v: &str) -> Option<(u8, u8)> {
    let s: String = v.to_ascii_lowercase().chars().filter(|c| !c.is_whitespace() && *c != '_').collect();
    let (ssl, rest) = if let Some(r) = s.strip_prefix("ssl") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("tls") {
        (false, r)
    } else {
        return None;
    };
    let digits: Vec<u8> = rest.trim_start_matches('v').chars().filter_map(|c| c.to_digit(10)).map(|d| d as u8).collect();
    if ssl {
        return Some((0, digits.first().copied().unwrap_or(3)));
    }
    match digits.as_slice() {
        [] | [1] => Some((1, 0)),
        [1, m, ..] => Some((1, *m)),
        _ => None,
    }
}

/// A redacted `Set-Cookie` value: `name=<n bytes>; attributes…`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetCookie {
    pub name: String,
    /// Value size (from the redaction, or the plain value length).
    pub bytes: Option<u64>,
    pub secure: bool,
    pub http_only: bool,
    /// Lower-case `SameSite` value.
    pub same_site: Option<String>,
    /// Deletes the cookie (empty value, `Max-Age` ≤ 0 or an expiry in 1970).
    pub deletes: bool,
}

pub fn set_cookie(v: &str) -> SetCookie {
    let mut parts = v.split(';');
    let first = parts.next().unwrap_or("");
    let (name, value) = first.split_once('=').unwrap_or((first, ""));
    let value = value.trim();
    let bytes = redacted_bytes(value).or(if value.starts_with('<') { None } else { Some(value.len() as u64) });
    let mut c = SetCookie { name: name.trim().to_string(), bytes, ..Default::default() };
    for a in parts {
        let a = a.trim();
        let (k, val) = a.split_once('=').unwrap_or((a, ""));
        let (k, val) = (k.trim(), val.trim());
        if k.eq_ignore_ascii_case("secure") {
            c.secure = true;
        } else if k.eq_ignore_ascii_case("httponly") {
            c.http_only = true;
        } else if k.eq_ignore_ascii_case("samesite") {
            c.same_site = Some(val.to_ascii_lowercase());
        } else if (k.eq_ignore_ascii_case("max-age") && val.parse::<i64>().is_ok_and(|n| n <= 0)) || (k.eq_ignore_ascii_case("expires") && val.contains("1970")) {
            c.deletes = true;
        }
    }
    if c.bytes == Some(0) {
        c.deletes = true;
    }
    c
}

#[cfg(test)]
mod header_helper_tests {
    use super::*;

    #[test]
    fn redaction_forms() {
        assert_eq!(redacted_bytes("Bearer <812 bytes>"), Some(812));
        assert_eq!(redacted_bytes("<1 byte>"), Some(1));
        assert_eq!(redacted_bytes("Bearer realm, error"), None);
        assert_eq!(redacted_bytes("<"), None);
        assert_eq!(auth_scheme("Negotiate <1320 bytes>"), "Negotiate");
        assert_eq!(auth_scheme("  Bearer, NTLM"), "Bearer");
        assert_eq!(auth_scheme(""), "");
    }

    #[test]
    fn windows_and_concurrency() {
        assert_eq!(max_in_window(&[0, 10, 20, 100, 105, 110, 115], 20), 4);
        assert_eq!(max_in_window(&[], 5), 0);
        assert_eq!(max_concurrency(&[(0, 10), (5, 15), (10, 20), (6, 7)]), 3);
        assert_eq!(max_concurrency(&[(0, 10), (10, 20)]), 1);
        assert_eq!(max_concurrency(&[]), 0);
    }

    #[test]
    fn tls_names() {
        assert_eq!(tls_version("TLSv1.2"), Some((1, 2)));
        assert_eq!(tls_version("Tls12"), Some((1, 2)));
        assert_eq!(tls_version("TLS 1.0"), Some((1, 0)));
        assert_eq!(tls_version("Tls"), Some((1, 0)));
        assert_eq!(tls_version("tls1.3"), Some((1, 3)));
        assert_eq!(tls_version("SSLv3"), Some((0, 3)));
        assert_eq!(tls_version("h2"), None);
        assert_eq!(tls_version(""), None);
    }

    #[test]
    fn set_cookie_forms() {
        let c = set_cookie("sid=<32 bytes>; Path=/; Secure; HttpOnly; SameSite=None");
        assert_eq!((c.name.as_str(), c.bytes, c.secure, c.http_only, c.same_site.as_deref(), c.deletes), ("sid", Some(32), true, true, Some("none"), false));
        let d = set_cookie("x=<5 bytes>; Max-Age=0");
        assert!(d.deletes && !d.secure);
        assert!(set_cookie("y=; expires=Thu, 01 Jan 1970 00:00:00 GMT").deletes);
        let e = set_cookie("");
        assert_eq!(e.name, "");
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// An HTTP date (IMF-fixdate, `Sun, 06 Nov 1994 08:49:37 GMT`) in seconds since the epoch.
pub fn parse_http_date(s: &str) -> Option<u64> {
    let p: Vec<&str> = s.split_whitespace().collect();
    if p.len() != 6 || !p[5].eq_ignore_ascii_case("GMT") {
        return None;
    }
    let day: u32 = p[1].parse().ok()?;
    const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let month = MONTHS.iter().position(|m| p[2].eq_ignore_ascii_case(m))? as u32 + 1;
    let year: i64 = p[3].parse().ok()?;
    let t: Vec<u64> = p[4].split(':').map(|x| x.parse().ok()).collect::<Option<Vec<u64>>>()?;
    if t.len() != 3 || t[0] > 23 || t[1] > 59 || t[2] > 60 || !(1..=31).contains(&day) || year < 1970 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(days as u64 * 86_400 + t[0] * 3600 + t[1] * 60 + t[2])
}

/// `Retry-After` in milliseconds relative to `response_us` (µs since the epoch): either
/// delay-seconds or an HTTP date. `None` if absent or not parseable.
pub fn retry_after_ms(value: &str, response_us: u64) -> Option<f64> {
    let v = value.trim();
    if let Ok(secs) = v.parse::<u64>() {
        return Some(secs as f64 * 1000.0);
    }
    let at = parse_http_date(v)? as f64 * 1000.0;
    Some((at - response_us as f64 / 1000.0).max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_dates() {
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(parse_http_date("garbage"), None);
        assert_eq!(retry_after_ms("120", 0), Some(120_000.0));
        // 10 s after the response
        assert_eq!(retry_after_ms("Thu, 01 Jan 1970 00:00:10 GMT", 0), Some(10_000.0));
        assert_eq!(retry_after_ms("soon", 0), None);
    }

    #[test]
    fn stats() {
        let (m, cv) = mean_cv(&[10.0, 10.0, 10.0]);
        assert_eq!((m, cv), (10.0, 0.0));
        assert_eq!(percentile(&[3.0, 1.0, 2.0], 50.0), 2.0);
    }
}
