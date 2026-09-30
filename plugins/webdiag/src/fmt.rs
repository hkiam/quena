//! Numbers in the report language (1,234.5 / 1.234,5).
use crate::model::Lang;

fn group(int: u64, sep: char) -> String {
    let s = int.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(sep);
        }
        out.push(c);
    }
    out
}

/// `n` with `decimals` places, thousands grouped.
pub fn num(n: f64, decimals: usize, lang: Lang) -> String {
    let (thou, dec) = match lang {
        Lang::En => (',', '.'),
        Lang::De => ('.', ','),
    };
    if !n.is_finite() {
        return "–".into();
    }
    let neg = n < 0.0;
    let s = format!("{:.*}", decimals, n.abs());
    let (int, frac) = s.split_once('.').unwrap_or((&s, ""));
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    out.push_str(&group(int.parse().unwrap_or(0), thou));
    if !frac.is_empty() {
        out.push(dec);
        out.push_str(frac);
    }
    out
}

pub fn count(n: f64, lang: Lang) -> String {
    num(n, 0, lang)
}

/// 850 ms, 1.2 s, 12 s, 2 min 5 s. The unit is chosen after rounding (999.6 ms → 1.0 s,
/// 59,999 ms → 1 min 0 s).
pub fn ms(ms: f64, lang: Lang) -> String {
    if !ms.is_finite() {
        return "–".into();
    }
    if ms.round() < 1000.0 {
        return format!("{} ms", num(ms, 0, lang));
    }
    let tenths = (ms / 100.0).round() / 10.0;
    if tenths < 10.0 {
        return format!("{} s", num(tenths, 1, lang));
    }
    let s = (ms / 1000.0).round();
    if s < 60.0 {
        return format!("{} s", num(s, 0, lang));
    }
    let s = s as u64;
    format!("{} min {} s", s / 60, s % 60)
}

/// 980 B, 12.3 KB, 4.1 MB (1 KB = 1024 B).
pub fn bytes(b: f64, lang: Lang) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    let d = if i == 0 || v >= 100.0 { 0 } else { 1 };
    format!("{} {}", num(v, d, lang), U[i])
}

/// 31 %, 4.5 % (ratio 0–1).
pub fn pct(ratio: f64, lang: Lang) -> String {
    let p = ratio * 100.0;
    format!("{} %", num(p, if p < 10.0 && p > 0.0 { 1 } else { 0 }, lang))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats() {
        assert_eq!(num(1234567.891, 2, Lang::En), "1,234,567.89");
        assert_eq!(num(1234567.891, 2, Lang::De), "1.234.567,89");
        assert_eq!(ms(850.0, Lang::En), "850 ms");
        assert_eq!(ms(3800.0, Lang::De), "3,8 s");
        assert_eq!(ms(125_000.0, Lang::En), "2 min 5 s");
        // The unit follows the rounded value.
        assert_eq!(ms(999.4, Lang::En), "999 ms");
        assert_eq!(ms(999.6, Lang::En), "1.0 s");
        assert_eq!(ms(9_999.0, Lang::En), "10 s");
        assert_eq!(ms(59_999.0, Lang::En), "1 min 0 s");
        assert_eq!(ms(f64::INFINITY, Lang::En), "–");
        assert_eq!(bytes(820.0 * 1024.0, Lang::En), "820 KB");
        assert_eq!(bytes(38.2 * 1024.0 * 1024.0, Lang::De), "38,2 MB");
        assert_eq!(pct(0.31, Lang::En), "31 %");
    }
}
