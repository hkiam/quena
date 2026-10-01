//! Number and date formatting as the UI shows it (`app/ui/src/lib/format.ts`,
//! `fmtValue` / `fmtDelta` in `diagReport.ts`), without `Intl`: the rounding rules of
//! `Intl.NumberFormat` and `Number.prototype.toFixed` are reproduced on decimal strings.

use crate::{Lang, MetricValue};

/// Shortest round-trip digits of a finite, non-negative `v` and its decimal exponent `n`:
/// `v = 0.digits × 10^n` (as in ECMAScript `Number::toString`).
fn shortest(v: f64) -> (Vec<u8>, i32) {
    let s = format!("{v:e}");
    let (mantissa, exp) = s.split_once('e').unwrap_or((&s, "0"));
    let digits: Vec<u8> = mantissa
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect();
    (digits, exp.parse::<i32>().unwrap_or(0) + 1)
}

/// `String(v)` of a JavaScript number.
pub(crate) fn js_num(v: f64) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    if v == 0.0 {
        return "0".into();
    }
    if v < 0.0 {
        return format!("-{}", js_num(-v));
    }
    let (digits, n) = shortest(v);
    let d: String = digits.iter().map(|d| char::from(b'0' + d)).collect();
    let k = digits.len() as i32;
    if k <= n && n <= 21 {
        format!("{d}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &d[..n as usize], &d[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{d}", "0".repeat(-n as usize))
    } else {
        let e = n - 1;
        let sign = if e < 0 { '-' } else { '+' };
        let rest = if k > 1 {
            format!(".{}", &d[1..])
        } else {
            String::new()
        };
        format!("{}{rest}e{sign}{}", &d[..1], e.abs())
    }
}

/// Decimal digits split into integer and fraction part, rounded half away from zero to
/// `frac` fraction digits.
fn round_digits(int: &str, fraction: &str, frac: usize) -> (String, String) {
    let mut digits: Vec<u8> = int
        .bytes()
        .chain(fraction.bytes())
        .map(|b| b - b'0')
        .collect();
    let int_len = int.len();
    let keep = int_len + frac;
    let round_up = digits.get(keep).is_some_and(|&d| d >= 5);
    digits.resize(keep, 0);
    let mut int_len = int_len;
    if round_up {
        let mut i = keep;
        loop {
            if i == 0 {
                digits.insert(0, 1);
                int_len += 1;
                break;
            }
            i -= 1;
            if digits[i] == 9 {
                digits[i] = 0;
            } else {
                digits[i] += 1;
                break;
            }
        }
    }
    let s: String = digits.iter().map(|d| char::from(b'0' + d)).collect();
    let (i, f) = s.split_at(int_len);
    let i = i.trim_start_matches('0');
    (if i.is_empty() { "0".into() } else { i.into() }, f.into())
}

fn group(int: &str, sep: char) -> String {
    let mut out = String::with_capacity(int.len() + int.len() / 3);
    for (i, c) in int.chars().enumerate() {
        if i > 0 && (int.len() - i).is_multiple_of(3) {
            out.push(sep);
        }
        out.push(c);
    }
    out
}

/// `v.toLocaleString(lang, { minimumFractionDigits: 0, maximumFractionDigits: digits })`.
pub(crate) fn decimal(v: f64, digits: usize, lang: Lang) -> String {
    if !v.is_finite() {
        return js_num(v);
    }
    let (ds, n) = if v == 0.0 {
        (vec![0], 1)
    } else {
        shortest(v.abs())
    };
    let s: String = ds.iter().map(|d| char::from(b'0' + d)).collect();
    let (int, fraction) = if n <= 0 {
        ("0".to_string(), format!("{}{s}", "0".repeat(-n as usize)))
    } else if n as usize >= s.len() {
        (
            format!("{s}{}", "0".repeat(n as usize - s.len())),
            String::new(),
        )
    } else {
        (s[..n as usize].to_string(), s[n as usize..].to_string())
    };
    let (int, fraction) = round_digits(&int, &fraction, digits);
    let fraction = fraction.trim_end_matches('0');
    let (gsep, dsep) = match lang {
        Lang::En => (',', '.'),
        Lang::De => ('.', ','),
    };
    let sign = if v.is_sign_negative() { "-" } else { "" };
    let int = group(&int, gsep);
    if fraction.is_empty() {
        format!("{sign}{int}")
    } else {
        format!("{sign}{int}{dsep}{fraction}")
    }
}

/// `v.toFixed(digits)` with a decimal comma in German.
fn fixed(v: f64, digits: usize, lang: Lang) -> String {
    let s = if !v.is_finite() || v.abs() >= 1e21 {
        js_num(v)
    } else {
        // The exact binary value: toFixed rounds it, not the shortest representation.
        let exact = format!("{:.1080}", v.abs());
        let (int, fraction) = exact.split_once('.').unwrap_or((&exact, ""));
        let (int, fraction) = round_digits(int, fraction, digits);
        let sign = if v < 0.0 { "-" } else { "" };
        if digits == 0 {
            format!("{sign}{int}")
        } else {
            format!("{sign}{int}.{fraction}")
        }
    };
    if lang == Lang::De {
        s.replacen('.', ",", 1)
    } else {
        s
    }
}

/// `Math.round`: halves round towards +∞.
pub(crate) fn js_round(x: f64) -> f64 {
    let f = x.floor();
    if x - f >= 0.5 { f + 1.0 } else { f }
}

/// Integer with thousands separators (`Intl.NumberFormat` defaults: up to 3 fraction digits).
pub(crate) fn fmt_int(n: f64, lang: Lang) -> String {
    decimal(n, 3, lang)
}

pub(crate) fn fmt_bytes(n: f64, lang: Lang) -> String {
    if n < 1024.0 {
        return format!("{} B", fmt_int(n, lang));
    }
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    let mut v = n / 1024.0;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!(
        "{} {}",
        fixed(v, if v < 10.0 { 2 } else { 1 }, lang),
        UNITS[i]
    )
}

pub(crate) fn fmt_ms(ms: f64, lang: Lang) -> String {
    if ms < 1000.0 {
        return format!("{} ms", fmt_int(ms, lang));
    }
    format!(
        "{} s",
        fixed(ms / 1000.0, if ms < 10000.0 { 2 } else { 1 }, lang)
    )
}

/// A metric value by its unit (count/bytes/ms/ratio/rate/text).
pub fn fmt_value(value: &MetricValue, unit: &str, lang: Lang) -> String {
    let v = match value {
        MetricValue::None => return "–".into(),
        MetricValue::Text(s) => return s.clone(),
        MetricValue::Number(v) => *v,
    };
    fmt_number(v, unit, lang)
}

pub(crate) fn fmt_number(v: f64, unit: &str, lang: Lang) -> String {
    match unit {
        "bytes" => fmt_bytes(js_round(v), lang),
        "ms" => fmt_ms(js_round(v), lang),
        "ratio" => format!("{} %", decimal(v * 100.0, 1, lang)),
        "rate" => format!("{}/s", decimal(v, 2, lang)),
        "count" if v.fract() == 0.0 => fmt_int(v, lang),
        _ => decimal(v, 2, lang),
    }
}

/// Signed difference between two values of a unit (`+1.2 MB`, `−3`, `+4 pp`).
pub fn fmt_delta(delta: f64, unit: &str, lang: Lang) -> String {
    let sign = if delta > 0.0 {
        "+"
    } else if delta < 0.0 {
        "−"
    } else {
        "±"
    };
    let abs = delta.abs();
    if unit == "ratio" {
        return format!("{sign}{} pp", decimal(abs * 100.0, 1, lang));
    }
    format!("{sign}{}", fmt_number(abs, unit, lang))
}

/// A µs timestamp as `2026-10-01 09:24:20 UTC`; empty for none or 0 (like `fmtDateTime`).
pub fn fmt_datetime(us: Option<f64>) -> String {
    let Some(us) = us.filter(|&u| u != 0.0 && u.is_finite()) else {
        return String::new();
    };
    let ms = (us / 1000.0).trunc() as i64;
    let secs = ms.div_euclid(1000);
    let (days, sod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60
    )
}

/// Days since 1970-01-01 → (year, month, day) in the proleptic Gregorian calendar
/// (H. Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_number_strings() {
        assert_eq!(js_num(5.0), "5");
        assert_eq!(js_num(1.5), "1.5");
        assert_eq!(js_num(-0.25), "-0.25");
        assert_eq!(js_num(1e21), "1e+21");
        assert_eq!(js_num(1.5e-7), "1.5e-7");
        assert_eq!(js_num(0.000001), "0.000001");
        assert_eq!(js_num(123456789012.0), "123456789012");
    }

    #[test]
    fn values_like_the_ui() {
        let n = |v: f64| MetricValue::Number(v);
        assert_eq!(fmt_value(&n(1234.0), "count", Lang::En), "1,234");
        assert_eq!(fmt_value(&n(1234.0), "count", Lang::De), "1.234");
        assert_eq!(fmt_value(&n(2048.0), "bytes", Lang::En), "2.00 KB");
        assert_eq!(fmt_value(&n(2048.0), "bytes", Lang::De), "2,00 KB");
        assert_eq!(fmt_value(&n(50331648.0), "bytes", Lang::En), "48.0 MB");
        assert_eq!(fmt_value(&n(1500.0), "ms", Lang::En), "1.50 s");
        assert_eq!(fmt_value(&n(999.0), "ms", Lang::En), "999 ms");
        assert_eq!(fmt_value(&n(0.31), "ratio", Lang::En), "31 %");
        assert_eq!(fmt_value(&n(0.3125), "ratio", Lang::De), "31,3 %");
        assert_eq!(fmt_value(&n(2.5), "rate", Lang::En), "2.5/s");
        assert_eq!(fmt_value(&n(1.005), "rate", Lang::En), "1.01/s");
        assert_eq!(fmt_value(&n(1234.5678), "count", Lang::De), "1.234,57");
        assert_eq!(
            fmt_value(&MetricValue::Text("n/a".into()), "text", Lang::En),
            "n/a"
        );
        assert_eq!(fmt_value(&MetricValue::None, "count", Lang::En), "–");
        assert_eq!(fmt_delta(-3.0, "count", Lang::En), "−3");
        assert_eq!(fmt_delta(0.05, "ratio", Lang::En), "+5 pp");
        assert_eq!(fmt_delta(0.0, "count", Lang::En), "±0");
        assert_eq!(fixed(1.125, 2, Lang::En), "1.13");
        assert_eq!(fixed(1.005, 2, Lang::En), "1.00");
        assert_eq!(fixed(9.999, 2, Lang::De), "10,00");
    }

    #[test]
    fn utc_dates() {
        assert_eq!(
            fmt_datetime(Some(1727690000000000.0)),
            "2024-09-30 09:53:20 UTC"
        );
        assert_eq!(fmt_datetime(Some(0.0)), "");
        assert_eq!(fmt_datetime(None), "");
        assert_eq!(
            fmt_datetime(Some(951782400000000.0)),
            "2000-02-29 00:00:00 UTC"
        );
        assert_eq!(fmt_datetime(Some(-1000000.0)), "1969-12-31 23:59:59 UTC");
    }
}
