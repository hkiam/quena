//! Small helpers shared by the analyzers.
use std::collections::HashMap;
use std::hash::Hash;

/// Group items by key, keeping the order in which keys first appear.
pub fn group_by<T, K: Hash + Eq + Clone>(items: impl IntoIterator<Item = T>, key: impl Fn(&T) -> K) -> Vec<(K, Vec<T>)> {
    let mut idx: HashMap<K, usize> = HashMap::new();
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
