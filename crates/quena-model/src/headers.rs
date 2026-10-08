use serde::{Deserialize, Serialize};

/// Ordered, case-preserving header list. Values are stored as Latin-1
/// decoded strings, which maps every byte to exactly one char and therefore
/// round-trips arbitrary header bytes losslessly.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Headers(pub Vec<(String, String)>);

impl Headers {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn push(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0.push((name.into(), value.into()));
    }
    pub fn push_bytes(&mut self, name: &str, value: &[u8]) {
        self.0.push((name.to_string(), latin1_to_string(value)));
    }
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.0
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
    pub fn remove(&mut self, name: &str) {
        self.0.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    }
    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        if let Some(pos) = self.0.iter().position(|(n, _)| n.eq_ignore_ascii_case(name)) {
            self.0[pos].1 = value;
            let mut i = pos + 1;
            while i < self.0.len() {
                if self.0[i].0.eq_ignore_ascii_case(name) {
                    self.0.remove(i);
                } else {
                    i += 1;
                }
            }
        } else {
            self.0.push((name.to_string(), value));
        }
    }
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Approximate wire size (`Name: value\r\n`).
    pub fn wire_size(&self) -> usize {
        self.0.iter().map(|(n, v)| n.len() + v.len() + 4).sum()
    }
    /// Whether a comma separated header contains a token (case-insensitive).
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.get_all(name)
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    }
}

pub fn latin1_to_string(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// Inverse of [`latin1_to_string`]; chars above U+00FF are encoded as UTF-8.
pub fn string_to_latin1(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for ch in s.chars() {
        if (ch as u32) < 256 {
            out.push(ch as u32 as u8);
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn latin1_roundtrip() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(string_to_latin1(&latin1_to_string(&bytes)), bytes);
    }
    #[test]
    fn set_replaces_all() {
        let mut h = Headers::new();
        h.push("A", "1");
        h.push("a", "2");
        h.push("B", "3");
        h.set("A", "x");
        assert_eq!(h.0, vec![("A".into(), "x".into()), ("B".into(), "3".into())]);
    }
}
