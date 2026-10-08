//! Host remapping: connections to a host (or a pattern) go to another host, IP or port,
//! like an entry in the hosts file, but only for traffic through Quena.
//!
//! By default the request keeps its host name: `Host`, the TLS server name (SNI) and the
//! certificate check stay those of the original host, only the TCP connection goes to the
//! target (a staging server with the real certificate, a local build). Without
//! [`HostRemap::keep_host`] the request is sent to the target as if it had been addressed
//! there (URL, `Host` and SNI of the target).

/// Session flag describing a remapped connection (`api.example.com → 10.0.0.5:8443`).
pub const FLAG: &str = "x-quena-remap";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRemap {
    /// `api.example.com`, `*.example.com` (also matches `example.com`), `10.1.*`.
    pub pattern: String,
    pub host: String,
    /// `None`: the original port.
    pub port: Option<u16>,
    /// Keep `Host` and SNI of the original host (only the connection moves).
    pub keep_host: bool,
}

/// Where a connection goes instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remapped {
    pub host: String,
    pub port: u16,
    pub keep_host: bool,
    /// `from → to`, for the session.
    pub note: String,
}

impl HostRemap {
    /// `pattern` and a target `host`, `ip`, `host:port`, `[v6]:port`.
    pub fn parse(pattern: &str, target: &str, keep_host: bool) -> Result<HostRemap, String> {
        let pattern = pattern.trim().to_ascii_lowercase();
        if pattern.is_empty() || pattern.contains(['/', ' ', ':']) && !pattern.starts_with('[') {
            return Err(format!(
                "{pattern}: a host name or pattern (no scheme, path or port)"
            ));
        }
        let target = target.trim();
        if target.is_empty() || target.contains(['/', ' ']) {
            return Err(format!(
                "{target}: a host name or address, optionally with :port"
            ));
        }
        let (host, port) = split_target(target).ok_or_else(|| format!("{target}: invalid port"))?;
        if host.is_empty() {
            return Err(format!("{target}: the target needs a host or address"));
        }
        Ok(HostRemap {
            pattern,
            host,
            port,
            keep_host,
        })
    }

    fn matches(&self, host: &str) -> bool {
        crate::host_matches(std::slice::from_ref(&self.pattern), host)
    }

    /// Exact names first, then the longest pattern.
    fn specificity(&self) -> (bool, usize) {
        (!self.pattern.contains('*'), self.pattern.len())
    }
}

/// `host[:port]` with IPv6 in brackets; `None` for a bad port.
fn split_target(t: &str) -> Option<(String, Option<u16>)> {
    if let Some(rest) = t.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None if after.is_empty() => None,
            None => return None,
        };
        return Some((h.to_string(), port));
    }
    match t.rsplit_once(':') {
        // A bare IPv6 address has several colons and no port.
        Some((h, p)) if !h.contains(':') => Some((
            h.to_ascii_lowercase(),
            Some(p.parse().ok().filter(|p: &u16| *p != 0)?),
        )),
        _ => Some((t.to_ascii_lowercase(), None)),
    }
}

/// The rule for `host:port`, the most specific one when several match.
pub fn lookup(rules: &[HostRemap], host: &str, port: u16) -> Option<Remapped> {
    let host = host.trim_matches(['[', ']']);
    let r = rules
        .iter()
        .filter(|r| r.matches(host))
        .max_by_key(|r| r.specificity())?;
    let to_port = r.port.unwrap_or(port);
    let to = crate::util::join_host_port(&r.host, to_port);
    Some(Remapped {
        host: r.host.clone(),
        port: to_port,
        keep_host: r.keep_host,
        note: format!("{} → {to}", crate::util::join_host_port(host, port)),
    })
}

impl Remapped {
    /// `scheme://host[:port]` of the target, for rewriting a URL (default ports left out).
    pub fn authority(&self, https: bool) -> String {
        let default = if https { 443 } else { 80 };
        let h = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == default {
            h
        } else {
            format!("{h}:{}", self.port)
        }
    }
}

/// `url` with its authority replaced by the remap target (for [`HostRemap::keep_host`] off).
pub fn rewrite_url(url: &str, r: &Remapped) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let https = scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("wss");
    Some(format!("{scheme}://{}{}", r.authority(https), &rest[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(p: &str, t: &str) -> HostRemap {
        HostRemap::parse(p, t, true).unwrap()
    }

    #[test]
    fn targets_parse() {
        assert_eq!(split_target("10.0.0.5"), Some(("10.0.0.5".into(), None)));
        assert_eq!(
            split_target("Staging.Example.com:8443"),
            Some(("staging.example.com".into(), Some(8443)))
        );
        assert_eq!(split_target("[::1]:8080"), Some(("::1".into(), Some(8080))));
        assert_eq!(split_target("::1"), Some(("::1".into(), None)));
        assert_eq!(split_target("host:x"), None);
        assert!(HostRemap::parse("https://a.com", "b", true).is_err());
        assert!(HostRemap::parse("a.com", "", true).is_err());
        assert!(HostRemap::parse("a.com", "b/c", true).is_err());
    }

    #[test]
    fn the_most_specific_rule_wins() {
        let rules = vec![
            rule("*.example.com", "10.0.0.1"),
            rule("api.example.com", "10.0.0.2:8443"),
            rule("other.org", "127.0.0.1"),
        ];
        let r = lookup(&rules, "api.example.com", 443).unwrap();
        assert_eq!((r.host.as_str(), r.port), ("10.0.0.2", 8443));
        assert_eq!(r.note, "api.example.com:443 → 10.0.0.2:8443");
        let r = lookup(&rules, "www.example.com", 80).unwrap();
        assert_eq!((r.host.as_str(), r.port), ("10.0.0.1", 80));
        assert_eq!(
            lookup(&rules, "example.com", 443).unwrap().host,
            "10.0.0.1",
            "*.x also takes x"
        );
        assert!(lookup(&rules, "example.org", 443).is_none());
    }

    #[test]
    fn urls_are_rewritten_to_the_target() {
        let r = lookup(
            &[rule("api.example.com", "staging.example.com:8443")],
            "api.example.com",
            443,
        )
        .unwrap();
        assert_eq!(
            rewrite_url("https://api.example.com/v1?x=1", &r).unwrap(),
            "https://staging.example.com:8443/v1?x=1"
        );
        let r = lookup(
            &[rule("api.example.com", "10.0.0.5")],
            "api.example.com",
            443,
        )
        .unwrap();
        assert_eq!(
            rewrite_url("https://api.example.com:443/", &r).unwrap(),
            "https://10.0.0.5/"
        );
        let r = lookup(&[rule("a", "::1")], "a", 80).unwrap();
        assert_eq!(rewrite_url("http://a/x", &r).unwrap(), "http://[::1]/x");
    }
}
