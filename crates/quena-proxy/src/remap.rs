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
    /// Only for this port of the original (`api.example.com:8443`).
    pub from_port: Option<u16>,
    /// Talk to the target over `http` or `https` whatever the client used (`None`: the same).
    pub scheme: Option<String>,
}

/// Where a connection goes instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remapped {
    pub host: String,
    pub port: u16,
    pub keep_host: bool,
    /// The scheme to use instead of the original one.
    pub scheme: Option<String>,
    /// `from → to`, for the session.
    pub note: String,
}

impl HostRemap {
    /// `pattern` and a target `host`, `ip`, `host:port`, `[v6]:port`.
    pub fn parse(pattern: &str, target: &str, keep_host: bool) -> Result<HostRemap, String> {
        let pattern = pattern.trim().to_ascii_lowercase();
        // `host:port`: only that port.
        let (pattern, from_port) = match pattern.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') && !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) => (h.to_string(), Some(p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| format!("{pattern}: invalid port"))?)),
            _ => (pattern, None),
        };
        if pattern.is_empty() || pattern.contains(['/', ' ', ':']) && !pattern.starts_with('[') {
            return Err(format!("{pattern}: a host name or pattern, optionally with :port (no scheme or path)"));
        }
        let target = target.trim();
        if target.is_empty() || target.contains(['/', ' ']) {
            return Err(format!("{target}: a host name or address, optionally with :port"));
        }
        let (host, port) = split_target(target).ok_or_else(|| format!("{target}: invalid port"))?;
        if host.is_empty() {
            return Err(format!("{target}: the target needs a host or address"));
        }
        Ok(HostRemap { pattern, host, port, keep_host, from_port, scheme: None })
    }

    /// The same rule talking `http` or `https` to the target (empty: as the client did).
    pub fn with_scheme(mut self, scheme: &str) -> Result<HostRemap, String> {
        self.scheme = match scheme.trim().to_ascii_lowercase().as_str() {
            "" => None,
            s @ ("http" | "https") => Some(s.to_string()),
            other => return Err(format!("{other}: the protocol is http or https")),
        };
        if self.scheme.is_some() && self.from_port.is_some() {
            return Err(format!("{}:{}: a forced protocol cannot be combined with a port in the pattern", self.pattern, self.from_port.unwrap_or(0)));
        }
        Ok(self)
    }

    fn matches(&self, host: &str) -> bool {
        crate::host_matches(std::slice::from_ref(&self.pattern), host)
    }

    /// A port in the pattern first, then exact names, then the longest pattern.
    fn specificity(&self) -> (bool, bool, usize) {
        (self.from_port.is_some(), !self.pattern.contains('*'), self.pattern.len())
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
        Some((h, p)) if !h.contains(':') => Some((h.to_ascii_lowercase(), Some(p.parse().ok().filter(|p: &u16| *p != 0)?))),
        _ => Some((t.to_ascii_lowercase(), None)),
    }
}

/// The rule for `host:port`, the most specific one when several match.
pub fn lookup(rules: &[HostRemap], host: &str, port: u16) -> Option<Remapped> {
    let host = host.trim_matches(['[', ']']);
    let r = rules.iter().filter(|r| r.matches(host) && r.from_port.is_none_or(|p| p == port)).max_by_key(|r| r.specificity())?;
    // A forced protocol on the default port of the other one takes its own default port.
    let to_port = r.port.unwrap_or(match r.scheme.as_deref() {
        Some("http") if port == 443 => 80,
        Some("https") if port == 80 => 443,
        _ => port,
    });
    let to = crate::util::join_host_port(&r.host, to_port);
    let via = r.scheme.as_deref().map(|s| format!(" ({s})")).unwrap_or_default();
    Some(Remapped { host: r.host.clone(), port: to_port, keep_host: r.keep_host, scheme: r.scheme.clone(), note: format!("{} → {to}{via}", crate::util::join_host_port(host, port)) })
}

impl Remapped {
    /// `scheme://host[:port]` of the target, for rewriting a URL (default ports left out).
    pub fn authority(&self, https: bool) -> String {
        let default = if https { 443 } else { 80 };
        let h = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == default { h } else { format!("{h}:{}", self.port) }
    }
}

fn new_scheme<'a>(scheme: &'a str, r: &Remapped) -> &'a str {
    let ws = scheme.eq_ignore_ascii_case("ws") || scheme.eq_ignore_ascii_case("wss");
    match r.scheme.as_deref() {
        Some("http") => if ws { "ws" } else { "http" },
        Some("https") => if ws { "wss" } else { "https" },
        _ => scheme,
    }
}

/// `url` with its authority replaced by the remap target (for [`HostRemap::keep_host`] off),
/// on the forced scheme if any.
pub fn rewrite_url(url: &str, r: &Remapped) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let scheme = new_scheme(scheme, r);
    let https = scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("wss");
    Some(format!("{scheme}://{}{}", r.authority(https), &rest[end..]))
}

/// `url` on the forced scheme, its host kept and its port left to the scheme (with
/// [`HostRemap::keep_host`]: the connection still goes to the target).
pub fn rescheme_url(url: &str, r: &Remapped) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let host = match authority.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|c| c.is_ascii_digit()) && (!h.contains(':') || h.ends_with(']')) => h,
        _ => authority,
    };
    Some(format!("{}://{host}{}", new_scheme(scheme, r), &rest[end..]))
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
        assert_eq!(split_target("Staging.Example.com:8443"), Some(("staging.example.com".into(), Some(8443))));
        assert_eq!(split_target("[::1]:8080"), Some(("::1".into(), Some(8080))));
        assert_eq!(split_target("::1"), Some(("::1".into(), None)));
        assert_eq!(split_target("host:x"), None);
        assert!(HostRemap::parse("https://a.com", "b", true).is_err());
        assert!(HostRemap::parse("a.com", "", true).is_err());
        assert!(HostRemap::parse("a.com", "b/c", true).is_err());
    }

    #[test]
    fn the_most_specific_rule_wins() {
        let rules = vec![rule("*.example.com", "10.0.0.1"), rule("api.example.com", "10.0.0.2:8443"), rule("other.org", "127.0.0.1")];
        let r = lookup(&rules, "api.example.com", 443).unwrap();
        assert_eq!((r.host.as_str(), r.port), ("10.0.0.2", 8443));
        assert_eq!(r.note, "api.example.com:443 → 10.0.0.2:8443");
        let r = lookup(&rules, "www.example.com", 80).unwrap();
        assert_eq!((r.host.as_str(), r.port), ("10.0.0.1", 80));
        assert_eq!(lookup(&rules, "example.com", 443).unwrap().host, "10.0.0.1", "*.x also takes x");
        assert!(lookup(&rules, "example.org", 443).is_none());
    }

    #[test]
    fn ports_and_protocols() {
        let rules = vec![rule("api.example.com:8443", "10.0.0.9"), rule("api.example.com", "10.0.0.1")];
        assert_eq!(lookup(&rules, "api.example.com", 8443).unwrap().host, "10.0.0.9", "the port's own rule first");
        assert_eq!(lookup(&rules, "api.example.com", 443).unwrap().host, "10.0.0.1");
        assert!(HostRemap::parse("a.com:0", "b", true).is_err());
        // HTTPS to a local HTTP dev server.
        let dev = HostRemap::parse("api.example.com", "localhost:3000", true).unwrap().with_scheme("http").unwrap();
        let r = lookup(std::slice::from_ref(&dev), "api.example.com", 443).unwrap();
        assert_eq!((r.port, r.scheme.as_deref()), (3000, Some("http")));
        assert_eq!(rescheme_url("https://api.example.com/v1?a=1", &r).unwrap(), "http://api.example.com/v1?a=1");
        assert_eq!(rescheme_url("wss://api.example.com:443/ws", &r).unwrap(), "ws://api.example.com/ws");
        assert_eq!(rescheme_url("https://[::1]:8443/x", &r).unwrap(), "http://[::1]/x");
        assert_eq!(rewrite_url("https://api.example.com/v1", &r).unwrap(), "http://localhost:3000/v1");
        // Without a target port: the other scheme's default port.
        let plain = HostRemap::parse("api.example.com", "staging.example.com", true).unwrap().with_scheme("http").unwrap();
        assert_eq!(lookup(&[plain], "api.example.com", 443).unwrap().port, 80);
        assert!(HostRemap::parse("a.com", "b", true).unwrap().with_scheme("ftp").is_err());
        assert!(HostRemap::parse("a.com:8443", "b", true).unwrap().with_scheme("http").is_err());
    }

    #[test]
    fn urls_are_rewritten_to_the_target() {
        let r = lookup(&[rule("api.example.com", "staging.example.com:8443")], "api.example.com", 443).unwrap();
        assert_eq!(rewrite_url("https://api.example.com/v1?x=1", &r).unwrap(), "https://staging.example.com:8443/v1?x=1");
        let r = lookup(&[rule("api.example.com", "10.0.0.5")], "api.example.com", 443).unwrap();
        assert_eq!(rewrite_url("https://api.example.com:443/", &r).unwrap(), "https://10.0.0.5/");
        let r = lookup(&[rule("a", "::1")], "a", 80).unwrap();
        assert_eq!(rewrite_url("http://a/x", &r).unwrap(), "http://[::1]/x");
    }
}
