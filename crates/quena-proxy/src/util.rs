use std::net::IpAddr;

/// IPv4/IPv6 network in CIDR notation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, p.parse().ok()?),
            None => (s, if s.contains(':') { 128 } else { 32 }),
        };
        // Short IPv4 networks as macOS writes them: `169.254/16` is 169.254.0.0/16.
        let addr: IpAddr = match a.parse() {
            Ok(addr) => addr,
            Err(_)
                if !a.is_empty()
                    && a.split('.').count() < 4
                    && a.split('.').all(|o| o.parse::<u8>().is_ok()) =>
            {
                format!("{a}{}", ".0".repeat(4 - a.split('.').count()))
                    .parse()
                    .ok()?
            }
            Err(_) => return None,
        };
        Some(Cidr { addr, prefix: p })
    }

    pub fn parse_list(s: &str) -> Vec<Cidr> {
        s.split([';', ',', ' ', '\n'])
            .filter(|t| !t.trim().is_empty())
            .filter_map(Cidr::parse)
            .collect()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let bits = self.prefix.min(32) as u32;
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                u32::from(n) & mask == u32::from(i) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let bits = self.prefix.min(128) as u32;
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                u128::from(n) & mask == u128::from(i) & mask
            }
            _ => false,
        }
    }
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_link_local() || v.is_loopback(),
        IpAddr::V6(v) => {
            v.is_loopback()
                || (v.segments()[0] & 0xfe00) == 0xfc00
                || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub fn is_loopback_host(h: &str) -> bool {
    let h = h.trim_matches(['[', ']']);
    h.eq_ignore_ascii_case("localhost")
        || h.parse::<IpAddr>()
            .map(|i| i.is_loopback())
            .unwrap_or(false)
}

/// `Content-Type` → `Title-Case` for HTTP/1 header names (hyper lower-cases them).
pub fn title_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut up = true;
    for c in name.chars() {
        if up {
            out.extend(c.to_uppercase());
        } else {
            out.push(c);
        }
        up = c == '-';
    }
    out
}

pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

/// Split `host[:port]` with a default port.
/// `host:port`, with brackets around an IPv6 address.
pub fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub fn split_host_port(authority: &str, default: u16) -> (String, u16) {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(i) = rest.find(']') {
            let host = &rest[..i];
            let port = rest[i + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default);
            return (host.to_string(), port);
        }
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().unwrap_or(default)),
        _ => (authority.to_string(), default),
    }
}

pub fn split_list(s: &str) -> Vec<String> {
    s.split([';', ',', '\n', ' ', '\t'])
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cidr() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains("192.168.1.77".parse().unwrap()));
        assert!(!c.contains("192.168.2.1".parse().unwrap()));
        assert!(
            Cidr::parse("fe80::/10")
                .unwrap()
                .contains("fe80::1".parse().unwrap())
        );
        assert!(is_private("10.1.2.3".parse().unwrap()));
        assert!(!is_private("8.8.8.8".parse().unwrap()));
        // Short networks as in macOS' proxy exceptions.
        let ll = Cidr::parse("169.254/16").unwrap();
        assert!(ll.contains("169.254.10.1".parse().unwrap()));
        assert!(!ll.contains("169.255.0.1".parse().unwrap()));
        assert!(
            Cidr::parse("10/8")
                .unwrap()
                .contains("10.9.8.7".parse().unwrap())
        );
        assert!(Cidr::parse("intranet/8").is_none());
    }
    #[test]
    fn bypass_patterns() {
        let l = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let local = l(&["<local>"]);
        assert!(crate::host_matches(&local, "appserver:8080"));
        assert!(!crate::host_matches(&local, "app.corp.example"));
        assert!(!crate::host_matches(&local, "10.1.2.3"));
        assert!(!crate::host_matches(&local, "[::1]:80"));
        let nets = l(&["169.254/16", "10.0.0.0/8", "*.corp"]);
        assert!(crate::host_matches(&nets, "169.254.1.1:80"));
        assert!(crate::host_matches(&nets, "10.20.30.40"));
        assert!(crate::host_matches(&nets, "corp"));
        assert!(crate::host_matches(&nets, "wiki.corp"));
        assert!(crate::host_matches(&l(&["*.Corp.Example"]), "corp.example"));
        assert!(!crate::host_matches(&nets, "192.168.0.1"));
    }
    #[test]
    fn hostport() {
        assert_eq!(split_host_port("a.b:8443", 443), ("a.b".into(), 8443));
        assert_eq!(split_host_port("a.b", 443), ("a.b".into(), 443));
        assert_eq!(split_host_port("[::1]:80", 443), ("::1".into(), 80));
        assert_eq!(title_case("content-type"), "Content-Type");
    }
}
