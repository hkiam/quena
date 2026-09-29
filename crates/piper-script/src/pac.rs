//! PAC (proxy auto-config) evaluation on a dedicated QuickJS thread.
//!
//! `FindProxyForURL(url, host)` is evaluated once per host and the result is
//! cached, so the forwarding path never blocks on JS after the first lookup.
//! DNS helpers (`dnsResolve`, `myIpAddress`, `isInNet`, `isResolvable`) are
//! implemented in Rust; the rest are pure-JS helpers in `pac_prelude.js`.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::mpsc::{Receiver, Sender};

const PAC_PRELUDE: &str = include_str!("pac_prelude.js");
const MEMORY_LIMIT: usize = 32 * 1024 * 1024;

/// A single directive from `FindProxyForURL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyEntry {
    Direct,
    /// An HTTP proxy `host:port`.
    Proxy(String, u16),
    /// A SOCKS proxy — not usable as an upstream by Piper's connector.
    Socks(String, u16),
}

enum Cmd {
    Eval { url: String, host: String, reply: Sender<Result<String, String>> },
    Shutdown,
}

/// A compiled PAC script. Evaluation is cached per host.
pub struct PacEngine {
    tx: Sender<Cmd>,
    cache: Mutex<HashMap<String, Vec<ProxyEntry>>>,
    source_error: Option<String>,
}

impl PacEngine {
    /// Compile a PAC script. Returns an engine even if the script is invalid;
    /// in that case every lookup yields DIRECT and [`PacEngine::error`] is set.
    pub fn new(source: &str) -> PacEngine {
        let (tx, rx) = std::sync::mpsc::channel::<Cmd>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let src = source.to_string();
        std::thread::Builder::new()
            .name("piper-pac".into())
            .spawn(move || worker(rx, &src, ready_tx))
            .expect("spawn pac worker");
        let source_error = match ready_rx.recv() {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e),
            Err(_) => Some("pac worker did not start".into()),
        };
        PacEngine { tx, cache: Mutex::new(HashMap::new()), source_error }
    }

    /// The compile error, if the PAC script failed to load.
    pub fn error(&self) -> Option<&str> {
        self.source_error.as_deref()
    }

    /// All directives `FindProxyForURL(url, host)` returns for this host.
    pub fn find(&self, url: &str, host: &str) -> Vec<ProxyEntry> {
        let key = host.to_ascii_lowercase();
        if let Some(v) = self.cache.lock().get(&key) {
            return v.clone();
        }
        let entries = if self.source_error.is_some() {
            vec![ProxyEntry::Direct]
        } else {
            let (reply, rx) = std::sync::mpsc::channel();
            if self.tx.send(Cmd::Eval { url: url.to_string(), host: host.to_string(), reply }).is_err() {
                vec![ProxyEntry::Direct]
            } else {
                match rx.recv() {
                    Ok(Ok(s)) => parse_pac_result(&s),
                    _ => vec![ProxyEntry::Direct],
                }
            }
        };
        self.cache.lock().insert(key, entries.clone());
        entries
    }

    /// The upstream HTTP proxy for `host`, mirroring Fiddler: the first `PROXY`
    /// directive, or `None` for DIRECT (or a SOCKS-only result we can't use).
    pub fn upstream_for(&self, host_port: &str) -> Option<(String, u16)> {
        let host = host_without_port(host_port);
        let url = format!("http://{host}/");
        for e in self.find(&url, host) {
            match e {
                ProxyEntry::Proxy(h, p) => return Some((h, p)),
                ProxyEntry::Direct => return None,
                ProxyEntry::Socks(..) => continue,
            }
        }
        None
    }

    /// Drop the per-host cache (e.g. after a network change).
    pub fn clear_cache(&self) {
        self.cache.lock().clear();
    }
}

impl Drop for PacEngine {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Shutdown);
    }
}

fn host_without_port(host_port: &str) -> &str {
    let hp = host_port.trim_matches(['[', ']']);
    // Only strip a trailing :port (not part of an IPv6 literal without brackets).
    if let Some(idx) = hp.rfind(':') {
        if hp[idx + 1..].chars().all(|c| c.is_ascii_digit()) && !hp[..idx].contains(':') {
            return &hp[..idx];
        }
    }
    hp
}

fn parse_pac_result(s: &str) -> Vec<ProxyEntry> {
    let mut out = Vec::new();
    for part in s.split(';') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let mut it = p.split_whitespace();
        let kind = it.next().unwrap_or("").to_ascii_uppercase();
        let addr = it.next();
        match (kind.as_str(), addr) {
            ("DIRECT", _) => out.push(ProxyEntry::Direct),
            ("PROXY" | "HTTP", Some(a)) => {
                if let Some((h, p)) = split_addr(a) {
                    out.push(ProxyEntry::Proxy(h, p));
                }
            }
            ("HTTPS", Some(a)) => {
                if let Some((h, p)) = split_addr_default(a, 443) {
                    out.push(ProxyEntry::Proxy(h, p));
                }
            }
            ("SOCKS" | "SOCKS4" | "SOCKS5", Some(a)) => {
                if let Some((h, p)) = split_addr_default(a, 1080) {
                    out.push(ProxyEntry::Socks(h, p));
                }
            }
            _ => {}
        }
    }
    if out.is_empty() {
        out.push(ProxyEntry::Direct);
    }
    out
}

fn split_addr(a: &str) -> Option<(String, u16)> {
    let (h, p) = a.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?))
}

fn split_addr_default(a: &str, default_port: u16) -> Option<(String, u16)> {
    match a.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((a.to_string(), default_port)),
    }
}

// ------------------------------------------------------------ worker thread

fn worker(rx: Receiver<Cmd>, source: &str, ready: Sender<Result<(), String>>) {
    use rquickjs::{Context, Runtime};
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready.send(Err(format!("pac runtime: {e}")));
            return;
        }
    };
    rt.set_memory_limit(MEMORY_LIMIT);
    let ctx = match Context::full(&rt) {
        Ok(c) => c,
        Err(e) => {
            let _ = ready.send(Err(format!("pac context: {e}")));
            return;
        }
    };

    let init = ctx.with(|cx| -> Result<(), String> {
        install_dns(&cx)?;
        cx.eval::<(), _>(PAC_PRELUDE).map_err(|e| e.to_string())?;
        cx.eval::<(), _>(source.as_bytes()).map_err(|e| exc(&cx, e))?;
        let f: Result<rquickjs::Function, _> = cx.globals().get("FindProxyForURL");
        if f.is_err() {
            return Err("PAC script defines no FindProxyForURL(url, host)".into());
        }
        Ok(())
    });
    if let Err(e) = init {
        let _ = ready.send(Err(e));
        return;
    }
    let _ = ready.send(Ok(()));

    for cmd in rx {
        match cmd {
            Cmd::Eval { url, host, reply } => {
                let out = ctx.with(|cx| -> Result<String, String> {
                    let f: rquickjs::Function = cx.globals().get("FindProxyForURL").map_err(|e| e.to_string())?;
                    let s: String = f.call((url, host)).map_err(|e| exc(&cx, e))?;
                    Ok(s)
                });
                let _ = reply.send(out);
            }
            Cmd::Shutdown => break,
        }
    }
}

fn install_dns(cx: &rquickjs::Ctx) -> Result<(), String> {
    let resolve = rquickjs::Function::new(cx.clone(), |host: String| -> rquickjs::Result<Option<String>> {
        Ok(dns_resolve(&host))
    })
    .map_err(|e| e.to_string())?;
    cx.globals().set("__dnsResolve", resolve).map_err(|e| e.to_string())?;

    let myip = rquickjs::Function::new(cx.clone(), || -> rquickjs::Result<String> { Ok(my_ip_address()) })
        .map_err(|e| e.to_string())?;
    cx.globals().set("__myIpAddress", myip).map_err(|e| e.to_string())?;
    Ok(())
}

fn dns_resolve(host: &str) -> Option<String> {
    // Prefer IPv4 to match classic PAC helpers (isInNet is IPv4).
    let addrs: Vec<IpAddr> = (host, 0u16).to_socket_addrs().ok()?.map(|s| s.ip()).collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .map(|a| a.to_string())
}

fn my_ip_address() -> String {
    // Best-effort local address: connect a UDP socket to a public address and
    // read back the chosen source IP (no packets are sent).
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:53")?;
            Ok(s.local_addr()?.ip().to_string())
        })
        .unwrap_or_else(|_| "127.0.0.1".into())
}

fn exc(cx: &rquickjs::Ctx, e: rquickjs::Error) -> String {
    if let rquickjs::Error::Exception = e {
        let v = cx.catch();
        if let Some(ex) = v.as_exception() {
            return ex.message().unwrap_or_else(|| "exception".into());
        }
    }
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_and_proxy() {
        let pac = PacEngine::new(
            r#"
            function FindProxyForURL(url, host) {
                if (isPlainHostName(host)) return "DIRECT";
                if (dnsDomainIs(host, ".internal.example")) return "DIRECT";
                if (shExpMatch(host, "*.corp.example")) return "PROXY proxy1.example:8080; PROXY proxy2.example:8080";
                return "PROXY gw.example:3128; DIRECT";
            }
            "#,
        );
        assert!(pac.error().is_none());
        assert_eq!(pac.find("http://intranet/", "intranet"), vec![ProxyEntry::Direct]);
        assert_eq!(pac.find("http://a.internal.example/", "a.internal.example"), vec![ProxyEntry::Direct]);
        assert_eq!(
            pac.find("http://a.corp.example/", "a.corp.example"),
            vec![ProxyEntry::Proxy("proxy1.example".into(), 8080), ProxyEntry::Proxy("proxy2.example".into(), 8080)]
        );
        assert_eq!(
            pac.find("http://x.example/", "x.example"),
            vec![ProxyEntry::Proxy("gw.example".into(), 3128), ProxyEntry::Direct]
        );
        // upstream_for picks the first PROXY, or None for DIRECT.
        assert_eq!(pac.upstream_for("intranet:80"), None);
        assert_eq!(pac.upstream_for("x.example:443"), Some(("gw.example".into(), 3128)));
    }

    #[test]
    fn cache_is_used() {
        let pac = PacEngine::new("function FindProxyForURL(u,h){ return 'DIRECT'; }");
        assert_eq!(pac.find("http://h/", "h"), vec![ProxyEntry::Direct]);
        assert!(pac.cache.lock().contains_key("h"));
    }

    #[test]
    fn invalid_script_is_direct() {
        let pac = PacEngine::new("this is not js {{{");
        assert!(pac.error().is_some());
        assert_eq!(pac.upstream_for("anything:80"), None);
    }

    #[test]
    fn missing_entry_point_is_error() {
        let pac = PacEngine::new("var x = 1;");
        assert!(pac.error().is_some());
    }

    #[test]
    fn parse_variants() {
        assert_eq!(parse_pac_result("DIRECT"), vec![ProxyEntry::Direct]);
        assert_eq!(parse_pac_result("PROXY p:8080"), vec![ProxyEntry::Proxy("p".into(), 8080)]);
        assert_eq!(parse_pac_result("  PROXY a:1 ; DIRECT "), vec![ProxyEntry::Proxy("a".into(), 1), ProxyEntry::Direct]);
        assert_eq!(parse_pac_result(""), vec![ProxyEntry::Direct]);
        assert_eq!(parse_pac_result("SOCKS5 s:1080"), vec![ProxyEntry::Socks("s".into(), 1080)]);
    }
}
