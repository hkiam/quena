//! PAC (proxy auto-config) evaluation on a dedicated QuickJS thread.
//!
//! `FindProxyForURL(url, host)` is evaluated once per host and the result is
//! cached, so the forwarding path never blocks on JS after the first lookup.
//! DNS helpers (`dnsResolve`, `myIpAddress`, `isInNet`, `isResolvable`) are
//! implemented in Rust; the rest are pure-JS helpers in `pac_prelude.js`.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender, TrySendError};
use std::time::{Duration, Instant};

const PAC_PRELUDE: &str = include_str!("pac_prelude.js");
const MEMORY_LIMIT: usize = 32 * 1024 * 1024;

/// A single directive from `FindProxyForURL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyEntry {
    Direct,
    /// An HTTP proxy `host:port`.
    Proxy(String, u16),
    /// A SOCKS proxy — not usable as an upstream by Quena's connector.
    Socks(String, u16),
}

enum Cmd {
    Eval {
        url: String,
        host: String,
        reply: Sender<Result<String, String>>,
    },
    Shutdown,
}

/// How long a per-host PAC result stays cached. A short TTL bounds the damage
/// from a transient DNS failure (which could otherwise pin a host to DIRECT and
/// bypass the corporate proxy) and picks up network changes automatically.
const CACHE_TTL: Duration = Duration::from_secs(300);
/// Upper bound on a single `FindProxyForURL` evaluation, so a slow/hung script
/// or DNS lookup can never block the caller indefinitely.
const EVAL_TIMEOUT: Duration = Duration::from_secs(5);
/// CPU budget for JS itself (an endless loop in the script is interrupted).
const JS_EVAL_BUDGET: Duration = Duration::from_secs(2);
const JS_LOAD_BUDGET: Duration = Duration::from_secs(3);
/// Pending evaluations; beyond this, lookups answer DIRECT instead of queueing up.
const QUEUE_BOUND: usize = 64;
/// Cached hosts before expired entries are swept.
const CACHE_MAX: usize = 4096;
/// Concurrent `dnsResolve` threads (a hung resolver must not pile up threads).
const DNS_MAX_INFLIGHT: usize = 16;
static DNS_INFLIGHT: AtomicUsize = AtomicUsize::new(0);

/// A compiled PAC script. Evaluation is cached per host.
pub struct PacEngine {
    tx: SyncSender<Cmd>,
    cache: Mutex<HashMap<String, (Vec<ProxyEntry>, Instant)>>,
    source_error: Option<String>,
}

impl PacEngine {
    /// Compile a PAC script. Returns an engine even if the script is invalid;
    /// in that case every lookup yields DIRECT and [`PacEngine::error`] is set.
    pub fn new(source: &str) -> PacEngine {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Cmd>(QUEUE_BOUND);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let src = source.to_string();
        std::thread::Builder::new()
            .name("quena-pac".into())
            .spawn(move || worker(rx, &src, ready_tx))
            .expect("spawn pac worker");
        let source_error = match ready_rx.recv_timeout(JS_LOAD_BUDGET + Duration::from_secs(5)) {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                Some("PAC script did not finish loading in time".into())
            }
            Err(_) => Some("pac worker did not start".into()),
        };
        PacEngine {
            tx,
            cache: Mutex::new(HashMap::new()),
            source_error,
        }
    }

    /// The compile error, if the PAC script failed to load.
    pub fn error(&self) -> Option<&str> {
        self.source_error.as_deref()
    }

    /// All directives `FindProxyForURL(url, host)` returns for this host.
    ///
    /// Results are cached per host with a TTL. Evaluation failures (script error,
    /// timeout, dead worker) fall back to DIRECT but are **not** cached, so a
    /// transient failure never sticks a host on DIRECT until restart.
    pub fn find(&self, url: &str, host: &str) -> Vec<ProxyEntry> {
        let key = host.to_ascii_lowercase();
        if let Some((v, at)) = self.cache.lock().get(&key) {
            if at.elapsed() < CACHE_TTL {
                return v.clone();
            }
        }
        if self.source_error.is_some() {
            return vec![ProxyEntry::Direct];
        }
        let (reply, rx) = std::sync::mpsc::channel();
        match self.tx.try_send(Cmd::Eval {
            url: url.to_string(),
            host: host.to_string(),
            reply,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                tracing::warn!(target: "quena", "PAC evaluation queue full; using DIRECT for {host} (not cached)");
                return vec![ProxyEntry::Direct];
            }
            Err(TrySendError::Disconnected(_)) => return vec![ProxyEntry::Direct],
        }
        match rx.recv_timeout(EVAL_TIMEOUT) {
            Ok(Ok(s)) => {
                let entries = parse_pac_result(&s);
                let mut cache = self.cache.lock();
                if cache.len() >= CACHE_MAX {
                    cache.retain(|_, (_, at)| at.elapsed() < CACHE_TTL);
                    if cache.len() >= CACHE_MAX {
                        cache.clear();
                    }
                }
                cache.insert(key, (entries.clone(), Instant::now()));
                entries
            }
            Ok(Err(e)) => {
                tracing::warn!(target: "quena", "PAC evaluation for {host} failed: {e}; using DIRECT (not cached)");
                vec![ProxyEntry::Direct]
            }
            Err(_) => {
                tracing::warn!(target: "quena", "PAC evaluation for {host} timed out; using DIRECT (not cached)");
                vec![ProxyEntry::Direct]
            }
        }
    }

    /// The upstream HTTP proxy for `host`, like browsers do: the first `PROXY`
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
        let _ = self.tx.try_send(Cmd::Shutdown);
    }
}

fn host_without_port(host_port: &str) -> &str {
    let s = host_port.trim();
    // Bracketed IPv6 literal: `[::1]` or `[::1]:8080`.
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    // Otherwise strip a trailing :port, unless the remainder is an unbracketed IPv6.
    if let Some(idx) = s.rfind(':') {
        if s[idx + 1..].chars().all(|c| c.is_ascii_digit()) && !s[..idx].contains(':') {
            return &s[..idx];
        }
    }
    s
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
    rt.set_max_stack_size(1 << 20);
    // Interrupt runaway JS (endless loops) once the current deadline passes.
    let base = Instant::now();
    let deadline = Arc::new(AtomicU64::new(u64::MAX));
    {
        let deadline = deadline.clone();
        rt.set_interrupt_handler(Some(Box::new(move || {
            base.elapsed().as_micros() as u64 > deadline.load(Ordering::Relaxed)
        })));
    }
    let arm = |budget: Duration| {
        deadline.store(
            (base.elapsed() + budget).as_micros() as u64,
            Ordering::Relaxed,
        )
    };
    let ctx = match Context::full(&rt) {
        Ok(c) => c,
        Err(e) => {
            let _ = ready.send(Err(format!("pac context: {e}")));
            return;
        }
    };

    arm(JS_LOAD_BUDGET);
    let init = ctx.with(|cx| -> Result<(), String> {
        install_dns(&cx)?;
        cx.eval::<(), _>(PAC_PRELUDE).map_err(|e| e.to_string())?;
        cx.eval::<(), _>(source.as_bytes())
            .map_err(|e| exc(&cx, e))?;
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
                arm(JS_EVAL_BUDGET);
                let out = ctx.with(|cx| -> Result<String, String> {
                    let f: rquickjs::Function = cx
                        .globals()
                        .get("FindProxyForURL")
                        .map_err(|e| e.to_string())?;
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
    let resolve = rquickjs::Function::new(
        cx.clone(),
        |host: String| -> rquickjs::Result<Option<String>> { Ok(dns_resolve(&host)) },
    )
    .map_err(|e| e.to_string())?;
    cx.globals()
        .set("__dnsResolve", resolve)
        .map_err(|e| e.to_string())?;

    let myip = rquickjs::Function::new(cx.clone(), || -> rquickjs::Result<String> {
        Ok(my_ip_address())
    })
    .map_err(|e| e.to_string())?;
    cx.globals()
        .set("__myIpAddress", myip)
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn dns_resolve(host: &str) -> Option<String> {
    // `getaddrinfo` can't be cancelled, so run it on a throwaway thread and give
    // up after a bound — a hung resolver must not wedge the PAC worker (and, via
    // the eval timeout, the caller). The abandoned thread finishes on its own.
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    if DNS_INFLIGHT.fetch_add(1, Ordering::SeqCst) >= DNS_MAX_INFLIGHT {
        DNS_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    let host = host.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("quena-pac-dns".into())
        .spawn(move || {
            let addrs = (host.as_str(), 0u16)
                .to_socket_addrs()
                .ok()
                .map(|it| it.map(|s| s.ip()).collect::<Vec<IpAddr>>());
            DNS_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
            let _ = tx.send(addrs);
        });
    if spawned.is_err() {
        DNS_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    let addrs = rx.recv_timeout(Duration::from_secs(3)).ok().flatten()?;
    // Prefer IPv4 to match classic PAC helpers (isInNet is IPv4).
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
    fn endless_loops_are_interrupted() {
        let t = Instant::now();
        let e = PacEngine::new("while (true) {}");
        assert!(e.error().is_some(), "top-level loop must fail to load");
        assert!(t.elapsed() < Duration::from_secs(8));
        let e = PacEngine::new(
            "function FindProxyForURL(u, h) { if (h == 'loop') { while (true) {} } return 'PROXY p:1'; }",
        );
        assert!(e.error().is_none());
        let t = Instant::now();
        assert_eq!(e.find("http://loop/", "loop"), vec![ProxyEntry::Direct]);
        assert!(t.elapsed() < EVAL_TIMEOUT, "loop not interrupted");
        // The worker is still usable afterwards.
        assert_eq!(
            e.find("http://ok/", "ok"),
            vec![ProxyEntry::Proxy("p".into(), 1)]
        );
    }

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
        assert_eq!(
            pac.find("http://intranet/", "intranet"),
            vec![ProxyEntry::Direct]
        );
        assert_eq!(
            pac.find("http://a.internal.example/", "a.internal.example"),
            vec![ProxyEntry::Direct]
        );
        assert_eq!(
            pac.find("http://a.corp.example/", "a.corp.example"),
            vec![
                ProxyEntry::Proxy("proxy1.example".into(), 8080),
                ProxyEntry::Proxy("proxy2.example".into(), 8080)
            ]
        );
        assert_eq!(
            pac.find("http://x.example/", "x.example"),
            vec![
                ProxyEntry::Proxy("gw.example".into(), 3128),
                ProxyEntry::Direct
            ]
        );
        // upstream_for picks the first PROXY, or None for DIRECT.
        assert_eq!(pac.upstream_for("intranet:80"), None);
        assert_eq!(
            pac.upstream_for("x.example:443"),
            Some(("gw.example".into(), 3128))
        );
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
        assert_eq!(
            parse_pac_result("PROXY p:8080"),
            vec![ProxyEntry::Proxy("p".into(), 8080)]
        );
        assert_eq!(
            parse_pac_result("  PROXY a:1 ; DIRECT "),
            vec![ProxyEntry::Proxy("a".into(), 1), ProxyEntry::Direct]
        );
        assert_eq!(parse_pac_result(""), vec![ProxyEntry::Direct]);
        assert_eq!(
            parse_pac_result("SOCKS5 s:1080"),
            vec![ProxyEntry::Socks("s".into(), 1080)]
        );
    }
}
