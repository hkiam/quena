use crate::{PlatformError, Result, SystemProxy};
use parking_lot::Mutex;
use quena_model::ProcessInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd).args(args).output()?;
    if !out.status.success() {
        return Err(PlatformError::Command(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ---------------------------------------------------------------- proxy

pub fn system_proxy() -> Result<SystemProxy> {
    let out = run("/usr/sbin/scutil", &["--proxy"])?;
    Ok(parse_scutil(&out))
}

fn parse_scutil(out: &str) -> SystemProxy {
    let mut kv: HashMap<String, String> = HashMap::new();
    let mut exceptions = Vec::new();
    let mut in_exc = false;
    for line in out.lines() {
        let l = line.trim();
        if l.starts_with("ExceptionsList") {
            in_exc = true;
            continue;
        }
        if in_exc {
            if l.starts_with('}') {
                in_exc = false;
            } else if let Some((_, v)) = l.split_once(" : ") {
                exceptions.push(v.trim().to_string());
            }
            continue;
        }
        if let Some((k, v)) = l.split_once(" : ") {
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    let pair = |en: &str, h: &str, p: &str| -> Option<(String, u16)> {
        if kv.get(en).map(|v| v == "1").unwrap_or(false) {
            Some((kv.get(h)?.clone(), kv.get(p)?.parse().ok()?))
        } else {
            None
        }
    };
    SystemProxy {
        http: pair("HTTPEnable", "HTTPProxy", "HTTPPort"),
        https: pair("HTTPSEnable", "HTTPSProxy", "HTTPSPort"),
        pac_url: if kv.get("ProxyAutoConfigEnable").map(|v| v == "1").unwrap_or(false) { kv.get("ProxyAutoConfigURLString").cloned() } else { None },
        auto_discovery: kv.get("ProxyAutoDiscoveryEnable").map(|v| v == "1").unwrap_or(false),
        exceptions,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceState {
    service: String,
    web: (bool, String, u16),
    secure: (bool, String, u16),
    bypass: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Backup {
    port: u16,
    services: Vec<ServiceState>,
}

fn services() -> Result<Vec<String>> {
    let out = run("/usr/sbin/networksetup", &["-listallnetworkservices"])?;
    Ok(out
        .lines()
        .skip(1) // "An asterisk (*) denotes that a network service is disabled."
        .filter(|l| !l.trim().is_empty() && !l.starts_with('*'))
        .map(|l| l.to_string())
        .collect())
}

fn get_proxy(kind: &str, service: &str) -> Result<(bool, String, u16)> {
    let out = run("/usr/sbin/networksetup", &[kind, service])?;
    let mut enabled = false;
    let mut host = String::new();
    let mut port = 0;
    for l in out.lines() {
        if let Some((k, v)) = l.split_once(':') {
            match k.trim() {
                "Enabled" => enabled = v.trim() == "Yes",
                "Server" => host = v.trim().to_string(),
                "Port" => port = v.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    Ok((enabled, host, port))
}

fn get_bypass(service: &str) -> Vec<String> {
    run("/usr/sbin/networksetup", &["-getproxybypassdomains", service])
        .map(|o| o.lines().filter(|l| !l.contains("There aren't any")).map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default()
}

/// Run `f` for every network service at once. Each `networksetup` call is its own process
/// (~50 ms); a Mac often has 5–10 services (Wi-Fi, Ethernet adapters, VPNs, iPhone USB…),
/// so doing them one after another made starting and stopping the capture take seconds.
fn per_service<T: Send>(svcs: &[String], f: impl Fn(&str) -> T + Sync) -> Vec<T> {
    std::thread::scope(|scope| {
        let f = &f;
        let handles: Vec<_> = svcs.iter().map(|s| scope.spawn(move || f(s))).collect();
        handles.into_iter().map(|h| h.join().expect("networksetup worker")).collect()
    })
}

pub fn set_system_proxy(port: u16, bypass: &[String], backup: &Path) -> Result<()> {
    let svcs = services()?;
    // Keep an existing backup (e.g. after a crash) – it holds the original state.
    if !backup.exists() {
        let states = per_service(&svcs, |s| -> Result<ServiceState> {
            Ok(ServiceState { service: s.to_string(), web: get_proxy("-getwebproxy", s)?, secure: get_proxy("-getsecurewebproxy", s)?, bypass: get_bypass(s) })
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
        let b = Backup { port, services: states };
        crate::write_atomic(backup, &serde_json::to_vec_pretty(&b).expect("backup json"))?;
    }
    let p = port.to_string();
    per_service(&svcs, |s| -> Result<()> {
        run("/usr/sbin/networksetup", &["-setwebproxy", s, "127.0.0.1", &p])?;
        run("/usr/sbin/networksetup", &["-setsecurewebproxy", s, "127.0.0.1", &p])?;
        if !bypass.is_empty() {
            let mut args: Vec<&str> = vec!["-setproxybypassdomains", s];
            args.extend(bypass.iter().map(|b| b.as_str()));
            let _ = run("/usr/sbin/networksetup", &args);
        }
        Ok(())
    })
    .into_iter()
    .collect::<Result<Vec<_>>>()?;
    tracing::info!(target: "quena::platform", "system proxy set to 127.0.0.1:{port} for {} service(s)", svcs.len());
    Ok(())
}

pub fn restore_system_proxy(backup: &Path) -> Result<bool> {
    let Ok(data) = std::fs::read(backup) else { return Ok(false) };
    let b: Backup = match serde_json::from_slice(&data) {
        Ok(b) => b,
        Err(e) => {
            // Damaged backup (e.g. power loss while writing): we cannot restore the old
            // settings, but we must not leave the Mac pointing at a proxy that is gone.
            tracing::error!(target: "quena::platform", "system proxy backup unreadable ({e}); turning off proxies that point to this Mac");
            if let Ok(svcs) = services() {
                per_service(&svcs, |s| {
                    for (get, state) in [("-getwebproxy", "-setwebproxystate"), ("-getsecurewebproxy", "-setsecurewebproxystate")] {
                        if let Ok((true, host, _)) = get_proxy(get, s) {
                            if host == "127.0.0.1" || host == "localhost" {
                                let _ = run("/usr/sbin/networksetup", &[state, s, "off"]);
                            }
                        }
                    }
                });
            }
            let _ = std::fs::remove_file(backup);
            return Ok(true);
        }
    };
    // Best effort per service: a service that no longer exists (VPN, USB adapter) must
    // not stop the others from being restored.
    let names: Vec<String> = b.services.iter().map(|s| s.service.clone()).collect();
    let failures: Vec<String> = per_service(&names, |name| {
        let mut failures = Vec::new();
        let Some(s) = b.services.iter().find(|x| x.service == name) else { return failures };
        let restore = |set: &str, state: &str, v: &(bool, String, u16)| -> Result<()> {
            if !v.1.is_empty() && v.2 != 0 && !(v.1 == "127.0.0.1" && v.2 == b.port) {
                run("/usr/sbin/networksetup", &[set, &s.service, &v.1, &v.2.to_string()])?;
            }
            run("/usr/sbin/networksetup", &[state, &s.service, if v.0 && !(v.1 == "127.0.0.1" && v.2 == b.port) { "on" } else { "off" }])?;
            Ok(())
        };
        for (set, state, v) in [("-setwebproxy", "-setwebproxystate", &s.web), ("-setsecurewebproxy", "-setsecurewebproxystate", &s.secure)] {
            if let Err(e) = restore(set, state, v) {
                failures.push(format!("{}: {e}", s.service));
            }
        }
        let mut args: Vec<&str> = vec!["-setproxybypassdomains", &s.service];
        if s.bypass.is_empty() {
            args.push("Empty");
        } else {
            args.extend(s.bypass.iter().map(|x| x.as_str()));
        }
        let _ = run("/usr/sbin/networksetup", &args);
        failures
    })
    .into_iter()
    .flatten()
    .collect();
    let _ = std::fs::remove_file(backup);
    if failures.is_empty() {
        tracing::info!(target: "quena::platform", "system proxy restored");
    } else {
        tracing::warn!(target: "quena::platform", "system proxy restored with errors: {}", failures.join("; "));
    }
    Ok(true)
}

// ---------------------------------------------------------- certificates

fn login_keychain() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/Library/Keychains/login.keychain-db")
}

pub fn install_root_ca(cert: &Path) -> Result<()> {
    let p = cert.to_string_lossy();
    run("/usr/bin/security", &["add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-p", "basic", "-k", &login_keychain(), &p])?;
    Ok(())
}

pub fn remove_root_ca(cert: &Path, sha1: &str) -> Result<()> {
    let p = cert.to_string_lossy();
    let _ = run("/usr/bin/security", &["remove-trusted-cert", &p]);
    run("/usr/bin/security", &["delete-certificate", "-Z", sha1, &login_keychain()])?;
    Ok(())
}

pub fn is_root_ca_trusted(cert: &Path) -> bool {
    let p = cert.to_string_lossy();
    run("/usr/bin/security", &["verify-cert", "-c", &p, "-p", "ssl", "-L", "-q"]).is_ok()
}

pub fn open(target: &str) -> Result<()> {
    run("/usr/bin/open", &[target]).map(|_| ())
}

pub fn reveal(path: &Path) -> Result<()> {
    run("/usr/bin/open", &["-R", &path.to_string_lossy()]).map(|_| ())
}

// -------------------------------------------------------------- secure store

pub fn secure_set(account: &str, secret: &[u8]) -> Result<()> {
    // Store hex so binary secrets survive; the value lives only in the child's argv
    // and then in the Keychain (protected by its ACL) – never in a Quena file.
    let value = format!("hex:{}", secret.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let _ = run("/usr/bin/security", &["delete-generic-password", "-a", account, "-s", crate::secure::SERVICE]);
    run("/usr/bin/security", &["add-generic-password", "-a", account, "-s", crate::secure::SERVICE, "-U", "-w", &value]).map(|_| ())
}

pub fn secure_get(account: &str) -> Result<Option<Vec<u8>>> {
    match run("/usr/bin/security", &["find-generic-password", "-a", account, "-s", crate::secure::SERVICE, "-w"]) {
        Ok(out) => {
            let v = out.trim();
            if let Some(hex) = v.strip_prefix("hex:") {
                let bytes = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()).collect();
                Ok(Some(bytes))
            } else {
                Ok(Some(v.as_bytes().to_vec()))
            }
        }
        Err(_) => Ok(None),
    }
}

pub fn secure_delete(account: &str) -> Result<()> {
    let _ = run("/usr/bin/security", &["delete-generic-password", "-a", account, "-s", crate::secure::SERVICE]);
    Ok(())
}

pub fn local_addresses() -> Vec<(String, String)> {
    let Ok(out) = run("/sbin/ifconfig", &[]) else { return vec![] };
    let mut res = Vec::new();
    let mut iface = String::new();
    for line in out.lines() {
        if !line.starts_with(['\t', ' ']) {
            iface = line.split(':').next().unwrap_or("").to_string();
            continue;
        }
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("inet ") {
            let ip = rest.split_whitespace().next().unwrap_or("");
            if !ip.starts_with("127.") && !ip.starts_with("169.254.") {
                res.push((iface.clone(), ip.to_string()));
            }
        }
    }
    res
}

// ---------------------------------------------------------------- process

/// Maps client source ports (connections to our listen port) to processes.
pub struct ProcessLookup {
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct Cache {
    by_port: HashMap<u16, (u32, Instant)>,
    names: HashMap<u32, String>,
    last_scan: Option<Instant>,
}

impl Default for ProcessLookup {
    fn default() -> Self {
        ProcessLookup { cache: Mutex::new(Cache::default()) }
    }
}

impl ProcessLookup {
    pub fn new() -> Self {
        Self::default()
    }

    /// Owning process of the TCP connection `client_port -> proxy_port` (blocking; call off the async runtime).
    pub fn lookup(&self, client_port: u16, proxy_port: u16) -> Option<ProcessInfo> {
        {
            let c = self.cache.lock();
            if let Some((pid, _)) = c.by_port.get(&client_port) {
                let name = c.names.get(pid).cloned().unwrap_or_default();
                return Some(ProcessInfo { pid: *pid, name });
            }
        }
        for attempt in 0..2 {
            let scanned = {
                let c = self.cache.lock();
                c.last_scan.is_some_and(|t| t.elapsed() < Duration::from_millis(40))
            };
            if scanned && attempt == 0 {
                std::thread::sleep(Duration::from_millis(40));
            }
            self.scan(proxy_port);
            let c = self.cache.lock();
            if let Some((pid, _)) = c.by_port.get(&client_port) {
                let name = c.names.get(pid).cloned().unwrap_or_default();
                return Some(ProcessInfo { pid: *pid, name });
            }
        }
        None
    }

    fn scan(&self, proxy_port: u16) {
        use libproc::libproc::bsd_info::BSDInfo;
        use libproc::libproc::file_info::{ListFDs, ProcFDType, pidfdinfo};
        use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
        use libproc::libproc::proc_pid::{listpidinfo, pidinfo};
        use libproc::processes::{ProcFilter, pids_by_type};
        let me = std::process::id();
        let Ok(pids) = pids_by_type(ProcFilter::All) else { return };
        let mut found: Vec<(u16, u32)> = Vec::new();
        for pid in pids {
            if pid == 0 || pid == me {
                continue;
            }
            let Ok(info) = pidinfo::<BSDInfo>(pid as i32, 0) else { continue };
            let Ok(fds) = listpidinfo::<ListFDs>(pid as i32, info.pbi_nfiles as usize) else { continue };
            for fd in fds {
                if !matches!(ProcFDType::from(fd.proc_fdtype), ProcFDType::Socket) {
                    continue;
                }
                let Ok(s) = pidfdinfo::<SocketFDInfo>(pid as i32, fd.proc_fd) else { continue };
                if !matches!(SocketInfoKind::from(s.psi.soi_kind), SocketInfoKind::Tcp) {
                    continue;
                }
                let tcp = unsafe { s.psi.soi_proto.pri_tcp };
                let lport = u16::from_be(tcp.tcpsi_ini.insi_lport as u16);
                let fport = u16::from_be(tcp.tcpsi_ini.insi_fport as u16);
                if fport == proxy_port {
                    found.push((lport, pid));
                }
            }
        }
        let now = Instant::now();
        let mut c = self.cache.lock();
        for (port, pid) in found {
            c.by_port.insert(port, (pid, now));
            if let std::collections::hash_map::Entry::Vacant(e) = c.names.entry(pid) {
                e.insert(process_name(pid));
            }
        }
        // Forget old entries (ports are reused).
        c.by_port.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(120));
        if c.names.len() > 4096 {
            c.names.clear();
        }
        c.last_scan = Some(now);
    }
}

fn process_name(pid: u32) -> String {
    use libproc::libproc::proc_pid::{name, pidpath};
    if let Ok(path) = pidpath(pid as i32) {
        // Prefer the app bundle name ("Google Chrome Helper" -> "Google Chrome Helper").
        if let Some(file) = Path::new(&path).file_name() {
            return file.to_string_lossy().into_owned();
        }
    }
    name(pid as i32).unwrap_or_else(|_| format!("pid{pid}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scutil_parse() {
        let out = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n    1 : 169.254/16\n  }\n  FTPPassive : 1\n  HTTPEnable : 1\n  HTTPPort : 8080\n  HTTPProxy : proxy.corp\n  HTTPSEnable : 0\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://wpad/wpad.dat\n}\n";
        let p = parse_scutil(out);
        assert_eq!(p.http, Some(("proxy.corp".into(), 8080)));
        assert_eq!(p.https, None);
        assert_eq!(p.pac_url.as_deref(), Some("http://wpad/wpad.dat"));
        assert_eq!(p.exceptions, vec!["*.local", "169.254/16"]);
    }

    #[test]
    fn lookup_own_connection() {
        // Connect a child process (curl) to a local listener and find it.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let mut child = std::process::Command::new("/usr/bin/nc").args(["127.0.0.1", &port.to_string()]).stdin(std::process::Stdio::piped()).spawn().unwrap();
        let (_s, peer) = l.accept().unwrap();
        let pl = ProcessLookup::new();
        let t = Instant::now();
        let info = pl.lookup(peer.port(), port);
        let el = t.elapsed();
        let _ = child.kill();
        let info = info.expect("process found");
        assert_eq!(info.name, "nc");
        eprintln!("lookup took {el:?}");
    }
}

pub fn vpn_domains() -> Vec<String> {
    run("/usr/sbin/scutil", &["--dns"]).map(|t| crate::parse_scutil_dns(&format!("\n{t}"))).unwrap_or_default()
}
