//! Windows platform services.
//!
//! * system proxy: WinINet settings in `HKCU\\…\\Internet Settings`, followed by
//!   `InternetSetOption(SETTINGS_CHANGED/REFRESH)` so running apps pick it up
//! * root CA: current-user `Root` store via `certutil -user` (Windows asks the user)
//! * process lookup: `GetExtendedTcpTable` (IPv4 + IPv6)

use crate::{PlatformError, Result, SystemProxy};
use parking_lot::Mutex;
use quena_model::ProcessInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const INET_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd).args(args).creation_flags(CREATE_NO_WINDOW).output()?;
    if !out.status.success() {
        return Err(PlatformError::Command(format!(
            "{cmd} {}: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn reg_get(name: &str) -> Option<String> {
    let out = run("reg", &["query", INET_KEY, "/v", name]).ok()?;
    for line in out.lines() {
        let l = line.trim();
        if l.starts_with(name) {
            let mut parts = l.split_whitespace();
            parts.next(); // name
            let ty = parts.next()?;
            let rest: Vec<&str> = parts.collect();
            let v = rest.join(" ");
            if ty == "REG_DWORD" {
                return u32::from_str_radix(v.trim_start_matches("0x"), 16).ok().map(|n| n.to_string());
            }
            return Some(v);
        }
    }
    None
}

fn reg_set_str(name: &str, value: &str) -> Result<()> {
    run("reg", &["add", INET_KEY, "/v", name, "/t", "REG_SZ", "/d", value, "/f"]).map(|_| ())
}

fn reg_set_dword(name: &str, value: u32) -> Result<()> {
    run("reg", &["add", INET_KEY, "/v", name, "/t", "REG_DWORD", "/d", &value.to_string(), "/f"]).map(|_| ())
}

fn reg_delete(name: &str) {
    let _ = run("reg", &["delete", INET_KEY, "/v", name, "/f"]);
}

fn notify_wininet() {
    use windows_sys::Win32::Networking::WinInet::{INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW};
    unsafe {
        InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null_mut(), 0);
        InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null_mut(), 0);
    }
}

fn parse_server(v: &str, scheme: &str) -> Option<(String, u16)> {
    // "host:port" or "http=host:port;https=host:port"
    let entry = if v.contains('=') {
        v.split(';').find_map(|p| p.split_once('=').filter(|(k, _)| k.eq_ignore_ascii_case(scheme)).map(|(_, x)| x.to_string()))?
    } else {
        v.to_string()
    };
    let (h, p) = entry.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?))
}

pub fn system_proxy() -> Result<SystemProxy> {
    let enabled = reg_get("ProxyEnable").map(|v| v == "1").unwrap_or(false);
    let server = reg_get("ProxyServer").unwrap_or_default();
    let (http, https) = if enabled { (parse_server(&server, "http"), parse_server(&server, "https")) } else { (None, None) };
    Ok(SystemProxy {
        http,
        https,
        pac_url: reg_get("AutoConfigURL").filter(|s| !s.is_empty()),
        auto_discovery: false,
        exceptions: reg_get("ProxyOverride").map(|s| s.split(';').map(|x| x.to_string()).collect()).unwrap_or_default(),
    })
}

#[derive(Serialize, Deserialize)]
struct Backup {
    port: u16,
    enable: Option<String>,
    server: Option<String>,
    overrides: Option<String>,
    auto_config: Option<String>,
}

pub fn set_system_proxy(port: u16, bypass: &[String], backup: &Path) -> Result<()> {
    if !backup.exists() {
        let b = Backup {
            port,
            enable: reg_get("ProxyEnable"),
            server: reg_get("ProxyServer"),
            overrides: reg_get("ProxyOverride"),
            auto_config: reg_get("AutoConfigURL"),
        };
        crate::write_atomic(backup, &serde_json::to_vec_pretty(&b).expect("backup json"))?;
    }
    reg_set_str("ProxyServer", &format!("http=127.0.0.1:{port};https=127.0.0.1:{port}"))?;
    // No `<local>`: that is "bypass the proxy for local addresses", which would hide
    // intranet and VPN hosts without a dot from Quena.
    let o: Vec<String> = bypass.iter().map(|b| b.replace("169.254/16", "169.254.*")).collect();
    reg_set_str("ProxyOverride", &o.join(";"))?;
    reg_set_dword("ProxyEnable", 1)?;
    notify_wininet();
    tracing::info!(target: "quena::platform", "system proxy set to 127.0.0.1:{port}");
    Ok(())
}

pub fn restore_system_proxy(backup: &Path) -> Result<bool> {
    let Ok(data) = std::fs::read(backup) else { return Ok(false) };
    let b: Backup = match serde_json::from_slice(&data) {
        Ok(b) => b,
        Err(e) => {
            // Damaged backup: the old settings are lost, but never leave Windows pointing
            // at a proxy on this machine that is gone.
            tracing::error!(target: "quena::platform", "system proxy backup unreadable ({e}); turning the proxy off");
            let _ = reg_set_dword("ProxyEnable", 0);
            notify_wininet();
            let _ = std::fs::remove_file(backup);
            return Ok(true);
        }
    };
    match &b.server {
        Some(s) if !s.contains(&format!("127.0.0.1:{}", b.port)) => reg_set_str("ProxyServer", s)?,
        _ => reg_delete("ProxyServer"),
    }
    match &b.overrides {
        Some(o) => reg_set_str("ProxyOverride", o)?,
        None => reg_delete("ProxyOverride"),
    }
    let was_ours = b.server.as_deref().is_some_and(|s| s.contains(&format!("127.0.0.1:{}", b.port)));
    reg_set_dword("ProxyEnable", if b.enable.as_deref() == Some("1") && !was_ours { 1 } else { 0 })?;
    notify_wininet();
    std::fs::remove_file(backup)?;
    tracing::info!(target: "quena::platform", "system proxy restored");
    Ok(true)
}

pub fn install_root_ca(cert: &Path) -> Result<()> {
    run("certutil", &["-user", "-addstore", "Root", &cert.to_string_lossy()]).map(|_| ())
}

pub fn remove_root_ca(_cert: &Path, sha1: &str) -> Result<()> {
    run("certutil", &["-user", "-delstore", "Root", sha1]).map(|_| ())
}

/// The local machine's Root store, through an elevated certutil (UAC prompt).
pub fn machine_root_ca(cert: &Path, sha1: &str, trust: bool) -> Result<()> {
    let target = if trust { cert.to_string_lossy().replace('\'', "''") } else { sha1.replace('\'', "") };
    let verb = if trust { "-addstore" } else { "-delstore" };
    let script = format!("$p = Start-Process -FilePath certutil -ArgumentList '{verb}','Root','\"{target}\"' -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode");
    run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script]).map(|_| ())
}

pub fn is_root_ca_trusted(cert: &Path) -> bool {
    machine_or_user_trusted(cert, true) || machine_or_user_trusted(cert, false)
}

fn machine_or_user_trusted(cert: &Path, user: bool) -> bool {
    let args: &[&str] = if user { &["-user", "-verifystore", "Root"] } else { &["-verifystore", "Root"] };
    run("certutil", args).map(|out| {
        // Match by fingerprint of the given certificate file.
        let hash = run("certutil", &["-hashfile", &cert.to_string_lossy(), "SHA1"]).unwrap_or_default();
        let fp: String = hash.lines().nth(1).unwrap_or("").chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_ascii_lowercase();
        !fp.is_empty() && out.to_ascii_lowercase().replace(' ', "").contains(&fp)
    })
    .unwrap_or(false)
}

pub fn open(target: &str) -> Result<()> {
    run("cmd", &["/C", "start", "", target]).map(|_| ())
}

pub fn reveal(path: &Path) -> Result<()> {
    let _ = Command::new("explorer").arg(format!("/select,{}", path.display())).spawn()?;
    Ok(())
}

pub fn local_addresses() -> Vec<(String, String)> {
    let Ok(out) = run("ipconfig", &[]) else { return vec![] };
    let mut res = Vec::new();
    let mut iface = String::new();
    for line in out.lines() {
        if !line.starts_with(' ') && line.trim_end().ends_with(':') {
            iface = line.trim().trim_end_matches(':').to_string();
            continue;
        }
        if line.contains("IPv4") {
            if let Some((_, ip)) = line.rsplit_once(':') {
                let ip = ip.trim().trim_end_matches("(Preferred)").trim().to_string();
                if !ip.starts_with("127.") && !ip.starts_with("169.254.") && !ip.is_empty() {
                    res.push((iface.clone(), ip));
                }
            }
        }
    }
    res
}

// -------------------------------------------------------------- secure store

fn target(account: &str) -> Vec<u16> {
    format!("{}:{}", crate::secure::SERVICE, account).encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn secure_set(account: &str, secret: &[u8]) -> Result<()> {
    use windows_sys::Win32::Security::Credentials::{CredWriteW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW};
    let mut t = target(account);
    let mut blob = secret.to_vec();
    let cred = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: t.as_mut_ptr(),
        Comment: std::ptr::null_mut(),
        LastWritten: unsafe { std::mem::zeroed() },
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: std::ptr::null_mut(),
        UserName: std::ptr::null_mut(),
    };
    if unsafe { CredWriteW(&cred, 0) } == 0 {
        return Err(PlatformError::Command("CredWriteW failed".into()));
    }
    Ok(())
}

pub fn secure_get(account: &str) -> Result<Option<Vec<u8>>> {
    use windows_sys::Win32::Security::Credentials::{CredFree, CredReadW, CRED_TYPE_GENERIC, CREDENTIALW};
    let t = target(account);
    let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
    if unsafe { CredReadW(t.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) } == 0 {
        return Ok(None);
    }
    let out = unsafe {
        let c = &*cred;
        let slice = std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize).to_vec();
        CredFree(cred as *const _);
        slice
    };
    Ok(Some(out))
}

pub fn secure_delete(account: &str) -> Result<()> {
    use windows_sys::Win32::Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC};
    let t = target(account);
    unsafe { CredDeleteW(t.as_ptr(), CRED_TYPE_GENERIC, 0) };
    Ok(())
}

// ---------------------------------------------------------------- process

pub struct ProcessLookup {
    names: Mutex<HashMap<u32, (String, Instant)>>,
}

impl Default for ProcessLookup {
    fn default() -> Self {
        ProcessLookup { names: Mutex::new(HashMap::new()) }
    }
}

fn owning_pid(client_port: u16, proxy_port: u16) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    let port_of = |p: u32| u16::from_be(p as u16);
    for af in [AF_INET as u32, AF_INET6 as u32] {
        let mut size: u32 = 0;
        unsafe { GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0) };
        if size == 0 {
            continue;
        }
        let mut buf = vec![0u8; size as usize + 4096];
        size = buf.len() as u32;
        let rc = unsafe { GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0) };
        if rc != 0 {
            continue;
        }
        unsafe {
            if af == AF_INET as u32 {
                let t = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let rows = std::slice::from_raw_parts(t.table.as_ptr() as *const MIB_TCPROW_OWNER_PID, t.dwNumEntries as usize);
                if let Some(r) = rows.iter().find(|r| port_of(r.dwLocalPort) == client_port && port_of(r.dwRemotePort) == proxy_port) {
                    return Some(r.dwOwningPid);
                }
            } else {
                let t = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
                let rows = std::slice::from_raw_parts(t.table.as_ptr() as *const MIB_TCP6ROW_OWNER_PID, t.dwNumEntries as usize);
                if let Some(r) = rows.iter().find(|r| port_of(r.dwLocalPort) == client_port && port_of(r.dwRemotePort) == proxy_port) {
                    return Some(r.dwOwningPid);
                }
            }
        }
    }
    None
}

fn process_name(pid: u32) -> String {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return format!("pid{pid}");
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return format!("pid{pid}");
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        let file = path.rsplit('\\').next().unwrap_or(&path);
        file.trim_end_matches(".exe").trim_end_matches(".EXE").to_ascii_lowercase()
    }
}

impl ProcessLookup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lookup(&self, client_port: u16, proxy_port: u16) -> Option<ProcessInfo> {
        let pid = owning_pid(client_port, proxy_port)?;
        let mut names = self.names.lock();
        let name = match names.get(&pid) {
            Some((n, t)) if t.elapsed() < Duration::from_secs(60) => n.clone(),
            _ => {
                let n = process_name(pid);
                names.insert(pid, (n.clone(), Instant::now()));
                if names.len() > 4096 {
                    names.clear();
                }
                n
            }
        };
        Some(ProcessInfo { pid, name })
    }
}

/// Connection-specific DNS suffixes of adapters that look like VPN clients.
pub fn vpn_domains() -> Vec<String> {
    let script = "Get-DnsClient | Where-Object { $_.ConnectionSpecificSuffix -and ((Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).InterfaceDescription -match 'VPN|TAP|TUN|WireGuard|Wintun|AnyConnect|Fortinet|GlobalProtect|Juniper|Pulse|OpenVPN|Zscaler') } | ForEach-Object { $_.ConnectionSpecificSuffix }";
    run("powershell", &["-NoProfile", "-NonInteractive", "-Command", script])
        .map(|t| {
            let mut out: Vec<String> = Vec::new();
            for l in t.lines().map(|l| l.trim().trim_end_matches('.').to_ascii_lowercase()).filter(|l| !l.is_empty()) {
                if !out.contains(&l) {
                    out.push(l);
                }
            }
            out
        })
        .unwrap_or_default()
}
