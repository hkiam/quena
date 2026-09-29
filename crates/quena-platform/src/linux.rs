//! Linux: desktop proxy settings (GNOME/KDE), NSS + system certificate trust,
//! `/proc` process lookup, Secret Service credentials, xdg helpers.
//!
//! Linux has no single system proxy or trust store. Quena configures what desktop
//! browsers actually use: the GNOME (`gsettings`) or KDE (`kioslaverc`) proxy settings,
//! and the NSS databases of Chrome/Chromium and Firefox. The system CA bundle (curl,
//! wget, most CLI tools) is updated too when the user approves the `pkexec` prompt.

use crate::{PlatformError, Result, SystemProxy};
use parking_lot::Mutex;
use quena_model::ProcessInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd).args(args).stdin(Stdio::null()).output().map_err(|e| PlatformError::Command(format!("{cmd}: {e}")))?;
    if !out.status.success() {
        return Err(PlatformError::Command(format!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim())));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn has(cmd: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(cmd).is_file()))
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"))
}

// ---------------------------------------------------------------- proxy

const GNOME: &str = "org.gnome.system.proxy";

fn gnome_available() -> bool {
    has("gsettings") && run("gsettings", &["list-keys", GNOME]).is_ok_and(|o| o.lines().any(|l| l.trim() == "mode"))
}

fn gget(schema: &str, key: &str) -> Option<String> {
    run("gsettings", &["get", schema, key]).ok().map(|s| s.trim().to_string())
}

fn gset(schema: &str, key: &str, value: &str) -> Result<()> {
    run("gsettings", &["set", schema, key, value]).map(|_| ())
}

/// `'text'` → `text` (gsettings prints GVariant strings quoted).
fn unquote(v: &str) -> String {
    let v = v.trim();
    let v = v.strip_prefix("@as ").unwrap_or(v);
    v.trim_matches('\'').to_string()
}

/// `['a', 'b']` → `["a", "b"]`.
fn parse_str_array(v: &str) -> Vec<String> {
    let v = v.trim();
    let v = v.strip_prefix("@as ").unwrap_or(v);
    let inner = v.trim_start_matches('[').trim_end_matches(']');
    inner.split(',').map(|s| s.trim().trim_matches('\'').to_string()).filter(|s| !s.is_empty()).collect()
}

fn str_array(items: &[String]) -> String {
    format!("[{}]", items.iter().map(|s| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))).collect::<Vec<_>>().join(", "))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GnomeState {
    mode: String,
    http_host: String,
    http_port: u16,
    https_host: String,
    https_port: u16,
    ignore_hosts: String,
    autoconfig_url: String,
}

fn gnome_read() -> Option<GnomeState> {
    if !gnome_available() {
        return None;
    }
    let port = |s: &str| gget(s, "port").and_then(|p| p.trim().parse().ok()).unwrap_or(0);
    Some(GnomeState {
        mode: unquote(&gget(GNOME, "mode")?),
        http_host: unquote(&gget(&format!("{GNOME}.http"), "host").unwrap_or_default()),
        http_port: port(&format!("{GNOME}.http")),
        https_host: unquote(&gget(&format!("{GNOME}.https"), "host").unwrap_or_default()),
        https_port: port(&format!("{GNOME}.https")),
        ignore_hosts: gget(GNOME, "ignore-hosts").unwrap_or_else(|| "[]".into()),
        autoconfig_url: unquote(&gget(GNOME, "autoconfig-url").unwrap_or_default()),
    })
}

fn gnome_apply(s: &GnomeState) -> Result<()> {
    gset(&format!("{GNOME}.http"), "host", &format!("'{}'", s.http_host))?;
    gset(&format!("{GNOME}.http"), "port", &s.http_port.to_string())?;
    gset(&format!("{GNOME}.https"), "host", &format!("'{}'", s.https_host))?;
    gset(&format!("{GNOME}.https"), "port", &s.https_port.to_string())?;
    gset(GNOME, "ignore-hosts", &s.ignore_hosts)?;
    gset(GNOME, "autoconfig-url", &format!("'{}'", s.autoconfig_url))?;
    // Mode last: switching to manual only once the addresses are in place.
    gset(GNOME, "mode", &format!("'{}'", s.mode))
}

/// KDE keeps proxy settings in `~/.config/kioslaverc`, group `[Proxy Settings]`.
fn kde_rc() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".config")).join("kioslaverc")
}

fn kde_active() -> bool {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().to_ascii_uppercase();
    desktop.contains("KDE") || kde_rc().exists()
}

fn kwrite_tool() -> Option<&'static str> {
    ["kwriteconfig6", "kwriteconfig5"].into_iter().find(|t| has(t))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct KdeState {
    /// Key → value of `[Proxy Settings]`; `None` = key absent.
    keys: Vec<(String, Option<String>)>,
}

const KDE_KEYS: [&str; 5] = ["ProxyType", "httpProxy", "httpsProxy", "NoProxyFor", "Proxy Config Script"];

fn kde_read_group() -> HashMap<String, String> {
    let Ok(text) = std::fs::read_to_string(kde_rc()) else { return HashMap::new() };
    let mut out = HashMap::new();
    let mut in_group = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_group = l == "[Proxy Settings]";
            continue;
        }
        if in_group {
            if let Some((k, v)) = l.split_once('=') {
                out.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    out
}

fn kde_read() -> Option<KdeState> {
    if !kde_active() || kwrite_tool().is_none() {
        return None;
    }
    let g = kde_read_group();
    Some(KdeState { keys: KDE_KEYS.iter().map(|k| (k.to_string(), g.get(*k).cloned())).collect() })
}

fn kde_write(key: &str, value: Option<&str>) -> Result<()> {
    let tool = kwrite_tool().ok_or(PlatformError::Unsupported)?;
    let rc = kde_rc();
    let rc = rc.to_string_lossy();
    match value {
        Some(v) => run(tool, &["--file", &rc, "--group", "Proxy Settings", "--key", key, v]).map(|_| ()),
        None => run(tool, &["--file", &rc, "--group", "Proxy Settings", "--key", key, "--delete"]).map(|_| ()),
    }
}

fn kde_notify() {
    // Running KIO workers and Plasma pick up the change on this signal.
    let _ = run("dbus-send", &["--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:"]);
}

/// "http://host:port", "http://host port" or "host:port" → (host, port).
fn parse_kde_proxy(v: &str) -> Option<(String, u16)> {
    let v = v.trim();
    let rest = v.split_once("://").map(|(_, r)| r).unwrap_or(v);
    let (host, port) = if let Some((h, p)) = rest.split_once(' ') { (h, p) } else { rest.rsplit_once(':')? };
    let port: u16 = port.trim().trim_end_matches('/').parse().ok()?;
    (!host.is_empty() && port != 0).then(|| (host.trim_end_matches('/').to_string(), port))
}

fn env_proxy(names: &[&str]) -> Option<(String, u16)> {
    names.iter().find_map(|n| std::env::var(n).ok()).and_then(|v| parse_kde_proxy(&v))
}

pub fn system_proxy() -> Result<SystemProxy> {
    let mut p = SystemProxy::default();
    if let Some(g) = gnome_read().filter(|_| !kde_active()) {
        match g.mode.as_str() {
            "manual" => {
                p.http = (!g.http_host.is_empty() && g.http_port != 0).then(|| (g.http_host.clone(), g.http_port));
                p.https = (!g.https_host.is_empty() && g.https_port != 0).then(|| (g.https_host.clone(), g.https_port));
                p.exceptions = parse_str_array(&g.ignore_hosts);
            }
            "auto" => {
                if g.autoconfig_url.is_empty() {
                    p.auto_discovery = true;
                } else {
                    p.pac_url = Some(g.autoconfig_url.clone());
                }
            }
            _ => {}
        }
        return Ok(p);
    }
    if kde_active() {
        let g = kde_read_group();
        match g.get("ProxyType").map(|s| s.as_str()) {
            Some("1") => {
                p.http = g.get("httpProxy").and_then(|v| parse_kde_proxy(v));
                p.https = g.get("httpsProxy").and_then(|v| parse_kde_proxy(v));
                p.exceptions = g.get("NoProxyFor").map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
            }
            Some("2") => p.pac_url = g.get("Proxy Config Script").cloned().filter(|s| !s.is_empty()),
            Some("3") => p.auto_discovery = true,
            Some("4") => {
                p.http = env_proxy(&["http_proxy", "HTTP_PROXY"]);
                p.https = env_proxy(&["https_proxy", "HTTPS_PROXY"]);
            }
            _ => {}
        }
        return Ok(p);
    }
    // No desktop settings: what command-line tools of this session use.
    p.http = env_proxy(&["http_proxy", "HTTP_PROXY"]);
    p.https = env_proxy(&["https_proxy", "HTTPS_PROXY"]);
    p.exceptions = std::env::var("no_proxy").or_else(|_| std::env::var("NO_PROXY")).map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
    Ok(p)
}

#[derive(Serialize, Deserialize)]
struct Backup {
    port: u16,
    gnome: Option<GnomeState>,
    kde: Option<KdeState>,
}

/// macOS-style bypass entries (`169.254/16`) → CIDR (`169.254.0.0/16`).
fn cidr(b: &str) -> String {
    match b.split_once('/') {
        Some((net, bits)) if net.chars().all(|c| c.is_ascii_digit() || c == '.') => {
            let mut parts: Vec<&str> = net.split('.').filter(|s| !s.is_empty()).collect();
            while parts.len() < 4 {
                parts.push("0");
            }
            format!("{}/{bits}", parts.join("."))
        }
        _ => b.to_string(),
    }
}

pub fn set_system_proxy(port: u16, bypass: &[String], backup: &Path) -> Result<()> {
    let gnome = gnome_read();
    let kde = kde_read();
    if gnome.is_none() && kde.is_none() {
        return Err(PlatformError::Command(format!(
            "no desktop proxy settings found (GNOME or KDE); point your browser or HTTP_PROXY/HTTPS_PROXY to http://127.0.0.1:{port}"
        )));
    }
    // Keep an existing backup (e.g. after a crash) – it holds the original state.
    if !backup.exists() {
        let b = Backup { port, gnome: gnome.clone(), kde: kde.clone() };
        crate::write_atomic(backup, &serde_json::to_vec_pretty(&b).expect("backup json"))?;
    }
    let mut ignore = vec!["localhost".to_string(), "127.0.0.0/8".to_string(), "::1".to_string()];
    ignore.extend(bypass.iter().map(|b| cidr(b)));
    if gnome.is_some() {
        gnome_apply(&GnomeState {
            mode: "manual".into(),
            http_host: "127.0.0.1".into(),
            http_port: port,
            https_host: "127.0.0.1".into(),
            https_port: port,
            ignore_hosts: str_array(&ignore),
            autoconfig_url: String::new(),
        })?;
    }
    if kde.is_some() {
        let url = format!("http://127.0.0.1:{port}");
        kde_write("httpProxy", Some(&url))?;
        kde_write("httpsProxy", Some(&url))?;
        kde_write("NoProxyFor", Some(&ignore.join(",")))?;
        kde_write("ProxyType", Some("1"))?;
        kde_notify();
    }
    tracing::info!(target: "quena::platform", "system proxy set to 127.0.0.1:{port} ({})", [gnome.is_some().then_some("GNOME"), kde.is_some().then_some("KDE")].into_iter().flatten().collect::<Vec<_>>().join(" + "));
    Ok(())
}

fn points_here(host: &str, port: u16, ours: Option<u16>) -> bool {
    (host == "127.0.0.1" || host == "localhost" || host == "::1") && ours.is_none_or(|o| o == port)
}

pub fn restore_system_proxy(backup: &Path) -> Result<bool> {
    let Ok(data) = std::fs::read(backup) else { return Ok(false) };
    let b: Backup = match serde_json::from_slice(&data) {
        Ok(b) => b,
        Err(e) => {
            // Damaged backup: the old settings are lost, but never leave the desktop pointing
            // at a proxy on this machine that is gone.
            tracing::error!(target: "quena::platform", "system proxy backup unreadable ({e}); turning off proxies that point to this machine");
            if let Some(g) = gnome_read() {
                if g.mode == "manual" && points_here(&g.http_host, g.http_port, None) {
                    let _ = gset(GNOME, "mode", "'none'");
                }
            }
            if kde_active() {
                let g = kde_read_group();
                if g.get("ProxyType").map(|s| s.as_str()) == Some("1") && g.get("httpProxy").and_then(|v| parse_kde_proxy(v)).is_some_and(|(h, p)| points_here(&h, p, None)) {
                    let _ = kde_write("ProxyType", Some("0"));
                    kde_notify();
                }
            }
            let _ = std::fs::remove_file(backup);
            return Ok(true);
        }
    };
    let mut failures = Vec::new();
    if let Some(mut g) = b.gnome {
        // A backup taken while already pointing at us (crash loop) must not restore that.
        if g.mode == "manual" && points_here(&g.http_host, g.http_port, Some(b.port)) {
            g.mode = "none".into();
        }
        if let Err(e) = gnome_apply(&g) {
            failures.push(format!("GNOME: {e}"));
        }
    }
    if let Some(k) = b.kde {
        for (key, value) in &k.keys {
            let value = match (key.as_str(), value.as_deref()) {
                ("ProxyType", Some("1")) if k.keys.iter().any(|(k2, v)| k2 == "httpProxy" && v.as_deref().and_then(parse_kde_proxy).is_some_and(|(h, p)| points_here(&h, p, Some(b.port)))) => Some("0"),
                (_, v) => v,
            };
            if let Err(e) = kde_write(key, value) {
                failures.push(format!("KDE {key}: {e}"));
            }
        }
        kde_notify();
    }
    let _ = std::fs::remove_file(backup);
    if failures.is_empty() {
        tracing::info!(target: "quena::platform", "system proxy restored");
    } else {
        tracing::warn!(target: "quena::platform", "system proxy restored with errors: {}", failures.join("; "));
    }
    Ok(true)
}

// ---------------------------------------------------------- certificates

const NSS_NICK: &str = "Quena Root CA";
const SYSTEM_CERT_NAME: &str = "quena-root-ca.crt";

/// NSS databases browsers use: Chrome/Chromium (`~/.pki/nssdb`) and every Firefox
/// profile (regular, Snap and Flatpak installs).
fn nss_dbs(create_default: bool) -> Vec<PathBuf> {
    let h = home();
    let mut dbs = Vec::new();
    let chrome = h.join(".pki/nssdb");
    if chrome.join("cert9.db").exists() {
        dbs.push(chrome);
    } else if create_default && has("certutil") {
        if std::fs::create_dir_all(&chrome).is_ok() && run("certutil", &["-N", "--empty-password", "-d", &format!("sql:{}", chrome.display())]).is_ok() {
            dbs.push(chrome);
        }
    }
    for base in [".mozilla/firefox", "snap/firefox/common/.mozilla/firefox", ".var/app/org.mozilla.firefox/.mozilla/firefox"] {
        if let Ok(rd) = std::fs::read_dir(h.join(base)) {
            for e in rd.flatten() {
                let p = e.path();
                if p.join("cert9.db").exists() {
                    dbs.push(p);
                }
            }
        }
    }
    dbs
}

fn pem_body(pem: &str) -> String {
    pem.lines().filter(|l| !l.starts_with("-----")).map(|l| l.trim()).collect()
}

fn nss_contains(db: &Path, cert_body: &str) -> bool {
    run("certutil", &["-d", &format!("sql:{}", db.display()), "-L", "-n", NSS_NICK, "-a"]).is_ok_and(|out| {
        // All certificates under the nickname, PEM concatenated.
        out.split("-----END CERTIFICATE-----").any(|c| pem_body(c) == cert_body)
    })
}

/// Anchor directory and refresh command of the distribution's system trust store.
fn system_store() -> Option<(&'static str, &'static str)> {
    [
        ("/usr/local/share/ca-certificates", "update-ca-certificates"), // Debian, Ubuntu
        ("/etc/pki/ca-trust/source/anchors", "update-ca-trust"),        // Fedora, RHEL
        ("/etc/ca-certificates/trust-source/anchors", "update-ca-trust"), // Arch
        ("/usr/share/pki/trust/anchors", "update-ca-certificates"),     // openSUSE
    ]
    .into_iter()
    .find(|(dir, tool)| Path::new(dir).is_dir() && (has(tool) || Path::new("/usr/sbin").join(tool).exists()))
}

fn system_has(cert_body: &str) -> bool {
    system_store().is_some_and(|(dir, _)| std::fs::read_to_string(Path::new(dir).join(SYSTEM_CERT_NAME)).is_ok_and(|p| pem_body(&p) == cert_body))
}

/// Run `script` as root via polkit (the desktop asks for the password, like macOS does).
fn pkexec_sh(script: &str) -> Result<()> {
    if !has("pkexec") {
        return Err(PlatformError::Command("pkexec is not available".into()));
    }
    run("pkexec", &["/bin/sh", "-c", script]).map(|_| ())
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn install_root_ca(cert: &Path) -> Result<()> {
    let body = pem_body(&std::fs::read_to_string(cert)?);
    let mut done = Vec::new();
    let mut errors = Vec::new();
    if has("certutil") {
        for db in nss_dbs(true) {
            if nss_contains(&db, &body) {
                done.push(db.display().to_string());
                continue;
            }
            match run("certutil", &["-d", &format!("sql:{}", db.display()), "-A", "-t", "C,,", "-n", NSS_NICK, "-i", &cert.to_string_lossy()]) {
                Ok(_) => done.push(db.display().to_string()),
                Err(e) => errors.push(e.to_string()),
            }
        }
    } else {
        errors.push("certutil (package libnss3-tools / nss-tools) is not installed, so browsers were not updated".into());
    }
    if let Some((dir, tool)) = system_store() {
        if !system_has(&body) {
            let script = format!("cp {} {} && chmod 644 {} && {tool}", sh_quote(&cert.to_string_lossy()), sh_quote(&format!("{dir}/{SYSTEM_CERT_NAME}")), sh_quote(&format!("{dir}/{SYSTEM_CERT_NAME}")));
            match pkexec_sh(&script) {
                Ok(()) => done.push("system trust store".into()),
                Err(e) => errors.push(format!("system trust store: {e}")),
            }
        }
    }
    if done.is_empty() {
        return Err(PlatformError::Command(errors.join("; ")));
    }
    if !errors.is_empty() {
        tracing::warn!(target: "quena::platform", "root certificate partly installed: {}", errors.join("; "));
    }
    tracing::info!(target: "quena::platform", "root certificate trusted in {}", done.join(", "));
    Ok(())
}

pub fn remove_root_ca(_cert: &Path, _sha1: &str) -> Result<()> {
    if has("certutil") {
        for db in nss_dbs(false) {
            // Remove every certificate stored under our nickname (older CAs included).
            for _ in 0..16 {
                if run("certutil", &["-d", &format!("sql:{}", db.display()), "-D", "-n", NSS_NICK]).is_err() {
                    break;
                }
            }
        }
    }
    if let Some((dir, tool)) = system_store() {
        let file = format!("{dir}/{SYSTEM_CERT_NAME}");
        if Path::new(&file).exists() {
            pkexec_sh(&format!("rm -f {} && {tool} --fresh 2>/dev/null || {tool}", sh_quote(&file)))?;
        }
    }
    Ok(())
}

pub fn is_root_ca_trusted(cert: &Path) -> bool {
    let Ok(pem) = std::fs::read_to_string(cert) else { return false };
    let body = pem_body(&pem);
    (has("certutil") && nss_dbs(false).iter().any(|db| nss_contains(db, &body))) || system_has(&body)
}

pub fn open(target: &str) -> Result<()> {
    // xdg-open may stay around while the handler starts; don't wait for it.
    Command::new("xdg-open").arg(target).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(|_| ()).map_err(|e| PlatformError::Command(format!("xdg-open: {e}")))
}

pub fn reveal(path: &Path) -> Result<()> {
    // The freedesktop file-manager interface selects the file (Nautilus, Dolphin, Nemo…).
    let uri = format!("file://{}", path.display());
    let shown = run(
        "dbus-send",
        &["--session", "--print-reply", "--dest=org.freedesktop.FileManager1", "/org/freedesktop/FileManager1", "org.freedesktop.FileManager1.ShowItems", &format!("array:string:{uri}"), "string:"],
    );
    if shown.is_ok() {
        return Ok(());
    }
    let dir = if path.is_dir() { path } else { path.parent().unwrap_or(path) };
    open(&dir.to_string_lossy())
}

// -------------------------------------------------------------- secure store

/// Secrets live in the desktop keyring (Secret Service: GNOME Keyring, KWallet) via
/// `secret-tool`. Without a keyring they are kept in memory for this run only.
fn mem() -> &'static Mutex<HashMap<String, Vec<u8>>> {
    static M: std::sync::OnceLock<Mutex<HashMap<String, Vec<u8>>>> = std::sync::OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

pub fn secure_set(account: &str, secret: &[u8]) -> Result<()> {
    if has("secret-tool") {
        // The value goes through stdin, never into argv or a file.
        let child = Command::new("secret-tool")
            .args(["store", "--label=Quena credentials", "service", crate::secure::SERVICE, "account", account])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn();
        if let Ok(mut c) = child {
            if let Some(mut stdin) = c.stdin.take() {
                let _ = stdin.write_all(format!("hex:{}", hex(secret)).as_bytes());
            }
            if c.wait().is_ok_and(|s| s.success()) {
                mem().lock().remove(account);
                return Ok(());
            }
        }
    }
    tracing::warn!(target: "quena::platform", "no desktop keyring (Secret Service) available; the credential is kept until Quena quits");
    mem().lock().insert(account.to_string(), secret.to_vec());
    Ok(())
}

pub fn secure_get(account: &str) -> Result<Option<Vec<u8>>> {
    if let Some(v) = mem().lock().get(account) {
        return Ok(Some(v.clone()));
    }
    if !has("secret-tool") {
        return Ok(None);
    }
    match run("secret-tool", &["lookup", "service", crate::secure::SERVICE, "account", account]) {
        Ok(out) => {
            let v = out.trim_end_matches('\n');
            if v.is_empty() {
                return Ok(None);
            }
            Ok(Some(match v.strip_prefix("hex:") {
                Some(h) => unhex(h),
                None => v.as_bytes().to_vec(),
            }))
        }
        Err(_) => Ok(None),
    }
}

pub fn secure_delete(account: &str) -> Result<()> {
    mem().lock().remove(account);
    if has("secret-tool") {
        let _ = run("secret-tool", &["clear", "service", crate::secure::SERVICE, "account", account]);
    }
    Ok(())
}

// ------------------------------------------------------------ addresses

pub fn local_addresses() -> Vec<(String, String)> {
    let mut res = Vec::new();
    // SAFETY: getifaddrs allocates a list we only read and free with freeifaddrs.
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return res;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET && ifa.ifa_flags & libc::IFF_UP as u32 != 0 {
                let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                if !ip.is_loopback() && !ip.is_link_local() {
                    let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                    res.push((name, ip.to_string()));
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    res
}

// ---------------------------------------------------------------- process

/// Maps client source ports (connections to our listen port) to processes via
/// `/proc/net/tcp{,6}` (port → socket inode) and `/proc/<pid>/fd` (inode → pid).
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

/// Socket inodes of connections `local_port -> proxy_port` from a `/proc/net/tcp` table.
fn parse_proc_tcp(table: &str, proxy_port: u16, out: &mut HashMap<u64, u16>) {
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let port = |addr: &str| addr.rsplit_once(':').and_then(|(_, p)| u16::from_str_radix(p, 16).ok());
        let (Some(lport), Some(rport)) = (port(f[1]), port(f[2])) else { continue };
        if rport != proxy_port {
            continue;
        }
        if let Ok(inode) = f[9].parse::<u64>() {
            if inode != 0 {
                out.insert(inode, lport);
            }
        }
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
        let mut inodes: HashMap<u64, u16> = HashMap::new();
        for t in ["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(s) = std::fs::read_to_string(t) {
                parse_proc_tcp(&s, proxy_port, &mut inodes);
            }
        }
        let now = Instant::now();
        let mut found: Vec<(u16, u32)> = Vec::new();
        if !inodes.is_empty() {
            let me = std::process::id();
            if let Ok(procs) = std::fs::read_dir("/proc") {
                'pids: for p in procs.flatten() {
                    let Some(pid) = p.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
                    if pid == me {
                        continue;
                    }
                    // Other users' processes are not readable; skip them silently.
                    let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else { continue };
                    for fd in fds.flatten() {
                        let Ok(link) = std::fs::read_link(fd.path()) else { continue };
                        let l = link.to_string_lossy();
                        if let Some(n) = l.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')).and_then(|n| n.parse::<u64>().ok()) {
                            if let Some(port) = inodes.remove(&n) {
                                found.push((port, pid));
                                if inodes.is_empty() {
                                    break 'pids;
                                }
                            }
                        }
                    }
                }
            }
        }
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
    // The executable's file name ("chrome", "firefox", "curl"); `comm` is cut at 15 bytes.
    if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        if let Some(f) = exe.file_name() {
            return f.to_string_lossy().trim_end_matches(" (deleted)").to_string();
        }
    }
    std::fs::read_to_string(format!("/proc/{pid}/comm")).map(|s| s.trim().to_string()).unwrap_or_else(|_| format!("pid{pid}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_tcp_parse() {
        let t = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:D431 0100007F:22A2 01 00000000:00000000 00:00000000 00000000  1000        0 424242 1 0000000000000000 20 4 30 10 -1\n   1: 0100007F:22A2 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 424243 1 0000000000000000 20 4 30 10 -1\n";
        let mut m = HashMap::new();
        parse_proc_tcp(t, 0x22A2, &mut m);
        assert_eq!(m.get(&424242), Some(&0xD431));
        assert_eq!(m.len(), 1, "only the client side of the connection");
    }

    #[test]
    fn kde_and_gsettings_values() {
        assert_eq!(parse_kde_proxy("http://proxy.corp:8080"), Some(("proxy.corp".into(), 8080)));
        assert_eq!(parse_kde_proxy("http://proxy.corp 8080"), Some(("proxy.corp".into(), 8080)));
        assert_eq!(parse_kde_proxy("127.0.0.1:8866/"), Some(("127.0.0.1".into(), 8866)));
        assert_eq!(parse_kde_proxy("garbage"), None);
        assert_eq!(parse_str_array("['localhost', '127.0.0.0/8', '::1']"), vec!["localhost", "127.0.0.0/8", "::1"]);
        assert_eq!(parse_str_array("@as []"), Vec::<String>::new());
        assert_eq!(unquote("'manual'"), "manual");
        assert_eq!(str_array(&["a".into(), "it's".into()]), "['a', 'it\\'s']");
        assert_eq!(cidr("169.254/16"), "169.254.0.0/16");
        assert_eq!(cidr("*.local"), "*.local");
    }

    #[test]
    fn lookup_own_connection() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        // A child process holding the client socket.
        let mut child = match std::process::Command::new("python3")
            .args(["-c", &format!("import socket,time; s=socket.create_connection(('127.0.0.1',{port})); time.sleep(10)")])
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return, // no python3: nothing to test against
        };
        let (_s, peer) = l.accept().unwrap();
        let info = ProcessLookup::new().lookup(peer.port(), port);
        let _ = child.kill();
        let info = info.expect("process found");
        assert!(info.name.starts_with("python"), "name = {}", info.name);
    }

    #[test]
    fn addresses_do_not_panic() {
        let _ = local_addresses();
    }

    /// Real desktop round trip: GNOME proxy settings and NSS trust. Needs a session bus
    /// with dconf and `certutil`; run with
    /// `dbus-run-session -- cargo test -p quena-platform -- --ignored`.
    #[test]
    #[ignore]
    fn desktop_roundtrip() {
        let dir = std::env::temp_dir().join(format!("quena-plat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Proxy: set, read back, restore.
        gset(GNOME, "mode", "'auto'").unwrap();
        gset(GNOME, "autoconfig-url", "'http://wpad.example/wpad.dat'").unwrap();
        let backup = dir.join("backup.json");
        set_system_proxy(8866, &["*.local".into(), "169.254/16".into()], &backup).unwrap();
        let p = system_proxy().unwrap();
        assert_eq!(p.http, Some(("127.0.0.1".into(), 8866)));
        assert!(p.points_to(8866));
        assert!(p.exceptions.contains(&"169.254.0.0/16".to_string()), "{:?}", p.exceptions);
        assert!(restore_system_proxy(&backup).unwrap());
        let p = system_proxy().unwrap();
        assert_eq!(p.pac_url.as_deref(), Some("http://wpad.example/wpad.dat"));
        assert!(!backup.exists());
        // Damaged backup: proxies pointing here are switched off.
        set_system_proxy(8866, &[], &backup).unwrap();
        std::fs::write(&backup, b"{broken").unwrap();
        assert!(restore_system_proxy(&backup).unwrap());
        assert_eq!(unquote(&gget(GNOME, "mode").unwrap()), "none");
        // Trust: NSS round trip with a throwaway CA.
        let pem = rcgen_like_pem();
        let cert = dir.join("ca.pem");
        std::fs::write(&cert, pem).unwrap();
        assert!(!is_root_ca_trusted(&cert));
        install_root_ca(&cert).unwrap();
        assert!(is_root_ca_trusted(&cert));
        remove_root_ca(&cert, "").unwrap();
        assert!(!is_root_ca_trusted(&cert));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A self-signed CA certificate made with openssl (only needed by the ignored test).
    fn rcgen_like_pem() -> String {
        let d = std::env::temp_dir().join(format!("quena-ca-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let key = d.join("k.pem");
        let crt = d.join("c.pem");
        let ok = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Quena Test Root", "-keyout"])
            .arg(&key)
            .arg("-out")
            .arg(&crt)
            .args(["-addext", "basicConstraints=critical,CA:TRUE"])
            .output()
            .unwrap();
        assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stderr));
        std::fs::read_to_string(crt).unwrap()
    }
}
