//! Starting other programs for capture: installed browsers (with their own profile and
//! Quena as proxy) and a terminal whose environment points command-line tools at Quena.

use crate::{PlatformError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// How a browser takes proxy and certificate settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BrowserFamily {
    /// Command-line flags (Chrome, Edge, Brave, Vivaldi, Chromium).
    Chromium,
    /// A profile with `user.js` preferences.
    Firefox,
}

/// An installed browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Browser {
    /// Stable key: `chrome`, `edge`, `brave`, `vivaldi`, `chromium`, `firefox`.
    pub kind: String,
    pub name: String,
    pub exe: PathBuf,
    pub family: BrowserFamily,
}

/// (kind, display name, family)
const KINDS: &[(&str, &str, BrowserFamily)] = &[
    ("chrome", "Google Chrome", BrowserFamily::Chromium),
    ("edge", "Microsoft Edge", BrowserFamily::Chromium),
    ("brave", "Brave", BrowserFamily::Chromium),
    ("vivaldi", "Vivaldi", BrowserFamily::Chromium),
    ("chromium", "Chromium", BrowserFamily::Chromium),
    ("firefox", "Firefox", BrowserFamily::Firefox),
];

/// Where each browser's program usually is.
fn candidates(kind: &str) -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let app = |bundle: &str, bin: &str| {
            let rel = format!("{bundle}.app/Contents/MacOS/{bin}");
            let mut v = vec![PathBuf::from("/Applications").join(&rel)];
            if let Some(h) = std::env::var_os("HOME") {
                v.push(PathBuf::from(h).join("Applications").join(&rel));
            }
            v
        };
        match kind {
            "chrome" => app("Google Chrome", "Google Chrome"),
            "edge" => app("Microsoft Edge", "Microsoft Edge"),
            "brave" => app("Brave Browser", "Brave Browser"),
            "vivaldi" => app("Vivaldi", "Vivaldi"),
            "chromium" => app("Chromium", "Chromium"),
            "firefox" => app("Firefox", "firefox"),
            _ => vec![],
        }
    }
    #[cfg(windows)]
    {
        let roots: Vec<PathBuf> = ["ProgramFiles", "ProgramFiles(x86)", "LocalAppData"].iter().filter_map(|v| std::env::var_os(v)).map(PathBuf::from).collect();
        let rel: &[&str] = match kind {
            "chrome" => &[r"Google\Chrome\Application\chrome.exe"],
            "edge" => &[r"Microsoft\Edge\Application\msedge.exe"],
            "brave" => &[r"BraveSoftware\Brave-Browser\Application\brave.exe"],
            "vivaldi" => &[r"Vivaldi\Application\vivaldi.exe"],
            "chromium" => &[r"Chromium\Application\chrome.exe"],
            "firefox" => &[r"Mozilla Firefox\firefox.exe"],
            _ => &[],
        };
        roots.iter().flat_map(|r| rel.iter().map(move |p| r.join(p))).collect()
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let names: &[&str] = match kind {
            "chrome" => &["google-chrome", "google-chrome-stable"],
            "edge" => &["microsoft-edge", "microsoft-edge-stable"],
            "brave" => &["brave-browser", "brave"],
            "vivaldi" => &["vivaldi", "vivaldi-stable"],
            "chromium" => &["chromium", "chromium-browser"],
            "firefox" => &["firefox"],
            _ => &[],
        };
        names.iter().filter_map(|n| which(n)).collect()
    }
}

/// A program on the PATH.
pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file())
}

/// The browsers installed on this machine, in a fixed order.
pub fn find_browsers() -> Vec<Browser> {
    KINDS
        .iter()
        .filter_map(|(kind, name, family)| {
            candidates(kind).into_iter().find(|p| p.is_file()).map(|exe| Browser { kind: kind.to_string(), name: name.to_string(), exe, family: *family })
        })
        .collect()
}

/// Start a program and leave it running on its own (Quena does not wait for it).
pub fn launch_detached(exe: &Path, args: &[String], env: &[(String, String)]) -> Result<()> {
    let mut c = Command::new(exe);
    c.args(args).envs(env.iter().map(|(k, v)| (k, v))).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        c.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Its own process group: closing Quena (or Ctrl-C in the dev terminal) leaves it alone.
        c.process_group(0);
    }
    c.spawn().map(|_| ()).map_err(|e| PlatformError::Command(format!("{}: {e}", exe.display())))
}

/// Open a terminal window whose shell has `env` set. `dir` is a folder for the start script.
pub fn open_terminal(env: &[(String, String)], dir: &Path) -> Result<()> {
    open_terminal_with(env, dir, None)
}

/// [`open_terminal`] that runs `command` in it first (an AI agent, say); the shell stays open
/// after it.
pub fn open_terminal_with(env: &[(String, String)], dir: &Path, command: Option<&str>) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(target_os = "macos")]
    {
        // Terminal.app runs `.command` files in a new window.
        let script = dir.join("quena-terminal.command");
        let mut s = String::from("#!/bin/sh\n");
        for (k, v) in env {
            s.push_str(&format!("export {k}={}\n", sh_quote(v)));
        }
        s.push_str(BANNER_SH);
        match command {
            // In a login shell, so the user's PATH finds the agent.
            Some(c) => s.push_str(&format!("cd \"$HOME\"\nexec \"${{SHELL:-/bin/zsh}}\" -l -c {}\n", sh_quote(&format!("{c}; exec \"${{SHELL:-/bin/zsh}}\" -l")))),
            None => s.push_str("cd \"$HOME\"\nexec \"${SHELL:-/bin/zsh}\" -l\n"),
        }
        std::fs::write(&script, s)?;
        set_executable(&script)?;
        let out = Command::new("/usr/bin/open").args(["-a", "Terminal"]).arg(&script).output()?;
        if !out.status.success() {
            return Err(PlatformError::Command(String::from_utf8_lossy(&out.stderr).trim().to_string()));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let script = dir.join("quena-terminal.cmd");
        let mut s = String::from("@echo off\r\n");
        for (k, v) in env {
            s.push_str(&format!("set \"{k}={v}\"\r\n"));
        }
        s.push_str("echo Quena: HTTP(S)_PROXY and the root certificate are set for this window.\r\ncd /d \"%USERPROFILE%\"\r\n");
        if let Some(c) = command {
            s.push_str(&format!("call {c}\r\n"));
        }
        std::fs::write(&script, s)?;
        let script_s = script.display().to_string();
        let args: Vec<String> = match which_windows("wt.exe") {
            Some(_) => vec!["-w".into(), "new".into(), "cmd".into(), "/K".into(), script_s],
            None => vec!["/C".into(), "start".into(), "Quena".into(), "cmd".into(), "/K".into(), script_s],
        };
        let exe = which_windows("wt.exe").unwrap_or_else(|| PathBuf::from("cmd.exe"));
        launch_detached(&exe, &args, &[])
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = dir;
        // The terminal inherits the environment; its shell starts with it.
        for term in ["x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "alacritty", "kitty", "xterm"] {
            if let Some(exe) = which(term) {
                let args: Vec<String> = match command {
                    None => vec![],
                    Some(c) => {
                        let script = format!("{c}; exec \"${{SHELL:-/bin/sh}}\" -l");
                        match term {
                            "gnome-terminal" => vec!["--".into(), "sh".into(), "-c".into(), script],
                            "kitty" => vec!["sh".into(), "-c".into(), script],
                            _ => vec!["-e".into(), "sh".into(), "-c".into(), script],
                        }
                    }
                };
                return launch_detached(&exe, &args, env);
            }
        }
        Err(PlatformError::Command("no terminal program found (x-terminal-emulator, gnome-terminal, konsole, xterm …)".into()))
    }
}

#[cfg(windows)]
fn which_windows(name: &str) -> Option<PathBuf> {
    which(name).or_else(|| std::env::var_os("LocalAppData").map(|d| PathBuf::from(d).join(r"Microsoft\WindowsApps").join(name)).filter(|p| p.is_file()))
}

#[cfg(target_os = "macos")]
const BANNER_SH: &str = "echo 'Quena: HTTP(S)_PROXY and the root certificate are set for this shell.'\n";

#[cfg(target_os = "macos")]
fn set_executable(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))
}

/// Single-quoted for `sh`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn sh_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', r"'\''"))
}

/// The trusted root certificates of the system as PEM, for a bundle that tools taking one
/// file (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` …) can use next to Quena's. `None` where the
/// system keeps no such list (Windows).
pub fn system_ca_pem() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let mut pem = String::new();
        for kc in ["/System/Library/Keychains/SystemRootCertificates.keychain", "/Library/Keychains/System.keychain"] {
            if let Ok(out) = Command::new("/usr/bin/security").args(["find-certificate", "-a", "-p", kc]).output() {
                if out.status.success() {
                    pem.push_str(&String::from_utf8_lossy(&out.stdout));
                }
            }
        }
        pem.contains("BEGIN CERTIFICATE").then_some(pem)
    }
    #[cfg(windows)]
    {
        None
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem"]
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok())
            .filter(|s| s.contains("BEGIN CERTIFICATE"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn browsers_are_listed_in_order_without_panicking() {
        let found = find_browsers();
        let order: Vec<usize> = found.iter().map(|b| KINDS.iter().position(|(k, ..)| *k == b.kind).unwrap()).collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{found:?}");
        assert!(found.iter().all(|b| b.exe.is_file()));
    }
}
