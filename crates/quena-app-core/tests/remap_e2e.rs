//! Host remapping through the settings and the real proxy engine.

use quena_app_core::settings::{HostRemapEntry, HostRemapSettings, parse_hosts_file};
use quena_app_core::{AppCore, Paths};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::Command;

/// HTTP/1.1 server answering with the Host header it saw.
fn host_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut host = String::new();
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line
                        .strip_prefix("Host: ")
                        .or_else(|| line.strip_prefix("host: "))
                    {
                        host = v.trim().to_string();
                    }
                }
                let mut s = s;
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{host}",
                    host.len()
                );
            });
        }
    });
    port
}

#[test]
fn hosts_files_are_parsed() {
    let e = parse_hosts_file(
        "127.0.0.1 localhost\n::1 localhost ip6-localhost\n# comment\n10.0.0.5 api.example.com API.Example.com www.example.com # staging\nnot-an-ip x.y\n10.0.0.6 api.example.com\n",
    );
    let names: Vec<(&str, &str)> = e
        .iter()
        .map(|e| (e.host.as_str(), e.target.as_str()))
        .collect();
    assert_eq!(
        names,
        vec![
            ("api.example.com", "10.0.0.5"),
            ("www.example.com", "10.0.0.5")
        ]
    );
    assert!(e.iter().all(|e| e.keep_host && e.enabled));
}

#[test]
fn remap_rules_apply_when_saved() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        r#"{"proxy":{"port":18883,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#,
    )
    .unwrap();
    let core = AppCore::new(
        Paths::at(dir.path().to_path_buf()),
        quena_app_core::logbuf::LogBuffer::new(100),
    )
    .unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let addr = engine
        .proxy
        .listen_addrs()
        .into_iter()
        .find(|a| a.is_ipv4())
        .unwrap();
    let port = host_echo();
    let get = |url: &str| {
        let o = Command::new("curl")
            .args([
                "-sS",
                "--max-time",
                "20",
                "-x",
                &format!("http://{addr}"),
                url,
            ])
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    };

    // Invalid entries are refused.
    let mut s = core.settings();
    s.host_remap = HostRemapSettings {
        enabled: true,
        entries: vec![HostRemapEntry {
            host: "https://x".into(),
            target: "y".into(),
            ..Default::default()
        }],
    };
    assert!(core.update_settings(s.clone()).is_err());

    s.host_remap.entries = vec![HostRemapEntry {
        id: "1".into(),
        host: "app.remap.invalid".into(),
        target: format!("127.0.0.1:{port}"),
        ..Default::default()
    }];
    core.update_settings(s.clone()).unwrap();
    assert_eq!(get("http://app.remap.invalid/"), "app.remap.invalid");

    // Without keep host the target's name is sent.
    s.host_remap.entries[0].keep_host = false;
    core.update_settings(s.clone()).unwrap();
    assert_eq!(
        get("http://app.remap.invalid/"),
        format!("127.0.0.1:{port}")
    );

    // Switched off: the name does not resolve any more.
    s.host_remap.enabled = false;
    core.update_settings(s).unwrap();
    assert!(get("http://app.remap.invalid/").contains("failed"));
    core.shutdown();
}
