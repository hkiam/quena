//! Packet captures with TLS: secrets from a file next to the capture, from the setting, and
//! from a key log chosen after the import (which replaces the sessions of the first one).
//! `fixtures/tls12-cbc.pcap`: `openssl s_client` → `s_server -www` on localhost (TLS 1.2,
//! ECDHE-RSA-AES128-SHA with encrypt-then-MAC), recorded with its `-keylogfile`.
use quena_app_core::{AppCore, EventSink, Paths};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct Events(Mutex<Vec<(String, serde_json::Value)>>);
impl EventSink for Events {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        self.0.lock().unwrap().push((event.to_string(), payload));
    }
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn start(settings: &str) -> (tempfile::TempDir, Arc<AppCore>, Arc<Events>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), settings).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let events = Arc::new(Events::default());
    core.set_sink(events.clone());
    (dir, core, events)
}

fn wait(core: &AppCore, job: u64) {
    let info = core.jobs.wait(job, Duration::from_secs(30)).expect("job did not finish");
    assert_eq!(format!("{:?}", info.status), "Done", "{:?}", info.error);
}

fn last_import(events: &Events) -> serde_json::Value {
    events.0.lock().unwrap().iter().rev().find(|(e, _)| e == "pcap-import").expect("pcap-import event").1.clone()
}

fn urls(core: &AppCore) -> Vec<String> {
    let cap = core.capture();
    cap.index.tick();
    cap.index.find(|_| true).into_iter().map(|id| cap.detail(id).unwrap().request.url).collect()
}

fn copy(from: &str, to: &Path) {
    std::fs::copy(fixture(from), to).unwrap();
}

const NO_PROXY: &str = r#"{"proxy":{"actAsSystemProxy":false,"captureOnStartup":false}}"#;

#[test]
fn key_log_chosen_after_the_import_replaces_the_tunnel() {
    let (dir, core, events) = start(NO_PROXY);
    let pcap = dir.path().join("trace.pcap");
    copy("tls12-cbc.pcap", &pcap);
    wait(&core, core.import_archive(pcap.clone()).unwrap());
    let ev = last_import(&events);
    assert_eq!((ev["tls"].as_u64(), ev["decrypted"].as_u64(), ev["noKeys"].as_u64()), (Some(1), Some(0), Some(1)));
    assert_eq!(urls(&core), ["10.0.0.2:443"], "no SNI for an IP address: named after the server");
    let ids: Vec<u64> = serde_json::from_value(ev["ids"].clone()).unwrap();
    wait(&core, core.import_capture(pcap, None, vec![fixture("tls12-cbc.keylog")], ids, ev["numbering"].as_u64()).unwrap());
    assert_eq!(last_import(&events)["decrypted"].as_u64(), Some(1));
    assert_eq!(urls(&core), ["https://localhost/index.html"], "the tunnel is replaced");
}

#[test]
fn key_log_next_to_the_capture_and_in_the_settings() {
    let (dir, core, events) = start(NO_PROXY);
    let pcap = dir.path().join("trace.pcap");
    copy("tls12-cbc.pcap", &pcap);
    copy("tls12-cbc.keylog", &dir.path().join("trace.keys"));
    wait(&core, core.import_archive(pcap).unwrap());
    assert_eq!(last_import(&events)["decrypted"].as_u64(), Some(1));

    let keys = fixture("tls12-cbc.keylog");
    let settings = format!(r#"{{"proxy":{{"actAsSystemProxy":false,"captureOnStartup":false}},"https":{{"tlsKeyLogFile":{}}}}}"#, serde_json::to_string(&keys).unwrap());
    let (dir, core, events) = start(&settings);
    let pcap = dir.path().join("other.pcap");
    copy("tls12-cbc.pcap", &pcap);
    wait(&core, core.import_archive(pcap).unwrap());
    assert_eq!(last_import(&events)["decrypted"].as_u64(), Some(1));
    assert_eq!(urls(&core), ["https://localhost/index.html"]);
}

#[test]
fn replacing_after_remove_all_keeps_the_new_sessions() {
    let (dir, core, events) = start(NO_PROXY);
    let pcap = dir.path().join("trace.pcap");
    copy("tls12-cbc.pcap", &pcap);
    wait(&core, core.import_archive(pcap.clone()).unwrap());
    let ev = last_import(&events);
    let ids: Vec<u64> = serde_json::from_value(ev["ids"].clone()).unwrap();
    // Remove All restarts numbering: the old ids now name other sessions.
    core.remove_all();
    let other = dir.path().join("other.pcap");
    copy("tls12-cbc.pcap", &other);
    wait(&core, core.import_archive(other).unwrap());
    assert_eq!(urls(&core), ["10.0.0.2:443"]);
    wait(&core, core.import_capture(pcap, None, vec![fixture("tls12-cbc.keylog")], ids, ev["numbering"].as_u64()).unwrap());
    let mut u = urls(&core);
    u.sort();
    assert_eq!(u, ["10.0.0.2:443", "https://localhost/index.html"], "the session of the other import stays");
}

#[test]
fn only_files_in_the_drop_folder_are_removed_after_the_import() {
    let (dir, core, _events) = start(NO_PROXY);
    std::fs::create_dir_all(dir.path().join("dropped")).unwrap();
    let outside = dir.path().join("keep.pcap");
    copy("tls12-cbc.pcap", &outside);
    let detour = dir.path().join("dropped").join("..").join("keep.pcap");
    wait(&core, core.import_capture(detour, None, vec![fixture("tls12-cbc.keylog")], Vec::new(), None).unwrap());
    assert!(outside.exists(), "a file outside the drop folder is not a temporary copy");
}
