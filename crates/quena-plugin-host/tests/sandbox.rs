//! WP-I: load, detect, decode, errors, timeout, memory limit.
//! Requires `plugins/build.sh` to have been run (skips otherwise).

use quena_plugin_host::PluginHost;
use std::path::PathBuf;
use std::time::Instant;

fn host() -> Option<std::sync::Arc<PluginHost>> {
    let dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/dist");
    if !dist.join("rot13-test").exists() {
        eprintln!("plugins not built – run plugins/build.sh");
        return None;
    }
    let state = tempfile::tempdir().unwrap().keep();
    Some(PluginHost::new(vec![dist], &state).unwrap())
}

fn index(h: &PluginHost, id: &str) -> u16 {
    h.list().into_iter().find(|p| p.id == id).unwrap().index
}

#[test]
fn rot13_decodes_streaming() {
    let Some(h) = host() else { return };
    let list = h.list();
    assert!(list.iter().any(|p| p.id == "io.github.hkiam.rot13-test" && p.error.is_none()), "{list:#?}");
    let c = h.candidates(Some("text/x-rot13"), b"Uryyb");
    assert_eq!(c.first().map(|x| x.1.as_str()), Some("ROT13"));
    let idx = index(&h, "io.github.hkiam.rot13-test");
    let input = "Uryyb Jbeyq! ".repeat(100_000); // 1.3 MB, several chunks
    let mut out = Vec::new();
    let t = Instant::now();
    h.decode(idx, Some("text/x-rot13"), &mut input.as_bytes(), &mut out, &|| false).unwrap();
    eprintln!("rot13 1.3 MB in {:?}", t.elapsed());
    assert_eq!(String::from_utf8(out).unwrap(), "Hello World! ".repeat(100_000));
}

#[test]
fn misbehaving_plugin_is_contained() {
    let Some(h) = host() else { return };
    let idx = index(&h, "io.github.hkiam.evil-test");
    let mut out = Vec::new();
    // Trap (panic inside the plugin)
    let e = h.decode(idx, Some("trap"), &mut &b"x"[..], &mut out, &|| false).unwrap_err();
    assert!(e.to_string().contains("trap"), "{e}");
    // Error result
    let e = h.decode(idx, Some("error"), &mut &b"x"[..], &mut out, &|| false).unwrap_err();
    assert!(e.to_string().contains("evil decoding error"));
    // Infinite loop → deadline
    let t = Instant::now();
    let e = h.decode(idx, Some("loop"), &mut &b"x"[..], &mut out, &|| false).unwrap_err();
    assert!(t.elapsed().as_secs() < 30, "deadline not enforced");
    eprintln!("loop stopped after {:?}: {e}", t.elapsed());
    // Memory hog → limit
    let e = h.decode(idx, Some("oom"), &mut &b"x"[..], &mut out, &|| false).unwrap_err();
    eprintln!("oom: {e}");
    // The host still works afterwards.
    let r = index(&h, "io.github.hkiam.rot13-test");
    let mut out = Vec::new();
    h.decode(r, None, &mut &b"nop"[..], &mut out, &|| false).unwrap();
    assert_eq!(out, b"abc");
}
