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

#[test]
fn header_inspector_decodes_auth_tokens() {
    let Some(h) = host() else { return };
    if !h.list().iter().any(|p| p.id == "io.github.hkiam.auth-tokens") {
        eprintln!("auth-tokens plugin not built – run plugins/build.sh");
        return;
    }
    let p = h.list().into_iter().find(|p| p.id == "io.github.hkiam.auth-tokens").unwrap();
    assert!(p.error.is_none(), "{p:#?}");
    assert_eq!(p.kind, quena_plugin_host::PluginKind::HeaderInspector);
    assert!(p.headers.iter().any(|x| x == "www-authenticate"));
    // Header inspectors are no body decoders.
    assert!(h.candidates(Some("text/plain"), b"Negotiate").iter().all(|c| c.1 != p.tab));

    // NTLM Type 1 inside Negotiate (a client that found no Kerberos ticket).
    let r = h.inspect_header("Authorization", "Negotiate TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAPRlAAAADw==");
    assert_eq!(r.len(), 1, "{r:#?}");
    let r = &r[0];
    assert!(r.error.is_none(), "{r:#?}");
    assert_eq!((r.nodes[0].depth, r.nodes[0].kind, r.nodes[0].name.as_str()), (0, "section", "NTLM Type 1 (Negotiate)"));
    assert!(r.nodes.iter().any(|n| n.kind == "field" && n.name == "OS version" && n.value == "10.0 (build 26100), NTLM revision 15"));
    assert!(r.nodes.iter().any(|n| n.kind == "note" && n.value.contains("fell back to NTLM")));
    assert_eq!(r.nodes.last().map(|n| n.kind), Some("code"));

    // Not for the plugin: other headers, other schemes, challenges without token.
    assert!(h.inspect_header("Cookie", "Negotiate TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAPRlAAAADw==").is_empty());
    assert!(h.inspect_header("Authorization", "Basic dXNlcjpwYXNz").is_empty());
    assert!(h.inspect_header("WWW-Authenticate", "Negotiate").is_empty());

    // Disabled plugins are not asked.
    h.set_enabled("io.github.hkiam.auth-tokens", false).unwrap();
    assert!(h.inspect_header("Authorization", "NTLM TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKAPRlAAAADw==").is_empty());
}

/// The second start loads compiled machine code instead of compiling again, and a
/// damaged cache file is ignored (recompiled).
#[test]
fn compiled_plugins_are_cached() {
    let dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/dist");
    if !dist.join("rot13-test").exists() {
        return;
    }
    let state = tempfile::tempdir().unwrap();
    let t = Instant::now();
    drop(PluginHost::new(vec![dist.clone()], state.path()).unwrap());
    let cold = t.elapsed();
    let cache: Vec<_> = std::fs::read_dir(state.path().join("plugin-cache")).unwrap().flatten().map(|e| e.path()).collect();
    assert!(!cache.is_empty(), "no compile cache written");
    let t = Instant::now();
    let h = PluginHost::new(vec![dist.clone()], state.path()).unwrap();
    let warm = t.elapsed();
    eprintln!("plugin load cold {cold:?}, warm {warm:?}");
    assert!(h.list().iter().all(|p| p.error.is_none()));
    // Damaged cache: still works.
    for f in &cache {
        std::fs::write(f, b"garbage").unwrap();
    }
    let h = PluginHost::new(vec![dist], state.path()).unwrap();
    let idx = h.list().into_iter().find(|p| p.id == "io.github.hkiam.rot13-test").unwrap().index;
    let mut out = Vec::new();
    h.decode(idx, Some("text/x-rot13"), &mut &b"Uryyb"[..], &mut out, &|| false).unwrap();
    assert_eq!(out, b"Hello");
}

/// JWT header inspector (with the sandbox's wall clock for relative dates) and GraphQL decoder.
#[test]
fn jwt_and_graphql_plugins() {
    let Some(h) = host() else { return };
    if !h.list().iter().any(|p| p.id == "io.github.hkiam.jwt") || !h.list().iter().any(|p| p.id == "io.github.hkiam.graphql") {
        eprintln!("jwt/graphql plugins not built – run plugins/build.sh");
        return;
    }
    // {"alg":"HS256","typ":"JWT"} . {"sub":"42","exp":4102444800} (2100-01-01) . 32-byte signature
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsImV4cCI6NDEwMjQ0NDgwMH0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let r = h.inspect_header("Authorization", &format!("Bearer {jwt}"));
    let r = r.iter().find(|r| r.plugin_id == "io.github.hkiam.jwt").expect("jwt inspection");
    assert!(r.error.is_none(), "{r:#?}");
    assert!(r.nodes.iter().any(|n| n.name == "exp (Expiration time)" && n.value.starts_with("2100-01-01 00:00:00 UTC") && n.value.contains("valid for")), "{r:#?}");
    assert!(h.inspect_header("Cookie", &format!("theme=dark; access_token={jwt}")).iter().any(|r| r.plugin_id == "io.github.hkiam.jwt"));

    let body = br#"{"operationName":"Me","query":"query Me { me { name } }","variables":{}}"#;
    let c = h.candidates(Some("application/json"), body);
    assert_eq!(c.first().map(|x| x.1.as_str()), Some("GraphQL"), "{c:?}");
    let mut out = Vec::new();
    h.decode(c[0].0, Some("application/json"), &mut &body[..], &mut out, &|| false).unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(out.starts_with("Operation: query Me\n\n--- Query ---\nquery Me {\n  me {\n    name\n  }\n}\n"), "{out}");
}
