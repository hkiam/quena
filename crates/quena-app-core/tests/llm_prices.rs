//! LLM prices: an unreadable `llm-prices.json` is reported, and a price list fetched on
//! request (through the proxy engine's connector) is kept and used.

use quena_app_core::{AppCore, Paths};
use std::io::{Read, Write};

/// Answers every request with `body` (HTTP/1.1, then closes).
fn server(body: &'static str) -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    port
}

#[test]
fn own_prices_errors_and_fetched_list() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine);

    let info = core.llm_prices_info();
    assert!(!info.exists && info.custom == 0 && info.custom_error.is_none() && info.fetched == 0 && info.built_in > 10);

    // A typo: reported, not silently empty.
    std::fs::write(dir.path().join("llm-prices.json"), "{ \"my-model\": { \"input\": 1, } }").unwrap();
    let e = core.llm_prices_info().custom_error.expect("the error is reported");
    assert!(e.contains("line 1"), "{e}");
    std::fs::write(dir.path().join("llm-prices.json"), r#"{ "my-model": { "input": 1, "output": 2 } }"#).unwrap();
    let info = core.llm_prices_info();
    assert_eq!((info.custom, info.custom_error), (1, None), "read again after the change");

    let port = server(r#"{"sample_spec":{},"gpt-9":{"input_cost_per_token":2e-6,"output_cost_per_token":8e-6},"vertex_ai/gpt-9":{"input_cost_per_token":1}}"#);
    let info = core.llm_prices_update_from(&format!("http://127.0.0.1:{port}/prices.json")).unwrap();
    assert_eq!(info.fetched, 1);
    assert!(info.fetched_at.is_some());
    let p = core.llm_prices();
    assert!((p.fetched["gpt-9"].output - 8.0).abs() < 1e-9);
    assert!(quena_app_core::llm::price_of("gpt-9-2026-01-01", &p).unwrap().0.contains("LiteLLM"));

    let bad = server("<html>not here</html>");
    assert!(core.llm_prices_update_from(&format!("http://127.0.0.1:{bad}/")).is_err());
    assert_eq!(core.llm_prices_info().fetched, 1, "a failed update keeps the list");
    assert_eq!(core.llm_prices_forget().unwrap().fetched, 0);
}
