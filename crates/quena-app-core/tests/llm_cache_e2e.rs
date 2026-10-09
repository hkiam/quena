//! Agent cache: an LLM API call cached once is answered by Quena the next time (the server is
//! not asked), flagged with what it saved; *Cache every LLM call* caches by itself; repeats
//! not cached are advised.

use quena_app_core::{AppCore, Paths};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Answers like OpenAI's Chat Completions API; counts the calls.
fn fake_llm(calls: Arc<AtomicUsize>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let calls = calls.clone();
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                let out = format!(r#"{{"model":"gpt-4o","choices":[{{"message":{{"role":"assistant","content":"answer {n}"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":1000,"completion_tokens":200}}}}"#);
                let mut s = s;
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
            });
        }
    });
    port
}

fn wait<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let t = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(t.elapsed() < Duration::from_secs(20), "timed out: {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn llm_answers_served_from_the_cache() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let addr = engine.proxy.listen_addrs().into_iter().find(|a| a.is_ipv4()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let port = fake_llm(calls.clone());
    let url = format!("http://127.0.0.1:{port}/v1/chat/completions");
    let post = |body: &str| -> String {
        let o = Command::new("curl").args(["-sS", "--max-time", "20", "-x", &format!("http://{addr}"), "-H", "Content-Type: application/json", "--data-binary", body, &url]).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    let ask = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Weather?"}]}"#;
    let marked = |n: usize| {
        wait("sessions marked", || {
            core.capture().index.tick();
            let ids = core.capture().index.find_all(|s| !s.llm.is_empty());
            (ids.len() == n).then_some(ids)
        })
    };

    // Asked twice, not cached: the server answers both, and the repeat is advised.
    assert!(post(ask).contains("answer 1"));
    assert!(post(ask).contains("answer 2"));
    let mut ids = wait("tokens", || {
        let ids = marked(2);
        ids.iter().all(|id| core.capture().index.get(*id).is_some_and(|s| s.llm_tokens.is_some())).then_some(ids)
    });
    ids.sort_unstable();
    let advice = core.llm_cache_advice();
    assert_eq!(advice.len(), 1, "{advice:?}");
    assert_eq!(advice[0].sessions, ids);
    assert_eq!(advice[0].repeat_tokens, 1200);

    // Cache the first; the same question (other key order, other `user`) is answered by Quena.
    core.llm_cache_set(ids[0], true).unwrap();
    assert!(core.llm_cached(ids[1]), "the same request");
    assert!(core.llm_cache_advice().is_empty());
    let again = post(r#"{ "messages": [{"content":"Weather?","role":"user"}], "model": "gpt-4o", "user": "someone" }"#);
    assert!(again.contains("answer 1"), "{again}");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "the server was not asked");
    let hit = marked(3).into_iter().max().unwrap();
    let d = wait("hit marked", || core.capture().detail(hit).filter(|d| d.extra_flags.iter().any(|(k, _)| k == "x-quena-llm")));
    let flag = d.extra_flags.iter().find(|(k, _)| k == "x-quena-cache").map(|(_, v)| v.clone()).expect("cache flag");
    assert!(flag.starts_with("hit: 1200 tokens") && flag.contains(&format!("#{}", ids[0])), "{flag}");
    assert!(core.capture().index.get(hit).unwrap().llm_tokens.is_none(), "a hit spends no tokens");
    let st = core.llm_cache_status().unwrap();
    assert_eq!((st.entries.len(), st.hits, st.saved_tokens), (1, 1, 1200));

    // Another question goes to the server; with auto on it is cached by itself.
    core.llm_cache_set_auto(true).unwrap();
    let other = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Time?"}]}"#;
    assert!(post(other).contains("answer 3"));
    wait("auto cached", || (core.llm_cache_status().unwrap().entries.len() == 2).then_some(()));
    assert!(post(other).contains("answer 3"));
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    // Entries can be removed one by one or all at once.
    drop(engine);
    let st = core.llm_cache_status().unwrap();
    let key = st.entries.iter().find(|e| e.source == ids[0]).unwrap().key.clone();
    assert_eq!(core.llm_cache_remove(&key).unwrap().entries.len(), 1);
    assert!(!core.llm_cached(ids[1]));
    assert!(core.llm_cache_clear().unwrap().entries.is_empty());
    assert!(core.llm_cache_set(ids[0] + 1000, true).is_err());
}
