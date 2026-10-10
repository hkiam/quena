//! Agent cache: answers to LLM API calls kept and served again for the same request, so an
//! agent or app under development does not pay (and wait) for the same answer twice.
//!
//! A request is "the same" when method, URL (an API key parameter apart), the credentials and
//! API version headers, and the JSON body (key order, spacing and the fields `user`/`metadata`
//! not counting) are equal. Credentials count only as a hash: another key never gets this
//! key's answers. Calls are cached one by one (*Cache this call*) or all while *Cache every
//! LLM call* is on. Entries live in `llm-cache/` in the data folder, the least recently used
//! go when there are more than [`MAX_ENTRIES`] or [`MAX_BYTES`].

use crate::AppCore;
use crate::llm::{self, LlmCall};
use anyhow::{Result, anyhow};
use parking_lot::Mutex;
use quena_model::{Headers, ResponseHead, SessionId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The flag of a session answered from the cache (`hit: …`).
pub const CACHE_FLAG: &str = "x-quena-cache";
/// Largest request body looked at, and largest answer kept.
pub const MAX_REQUEST: usize = 4 << 20;
pub const MAX_ANSWER: usize = 16 << 20;
/// Most answers kept, and most bytes in all.
pub const MAX_ENTRIES: usize = 2000;
pub const MAX_BYTES: u64 = 1 << 30;
/// Body fields that identify the caller, not the question.
const IGNORED_FIELDS: &[&str] = &["user", "metadata"];
/// Request headers that choose who asks (hashed) and which API version answers.
const CREDENTIALS: &[&str] = &["authorization", "x-api-key", "api-key", "x-goog-api-key"];
const VERSIONS: &[&str] = &["anthropic-version", "anthropic-beta", "openai-beta", "openai-organization", "openai-project"];
/// Response headers not served again (they name the account or the original request).
const NOT_SERVED: &[&str] = &["set-cookie", "openai-organization", "openai-project", "anthropic-organization-id", "x-request-id", "request-id", "cf-ray", "content-encoding", "transfer-encoding"];
/// Hit counters are written at most this often.
const SAVE_EVERY: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheEntry {
    /// The request key (hex).
    pub key: String,
    pub method: String,
    pub url: String,
    pub provider: String,
    pub model: String,
    pub status: u16,
    pub headers: Headers,
    /// Tokens and estimated cost of the original call (saved on each hit).
    pub tokens: u64,
    pub cost_usd: Option<f64>,
    /// How long the original call took.
    pub duration_ms: Option<u32>,
    /// The session it was taken from.
    pub source: SessionId,
    /// Unix seconds.
    pub created: i64,
    pub hits: u64,
    /// Bytes of the kept answer.
    #[serde(default)]
    pub size: u64,
    /// Unix seconds of the last hit (or of saving).
    #[serde(default)]
    pub last_used: i64,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Saved {
    auto: bool,
    entries: Vec<CacheEntry>,
}

/// What the cache holds and saved.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheStatus {
    pub auto: bool,
    pub entries: Vec<CacheEntry>,
    pub hits: u64,
    pub saved_tokens: u64,
    pub saved_usd: f64,
    pub saved_ms: u64,
    pub folder: String,
}

/// Calls in the capture asked more than once and not cached (worth caching).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheAdvice {
    pub model: String,
    pub url: String,
    /// The sessions with the same request, oldest first.
    pub sessions: Vec<SessionId>,
    /// Tokens and estimated cost the repeats cost (all but the first).
    pub repeat_tokens: u64,
    pub repeat_usd: f64,
}

struct State {
    saved: Saved,
    dirty: bool,
    last_save: Instant,
}

pub struct LlmCache {
    dir: PathBuf,
    state: Mutex<State>,
    /// Whether requests have to be looked at (entries or auto on): checked on every request.
    active: AtomicBool,
    /// [`MAX_ENTRIES`] (smaller in tests).
    max_entries: std::sync::atomic::AtomicUsize,
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// The cache key of a request (`None`: not a cacheable LLM call, e.g. no JSON body).
pub fn key_of(method: &str, url: &str, headers: &Headers, body: &[u8]) -> Option<String> {
    llm::api_of(method, url)?;
    let mut v: Value = serde_json::from_slice(body).ok()?;
    let o = v.as_object_mut()?;
    for f in IGNORED_FIELDS {
        o.remove(*f);
    }
    let (base, query) = url.split_once('?').unwrap_or((url, ""));
    let mut q: Vec<&str> = query.split('&').filter(|p| !p.is_empty() && !p.to_ascii_lowercase().starts_with("key=")).collect();
    q.sort_unstable();
    // Who asks: the credentials (and Gemini's `?key=`), hashed apart.
    let mut cred = Sha256::new();
    for h in CREDENTIALS {
        if let Some(v) = headers.get(h) {
            cred.update(h.as_bytes());
            cred.update(b"=");
            cred.update(v.trim().as_bytes());
            cred.update(b"\n");
        }
    }
    for p in query.split('&').filter(|p| p.to_ascii_lowercase().starts_with("key=")) {
        cred.update(p.as_bytes());
    }
    let mut h = Sha256::new();
    h.update(method.to_ascii_uppercase().as_bytes());
    h.update(b"\n");
    h.update(base.to_ascii_lowercase().as_bytes());
    h.update(b"\n");
    h.update(q.join("&").as_bytes());
    h.update(b"\n");
    for name in VERSIONS {
        if let Some(v) = headers.get(name) {
            h.update(format!("{name}={}\n", v.trim()).as_bytes());
        }
    }
    h.update(cred.finalize());
    h.update(crate::capdiff::canonical_json(&v).as_bytes());
    Some(hex::encode(&h.finalize()[..16]))
}

impl LlmCache {
    pub fn load(data: &Path) -> LlmCache {
        let dir = data.join("llm-cache");
        let index = dir.join("index.json");
        let saved: Saved = match std::fs::read(&index) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                // Kept for a look, not overwritten by the next save.
                let keep = dir.join(format!("index.json.corrupt-{}", now()));
                let _ = std::fs::rename(&index, &keep);
                tracing::warn!(target: "quena", "agent cache: {} cannot be read ({e}); kept as {}", index.display(), keep.display());
                Saved::default()
            }),
            Err(_) => Saved::default(),
        };
        let mut saved = saved;
        // Entries whose answer file is gone are dropped.
        saved.entries.retain(|e| dir.join(format!("{}.body", e.key)).exists());
        let active = AtomicBool::new(saved.auto || !saved.entries.is_empty());
        LlmCache { dir, state: Mutex::new(State { saved, dirty: false, last_save: Instant::now() }), active, max_entries: std::sync::atomic::AtomicUsize::new(MAX_ENTRIES) }
    }

    /// Whether requests must be looked at.
    pub fn active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    fn save(&self, s: &mut State) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let tmp = self.dir.join("index.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&s.saved)?)?;
        std::fs::rename(&tmp, self.dir.join("index.json"))?;
        s.dirty = false;
        s.last_save = Instant::now();
        self.active.store(s.saved.auto || !s.saved.entries.is_empty(), Ordering::Relaxed);
        Ok(())
    }

    /// The kept answer for `key` (head, body bytes), counted as a hit. Reads a file: call it
    /// off the async workers.
    pub fn hit(&self, key: &str) -> Option<(CacheEntry, Vec<u8>)> {
        let mut s = self.state.lock();
        let i = s.saved.entries.iter().position(|e| e.key == key)?;
        // Under the lock: an answer is replaced or removed only under it too.
        let body = std::fs::read(self.dir.join(format!("{key}.body"))).ok()?;
        let e = &mut s.saved.entries[i];
        e.hits += 1;
        e.last_used = now();
        let e = e.clone();
        s.dirty = true;
        if s.last_save.elapsed() >= SAVE_EVERY {
            let _ = self.save(&mut s);
        }
        Some((e, body))
    }

    pub fn contains(&self, key: &str) -> bool {
        self.state.lock().saved.entries.iter().any(|e| e.key == key)
    }

    pub fn auto(&self) -> bool {
        self.state.lock().saved.auto
    }

    fn put(&self, mut e: CacheEntry, body: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        // Written beside, put in place under the lock (a hit never reads half a file).
        let tmp = self.dir.join(format!("{}.body.tmp-{}", e.key, std::process::id()));
        std::fs::write(&tmp, body)?;
        e.size = body.len() as u64;
        e.last_used = now();
        let mut s = self.state.lock();
        std::fs::rename(&tmp, self.dir.join(format!("{}.body", e.key)))?;
        s.saved.entries.retain(|x| x.key != e.key);
        s.saved.entries.push(e);
        // The least recently used go beyond the limits.
        let total = |s: &State| s.saved.entries.iter().map(|x| x.size).sum::<u64>();
        let max = self.max_entries.load(Ordering::Relaxed);
        while s.saved.entries.len() > max || (s.saved.entries.len() > 1 && total(&s) > MAX_BYTES) {
            let Some(i) = s.saved.entries.iter().enumerate().min_by_key(|(_, x)| x.last_used.max(x.created)).map(|(i, _)| i) else { break };
            let old = s.saved.entries.remove(i);
            let _ = std::fs::remove_file(self.dir.join(format!("{}.body", old.key)));
        }
        self.save(&mut s)
    }

    fn remove(&self, key: &str) -> Result<bool> {
        let mut s = self.state.lock();
        let before = s.saved.entries.len();
        s.saved.entries.retain(|x| x.key != key);
        let _ = std::fs::remove_file(self.dir.join(format!("{key}.body")));
        let removed = s.saved.entries.len() != before;
        self.save(&mut s)?;
        Ok(removed)
    }

    pub fn set_auto(&self, on: bool) -> Result<()> {
        let mut s = self.state.lock();
        s.saved.auto = on;
        self.save(&mut s)
    }

    pub fn clear(&self) -> Result<()> {
        let mut s = self.state.lock();
        for e in &s.saved.entries {
            let _ = std::fs::remove_file(self.dir.join(format!("{}.body", e.key)));
        }
        s.saved.entries.clear();
        self.save(&mut s)
    }

    pub fn status(&self) -> CacheStatus {
        let mut s = self.state.lock();
        if s.dirty {
            let _ = self.save(&mut s);
        }
        let mut st = CacheStatus { auto: s.saved.auto, entries: s.saved.entries.clone(), hits: 0, saved_tokens: 0, saved_usd: 0.0, saved_ms: 0, folder: self.dir.display().to_string() };
        for e in &s.saved.entries {
            st.hits += e.hits;
            st.saved_tokens = st.saved_tokens.saturating_add(e.tokens.saturating_mul(e.hits));
            st.saved_usd += e.cost_usd.unwrap_or(0.0) * e.hits as f64;
            st.saved_ms = st.saved_ms.saturating_add(u64::from(e.duration_ms.unwrap_or(0)).saturating_mul(e.hits));
        }
        st.entries.sort_by(|a, b| b.created.cmp(&a.created));
        st
    }
}

impl Drop for LlmCache {
    fn drop(&mut self) {
        let mut s = self.state.lock();
        if s.dirty {
            let _ = self.save(&mut s);
        }
    }
}

/// What a hit says on its session: `hit: 1234 tokens, $0.0123, 2300 ms saved`.
pub fn hit_flag(e: &CacheEntry) -> String {
    let mut parts = vec![format!("{} tokens", e.tokens)];
    if let Some(c) = e.cost_usd {
        parts.push(format!("${c:.4}"));
    }
    if let Some(ms) = e.duration_ms {
        parts.push(format!("{ms} ms"));
    }
    format!("hit: {} saved (from #{})", parts.join(", "), e.source)
}

impl AppCore {
    fn llm_cache(&self) -> Result<&LlmCache> {
        Ok(&self.rules.as_ref().ok_or_else(|| anyhow!("rules not available"))?.llm_cache)
    }

    /// The request key of a recorded session (`None`: not a cacheable LLM call).
    fn session_key(&self, id: SessionId) -> Option<String> {
        let cap = self.capture();
        let d = cap.detail(id)?;
        llm::api_of(&d.request.method, &d.request.url)?;
        let (req, _) = cap.bodies_of(id)?;
        let body = quena_body::text::decoded_prefix(&req, &crate::dto::spec_of(&d.request.headers), MAX_REQUEST + 1);
        if body.len() > MAX_REQUEST {
            return None;
        }
        key_of(&d.request.method, &d.request.url, &d.request.headers, &body)
    }

    /// Whether session `id`'s request is cached.
    pub fn llm_cached(&self, id: SessionId) -> bool {
        self.llm_cache().ok().zip(self.session_key(id)).is_some_and(|(c, k)| c.contains(&k))
    }

    /// Cache (`on`) or forget the answer of session `id`. An answer from the cache itself, an
    /// error answer or one still running cannot be cached. The answer is kept decoded (any
    /// client can read it), without the headers that name the account.
    pub fn llm_cache_set(&self, id: SessionId, on: bool) -> Result<()> {
        let cache = self.llm_cache()?;
        let key = self.session_key(id).ok_or_else(|| anyhow!("session #{id} is not a call to an LLM API with a JSON body"))?;
        if !on {
            cache.remove(&key)?;
            return Ok(());
        }
        let cap = self.capture();
        let d = cap.detail(id).ok_or_else(|| anyhow!("session #{id} not found"))?;
        if d.extra_flags.iter().any(|(k, _)| k == CACHE_FLAG) {
            return Err(anyhow!("session #{id} was answered from the cache"));
        }
        let resp = d.response.clone().ok_or_else(|| anyhow!("session #{id} has no response yet"))?;
        if !(200..300).contains(&resp.status) {
            return Err(anyhow!("only successful answers are cached (#{id}: {})", resp.status));
        }
        let (_, body) = cap.bodies_of(id).ok_or_else(|| anyhow!("session #{id} not found"))?;
        if !body.is_complete() || body.is_truncated() || body.len() > MAX_ANSWER as u64 {
            return Err(anyhow!("the answer of #{id} is not complete or too large"));
        }
        let bytes = quena_body::text::decoded_prefix(&body, &crate::dto::spec_of(&resp.headers), MAX_ANSWER + 1);
        if bytes.len() > MAX_ANSWER {
            return Err(anyhow!("the answer of #{id} is too large"));
        }
        let call: Option<LlmCall> = self.llm(id);
        let mut headers = resp.headers.clone();
        headers.0.retain(|(k, _)| !NOT_SERVED.contains(&k.to_ascii_lowercase().as_str()));
        headers.set("Content-Length", bytes.len().to_string());
        let e = CacheEntry {
            key,
            method: d.request.method.clone(),
            url: d.request.url.clone(),
            provider: call.as_ref().map(|c| c.provider.clone()).unwrap_or_default(),
            model: call.as_ref().map(|c| c.model.clone()).unwrap_or_default(),
            status: resp.status,
            headers,
            tokens: call.as_ref().and_then(|c| c.usage.as_ref()).map(|u| u.total()).unwrap_or(0),
            cost_usd: call.as_ref().and_then(|c| c.cost.as_ref()).map(|c| c.usd),
            duration_ms: d.summary.duration_ms,
            source: id,
            created: now(),
            hits: 0,
            size: 0,
            last_used: 0,
        };
        cache.put(e, &bytes)
    }

    pub fn llm_cache_status(&self) -> Result<CacheStatus> {
        Ok(self.llm_cache()?.status())
    }

    pub fn llm_cache_set_auto(&self, on: bool) -> Result<CacheStatus> {
        let c = self.llm_cache()?;
        c.set_auto(on)?;
        Ok(c.status())
    }

    pub fn llm_cache_remove(&self, key: &str) -> Result<CacheStatus> {
        let c = self.llm_cache()?;
        c.remove(key)?;
        Ok(c.status())
    }

    pub fn llm_cache_clear(&self) -> Result<CacheStatus> {
        let c = self.llm_cache()?;
        c.clear()?;
        Ok(c.status())
    }

    /// Requests to LLM APIs in the capture (the newest 5000) that were sent more than once and
    /// are not cached, most expensive repeats first.
    pub fn llm_cache_advice(&self) -> Vec<CacheAdvice> {
        let cap = self.capture();
        // Answers from the cache carry no tokens (nothing was spent).
        let mut ids = cap.index.find_all(|s| !s.llm.is_empty() && s.status / 100 == 2 && s.llm_tokens.is_some());
        ids.sort_unstable_by(|a, b| b.cmp(a));
        ids.truncate(5000);
        ids.reverse();
        let cache = self.llm_cache().ok();
        let mut groups: HashMap<String, Vec<SessionId>> = HashMap::new();
        for id in ids {
            if let Some(k) = self.session_key(id)
                && !cache.is_some_and(|c| c.contains(&k))
            {
                groups.entry(k).or_default().push(id);
            }
        }
        let mut out: Vec<CacheAdvice> = groups
            .into_values()
            .filter(|v| v.len() > 1)
            .filter_map(|v| {
                let s = cap.index.get(v[0])?;
                let repeats: Vec<_> = v[1..].iter().filter_map(|id| cap.index.get(*id)).collect();
                Some(CacheAdvice {
                    model: s.llm.clone(),
                    url: s.full_url(),
                    repeat_tokens: repeats.iter().map(|r| r.llm_tokens.unwrap_or(0)).fold(0u64, u64::saturating_add),
                    repeat_usd: repeats.iter().map(|r| r.llm_cost_micros.unwrap_or(0)).fold(0u64, u64::saturating_add) as f64 / 1_000_000.0,
                    sessions: v,
                })
            })
            .collect();
        out.sort_by(|a, b| b.repeat_usd.total_cmp(&a.repeat_usd).then(b.repeat_tokens.cmp(&a.repeat_tokens)));
        out.truncate(50);
        out
    }

    /// After a session finished: cache it when *Cache every LLM call* is on.
    pub(crate) fn llm_cache_auto(&self, id: SessionId) {
        if let Ok(c) = self.llm_cache()
            && c.auto()
            && let Some(k) = self.session_key(id)
            && !c.contains(&k)
        {
            let _ = self.llm_cache_set(id, true);
        }
    }
}

/// The response a hit is answered with.
pub fn response_of(e: &CacheEntry) -> ResponseHead {
    ResponseHead { status: e.status, headers: e.headers.clone(), ..Default::default() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(v: &[(&str, &str)]) -> Headers {
        Headers(v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect())
    }

    #[test]
    fn keys_ignore_order_spacing_callers_but_not_credentials() {
        let u = "https://api.openai.com/v1/chat/completions";
        let auth = h(&[("Authorization", "Bearer sk-A")]);
        let a = key_of("POST", u, &auth, br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"user":"u1"}"#).unwrap();
        let b = key_of("post", u, &auth, br#"{ "messages": [{"content":"hi","role":"user"}], "model": "m", "user": "u2" }"#).unwrap();
        assert_eq!(a, b);
        let c = key_of("POST", u, &auth, br#"{"model":"m","messages":[{"role":"user","content":"hi!"}]}"#).unwrap();
        assert_ne!(a, c, "another question");
        let other = key_of("POST", u, &h(&[("Authorization", "Bearer sk-B")]), br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#).unwrap();
        assert_ne!(a, other, "another key never gets this key's answers");
        let none = key_of("POST", u, &Headers::new(), br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#).unwrap();
        assert_ne!(a, none);
        let beta = key_of("POST", u, &h(&[("Authorization", "Bearer sk-A"), ("OpenAI-Beta", "assistants=v2")]), br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#).unwrap();
        assert_ne!(a, beta, "another API version");
        let g = |k: &str| key_of("POST", &format!("https://generativelanguage.googleapis.com/v1beta/models/g:generateContent?alt=sse&key={k}"), &Headers::new(), br#"{"contents":[]}"#);
        assert_ne!(g("A"), g("B"), "Gemini's key counts as a credential");
        assert_eq!(g("A"), g("A"));
        assert!(key_of("POST", "https://shop.example.com/cart", &Headers::new(), br#"{"messages":[]}"#).is_none(), "not an LLM API");
        assert!(key_of("POST", u, &Headers::new(), b"not json").is_none());
        assert_eq!(a.len(), 32, "a stable hex key");
    }

    #[test]
    fn least_recently_used_go_and_a_broken_index_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let c = LlmCache::load(dir.path());
        let entry = |k: &str, t: i64| CacheEntry { key: k.into(), method: "POST".into(), url: "u".into(), provider: String::new(), model: String::new(), status: 200, headers: Headers::new(), tokens: 0, cost_usd: None, duration_ms: None, source: 1, created: t, hits: 0, size: 0, last_used: t };
        c.max_entries.store(5, Ordering::Relaxed);
        for i in 0..8 {
            c.put(entry(&format!("{i:04}"), i as i64), b"x").unwrap();
        }
        assert_eq!(c.status().entries.len(), 5);
        assert!(c.hit("0002").is_none() && c.hit("0007").is_some());
        drop(c);
        std::fs::write(dir.path().join("llm-cache/index.json"), "{ broken").unwrap();
        let c = LlmCache::load(dir.path());
        assert!(c.status().entries.is_empty());
        assert!(std::fs::read_dir(dir.path().join("llm-cache")).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with("index.json.corrupt-")));
    }
}
