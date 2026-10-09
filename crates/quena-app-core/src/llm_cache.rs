//! Agent cache: answers to LLM API calls kept and served again for the same request, so an
//! agent or app under development does not pay (and wait) for the same answer twice.
//!
//! A request is "the same" when method, URL (without an API key parameter) and the JSON body
//! (key order, spacing and the fields `user`/`metadata` not counting) are equal; headers and
//! credentials do not count. Calls are cached one by one (*Cache this call*) or all while
//! *Cache every LLM call* is on. Entries live in `llm-cache/` in the data folder.

use crate::AppCore;
use crate::llm::{self, LlmCall};
use anyhow::{Result, anyhow};
use parking_lot::Mutex;
use quena_model::{Headers, ResponseHead, SessionId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// The flag of a session answered from the cache (`hit: …`).
pub const CACHE_FLAG: &str = "x-quena-cache";
/// Largest request body looked at, and largest answer kept.
pub const MAX_REQUEST: usize = 4 << 20;
pub const MAX_ANSWER: usize = 16 << 20;
/// Body fields that identify the caller, not the question.
const IGNORED_FIELDS: &[&str] = &["user", "metadata"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheEntry {
    /// Hex of the request key.
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

pub struct LlmCache {
    dir: PathBuf,
    state: Mutex<Saved>,
    /// Whether requests have to be looked at (entries or auto on): checked on every request.
    active: AtomicBool,
}

/// The cache key of a request (`None`: not a cacheable LLM call, e.g. no JSON body).
pub fn key_of(method: &str, url: &str, body: &[u8]) -> Option<u64> {
    use std::hash::{Hash, Hasher};
    llm::api_of(method, url)?;
    let mut v: Value = serde_json::from_slice(body).ok()?;
    let o = v.as_object_mut()?;
    for f in IGNORED_FIELDS {
        o.remove(*f);
    }
    // The URL without an API key (Gemini takes it as `?key=`).
    let (base, query) = url.split_once('?').unwrap_or((url, ""));
    let mut q: Vec<&str> = query.split('&').filter(|p| !p.is_empty() && !p.to_ascii_lowercase().starts_with("key=")).collect();
    q.sort_unstable();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    method.to_ascii_uppercase().hash(&mut h);
    base.to_ascii_lowercase().hash(&mut h);
    q.hash(&mut h);
    crate::capdiff::canonical_json(&v).hash(&mut h);
    Some(h.finish())
}

fn hex(k: u64) -> String {
    format!("{k:016x}")
}

impl LlmCache {
    pub fn load(data: &Path) -> LlmCache {
        let dir = data.join("llm-cache");
        let state: Saved = std::fs::read(dir.join("index.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        // Entries whose answer file is gone are dropped.
        let mut state = state;
        state.entries.retain(|e| dir.join(format!("{}.body", e.key)).exists());
        let active = AtomicBool::new(state.auto || !state.entries.is_empty());
        LlmCache { dir, state: Mutex::new(state), active }
    }

    /// Whether requests must be looked at.
    pub fn active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    fn save(&self, s: &Saved) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let tmp = self.dir.join("index.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(s)?)?;
        std::fs::rename(&tmp, self.dir.join("index.json"))?;
        self.active.store(s.auto || !s.entries.is_empty(), Ordering::Relaxed);
        Ok(())
    }

    /// The kept answer for `key` (head, body bytes), counted as a hit.
    pub fn hit(&self, key: u64) -> Option<(CacheEntry, Vec<u8>)> {
        let k = hex(key);
        let mut s = self.state.lock();
        let e = s.entries.iter_mut().find(|e| e.key == k)?;
        let body = std::fs::read(self.dir.join(format!("{k}.body"))).ok()?;
        e.hits += 1;
        let e = e.clone();
        let _ = self.save(&s);
        Some((e, body))
    }

    pub fn contains(&self, key: u64) -> bool {
        let k = hex(key);
        self.state.lock().entries.iter().any(|e| e.key == k)
    }

    pub fn auto(&self) -> bool {
        self.state.lock().auto
    }

    fn put(&self, e: CacheEntry, body: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(self.dir.join(format!("{}.body", e.key)), body)?;
        let mut s = self.state.lock();
        s.entries.retain(|x| x.key != e.key);
        s.entries.push(e);
        self.save(&s)
    }

    fn remove(&self, key: &str) -> Result<bool> {
        let mut s = self.state.lock();
        let before = s.entries.len();
        s.entries.retain(|x| x.key != key);
        let _ = std::fs::remove_file(self.dir.join(format!("{key}.body")));
        let removed = s.entries.len() != before;
        self.save(&s)?;
        Ok(removed)
    }

    pub fn set_auto(&self, on: bool) -> Result<()> {
        let mut s = self.state.lock();
        s.auto = on;
        self.save(&s)
    }

    pub fn clear(&self) -> Result<()> {
        let mut s = self.state.lock();
        for e in &s.entries {
            let _ = std::fs::remove_file(self.dir.join(format!("{}.body", e.key)));
        }
        s.entries.clear();
        self.save(&s)
    }

    pub fn status(&self) -> CacheStatus {
        let s = self.state.lock();
        let mut st = CacheStatus { auto: s.auto, entries: s.entries.clone(), hits: 0, saved_tokens: 0, saved_usd: 0.0, saved_ms: 0, folder: self.dir.display().to_string() };
        for e in &s.entries {
            st.hits += e.hits;
            st.saved_tokens = st.saved_tokens.saturating_add(e.tokens.saturating_mul(e.hits));
            st.saved_usd += e.cost_usd.unwrap_or(0.0) * e.hits as f64;
            st.saved_ms = st.saved_ms.saturating_add(u64::from(e.duration_ms.unwrap_or(0)).saturating_mul(e.hits));
        }
        st.entries.sort_by(|a, b| b.created.cmp(&a.created));
        st
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
    fn session_key(&self, id: SessionId) -> Option<u64> {
        let cap = self.capture();
        let d = cap.detail(id)?;
        let (req, _) = cap.bodies_of(id)?;
        let body = quena_body::text::decoded_prefix(&req, &crate::dto::spec_of(&d.request.headers), MAX_REQUEST + 1);
        if body.len() > MAX_REQUEST {
            return None;
        }
        key_of(&d.request.method, &d.request.url, &body)
    }

    /// Whether session `id`'s request is cached.
    pub fn llm_cached(&self, id: SessionId) -> bool {
        self.llm_cache().ok().zip(self.session_key(id)).is_some_and(|(c, k)| c.contains(k))
    }

    /// Cache (`on`) or forget the answer of session `id`. An answer from the cache itself, an
    /// error answer or one still running cannot be cached.
    pub fn llm_cache_set(&self, id: SessionId, on: bool) -> Result<()> {
        let cache = self.llm_cache()?;
        let key = self.session_key(id).ok_or_else(|| anyhow!("session #{id} is not a call to an LLM API with a JSON body"))?;
        if !on {
            cache.remove(&hex(key))?;
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
        let bytes = body.read_range(0, body.len() as usize).map_err(|e| anyhow!("read #{id}: {e}"))?;
        let call: Option<LlmCall> = self.llm(id);
        let mut headers = resp.headers.clone();
        headers.remove("transfer-encoding");
        headers.set("Content-Length", bytes.len().to_string());
        let e = CacheEntry {
            key: hex(key),
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
            created: time::OffsetDateTime::now_utc().unix_timestamp(),
            hits: 0,
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

    /// Requests to LLM APIs in the capture that were sent more than once and are not cached,
    /// most expensive repeats first.
    pub fn llm_cache_advice(&self) -> Vec<CacheAdvice> {
        let cap = self.capture();
        // Answers from the cache carry no tokens (nothing was spent).
        let mut ids = cap.index.find_all(|s| !s.llm.is_empty() && s.status / 100 == 2 && s.llm_tokens.is_some());
        ids.sort_unstable();
        ids.truncate(5000);
        let cache = self.llm_cache().ok();
        let mut groups: HashMap<u64, Vec<SessionId>> = HashMap::new();
        for id in ids {
            if let Some(k) = self.session_key(id)
                && !cache.is_some_and(|c| c.contains(k))
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
            && !c.contains(k)
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

    #[test]
    fn keys_ignore_order_spacing_callers_and_api_keys() {
        let a = key_of("POST", "https://api.openai.com/v1/chat/completions", br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"user":"u1"}"#).unwrap();
        let b = key_of("post", "https://api.openai.com/v1/chat/completions", br#"{ "messages": [{"content":"hi","role":"user"}], "model": "m", "user": "u2" }"#).unwrap();
        assert_eq!(a, b);
        let c = key_of("POST", "https://api.openai.com/v1/chat/completions", br#"{"model":"m","messages":[{"role":"user","content":"hi!"}]}"#).unwrap();
        assert_ne!(a, c, "another question");
        let g1 = key_of("POST", "https://generativelanguage.googleapis.com/v1beta/models/g:generateContent?key=A", br#"{"contents":[]}"#);
        let g2 = key_of("POST", "https://generativelanguage.googleapis.com/v1beta/models/g:generateContent?key=B", br#"{"contents":[]}"#);
        assert_eq!(g1, g2);
        assert!(key_of("POST", "https://shop.example.com/cart", br#"{"messages":[]}"#).is_none(), "not an LLM API");
        assert!(key_of("POST", "https://api.openai.com/v1/chat/completions", b"not json").is_none());
    }
}
