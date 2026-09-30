//! Find Sessions (Ctrl/Cmd+F): search URLs, headers and bodies as a job.

use crate::AppCore;
use crate::dto::spec_of;
use anyhow::{Result, anyhow};
use parking_lot::Mutex;
use quena_body::Variant;
use quena_body::decode::{Progress, variant_applies};
use quena_jobs::{JobId, Priority};
use quena_model::{MarkColor, SessionId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindOptions {
    pub text: String,
    #[serde(default)]
    pub match_case: bool,
    #[serde(default)]
    pub regex: bool,
    /// "all" | "requests" | "responses" | "urls"
    #[serde(default = "all")]
    pub scope: String,
    /// "all" | "headers" | "bodies"
    #[serde(default = "all")]
    pub examine: String,
    /// Restrict to these sessions (empty = all visible).
    #[serde(default)]
    pub ids: Vec<SessionId>,
    #[serde(default)]
    pub decode: bool,
    #[serde(default = "max_body")]
    pub max_body_mb: u64,
    pub mark: Option<MarkColor>,
}

/// At most this much of a body is decoded (in memory) for a decoded search.
const DECODE_SEARCH_LIMIT: u64 = 64 << 20;

/// Forwards only cancellation; body progress would clobber the per-session progress.
struct CancelOnly<'a>(&'a quena_jobs::JobCtx);
impl Progress for CancelOnly<'_> {
    fn cancelled(&self) -> bool {
        self.0.cancelled()
    }
    fn progress(&self, _: u64, _: u64) {}
}

fn all() -> String {
    "all".into()
}
fn max_body() -> u64 {
    64
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindResult {
    pub ids: Vec<SessionId>,
    pub examined: usize,
    pub total: usize,
    pub done: bool,
}

impl AppCore {
    pub fn find_sessions(self: &Arc<Self>, o: FindOptions) -> Result<JobId> {
        if o.text.is_empty() {
            return Err(anyhow!("nothing to find"));
        }
        let re = if o.regex {
            Some(regex::RegexBuilder::new(&o.text).case_insensitive(!o.match_case).build().map_err(|e| anyhow!("regex: {e}"))?)
        } else {
            None
        };
        let cap = self.capture();
        let ids = if o.ids.is_empty() { cap.index.find(|_| true) } else { o.ids.clone() };
        let result = Arc::new(Mutex::new(FindResult { total: ids.len(), ..Default::default() }));
        let r2 = result.clone();
        let core = Arc::downgrade(self);
        self.jobs.cancel_prefix("find:");
        let job = self.jobs.submit(format!("find:{}", quena_model::now_us()), format!("Finding \"{}\"", o.text), Priority::Interactive, true, move |ctx| {
            let Some(core) = core.upgrade() else { return Ok(()) };
            let needle_lc = o.text.to_lowercase();
            let text_hit = |t: &str| -> bool {
                match &re {
                    Some(re) => re.is_match(t),
                    None if o.match_case => t.contains(&o.text),
                    None => t.to_lowercase().contains(&needle_lc),
                }
            };
            let req = o.scope != "responses" && o.scope != "urls";
            let resp = o.scope != "requests" && o.scope != "urls";
            let headers = o.examine != "bodies";
            let bodies = o.examine != "headers";
            let max = o.max_body_mb << 20;
            for (n, id) in ids.iter().enumerate() {
                if ctx.cancelled() {
                    break;
                }
                ctx.progress(n as u64, ids.len() as u64);
                let Some(s) = cap.index.get(*id) else { continue };
                let mut hit = text_hit(&s.full_url());
                if !hit && o.scope != "urls" {
                    if let Some(d) = cap.detail(*id) {
                        if headers {
                            if req && d.request.headers.iter().any(|(k, v)| text_hit(&format!("{k}: {v}"))) {
                                hit = true;
                            }
                            if !hit && resp {
                                if let Some(r) = &d.response {
                                    hit = r.headers.iter().any(|(k, v)| text_hit(&format!("{k}: {v}"))) || text_hit(&r.reason);
                                }
                            }
                        }
                        if !hit && bodies {
                            if let Some((rb, sb)) = cap.bodies_of(*id) {
                                let parts: Vec<(quena_body::Body, quena_model::Headers)> = [
                                    req.then(|| (rb, d.request.headers.clone())),
                                    resp.then(|| (sb, d.response.as_ref().map(|r| r.headers.clone()).unwrap_or_default())),
                                ]
                                .into_iter()
                                .flatten()
                                .collect();
                                for (body, h) in parts {
                                    if body.is_empty() || body.len() > max {
                                        continue;
                                    }
                                    let spec = spec_of(&h);
                                    // Bodies are searched as text in their charset ("Grüße" finds
                                    // the windows-1252 bytes; UTF-16 is decoded first).
                                    let enc = quena_body::text::detect_body(&body, &spec).encoding;
                                    let as_text = |data: &[u8]| quena_body::charset::decode(data, enc).0.into_owned();
                                    // Decoded search works on a bounded in-memory decode instead of
                                    // deriving (and caching) every matching body; an existing complete
                                    // cache entry is searched directly.
                                    let decoded = match (o.decode && variant_applies(&spec, Variant::Decoded), spec.content_encoding.as_deref()) {
                                        (true, Some(ce)) => match cap.bodies.derived(body.id(), Variant::Decoded).filter(|b| b.is_complete()) {
                                            Some(cached) => Some(cached.read_range(0, DECODE_SEARCH_LIMIT.min(max) as usize).unwrap_or_default()),
                                            None => quena_body::decode::decode_prefix(&body, ce, DECODE_SEARCH_LIMIT.min(max) as usize, &CancelOnly(ctx)).ok(),
                                        },
                                        _ => None,
                                    };
                                    let found = match (&decoded, &re) {
                                        (Some(data), _) => text_hit(&as_text(data)),
                                        (None, Some(_)) => text_hit(&as_text(&body.read_range(0, max as usize).unwrap_or_default())),
                                        (None, None) if quena_body::text::needs_transcoding(enc) => text_hit(&as_text(&body.read_range(0, max as usize).unwrap_or_default())),
                                        (None, None) => {
                                            let mut f = false;
                                            let _ = quena_body::search::search_text(&body, &o.text, enc, !o.match_case, 0, &quena_body::decode::NoProgress, |_| {
                                                f = true;
                                                false
                                            });
                                            f
                                        }
                                    };
                                    if found {
                                        hit = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                let mut r = r2.lock();
                r.examined = n + 1;
                if hit {
                    r.ids.push(*id);
                    if let Some(c) = o.mark {
                        drop(r);
                        cap.update_summary(*id, |s| s.color = Some(c));
                    }
                }
            }
            r2.lock().done = true;
            let _ = &core;
            Ok(())
        });
        self.finds.lock().insert(job, result);
        Ok(job)
    }

    pub fn find_result(&self, job: JobId) -> Option<FindResult> {
        self.finds.lock().get(&job).map(|r| r.lock().clone())
    }
}
