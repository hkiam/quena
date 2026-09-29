//! Find Sessions (Ctrl/Cmd+F): search URLs, headers and bodies as a job.

use crate::AppCore;
use crate::bodies::CtxProgress;
use crate::dto::spec_of;
use anyhow::{Result, anyhow};
use parking_lot::Mutex;
use piper_body::Variant;
use piper_body::decode::{derive, variant_applies};
use piper_jobs::{JobId, Priority};
use piper_model::{MarkColor, SessionId};
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
        let job = self.jobs.submit(format!("find:{}", piper_model::now_us()), format!("Finding \"{}\"", o.text), Priority::Interactive, true, move |ctx| {
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
                                let parts: Vec<(piper_body::Body, piper_model::Headers)> = [
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
                                    let body = if o.decode && variant_applies(&spec, Variant::Decoded) {
                                        match derive(&cap.bodies, &body, Variant::Decoded, &spec) {
                                            Ok(dv) => {
                                                if let Some(w) = dv.work {
                                                    let _ = w(&CtxProgress(ctx));
                                                } else {
                                                    while !dv.body.is_complete() && !ctx.cancelled() {
                                                        std::thread::sleep(std::time::Duration::from_millis(5));
                                                    }
                                                }
                                                dv.body
                                            }
                                            Err(_) => body,
                                        }
                                    } else {
                                        body
                                    };
                                    let found = match &re {
                                        Some(re) => {
                                            let data = body.read_range(0, max as usize).unwrap_or_default();
                                            re.is_match(&String::from_utf8_lossy(&data))
                                        }
                                        None => {
                                            let mut f = false;
                                            let _ = piper_body::search::search(&body, o.text.as_bytes(), !o.match_case, 0, &piper_body::decode::NoProgress, |_| {
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
