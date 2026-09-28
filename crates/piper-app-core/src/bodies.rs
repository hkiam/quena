//! Body views for the inspectors (PLAN.md §2.12.4).

use crate::AppCore;
use crate::dto::*;
use anyhow::{Result, anyhow};
use parking_lot::Mutex;
use piper_body::decode::{DeriveSpec, Progress, derive, variant_applies};
use piper_body::{Body, Variant};
use piper_jobs::{JobCtx, JobId, JobStatus, Priority};
use piper_model::{Headers, SessionId};
use std::sync::Arc;

pub struct CtxProgress<'a>(pub &'a JobCtx);

impl Progress for CtxProgress<'_> {
    fn cancelled(&self) -> bool {
        self.0.cancelled()
    }
    fn progress(&self, done: u64, total: u64) {
        self.0.progress(done, total)
    }
}

/// Bodies above this size get a visible job entry.
const VISIBLE_JOB_BYTES: u64 = 8 << 20;

fn effective(spec: &DeriveSpec, v: Variant) -> Variant {
    match v {
        Variant::Plugin(_) => v,
        Variant::Pretty if variant_applies(spec, Variant::Pretty) => Variant::Pretty,
        Variant::Pretty | Variant::Decoded if variant_applies(spec, Variant::Decoded) => Variant::Decoded,
        _ => Variant::Raw,
    }
}

fn vname(v: Variant) -> String {
    v.name()
}

impl AppCore {
    fn body_source(&self, id: SessionId, part: Part) -> Result<(Body, Headers)> {
        let cap = self.capture();
        let (req, resp) = cap.bodies_of(id).ok_or_else(|| anyhow!("session {id} not found"))?;
        let d = cap.detail(id).ok_or_else(|| anyhow!("session {id} not found"))?;
        Ok(match part {
            Part::Request => (req, d.request.headers),
            Part::Response => (resp, d.response.map(|r| r.headers).unwrap_or_default()),
        })
    }

    /// Resolve (and start producing, if needed) a body variant.
    fn variant_body(&self, id: SessionId, part: Part, v: Variant) -> Result<(Body, Variant, Option<JobId>)> {
        let (src, headers) = self.body_source(id, part)?;
        let spec = spec_of(&headers);
        let v = effective(&spec, v);
        let d = derive(&self.capture().bodies, &src, v, &spec)?;
        let key = format!("derive:{}:{}", src.id(), vname(v));
        let job = match d.work {
            Some(work) => {
                let title = format!(
                    "{} body of #{id} ({})",
                    match v {
                        Variant::Pretty => "Formatting",
                        Variant::Plugin(_) => "Plugin-decoding",
                        _ => "Decoding",
                    },
                    human(src.len())
                );
                Some(self.jobs.submit(key, title, Priority::Interactive, src.len() > VISIBLE_JOB_BYTES, move |ctx| {
                    work(&CtxProgress(ctx)).map_err(|e| e.to_string())
                }))
            }
            None => self.jobs.by_key(&key).filter(|j| matches!(j.status(), JobStatus::Queued | JobStatus::Running)).map(|j| j.id),
        };
        Ok((d.body, v, job))
    }

    fn view_of(&self, body: &Body, v: Variant, job: Option<JobId>) -> BodyView {
        let cap = self.capture();
        let key = format!("derive:{}:{}", body.id(), vname(v));
        let error = self.jobs.by_key(&key).and_then(|j| j.snapshot().error);
        let (lines, lines_done, scanned, line_job) = match cap.bodies.line_index(body.id(), v) {
            Some(i) => {
                let info = i.info();
                let lj = self
                    .jobs
                    .by_key(&format!("lines:{}:{}", body.id(), vname(v)))
                    .filter(|j| matches!(j.status(), JobStatus::Queued | JobStatus::Running))
                    .map(|j| j.id);
                (info.lines, info.done, info.scanned, lj)
            }
            None => (0, false, 0, None),
        };
        BodyView { len: body.len(), complete: body.is_complete(), variant: v, job, line_job, lines, lines_done, scanned, error }
    }

    /// Open a body variant for line-based viewing: starts derivation and line indexing.
    pub fn body_open(&self, id: SessionId, part: Part, variant: Variant) -> Result<BodyView> {
        let (body, v, job) = self.variant_body(id, part, variant)?;
        let cap = self.capture();
        let (idx, created) = cap.bodies.line_index_or_create(body.id(), v);
        if created {
            let b = body.clone();
            let big = body.len() > VISIBLE_JOB_BYTES || !body.is_complete();
            self.jobs.submit(format!("lines:{}:{}", body.id(), vname(v)), format!("Indexing lines of #{id}"), Priority::Interactive, big, move |ctx| {
                idx.build(&b, &CtxProgress(ctx)).map_err(|e| e.to_string())
            });
        }
        Ok(self.view_of(&body, v, job))
    }

    /// Read lines of a variant (after [`body_open`]).
    pub fn body_lines(&self, id: SessionId, part: Part, variant: Variant, start: u64, count: usize) -> Result<LinesDto> {
        let (body, v, job) = self.variant_body(id, part, variant)?;
        let cap = self.capture();
        let idx = match cap.bodies.line_index(body.id(), v) {
            Some(i) => i,
            None => {
                self.body_open(id, part, variant)?;
                cap.bodies.line_index(body.id(), v).ok_or_else(|| anyhow!("no line index"))?
            }
        };
        let lines = idx.read_lines(&body, start, count.min(5000))?;
        Ok(LinesDto { start, lines, view: self.view_of(&body, v, job) })
    }

    /// Byte range of a variant (custom protocol handler, hex view, images).
    pub fn body_range(&self, id: SessionId, part: Part, variant: Variant, offset: u64, len: usize) -> Result<BodyRange> {
        let (body, v, _) = self.variant_body(id, part, variant)?;
        let data = body.read_range(offset, len.min(16 << 20))?;
        let (_, headers) = self.body_source(id, part)?;
        Ok(BodyRange {
            data,
            total: body.len(),
            complete: body.is_complete(),
            content_type: headers.get("content-type").map(|s| s.to_string()),
            variant: v,
        })
    }

    /// Current length of a variant (starts derivation).
    pub fn body_len(&self, id: SessionId, part: Part, variant: Variant) -> Result<(u64, bool, Variant)> {
        let (body, v, _) = self.variant_body(id, part, variant)?;
        Ok((body.len(), body.is_complete(), v))
    }

    /// Streaming search inside a body variant. Results via [`search_result`].
    pub fn body_search(&self, id: SessionId, part: Part, variant: Variant, needle: String, ignore_case: bool) -> Result<JobId> {
        let (body, v, _) = self.variant_body(id, part, variant)?;
        let prefix = format!("search:{}:{}", body.id(), vname(v));
        self.jobs.cancel_prefix(&prefix);
        let result = Arc::new(Mutex::new(SearchResult::default()));
        let r2 = result.clone();
        let idx = self.capture().bodies.line_index(body.id(), v);
        let key = format!("{prefix}:{}", piper_model::now_us());
        let job = self.jobs.submit(key, format!("Searching #{id} for \"{needle}\""), Priority::Interactive, body.len() > VISIBLE_JOB_BYTES, move |ctx| {
            // Wait for derivation to finish so offsets are stable.
            while !body.is_complete() {
                if ctx.cancelled() {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let mut pending = Vec::new();
            let res = piper_body::search::search(&body, needle.as_bytes(), ignore_case, 0, &CtxProgress(ctx), |off| {
                pending.push(off);
                if pending.len() >= 256 {
                    let mut r = r2.lock();
                    for o in pending.drain(..) {
                        let line = idx.as_ref().and_then(|i| i.line_of_offset(&body, o).ok()).unwrap_or(0);
                        r.hits.push(SearchHit { offset: o, line });
                    }
                }
                if r2.lock().hits.len() + pending.len() >= 10_000 {
                    r2.lock().truncated = true;
                    return false;
                }
                true
            });
            let mut r = r2.lock();
            for o in pending {
                let line = idx.as_ref().and_then(|i| i.line_of_offset(&body, o).ok()).unwrap_or(0);
                r.hits.push(SearchHit { offset: o, line });
            }
            r.done = true;
            res.map(|_| ()).map_err(|e| e.to_string())
        });
        let mut s = self.searches.lock();
        if s.len() > 64 {
            s.clear();
        }
        s.insert(job, result);
        Ok(job)
    }

    pub fn search_result(&self, job: JobId) -> Option<SearchResult> {
        self.searches.lock().get(&job).map(|r| r.lock().clone())
    }

    /// Save a body variant to a file (runs as a job, streaming).
    pub fn save_body(&self, id: SessionId, part: Part, variant: Variant, path: std::path::PathBuf) -> Result<JobId> {
        let (body, v, _) = self.variant_body(id, part, variant)?;
        let title = format!("Saving body of #{id} to {}", path.display());
        Ok(self.jobs.submit(format!("save:{}:{}:{}", body.id(), vname(v), path.display()), title, Priority::Background, true, move |ctx| {
            use std::io::{Read, Write};
            let mut out = std::io::BufWriter::new(std::fs::File::create(&path).map_err(|e| e.to_string())?);
            let mut r = body.stream(0, true).with_cancel(Arc::new({
                let c = ctx.clone();
                move || c.cancelled()
            }));
            let mut buf = vec![0u8; 1 << 20];
            let mut done = 0u64;
            loop {
                let n = r.read(&mut buf).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                done += n as u64;
                ctx.progress(done, body.len());
            }
            out.flush().map_err(|e| e.to_string())
        }))
    }
}

pub struct BodyRange {
    pub data: Vec<u8>,
    pub total: u64,
    pub complete: bool,
    pub content_type: Option<String>,
    pub variant: Variant,
}

pub fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", U[i]) }
}
