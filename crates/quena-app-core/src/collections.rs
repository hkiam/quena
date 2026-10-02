//! `.http` request collections: run them through the proxy (they appear in the capture and
//! rules apply), and write captured sessions as one.

use crate::AppCore;
use crate::compose::ComposeRequest;
use anyhow::{Context, Result, anyhow, bail};
use quena_formats::http_file::{self, Body, Captured};
use quena_model::SessionId;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Text bodies up to this size are written into a `.http` file.
const MAX_WRITTEN_BODY: usize = 64 << 10;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpEntry {
    pub name: Option<String>,
    pub line: usize,
    pub method: String,
    /// With the variables substituted (or as written, when they could not be).
    pub url: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpListing {
    pub environments: Vec<String>,
    pub requests: Vec<HttpEntry>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpRunResult {
    pub name: Option<String>,
    pub line: usize,
    pub method: String,
    pub url: String,
    pub session: Option<SessionId>,
    pub status: Option<u16>,
    pub duration_ms: Option<u32>,
    /// The request did not finish within the wait.
    pub pending: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpWritten {
    pub path: String,
    pub requests: usize,
    /// Environment files written or updated (environment `captured`).
    pub env_files: Vec<String>,
}

fn dir_of(path: &Path) -> PathBuf {
    path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."))
}

fn read(path: &Path) -> Result<http_file::HttpFile> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(http_file::parse(&text))
}

fn selected(r: &http_file::RawRequest, names: &[String]) -> bool {
    names.is_empty() || names.iter().any(|n| r.name.as_deref() == Some(n.as_str()) || n.strip_prefix("line:").and_then(|l| l.parse().ok()) == Some(r.line))
}

impl AppCore {
    /// The requests of a `.http` file, resolved with environment `env`.
    pub fn http_requests(&self, path: &Path, env: Option<&str>) -> Result<HttpListing> {
        let f = read(path)?;
        let dir = dir_of(path);
        let vars = http_file::load_environment(&dir, env).map_err(|e| anyhow!(e))?;
        let requests = f
            .requests
            .iter()
            .map(|r| match http_file::resolve(&f, r, &vars, &dir) {
                Ok(x) => HttpEntry { name: x.name, line: x.line, method: x.method, url: x.url, error: None },
                Err(e) => HttpEntry { name: r.name.clone(), line: r.line, method: r.method.clone(), url: r.url.clone(), error: Some(e) },
            })
            .collect();
        Ok(HttpListing { environments: http_file::environments(&dir).map_err(|e| anyhow!(e))?, requests, warnings: f.warnings })
    }

    /// Send the requests of a `.http` file one after the other (all, or those named in
    /// `names`: `@name`/`###` titles or `line:N`), each waiting up to `wait` for its response.
    pub fn run_http_file(self: &Arc<Self>, path: &Path, env: Option<&str>, names: &[String], wait: Duration) -> Result<Vec<HttpRunResult>> {
        let f = read(path)?;
        let dir = dir_of(path);
        let vars = http_file::load_environment(&dir, env).map_err(|e| anyhow!(e))?;
        let chosen: Vec<_> = f.requests.iter().filter(|r| selected(r, names)).collect();
        if chosen.is_empty() {
            bail!("no requests{} in {}", if names.is_empty() { String::new() } else { format!(" named {}", names.join(", ")) }, path.display());
        }
        let mut out = Vec::new();
        for raw in chosen {
            let mut res = HttpRunResult { name: raw.name.clone(), line: raw.line, method: raw.method.clone(), url: raw.url.clone(), session: None, status: None, duration_ms: None, pending: false, error: None };
            let sent = http_file::resolve(&f, raw, &vars, &dir).map_err(|e| anyhow!(e)).and_then(|r| {
                res.url = r.url.clone();
                let (body, body_file) = match r.body {
                    Body::None => (String::new(), None),
                    Body::Text(t) => (t, None),
                    Body::File(p) => (String::new(), Some(p.to_string_lossy().into_owned())),
                };
                self.compose(ComposeRequest {
                    method: r.method,
                    url: r.url,
                    version: None,
                    headers: r.headers.iter().map(|(n, v)| format!("{n}: {v}")).collect::<Vec<_>>().join("\n"),
                    body,
                    body_charset: None,
                    body_from_session: None,
                    body_file,
                    fix_content_length: true,
                    breakpoint: false,
                })
            });
            match sent {
                Ok(id) => {
                    res.session = Some(id);
                    res.pending = !self.wait_session(id, wait);
                    if let Some(s) = self.capture().index.get(id) {
                        res.status = (s.status != 0).then_some(s.status);
                        res.duration_ms = s.duration_ms;
                    }
                    if let Some(d) = self.capture().detail(id) {
                        res.error = d.error;
                    }
                }
                Err(e) => res.error = Some(format!("{e:#}")),
            }
            out.push(res);
        }
        Ok(out)
    }

    /// Write sessions as a `.http` file. A shared scheme and host becomes `{{host}}` in the
    /// environment `captured` of `http-client.env.json`; bearer tokens and cookies go to
    /// `http-client.private.env.json` (keep that one out of version control).
    pub fn sessions_to_http(&self, ids: &[SessionId], path: &Path, overwrite: bool) -> Result<HttpWritten> {
        if path.exists() && !overwrite {
            bail!("{} exists", path.display());
        }
        let cap = self.capture();
        let mut reqs = Vec::new();
        for id in ids {
            let Some(d) = cap.detail(*id) else { continue };
            if d.summary.kind == quena_model::SessionKind::Tunnel || d.request.method.eq_ignore_ascii_case("CONNECT") {
                continue;
            }
            let (body, omitted) = match cap.bodies_of(*id) {
                Some((b, _)) if b.is_empty() => (None, None),
                Some((b, _)) => {
                    let spec = crate::dto::spec_of(&d.request.headers);
                    let bytes = quena_body::text::decoded_prefix(&b, &spec, MAX_WRITTEN_BODY + 1);
                    let ct = d.request.headers.get("content-type");
                    let textual = ct.map(crate::dto::is_textual_type).unwrap_or_else(|| crate::dto::sniff_text(&bytes[..bytes.len().min(1024)]));
                    if !textual {
                        (None, Some(format!("binary, {} bytes", b.len())))
                    } else if bytes.len() > MAX_WRITTEN_BODY {
                        (None, Some(format!("{} bytes, larger than {} KiB", b.len(), MAX_WRITTEN_BODY >> 10)))
                    } else {
                        let det = quena_body::charset::detect(ct, &bytes);
                        (Some(quena_body::charset::decode(&bytes[det.bom_len.min(bytes.len())..], det.encoding).0.into_owned()), None)
                    }
                }
                None => (None, None),
            };
            let mut headers = d.request.headers.0.clone();
            if body.is_some() {
                // Sent decoded; the original coding would no longer match.
                headers.retain(|(n, _)| !n.eq_ignore_ascii_case("content-encoding"));
            }
            reqs.push(Captured { comment: format!("#{id} {} {}", d.request.method, d.summary.full_url()), method: d.request.method.clone(), url: d.summary.full_url(), headers, body, omitted });
        }
        if reqs.is_empty() {
            bail!("no HTTP requests among the sessions");
        }
        let (text, public, private) = http_file::write(&reqs);
        std::fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
        let dir = dir_of(path);
        let mut env_files = Vec::new();
        for (file, vars) in [(http_file::ENV_FILE, public), (http_file::PRIVATE_ENV_FILE, private)] {
            if vars.is_empty() {
                continue;
            }
            let p = dir.join(file);
            let mut all: serde_json::Map<String, serde_json::Value> = match std::fs::read(&p) {
                Ok(b) => serde_json::from_slice(&b).with_context(|| format!("{} is not a JSON object; not changed", p.display()))?,
                Err(_) => Default::default(),
            };
            all.insert("captured".into(), serde_json::to_value(vars)?);
            std::fs::write(&p, serde_json::to_vec_pretty(&all)?)?;
            env_files.push(p.display().to_string());
        }
        Ok(HttpWritten { path: path.display().to_string(), requests: reqs.len(), env_files })
    }
}
