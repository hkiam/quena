//! `.http` request collections: run them through the proxy (they appear in the capture and
//! rules apply), and write captured sessions as one.

use crate::AppCore;
use crate::compose::ComposeRequest;
use anyhow::{Context, Result, anyhow, bail};
use quena_formats::http_file::{self, Access, Body, Captured};
use quena_model::SessionId;
use serde::{Deserialize, Serialize};
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
    /// Credentials were replaced: `{{token}}` / `{{cookie}}` must be filled in by hand.
    pub secrets_redacted: bool,
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
    pub fn http_requests(&self, path: &Path, env: Option<&str>, access: &Access) -> Result<HttpListing> {
        let f = read(path)?;
        let dir = dir_of(path);
        let vars = http_file::load_environment(&dir, env).map_err(|e| anyhow!(e))?;
        let requests = f
            .requests
            .iter()
            .map(|r| match http_file::resolve(&f, r, &vars, &dir, access) {
                Ok(x) => HttpEntry { name: x.name, line: x.line, method: x.method, url: x.url, error: None },
                Err(e) => HttpEntry { name: r.name.clone(), line: r.line, method: r.method.clone(), url: r.url.clone(), error: Some(e) },
            })
            .collect();
        Ok(HttpListing { environments: http_file::environments(&dir).map_err(|e| anyhow!(e))?, requests, warnings: f.warnings })
    }

    /// Send the requests of a `.http` file one after the other (all, or those named in
    /// `names`: `@name`/`###` titles or `line:N`), each waiting up to `wait` for its response.
    pub fn run_http_file(self: &Arc<Self>, path: &Path, env: Option<&str>, names: &[String], wait: Duration, access: &Access) -> Result<Vec<HttpRunResult>> {
        let f = read(path)?;
        let dir = dir_of(path);
        let vars = http_file::load_environment(&dir, env).map_err(|e| anyhow!(e))?;
        let chosen: Vec<_> = f.requests.iter().filter(|r| selected(r, names)).collect();
        if chosen.is_empty() {
            bail!("no requests{} in {}", if names.is_empty() { String::new() } else { format!(" named {}", names.join(", ")) }, path.display());
        }
        Ok(chosen.into_iter().map(|raw| self.run_one(&f, raw, &vars, &dir, wait, access)).collect())
    }

    /// Resolve and send one request of `f`, waiting up to `wait` for its response.
    fn run_one(self: &Arc<Self>, f: &http_file::HttpFile, raw: &http_file::RawRequest, vars: &std::collections::HashMap<String, String>, dir: &Path, wait: Duration, access: &Access) -> HttpRunResult {
        {
            let mut res = HttpRunResult { name: raw.name.clone(), line: raw.line, method: raw.method.clone(), url: raw.url.clone(), session: None, status: None, duration_ms: None, pending: false, error: None };
            let sent = http_file::resolve(f, raw, vars, dir, access).map_err(|e| anyhow!(e)).and_then(|r| {
                res.url = r.url.clone();
                let (body, body_file) = match r.body {
                    Body::None => (String::new(), None),
                    Body::Text(t) => (t, None),
                    Body::File(p) => (String::new(), Some(p.to_string_lossy().into_owned())),
                };
                self.compose(ComposeRequest {
                    method: r.method,
                    url: r.url,
                    version: r.version.as_deref().and_then(quena_model::HttpVersion::parse),
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
            res
        }
    }

    /// Write sessions as a `.http` file. A shared scheme and host becomes `{{host}}` in the
    /// environment `captured` of `http-client.env.json`; bearer tokens and cookies go to
    /// `http-client.private.env.json` (keep that one out of version control).
    ///
    /// With `redact`, credentials and secret values are replaced first (the sanitizer's
    /// `credentials` preset) and no private environment file is written.
    pub fn sessions_to_http(&self, ids: &[SessionId], path: &Path, overwrite: bool, redact: bool) -> Result<HttpWritten> {
        if path.exists() && !overwrite {
            bail!("{} exists", path.display());
        }
        let cap = self.capture();
        let mut reqs = Vec::new();
        let mut san = redact.then(|| {
            let mut o = crate::sanitize::SanitizeOptions::preset("credentials").unwrap_or_default();
            o.bodies = crate::sanitize::BodyMode::Truncate;
            o.truncate_kib = (MAX_WRITTEN_BODY >> 10) as u32 + 1;
            crate::sanitize::Sanitizer::new(o)
        });
        for id in ids {
            let Some(d) = cap.detail(*id) else { continue };
            if d.summary.kind == quena_model::SessionKind::Tunnel || d.request.method.eq_ignore_ascii_case("CONNECT") {
                continue;
            }
            if let Some(san) = san.as_mut() {
                let Some((req, resp)) = cap.bodies_of(*id) else { continue };
                let s = san.session(&d, &req, &resp);
                let text = (!s.request.is_empty()).then(|| String::from_utf8_lossy(&s.request).into_owned());
                let (body, omitted) = match text {
                    Some(t) if t.len() <= MAX_WRITTEN_BODY && !t.contains('\0') => (Some(t), None),
                    Some(_) => (None, Some(format!("{} bytes, binary or larger than {} KiB", req.len(), MAX_WRITTEN_BODY >> 10))),
                    None => (None, None),
                };
                reqs.push(Captured { comment: format!("#{id} {} {}", s.detail.request.method, s.detail.request.url), method: s.detail.request.method.clone(), url: s.detail.request.url.clone(), headers: s.detail.request.headers.0.clone(), body, omitted });
                continue;
            }
            let (body, omitted) = match cap.bodies_of(*id) {
                Some((b, _)) if b.is_empty() => (None, None),
                Some((b, _)) => {
                    let ce = d.request.headers.get("content-encoding").map(str::trim).filter(|c| !c.is_empty() && !c.eq_ignore_ascii_case("identity"));
                    let decoded = match ce {
                        Some(ce) => quena_body::decode::decode_prefix(&b, ce, MAX_WRITTEN_BODY + 1, &quena_body::decode::NoProgress).map_err(|e| format!("cannot decode {ce}: {e}")),
                        None => b.read_range(0, MAX_WRITTEN_BODY + 1).map_err(|e| e.to_string()),
                    };
                    let bytes = decoded.unwrap_or_default();
                    let ct = d.request.headers.get("content-type");
                    let textual = ct.map(crate::dto::is_textual_type).unwrap_or_else(|| crate::dto::sniff_text(&bytes[..bytes.len().min(1024)]));
                    if bytes.is_empty() {
                        (None, Some(format!("{} bytes that could not be read or decoded", b.len())))
                    } else if !textual {
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
        let (text, public, mut private) = http_file::write(&reqs);
        if redact {
            private.clear();
        }
        let dir = dir_of(path);
        // Read (and check) the environment files first, so nothing is written half.
        let mut envs = Vec::new();
        for (file, vars) in [(http_file::ENV_FILE, public), (http_file::PRIVATE_ENV_FILE, private)] {
            if vars.is_empty() {
                continue;
            }
            let p = dir.join(file);
            let mut all: serde_json::Map<String, serde_json::Value> = match std::fs::read(&p) {
                Ok(b) => serde_json::from_slice(&b).with_context(|| format!("{} is not a JSON object; nothing written", p.display()))?,
                Err(_) => Default::default(),
            };
            all.insert("captured".into(), serde_json::to_value(vars)?);
            envs.push((p, all));
        }
        std::fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
        let mut env_files = Vec::new();
        for (p, all) in envs {
            std::fs::write(&p, serde_json::to_vec_pretty(&all)?)?;
            env_files.push(p.display().to_string());
        }
        Ok(HttpWritten { path: path.display().to_string(), requests: reqs.len(), env_files, secrets_redacted: redact })
    }
}

// ------------------------------------------------------------------ collections

/// Folder of the Composer's collections: one `.http` file per collection, the environments
/// (`http-client.env.json`, `http-client.private.env.json`) shared by all.
pub const COLLECTIONS_DIR: &str = "collections";

/// A collection in the list.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionInfo {
    pub name: String,
    pub path: String,
    pub requests: usize,
}

/// One request of a collection, as the Composer edits it.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct CollectionRequest {
    pub name: String,
    pub method: String,
    pub url: String,
    /// `HTTP/1.1`, `HTTP/2`; empty: automatic.
    pub version: String,
    /// `Name: value` lines.
    pub headers: String,
    pub body: String,
    /// `< path` (relative to the collections folder): the body is this file.
    pub body_file: String,
    /// With `body_file`: substitute variables in the file (`<@ path`).
    pub body_template: bool,
}

/// A collection: its variables and requests.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Collection {
    pub name: String,
    /// `@name = value` lines.
    pub variables: Vec<(String, String)>,
    pub requests: Vec<CollectionRequest>,
    /// Lines of the file Quena could not read (shown, and dropped when saving).
    #[serde(skip_deserializing)]
    pub warnings: Vec<String>,
    /// Environments of the collections folder.
    #[serde(skip_deserializing)]
    pub environments: Vec<String>,
}

fn check_name(name: &str) -> Result<&str> {
    let n = name.trim();
    if n.is_empty() || n.len() > 100 || n.starts_with('.') || n.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|']) || n.chars().any(char::is_control) {
        bail!("invalid collection name: {name:?}");
    }
    // Names Windows keeps for devices (`NUL.http` is no file there).
    let stem = n.split('.').next().unwrap_or(n).trim_end().to_ascii_uppercase();
    let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT")) && stem.len() == 4 && stem.as_bytes()[3].is_ascii_digit());
    if device || n.ends_with('.') {
        bail!("invalid collection name: {name:?}");
    }
    Ok(n)
}

fn to_raw(r: &CollectionRequest) -> http_file::RawRequest {
    let headers = r.headers.lines().filter(|l| !l.trim().is_empty()).map(|l| match l.split_once(':') {
        Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
        None => (l.trim().to_string(), String::new()),
    });
    let body = if !r.body_file.trim().is_empty() {
        if r.body_template { http_file::BodySource::FileWithVariables(r.body_file.trim().into()) } else { http_file::BodySource::File(r.body_file.trim().into()) }
    } else if r.body.trim().is_empty() {
        http_file::BodySource::None
    } else {
        http_file::BodySource::Text(r.body.trim_end().to_string())
    };
    http_file::RawRequest {
        name: Some(r.name.trim().to_string()).filter(|n| !n.is_empty()),
        line: 0,
        method: r.method.trim().to_ascii_uppercase(),
        url: r.url.trim().to_string(),
        version: Some(r.version.trim().to_ascii_uppercase()).filter(|v| !v.is_empty()),
        headers: headers.collect(),
        body,
    }
}

fn from_raw(r: &http_file::RawRequest) -> CollectionRequest {
    let (body, body_file, body_template) = match &r.body {
        http_file::BodySource::None => (String::new(), String::new(), false),
        http_file::BodySource::Text(t) => (t.clone(), String::new(), false),
        http_file::BodySource::File(p) => (String::new(), p.clone(), false),
        http_file::BodySource::FileWithVariables(p) => (String::new(), p.clone(), true),
    };
    CollectionRequest {
        name: r.name.clone().unwrap_or_default(),
        method: r.method.clone(),
        url: r.url.clone(),
        version: r.version.clone().unwrap_or_default(),
        headers: r.headers.iter().map(|(n, v)| format!("{n}: {v}")).collect::<Vec<_>>().join("\n"),
        body,
        body_file,
        body_template,
    }
}

impl AppCore {
    pub fn collections_dir(&self) -> PathBuf {
        self.paths.data.join(COLLECTIONS_DIR)
    }

    /// The `.http` file of collection `name`.
    pub fn collection_path(&self, name: &str) -> Result<PathBuf> {
        Ok(self.collections_dir().join(format!("{}.http", check_name(name)?)))
    }

    /// The collections, by name.
    pub fn collections_list(&self) -> Result<Vec<CollectionInfo>> {
        let dir = self.collections_dir();
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(&dir) else { return Ok(out) };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "http")
                && let Some(name) = p.file_stem().map(|s| s.to_string_lossy().into_owned())
            {
                let requests = read(&p).map(|f| f.requests.len()).unwrap_or(0);
                out.push(CollectionInfo { name, path: p.display().to_string(), requests });
            }
        }
        out.sort_by_key(|c| c.name.to_lowercase());
        Ok(out)
    }

    pub fn collection_read(&self, name: &str) -> Result<Collection> {
        let path = self.collection_path(name)?;
        let f = read(&path)?;
        Ok(Collection {
            name: check_name(name)?.to_string(),
            variables: f.variables.clone(),
            requests: f.requests.iter().map(from_raw).collect(),
            warnings: f.warnings,
            environments: http_file::environments(&self.collections_dir()).unwrap_or_default(),
        })
    }

    /// Write a collection (creating or replacing it).
    pub fn collection_save(&self, c: &Collection) -> Result<CollectionInfo> {
        let path = self.collection_path(&c.name)?;
        let mut f = http_file::HttpFile { variables: Vec::new(), requests: Vec::new(), warnings: Vec::new() };
        for (n, v) in &c.variables {
            let n = n.trim();
            if n.is_empty() || !n.chars().all(|ch| ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '.') || v.contains(['\n', '\r']) {
                bail!("invalid variable {n:?}");
            }
            f.variables.push((n.to_string(), v.trim().to_string()));
        }
        for (i, r) in c.requests.iter().enumerate() {
            let raw = to_raw(r);
            http_file::check_writable(&raw).map_err(|e| anyhow!("request {} ({}): {e}", i + 1, if r.name.is_empty() { &raw.url } else { &r.name }))?;
            f.requests.push(raw);
        }
        std::fs::create_dir_all(self.collections_dir())?;
        // A file written elsewhere may hold what the Composer does not keep (comments, response
        // handlers, requests it could not read): the first rewrite leaves a copy beside it.
        if let Ok(old) = std::fs::read(&path)
            && String::from_utf8(old.clone()).ok().is_none_or(|t| http_file::write_file(&http_file::parse(&t)) != t)
        {
            std::fs::write(path.with_extension("http.bak"), old)?;
        }
        let tmp = path.with_extension("http.tmp");
        std::fs::write(&tmp, http_file::write_file(&f))?;
        std::fs::rename(&tmp, &path)?;
        Ok(CollectionInfo { name: check_name(&c.name)?.to_string(), path: path.display().to_string(), requests: f.requests.len() })
    }

    pub fn collection_rename(&self, from: &str, to: &str) -> Result<()> {
        let (a, b) = (self.collection_path(from)?, self.collection_path(to)?);
        // `b` exists as a file of its own (not only as `a` under another case, as on macOS
        // and Windows): a clash.
        let own = b.file_name().is_some_and(|n| std::fs::read_dir(self.collections_dir()).is_ok_and(|mut d| d.any(|e| e.is_ok_and(|e| e.file_name() == n))));
        if b.exists() && (own || from.trim().to_lowercase() != to.trim().to_lowercase()) && a != b {
            bail!("a collection named {to} exists already");
        }
        std::fs::rename(a, b)?;
        Ok(())
    }

    pub fn collection_delete(&self, name: &str) -> Result<()> {
        std::fs::remove_file(self.collection_path(name)?)?;
        Ok(())
    }

    /// Copy a `.http` file into the collections (and its environment files, where the
    /// collections have none yet). Returns the new collection's name.
    pub fn collection_import(&self, src: &Path) -> Result<String> {
        let text = std::fs::read_to_string(src).with_context(|| format!("read {}", src.display()))?;
        if http_file::parse(&text).requests.is_empty() {
            bail!("{} contains no requests", src.display());
        }
        let stem = src.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "imported".into());
        let base: String = stem.chars().map(|c| if c.is_control() || "/\\:*?\"<>|".contains(c) { '_' } else { c }).collect();
        let base = base.trim_start_matches('.').to_string();
        let mut name = if base.is_empty() { "imported".to_string() } else { base };
        let mut n = 2;
        while self.collection_path(&name)?.exists() {
            name = format!("{} {n}", name.trim_end_matches(|c: char| c.is_ascii_digit()).trim_end());
            n += 1;
        }
        let dir = self.collections_dir();
        std::fs::create_dir_all(&dir)?;
        std::fs::write(self.collection_path(&name)?, text)?;
        for env in [http_file::ENV_FILE, http_file::PRIVATE_ENV_FILE] {
            let from = dir_of(src).join(env);
            if from.is_file() && !dir.join(env).exists() {
                std::fs::copy(&from, dir.join(env))?;
            }
        }
        Ok(name)
    }

    /// Send one request as the Composer edits it (saved or not), with the variables of
    /// collection `name` and environment `env`. Returns at once with the session.
    pub fn collection_send(self: &Arc<Self>, name: Option<&str>, req: &CollectionRequest, env: Option<&str>) -> Result<HttpRunResult> {
        let dir = self.collections_dir();
        let variables = match name.filter(|n| !n.trim().is_empty()) {
            Some(n) => read(&self.collection_path(n)?)?.variables,
            None => Vec::new(),
        };
        let raw = to_raw(req);
        let f = http_file::HttpFile { variables, requests: vec![raw.clone()], warnings: Vec::new() };
        let vars = http_file::load_environment(&dir, env).map_err(|e| anyhow!(e))?;
        let res = self.run_one(&f, &raw, &vars, &dir, Duration::ZERO, &Access { process_env: true, root: None });
        match (&res.session, &res.error) {
            (None, Some(e)) => Err(anyhow!("{e}")),
            _ => Ok(res),
        }
    }

    /// Run requests of a collection (all, or those named): see [`AppCore::run_http_file`].
    pub fn collection_run(self: &Arc<Self>, name: &str, names: &[String], env: Option<&str>, wait: Duration) -> Result<Vec<HttpRunResult>> {
        let path = self.collection_path(name)?;
        self.run_http_file(&path, env, names, wait, &Access { process_env: true, root: None })
    }
}
