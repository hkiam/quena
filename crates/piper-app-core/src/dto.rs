//! Data transfer objects for the UI.

use crate::EngineStatus;
use piper_body::decode::{DeriveSpec, variant_applies};
use piper_body::{Body, Variant};
use piper_model::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListEvent {
    pub version: u64,
    pub total: usize,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StatusDto {
    pub engine: EngineStatus,
    pub sessions: usize,
    pub visible: usize,
    pub jobs_active: usize,
    pub used_bytes: u64,
    pub free_bytes: Option<u64>,
    pub recording_suspended: bool,
    pub filter_active: bool,
    pub capture_dir: String,
    pub uptime_s: u64,
    pub mock_running: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickExecResult {
    pub message: Option<String>,
    pub error: Option<String>,
    pub select: Option<Vec<SessionId>>,
    /// UI action to perform (help, dump …).
    pub action: Option<String>,
    /// Command to forward to the capture engine.
    pub engine_command: Option<String>,
}

impl QuickExecResult {
    pub fn msg(m: impl Into<String>) -> Self {
        QuickExecResult { message: Some(m.into()), ..Default::default() }
    }
    pub fn error(m: impl Into<String>) -> Self {
        QuickExecResult { error: Some(m.into()), ..Default::default() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Part {
    Request,
    Response,
}

impl Part {
    pub fn parse(s: &str) -> Option<Part> {
        match s {
            "request" | "req" | "c" => Some(Part::Request),
            "response" | "resp" | "s" => Some(Part::Response),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyInfo {
    pub body_id: u64,
    pub len: u64,
    pub wire_len: u64,
    pub complete: bool,
    pub truncated: bool,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub transfer_encoding: Option<String>,
    pub is_text: bool,
    pub is_image: bool,
    /// Variants that differ from raw.
    pub variants: Vec<Variant>,
}

pub fn spec_of(headers: &Headers) -> DeriveSpec {
    DeriveSpec {
        content_encoding: headers.get("content-encoding").map(|s| s.to_string()),
        content_type: headers.get("content-type").map(|s| s.to_string()),
    }
}

pub fn is_textual_type(ct: &str) -> bool {
    let ct = ct.to_ascii_lowercase();
    ct.starts_with("text/")
        || ct.contains("json")
        || ct.contains("xml")
        || ct.contains("javascript")
        || ct.contains("ecmascript")
        || ct.contains("x-www-form-urlencoded")
        || ct.contains("graphql")
        || ct.contains("yaml")
        || ct.contains("csv")
        || ct.contains("x-ndjson")
}

pub fn sniff_text(sample: &[u8]) -> bool {
    if sample.is_empty() {
        return true;
    }
    if sample.contains(&0) {
        return false;
    }
    let printable = sample
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b) || b >= 0x80)
        .count();
    printable * 100 / sample.len() >= 95
}

impl BodyInfo {
    pub fn build(body: &Body, headers: &Headers) -> BodyInfo {
        let spec = spec_of(headers);
        let ct = headers.get("content-type").map(|s| s.to_string());
        let encoded = variant_applies(&spec, Variant::Decoded);
        let is_text = match &ct {
            Some(c) if is_textual_type(c) => true,
            Some(c) if c.starts_with("image/") || c.starts_with("video/") || c.starts_with("audio/") => false,
            _ if encoded => false,
            _ => sniff_text(&body.read_range(0, 1024).unwrap_or_default()),
        };
        let mut variants = vec![Variant::Raw];
        if encoded {
            variants.push(Variant::Decoded);
        }
        if variant_applies(&spec, Variant::Pretty) {
            variants.push(Variant::Pretty);
        }
        BodyInfo {
            body_id: body.id(),
            len: body.len(),
            wire_len: body.wire_len(),
            complete: body.is_complete(),
            truncated: body.is_truncated(),
            is_image: ct.as_deref().is_some_and(|c| c.starts_with("image/")),
            content_type: ct,
            content_encoding: spec.content_encoding,
            transfer_encoding: headers.get("transfer-encoding").map(|s| s.to_string()),
            is_text,
            variants,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailDto {
    pub summary: SessionSummary,
    pub request: RequestHead,
    pub response: Option<ResponseHead>,
    pub request_body: BodyInfo,
    pub response_body: BodyInfo,
    pub timers: Timers,
    pub connection: ConnectionInfo,
    pub process: Option<ProcessInfo>,
    pub error: Option<String>,
    pub extra_flags: Vec<(String, String)>,
}

impl DetailDto {
    pub fn build(d: SessionDetail, req: &Body, resp: &Body) -> DetailDto {
        let empty = Headers::default();
        DetailDto {
            request_body: BodyInfo::build(req, &d.request.headers),
            response_body: BodyInfo::build(resp, d.response.as_ref().map(|r| &r.headers).unwrap_or(&empty)),
            summary: d.summary,
            request: d.request,
            response: d.response,
            timers: d.timers,
            connection: d.connection,
            process: d.process,
            error: d.error,
            extra_flags: d.extra_flags,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyView {
    pub len: u64,
    pub complete: bool,
    pub variant: Variant,
    /// Job producing the variant (if still running).
    pub job: Option<u64>,
    pub line_job: Option<u64>,
    pub lines: u64,
    pub lines_done: bool,
    pub scanned: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinesDto {
    pub start: u64,
    pub lines: Vec<String>,
    pub view: BodyView,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub hits: Vec<SearchHit>,
    pub done: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    pub offset: u64,
    pub line: u64,
}
