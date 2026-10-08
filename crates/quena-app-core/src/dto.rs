//! Data transfer objects for the UI.

use crate::EngineStatus;
use quena_body::decode::{DeriveSpec, variant_applies};
use quena_body::{Body, Variant};
use quena_model::*;
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
    /// Decoder plugins that apply (tab title, confidence).
    pub plugins: Vec<PluginCandidate>,
    /// Effective charset of a text body (determined on the decoded body).
    pub charset: Option<CharsetDto>,
    /// What the text is, judged from its start (see [`shape_of`]); picks the inspector views.
    pub shape: Option<&'static str>,
}

/// The charset a text is in and where that came from (see `quena_body::charset`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CharsetDto {
    /// WHATWG name (`UTF-8`, `windows-1252`, `UTF-16LE` …).
    pub name: String,
    /// `bom` | `header` | `document` | `default`
    pub source: String,
    /// `charset` of the Content-Type as sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// Declaration inside the document (XML declaration, HTML meta), as written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<String>,
}

impl From<&quena_body::charset::Detected> for CharsetDto {
    fn from(d: &quena_body::charset::Detected) -> Self {
        CharsetDto { name: d.name().to_string(), source: d.source.as_str().to_string(), header: d.header.clone(), document: d.document.clone() }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginCandidate {
    pub variant: Variant,
    pub tab: String,
    pub confidence: u8,
    /// "text" | "xml" | "json"
    pub output: String,
}

pub fn spec_of(headers: &Headers) -> DeriveSpec {
    DeriveSpec {
        content_encoding: headers.get("content-encoding").map(|s| s.to_string()),
        content_type: headers.get("content-type").map(|s| s.to_string()),
        charset: None,
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

/// Bytes of a text body looked at to tell its shape.
const SHAPE_PREFIX: usize = 8 << 10;

const SOAP_NS: &[&str] = &["http://schemas.xmlsoap.org/soap/envelope/", "http://www.w3.org/2003/05/soap-envelope"];
const ATOM_NS: &str = "http://www.w3.org/2005/Atom";
const EDMX_NS: &[&str] = &["http://schemas.microsoft.com/ado/2007/06/edmx", "http://docs.oasis-open.org/odata/ns/edmx"];

/// The kind of a text from its start, whatever the Content-Type claims:
/// `json`, `odata-json`, `soap`, `atom` (Atom feed or entry), `edmx` (OData metadata),
/// `xml`, `html`; `None` for anything else.
pub fn shape_of(text: &str) -> Option<&'static str> {
    let t = text.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if t.starts_with('{') || t.starts_with('[') {
        let odata = t.contains("\"@odata.context\"") || t.contains("\"odata.metadata\"") || {
            let rest = t[1..].trim_start();
            rest.starts_with("\"d\"") && rest[3..].trim_start().starts_with(':')
        };
        return Some(if odata { "odata-json" } else { "json" });
    }
    if !t.starts_with('<') {
        return None;
    }
    let lower = t[..t.len().min(64)].to_ascii_lowercase();
    if lower.starts_with("<!doctype html") || lower.starts_with("<html") {
        return Some("html");
    }
    let (name, tag) = xml_root(t)?;
    let (prefix, local) = name.split_once(':').unwrap_or(("", name));
    if local.eq_ignore_ascii_case("html") && prefix.is_empty() {
        return Some("html");
    }
    let ns = xml_namespace(tag, prefix).unwrap_or("");
    Some(match local {
        "Envelope" if SOAP_NS.contains(&ns) => "soap",
        "feed" | "entry" if ns == ATOM_NS => "atom",
        "Edmx" if EDMX_NS.contains(&ns) => "edmx",
        _ => "xml",
    })
}

/// Name and start tag (without `<`/`>`) of the root element, after the XML declaration,
/// processing instructions, comments and a doctype.
fn xml_root(mut t: &str) -> Option<(&str, &str)> {
    loop {
        t = t.trim_start();
        if let Some(r) = t.strip_prefix("<?") {
            t = &r[r.find("?>")? + 2..];
        } else if let Some(r) = t.strip_prefix("<!--") {
            t = &r[r.find("-->")? + 3..];
        } else if let Some(r) = t.strip_prefix("<!") {
            // A doctype; an internal subset in brackets may hold `>`.
            let end = match (r.find('['), r.find('>')) {
                (Some(b), Some(g)) if b < g => r[b..].find("]>").map(|e| b + e + 1)?,
                (_, g) => g?,
            };
            t = &r[end + 1..];
        } else {
            let r = t.strip_prefix('<')?;
            let mut quote = None;
            let end = r.char_indices().find(|&(_, c)| match quote {
                Some(q) => {
                    if c == q {
                        quote = None;
                    }
                    false
                }
                None if c == '"' || c == '\'' => {
                    quote = Some(c);
                    false
                }
                None => c == '>',
            });
            // Without the end of the start tag (cut off), what is there is still checked.
            let tag = end.map(|(i, _)| &r[..i]).unwrap_or(r);
            let name_end = tag.find(|c: char| c.is_whitespace() || c == '/').unwrap_or(tag.len());
            let name = &tag[..name_end];
            return (!name.is_empty() && name.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_')).then_some((name, tag));
        }
    }
}

/// The namespace bound to `prefix` (`""`: the default namespace) in a start tag.
fn xml_namespace<'a>(tag: &'a str, prefix: &str) -> Option<&'a str> {
    let attr = if prefix.is_empty() { "xmlns".to_string() } else { format!("xmlns:{prefix}") };
    let mut rest = tag;
    while let Some(i) = rest.find(&attr) {
        let before_ok = i == 0 || rest[..i].ends_with(|c: char| c.is_whitespace());
        let after = rest[i + attr.len()..].trim_start();
        rest = &rest[i + attr.len()..];
        if !before_ok {
            continue;
        }
        let Some(v) = after.strip_prefix('=') else { continue };
        let v = v.trim_start();
        let q = v.chars().next()?;
        if q != '"' && q != '\'' {
            continue;
        }
        let v = &v[1..];
        return Some(&v[..v.find(q)?]);
    }
    None
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
        let (charset, shape) = if is_text {
            let prefix = quena_body::text::decoded_prefix(body, &spec, quena_body::text::DETECT_PREFIX);
            let det = quena_body::charset::detect(spec.content_type.as_deref(), &prefix);
            let head = &prefix[det.bom_len.min(prefix.len())..];
            let head = quena_body::charset::decode(&head[..head.len().min(SHAPE_PREFIX)], det.encoding).0;
            (Some(CharsetDto::from(&det)), shape_of(&head))
        } else {
            (None, None)
        };
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
            plugins: vec![],
            charset,
            shape,
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
    /// Charset of the variant's bytes when the variant fixes it (`UTF-8` for transcoded text
    /// and plugin output); `null`: the body's own charset.
    pub charset: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use quena_body::{BodyConfig, BodyStore};
    use std::io::Write;

    fn info(store: &std::sync::Arc<BodyStore>, bytes: &[u8], headers: &[(&str, &str)]) -> BodyInfo {
        let h = Headers(headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect());
        BodyInfo::build(&store.store_bytes(bytes), &h)
    }

    #[test]
    fn body_info_reports_the_charset() {
        let dir = tempfile::tempdir().unwrap();
        let store = BodyStore::open(dir.path(), BodyConfig::default()).unwrap();
        let cs = |i: BodyInfo| i.charset.map(|c| (c.name, c.source, c.header, c.document));
        // Header charset, on a gzip body: determined on the decoded bytes.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"Gr\xfc\xdfe").unwrap();
        let i = info(&store, &gz.finish().unwrap(), &[("Content-Type", "text/plain; charset=ISO-8859-1"), ("Content-Encoding", "gzip")]);
        assert_eq!(cs(i), Some(("windows-1252".into(), "header".into(), Some("ISO-8859-1".into()), None)));
        // XML declaration.
        let i = info(&store, b"<?xml version=\"1.0\" encoding=\"ISO-8859-15\"?><a>\xa4</a>", &[("Content-Type", "application/xml")]);
        assert_eq!(cs(i), Some(("ISO-8859-15".into(), "document".into(), None, Some("ISO-8859-15".into()))));
        // BOM.
        let i = info(&store, &[0xFF, 0xFE, b'a', 0], &[("Content-Type", "text/plain")]);
        assert_eq!(cs(i).map(|c| (c.0, c.1)), Some(("UTF-16LE".into(), "bom".into())));
        // Default: valid UTF-8, else windows-1252.
        assert_eq!(cs(info(&store, "Grüße".as_bytes(), &[("Content-Type", "text/plain")])).map(|c| c.0), Some("UTF-8".into()));
        assert_eq!(cs(info(&store, b"Gr\xfc\xdfe", &[("Content-Type", "text/plain")])).map(|c| c.0), Some("windows-1252".into()));
        // Binary bodies have none.
        assert_eq!(cs(info(&store, b"\x89PNG\r\n", &[("Content-Type", "image/png")])), None);
        // Serialised for the UI without empty fields.
        let j = serde_json::to_value(info(&store, b"{}", &[("Content-Type", "application/json")]).charset).unwrap();
        assert_eq!(j, serde_json::json!({ "name": "UTF-8", "source": "default" }));
    }

    #[test]
    fn shapes() {
        let s = shape_of;
        assert_eq!(s(" \n{\"a\":1}"), Some("json"));
        assert_eq!(s("\u{feff}[1,2]"), Some("json"));
        assert_eq!(s("{\"@odata.context\":\"$metadata#X\",\"value\":[]}"), Some("odata-json"));
        assert_eq!(s("{ \"d\" : {\"results\":[]}}"), Some("odata-json"));
        assert_eq!(s("{\"data\":1}"), Some("json"));
        let soap11 = r#"<?xml version="1.0"?><!-- c --><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>"#;
        assert_eq!(s(soap11), Some("soap"));
        assert_eq!(s(r#"<env:Envelope xmlns:env='http://www.w3.org/2003/05/soap-envelope'>"#), Some("soap"));
        // An Envelope in another namespace is plain XML.
        assert_eq!(s(r#"<Envelope xmlns="urn:x"><a/></Envelope>"#), Some("xml"));
        assert_eq!(s(r#"<feed xml:base="x" xmlns="http://www.w3.org/2005/Atom" xmlns:m="m"><entry/></feed>"#), Some("atom"));
        assert_eq!(s(r#"<a:entry xmlns:a="http://www.w3.org/2005/Atom">"#), Some("atom"));
        assert_eq!(s(r#"<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">"#), Some("edmx"));
        assert_eq!(s(r#"<?xml version="1.0"?><!DOCTYPE note [<!ENTITY a "b">]><note><to>x</to></note>"#), Some("xml"));
        // Cut off inside the start tag: still judged.
        assert_eq!(s(r#"<soap:Envelope a="1" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" b="lon"#), Some("soap"));
        assert_eq!(s("<!DOCTYPE html><html>"), Some("html"));
        assert_eq!(s("<html lang=de>"), Some("html"));
        assert_eq!(s("hello"), None);
        assert_eq!(s("<"), None);
        assert_eq!(s("< 3"), None);
    }

    #[test]
    fn body_info_reports_the_shape() {
        let dir = tempfile::tempdir().unwrap();
        let store = BodyStore::open(dir.path(), BodyConfig::default()).unwrap();
        // Plain XML sent as text/xml is not SOAP.
        assert_eq!(info(&store, b"<note/>", &[("Content-Type", "text/xml")]).shape, Some("xml"));
        // Decoded first.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"<feed xmlns=\"http://www.w3.org/2005/Atom\"/>").unwrap();
        assert_eq!(info(&store, &gz.finish().unwrap(), &[("Content-Type", "application/xml"), ("Content-Encoding", "gzip")]).shape, Some("atom"));
        // UTF-16 with BOM.
        let mut u16 = vec![0xFF, 0xFE];
        u16.extend("{\"a\":1}".encode_utf16().flat_map(|c| c.to_le_bytes()));
        assert_eq!(info(&store, &u16, &[("Content-Type", "application/json")]).shape, Some("json"));
        // JSON sent as text/plain is still JSON; binary has no shape.
        assert_eq!(info(&store, b"[1]", &[("Content-Type", "text/plain")]).shape, Some("json"));
        assert_eq!(info(&store, b"\x89PNG\r\n", &[("Content-Type", "image/png")]).shape, None);
    }
}
