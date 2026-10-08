//! gRPC + protobuf inspector (M16). Decodes gRPC length-prefixed messages (also grpc-web,
//! compressed per `grpc-encoding`, and base64 `grpc-web-text`) and renders protobuf wire
//! format as a field tree. With a schema (`.proto` files or server reflection, see
//! [`crate::protobuf`]) fields get their names, types and enum values; without one, or for
//! fields the schema does not know, it stays schemaless: field number + wire type, with a
//! best-effort interpretation (varint as int, length-delimited as nested message / UTF-8
//! string / bytes).

use crate::AppCore;
use crate::dto::Part;
use prost_reflect::{DescriptorPool, Kind, MessageDescriptor};
use quena_body::Body;
use quena_model::SessionId;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub number: u64,
    /// 0=varint,1=i64,2=len,5=i32
    pub wire_type: u8,
    /// Interpretation label, e.g. "varint", "string", "message", "bytes", "double", or the
    /// schema's type ("int32", "bool", "enum", …).
    pub kind: String,
    pub value: String,
    pub children: Vec<Field>,
    /// Field name from the schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Message or enum type from the schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrpcMessage {
    pub index: usize,
    /// gRPC frame flag (1 = compressed).
    pub compressed: bool,
    pub len: u32,
    pub fields: Vec<Field>,
    pub error: Option<String>,
    /// Field tree or string values were cut (see the `MAX_*` limits).
    pub truncated: bool,
    /// The schema's message type it was decoded as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Grpc {
    pub is_grpc: bool,
    pub messages: Vec<GrpcMessage>,
    /// grpc-status / grpc-message from trailers or headers.
    pub status: Option<String>,
    pub status_message: Option<String>,
    pub error: Option<String>,
    /// Not all messages are listed (message or field limit reached).
    pub truncated: bool,
    /// The service method from the URL (`pkg.Service/Method`), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// How the schema was found, or why not (`None`: no schemas configured).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn varint(&mut self) -> Option<u64> {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let byte = *self.b.get(self.p)?;
            self.p += 1;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.b.len() - self.p < n {
            return None;
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Some(s)
    }
}

const MAX_DEPTH: usize = 32;
/// Bytes of one gRPC message (or raw protobuf body) that are decoded.
const MAX_MESSAGE: u32 = 16 << 20;
/// Messages listed per body.
const MAX_MESSAGES: usize = 1000;
/// Fields decoded per message and per body (each one is a DTO for the UI).
const MAX_FIELDS: usize = 50_000;
const MAX_FIELDS_TOTAL: usize = 200_000;
/// Longest string value shown.
const MAX_STRING: usize = 4096;
/// A `grpc-web-text` body is read (and base64-decoded) up to this size.
const MAX_TEXT_BODY: u64 = 64 << 20;

/// Field budget and truncation flag shared by one decode.
struct Budget {
    fields: usize,
    truncated: bool,
}

/// Decode a protobuf message into fields. Returns None if it is clearly not protobuf.
#[cfg(test)]
fn decode_message(data: &[u8], depth: usize) -> Option<Vec<Field>> {
    decode_limited(data, depth, &mut Budget { fields: MAX_FIELDS, truncated: false })
}

/// Schemaless [`decode_typed`].
#[cfg(test)]
fn decode_limited(data: &[u8], depth: usize, budget: &mut Budget) -> Option<Vec<Field>> {
    decode_typed(data, depth, budget, None)
}

fn field(number: u64, wire_type: u8, kind: &str, value: String) -> Field {
    Field { number, wire_type, kind: kind.into(), value, children: vec![], name: None, type_name: None }
}

/// A varint as the schema's scalar type: (kind, value, type name).
fn typed_varint(kind: &Kind, v: u64) -> Option<(String, String, Option<String>)> {
    Some(match kind {
        Kind::Bool => ("bool".into(), (v != 0).to_string(), None),
        Kind::Int32 => ("int32".into(), (v as i64 as i32).to_string(), None),
        Kind::Int64 => ("int64".into(), (v as i64).to_string(), None),
        Kind::Uint32 => ("uint32".into(), (v as u32).to_string(), None),
        Kind::Uint64 => ("uint64".into(), v.to_string(), None),
        Kind::Sint32 => ("sint32".into(), (zigzag(v) as i32).to_string(), None),
        Kind::Sint64 => ("sint64".into(), zigzag(v).to_string(), None),
        Kind::Enum(e) => {
            let n = v as i64 as i32;
            let value = match e.get_value(n) {
                Some(ev) => format!("{} ({n})", ev.name()),
                None => n.to_string(),
            };
            ("enum".into(), value, Some(e.full_name().to_string()))
        }
        _ => return None,
    })
}

fn typed_fixed64(kind: &Kind, u: u64) -> Option<(String, String)> {
    Some(match kind {
        Kind::Double => ("double".into(), f64::from_bits(u).to_string()),
        Kind::Fixed64 => ("fixed64".into(), u.to_string()),
        Kind::Sfixed64 => ("sfixed64".into(), (u as i64).to_string()),
        _ => return None,
    })
}

fn typed_fixed32(kind: &Kind, u: u32) -> Option<(String, String)> {
    Some(match kind {
        Kind::Float => ("float".into(), f32::from_bits(u).to_string()),
        Kind::Fixed32 => ("fixed32".into(), u.to_string()),
        Kind::Sfixed32 => ("sfixed32".into(), (u as i32).to_string()),
        _ => return None,
    })
}

/// Elements of a packed repeated scalar field, or `None` if the bytes do not fit the type.
fn packed(kind: &Kind, bytes: &[u8], budget: &mut Budget) -> Option<Vec<Field>> {
    let mut r = Reader { b: bytes, p: 0 };
    let mut out = Vec::new();
    while r.p < bytes.len() {
        if budget.fields == 0 {
            budget.truncated = true;
            break;
        }
        budget.fields -= 1;
        let i = out.len() as u64;
        let f = match kind {
            Kind::Double | Kind::Fixed64 | Kind::Sfixed64 => {
                let (k, v) = typed_fixed64(kind, u64::from_le_bytes(r.take(8)?.try_into().ok()?))?;
                field(i, 1, &k, v)
            }
            Kind::Float | Kind::Fixed32 | Kind::Sfixed32 => {
                let (k, v) = typed_fixed32(kind, u32::from_le_bytes(r.take(4)?.try_into().ok()?))?;
                field(i, 5, &k, v)
            }
            _ => {
                let (k, v, t) = typed_varint(kind, r.varint()?)?;
                Field { type_name: t, ..field(i, 0, &k, v) }
            }
        };
        out.push(f);
    }
    Some(out)
}

/// Decode a protobuf message into fields, named and typed by `desc` where it knows them.
/// Returns `None` if it is clearly not protobuf; when the budget runs out the fields so
/// far are returned and `truncated` is set.
fn decode_typed(data: &[u8], depth: usize, budget: &mut Budget, desc: Option<&MessageDescriptor>) -> Option<Vec<Field>> {
    if depth > MAX_DEPTH {
        return None;
    }
    let mut r = Reader { b: data, p: 0 };
    let mut fields = Vec::new();
    while r.p < data.len() {
        if budget.fields == 0 {
            budget.truncated = true;
            break;
        }
        budget.fields -= 1;
        let tag = r.varint()?;
        let number = tag >> 3;
        let wire = (tag & 7) as u8;
        if number == 0 {
            return None;
        }
        let fd = desc.and_then(|d| u32::try_from(number).ok().and_then(|n| d.get_field(n)));
        let kind = fd.as_ref().map(|f| f.kind());
        let mut out = match wire {
            0 => {
                let v = r.varint()?;
                match kind.as_ref().and_then(|k| typed_varint(k, v)) {
                    Some((k, value, t)) => Field { type_name: t, ..field(number, 0, &k, value) },
                    None => field(number, 0, "varint", format!("{v}  (zigzag {})", zigzag(v))),
                }
            }
            1 => {
                let u = u64::from_le_bytes(r.take(8)?.try_into().unwrap());
                match kind.as_ref().and_then(|k| typed_fixed64(k, u)) {
                    Some((k, value)) => field(number, 1, &k, value),
                    None => field(number, 1, "i64/double", format!("{u}  ({})", f64::from_bits(u))),
                }
            }
            5 => {
                let u = u32::from_le_bytes(r.take(4)?.try_into().unwrap());
                match kind.as_ref().and_then(|k| typed_fixed32(k, u)) {
                    Some((k, value)) => field(number, 5, &k, value),
                    None => field(number, 5, "i32/float", format!("{u}  ({})", f32::from_bits(u))),
                }
            }
            2 => {
                let len = usize::try_from(r.varint()?).ok()?;
                let bytes = r.take(len)?;
                len_delimited(number, bytes, kind.as_ref(), fd.as_ref().is_some_and(|f| f.is_list()), depth, budget)
            }
            _ => return None, // 3/4 (groups) deprecated, 6/7 invalid
        };
        if let Some(f) = &fd {
            out.name = Some(f.name().to_string());
        }
        fields.push(out);
    }
    Some(fields)
}

/// A length-delimited field: by the schema's kind when known, else nested message, then
/// UTF-8 string, else bytes.
fn len_delimited(number: u64, bytes: &[u8], kind: Option<&Kind>, list: bool, depth: usize, budget: &mut Budget) -> Field {
    match kind {
        Some(Kind::Message(m)) => {
            let saved = (budget.fields, budget.truncated);
            match decode_typed(bytes, depth + 1, budget, Some(m)) {
                Some(nested) => {
                    return Field { children: nested.clone(), type_name: Some(m.full_name().to_string()), ..field(number, 2, "message", format!("{{{} fields}}", nested.len())) };
                }
                None => (budget.fields, budget.truncated) = saved,
            }
        }
        Some(Kind::String) => {
            if let Ok(s) = std::str::from_utf8(bytes) {
                return field(number, 2, "string", cut_string(s, budget));
            }
        }
        Some(Kind::Bytes) => return field(number, 2, "bytes", hex_preview(bytes)),
        Some(k) if list => {
            let saved = (budget.fields, budget.truncated);
            match packed(k, bytes, budget) {
                Some(items) => {
                    let label = items.first().map(|f| f.kind.clone()).unwrap_or_else(|| "packed".into());
                    return Field { children: items.clone(), ..field(number, 2, &format!("repeated {label}"), format!("[{}]", items.len())) };
                }
                None => (budget.fields, budget.truncated) = saved,
            }
        }
        _ => {}
    }
    if bytes.is_empty() {
        return field(number, 2, "empty", String::new());
    }
    // A failed nested attempt must not use up the budget.
    let saved = (budget.fields, budget.truncated);
    let nested = decode_typed(bytes, depth + 1, budget, None);
    if nested.is_none() {
        (budget.fields, budget.truncated) = saved;
    }
    if let Some(nested) = nested {
        Field { children: nested.clone(), ..field(number, 2, "message", format!("{{{} fields}}", nested.len())) }
    } else if let Ok(s) = std::str::from_utf8(bytes) {
        if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t') { field(number, 2, "string", cut_string(s, budget)) } else { field(number, 2, "bytes", hex_preview(bytes)) }
    } else {
        field(number, 2, "bytes", hex_preview(bytes))
    }
}

/// `s`, cut at `MAX_STRING` bytes (on a char boundary) with a size note.
fn cut_string(s: &str, budget: &mut Budget) -> String {
    if s.len() <= MAX_STRING {
        return s.to_string();
    }
    budget.truncated = true;
    let mut end = MAX_STRING;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} … ({} bytes)", &s[..end], s.len())
}

fn zigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

fn hex_preview(b: &[u8]) -> String {
    let hex: String = b.iter().take(64).map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ");
    if b.len() > 64 { format!("{hex} … ({} bytes)", b.len()) } else { hex }
}

/// Where gRPC frames are read from: a stored body, or decoded `grpc-web-text` bytes.
trait Source {
    fn size(&self) -> u64;
    fn read(&self, pos: u64, len: usize) -> Vec<u8>;
}

impl Source for Body {
    fn size(&self) -> u64 {
        self.len()
    }
    fn read(&self, pos: u64, len: usize) -> Vec<u8> {
        self.read_range(pos, len).unwrap_or_default()
    }
}

impl Source for Vec<u8> {
    fn size(&self) -> u64 {
        self.len() as u64
    }
    fn read(&self, pos: u64, len: usize) -> Vec<u8> {
        let start = (pos as usize).min(self.len());
        self[start..(start + len).min(self.len())].to_vec()
    }
}

/// Decode a gRPC message stream (5-byte prefix framing) from a body (schemaless, as sent).
#[cfg(test)]
fn decode_grpc(body: &Body) -> Grpc {
    decode_frames(body, None, None)
}

/// Decode gRPC frames: messages as `desc` (if any), uncompressed with `encoding`
/// (`grpc-encoding`); grpc-web trailer frames give the status.
fn decode_frames(src: &dyn Source, desc: Option<&MessageDescriptor>, encoding: Option<&str>) -> Grpc {
    let mut out = Grpc { is_grpc: true, ..Default::default() };
    let total = src.size();
    let mut pos = 0u64;
    let mut idx = 0;
    let mut fields_left = MAX_FIELDS_TOTAL;
    while pos + 5 <= total {
        if idx >= MAX_MESSAGES || fields_left == 0 {
            out.truncated = true;
            break;
        }
        let hdr = src.read(pos, 5);
        if hdr.len() < 5 {
            break;
        }
        let flags = hdr[0];
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
        let msg_start = pos + 5;
        if msg_start + len as u64 > total {
            out.error = Some("truncated gRPC frame".into());
            break;
        }
        pos = msg_start + len as u64;
        // grpc-web: the trailers travel as a last frame with flag 0x80.
        if flags & 0x80 != 0 {
            let text = String::from_utf8_lossy(&src.read(msg_start, len.min(64 << 10) as usize)).into_owned();
            for line in text.split("\r\n").chain(std::iter::once("")).filter(|l| !l.is_empty()) {
                if let Some((k, v)) = line.split_once(':') {
                    match k.trim().to_ascii_lowercase().as_str() {
                        "grpc-status" => out.status = Some(v.trim().to_string()),
                        "grpc-message" => out.status_message = Some(v.trim().to_string()),
                        _ => {}
                    }
                }
            }
            continue;
        }
        let compressed = flags & 1 != 0;
        let mut budget = Budget { fields: MAX_FIELDS.min(fields_left), truncated: false };
        let (fields, error) = if len > MAX_MESSAGE {
            (vec![], Some(format!("message of {len} bytes is above the {} MB decode limit; not decoded", MAX_MESSAGE >> 20)))
        } else {
            let raw = src.read(msg_start, len as usize);
            let data = match (compressed, encoding.map(str::trim).filter(|e| !e.is_empty() && !e.eq_ignore_ascii_case("identity"))) {
                (false, _) => Ok(raw),
                (true, Some(enc)) => quena_body::decode::decode_bytes(&raw, enc, MAX_MESSAGE as usize).map_err(|e| format!("cannot uncompress ({enc}): {e}")),
                (true, None) => Err("compressed message without grpc-encoding header".to_string()),
            };
            match data {
                Ok(data) => match decode_typed(&data, 0, &mut budget, desc) {
                    Some(f) => (f, None),
                    None if desc.is_some() => match decode_typed(&data, 0, &mut Budget { fields: budget.fields, truncated: false }, None) {
                        Some(f) => (f, Some("does not fit the schema; shown without it".to_string())),
                        None => (vec![], Some("not valid protobuf".into())),
                    },
                    None => (vec![], Some("not valid protobuf".into())),
                },
                Err(e) => (vec![], Some(e)),
            }
        };
        fields_left -= MAX_FIELDS.min(fields_left) - budget.fields;
        out.messages.push(GrpcMessage { index: idx, compressed, len, fields, error, truncated: budget.truncated, message_type: desc.map(|d| d.full_name().to_string()) });
        idx += 1;
    }
    out
}

/// A `grpc-web-text` body: base64, possibly several padded chunks one after the other
/// (each message or trailer frame encoded on its own). Returns the bytes decoded and the
/// error that stopped decoding.
fn web_text(text: &[u8]) -> (Vec<u8>, Option<String>) {
    let mut bytes = Vec::new();
    let clean: Vec<u8> = text.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut rest = &clean[..];
    while !rest.is_empty() {
        // A chunk ends after its padding, or at the end.
        let end = match rest.iter().position(|c| *c == b'=') {
            Some(p) => p + rest[p..].iter().take_while(|c| **c == b'=').count(),
            None => rest.len(),
        };
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &rest[..end]) {
            Ok(b) => bytes.extend(b),
            Err(e) => {
                return (bytes, Some(format!("grpc-web-text is not valid base64: {e}")));
            }
        }
        rest = &rest[end..];
    }
    (bytes, None)
}

/// `/pkg.Service/Method` of a URL → (`pkg.Service`, `Method`).
fn service_method(url: &str) -> Option<(String, String)> {
    let path = url.parse::<http::Uri>().ok()?.path().to_string();
    let (svc, method) = path.trim_start_matches('/').rsplit_once('/')?;
    // gRPC paths name a package-qualified service (`pkg.Service`); `/v1/items` is REST.
    (svc.contains('.') && !method.is_empty() && !svc.contains('/')).then(|| (svc.to_string(), method.to_string()))
}

/// The message type of a part: `type_override`, else the method's input (request) or output
/// (response). Also says how it was found, or why not.
fn message_type(pool: &DescriptorPool, method: Option<&(String, String)>, part: Part, type_override: Option<&str>) -> (Option<MessageDescriptor>, String) {
    if let Some(t) = type_override.filter(|t| !t.trim().is_empty()) {
        return match pool.get_message_by_name(t.trim()) {
            Some(m) => (Some(m), format!("{} (chosen)", t.trim())),
            None => (None, format!("message type {} is not in the schemas", t.trim())),
        };
    }
    let Some((svc, name)) = method else {
        return (None, "choose a message type: the URL names no gRPC method".into());
    };
    let Some(service) = pool.get_service_by_name(svc) else {
        return (None, format!("service {svc} is not in the schemas"));
    };
    let Some(m) = service.methods().find(|m| m.name() == name) else {
        return (None, format!("method {svc}/{name} is not in the schemas"));
    };
    let d = if part == Part::Request { m.input() } else { m.output() };
    let label = format!("{} ({svc}/{name})", d.full_name());
    (Some(d), label)
}

impl AppCore {
    /// The gRPC or protobuf body of a session as a field tree (`None`: neither), named by
    /// the schemas when they know the message type (`type_override`, or the URL's method).
    pub fn grpc(&self, id: SessionId, part: Part, type_override: Option<&str>) -> Option<Grpc> {
        let cap = self.capture();
        let (req, resp) = cap.bodies_of(id)?;
        let d = cap.detail(id)?;
        let (body, headers) = match part {
            Part::Request => (req, d.request.headers.clone()),
            Part::Response => (resp, d.response.as_ref().map(|r| r.headers.clone()).unwrap_or_default()),
        };
        let ct = headers.get("content-type").unwrap_or("").to_ascii_lowercase();
        let is_grpc = ct.starts_with("application/grpc");
        if !is_grpc && !ct.contains("protobuf") {
            return None;
        }
        let method = service_method(&d.request.url);
        let pool = self.protobuf.pool(&self.settings().protobuf, &self.paths.data);
        let (desc, schema) = match &pool {
            Some(p) => {
                let (m, s) = message_type(p, method.as_ref(), part, type_override);
                (m, Some(s))
            }
            None => (None, None),
        };
        let mut g = if is_grpc {
            let encoding = headers.get("grpc-encoding");
            let mut g = if ct.starts_with("application/grpc-web-text") {
                // Base64, possibly several padded chunks one after the other.
                let text = body.read_range(0, body.len().min(MAX_TEXT_BODY) as usize).unwrap_or_default();
                let (bytes, err) = web_text(&text);
                let mut g = decode_frames(&bytes, desc.as_ref(), encoding);
                if err.is_some() {
                    g.error = err;
                }
                g
            } else {
                decode_frames(&body, desc.as_ref(), encoding)
            };
            // grpc-status may be in response headers (trailers-only); grpc-web trailers win.
            if let Some(r) = &d.response {
                g.status = g.status.take().or_else(|| r.headers.get("grpc-status").map(|s| s.to_string()));
                g.status_message = g.status_message.take().or_else(|| r.headers.get("grpc-message").map(|s| s.to_string()));
            }
            g
        } else {
            // Raw protobuf (not gRPC framed).
            let data = body.read_range(0, body.len().min(MAX_MESSAGE as u64) as usize).unwrap_or_default();
            let mut budget = Budget { fields: MAX_FIELDS, truncated: body.len() > MAX_MESSAGE as u64 };
            let fields = decode_typed(&data, 0, &mut budget, desc.as_ref()).or_else(|| decode_typed(&data, 0, &mut Budget { fields: MAX_FIELDS, truncated: false }, None));
            Grpc {
                is_grpc: false,
                truncated: budget.truncated,
                messages: vec![GrpcMessage {
                    index: 0,
                    compressed: false,
                    len: body.len().min(u32::MAX as u64) as u32,
                    error: fields.is_none().then(|| "not valid protobuf".into()),
                    fields: fields.unwrap_or_default(),
                    truncated: budget.truncated,
                    message_type: desc.as_ref().map(|d| d.full_name().to_string()),
                }],
                ..Default::default()
            }
        };
        g.method = method.map(|(s, m)| format!("{s}/{m}"));
        g.schema = schema;
        Some(g)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quena_body::{BodyConfig, BodyStore};

    // Build a protobuf message by hand: field1=varint 150, field2="testing", field3={field1=1}
    fn sample() -> Vec<u8> {
        let mut m = Vec::new();
        // field 1, wire 0, value 150
        m.push(0x08);
        m.extend_from_slice(&[0x96, 0x01]);
        // field 2, wire 2, "testing"
        m.push(0x12);
        m.push(7);
        m.extend_from_slice(b"testing");
        // field 3, wire 2, nested {field1=1}
        m.push(0x1a);
        m.push(2);
        m.push(0x08);
        m.push(0x01);
        m
    }

    #[test]
    fn protobuf_tree() {
        let f = decode_message(&sample(), 0).unwrap();
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].number, 1);
        assert!(f[0].value.starts_with("150"));
        assert_eq!(f[1].kind, "string");
        assert_eq!(f[1].value, "testing");
        assert_eq!(f[2].kind, "message");
        assert_eq!(f[2].children[0].number, 1);
    }

    #[test]
    fn grpc_framing() {
        let dir = tempfile::tempdir().unwrap();
        let store = BodyStore::open(dir.path(), BodyConfig::default()).unwrap();
        let msg = sample();
        let mut framed = vec![0u8]; // not compressed
        framed.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        framed.extend_from_slice(&msg);
        // second message
        framed.push(0);
        framed.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        framed.extend_from_slice(&msg);
        let b = store.store_bytes(&framed);
        let g = decode_grpc(&b);
        assert_eq!(g.messages.len(), 2);
        assert_eq!(g.messages[0].fields.len(), 3);
        assert!(g.messages[1].error.is_none());
    }

    #[test]
    fn field_and_string_caps() {
        // 60k varint fields: field 1 = 1.
        let data: Vec<u8> = std::iter::repeat([0x08u8, 0x01]).take(60_000).flatten().collect();
        let mut b = Budget { fields: MAX_FIELDS, truncated: false };
        let f = decode_limited(&data, 0, &mut b).unwrap();
        assert_eq!(f.len(), MAX_FIELDS);
        assert!(b.truncated);
        // Long string with a multi-byte char straddling the cut.
        let s = format!("a{}", "ä".repeat(5000));
        let mut m = vec![0x12u8];
        let mut n = s.len();
        while n >= 0x80 {
            m.push((n as u8) | 0x80);
            n >>= 7;
        }
        m.push(n as u8);
        m.extend_from_slice(s.as_bytes());
        let mut b = Budget { fields: MAX_FIELDS, truncated: false };
        let f = decode_limited(&m, 0, &mut b).unwrap();
        assert_eq!(f[0].kind, "string");
        assert!(f[0].value.len() < MAX_STRING + 32 && b.truncated);
    }

    #[test]
    fn message_count_and_size_caps() {
        let dir = tempfile::tempdir().unwrap();
        let store = BodyStore::open(dir.path(), BodyConfig::default()).unwrap();
        let msg = sample();
        let mut framed = Vec::new();
        for _ in 0..1500 {
            framed.push(0);
            framed.extend_from_slice(&(msg.len() as u32).to_be_bytes());
            framed.extend_from_slice(&msg);
        }
        let g = decode_grpc(&store.store_bytes(&framed));
        assert_eq!(g.messages.len(), MAX_MESSAGES);
        assert!(g.truncated);
        // A frame claiming more than the per-message limit is reported, not read.
        let big = MAX_MESSAGE as usize + 10;
        let mut framed = vec![0u8];
        framed.extend_from_slice(&(big as u32).to_be_bytes());
        framed.resize(5 + big, 0);
        let g = decode_grpc(&store.store_bytes(&framed));
        assert_eq!(g.messages.len(), 1);
        assert!(g.messages[0].error.as_deref().unwrap().contains("decode limit"));
    }

    /// A schema compiled with protox, as the settings would load it.
    fn shop_pool() -> (tempfile::TempDir, DescriptorPool) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("shop.proto"),
            r#"syntax = "proto3";
package shop;
enum Color { COLOR_UNSPECIFIED = 0; RED = 1; GREEN = 2; }
message Money { int64 cents = 1; }
message Item {
  string name = 1;
  Money price = 2;
  Color color = 3;
  repeated int32 sizes = 4;
  sint32 delta = 5;
  double weight = 6;
  bytes raw = 7;
}
service Shop { rpc Get(Item) returns (Item); }
"#,
        )
        .unwrap();
        let s = crate::settings::ProtobufSettings { proto_paths: vec![dir.path().join("shop.proto").display().to_string()], ..Default::default() };
        let pool = crate::protobuf::Schemas::default().pool(&s, dir.path()).unwrap();
        (dir, pool)
    }

    fn item(pool: &DescriptorPool) -> Vec<u8> {
        use prost::Message;
        use prost_reflect::{DynamicMessage, Value};
        let desc = pool.get_message_by_name("shop.Item").unwrap();
        let mut m = DynamicMessage::new(desc);
        m.set_field_by_name("name", Value::String("flute".into()));
        let mut price = DynamicMessage::new(pool.get_message_by_name("shop.Money").unwrap());
        price.set_field_by_name("cents", Value::I64(1999));
        m.set_field_by_name("price", Value::Message(price));
        m.set_field_by_name("color", Value::EnumNumber(2));
        m.set_field_by_name("sizes", Value::List(vec![Value::I32(1), Value::I32(-2), Value::I32(300)]));
        m.set_field_by_name("delta", Value::I32(-5));
        m.set_field_by_name("weight", Value::F64(0.25));
        m.set_field_by_name("raw", Value::Bytes(vec![0, 1, 2].into()));
        let mut out = m.encode_to_vec();
        // A field the schema does not know (number 99, varint 7).
        out.extend_from_slice(&[0x98, 0x06, 0x07]);
        out
    }

    fn frame(flags: u8, msg: &[u8]) -> Vec<u8> {
        let mut f = vec![flags];
        f.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        f.extend_from_slice(msg);
        f
    }

    #[test]
    fn schema_names_types_and_enums() {
        let (_dir, pool) = shop_pool();
        let desc = pool.get_message_by_name("shop.Item").unwrap();
        let f = decode_typed(&item(&pool), 0, &mut Budget { fields: MAX_FIELDS, truncated: false }, Some(&desc)).unwrap();
        let get = |n: &str| f.iter().find(|x| x.name.as_deref() == Some(n)).unwrap_or_else(|| panic!("no field {n}"));
        assert_eq!((get("name").kind.as_str(), get("name").value.as_str()), ("string", "flute"));
        let price = get("price");
        assert_eq!(price.type_name.as_deref(), Some("shop.Money"));
        assert_eq!((price.children[0].name.as_deref(), price.children[0].kind.as_str(), price.children[0].value.as_str()), (Some("cents"), "int64", "1999"));
        assert_eq!(get("color").value, "GREEN (2)");
        assert_eq!(get("color").type_name.as_deref(), Some("shop.Color"));
        let sizes = get("sizes");
        assert_eq!(sizes.kind, "repeated int32");
        assert_eq!(sizes.children.iter().map(|c| c.value.as_str()).collect::<Vec<_>>(), ["1", "-2", "300"]);
        assert_eq!(get("delta").value, "-5");
        assert_eq!(get("weight").value, "0.25");
        assert_eq!(get("raw").value, "00 01 02");
        // The unknown field stays, without a name.
        let unknown = f.iter().find(|x| x.number == 99).unwrap();
        assert_eq!((unknown.name.as_deref(), unknown.kind.as_str()), (None, "varint"));
        // Without the schema: numbers only, the same field count.
        let plain = decode_message(&item(&pool), 0).unwrap();
        assert_eq!(plain.len(), f.len());
        assert!(plain.iter().all(|x| x.name.is_none()));
    }

    #[test]
    fn method_picks_the_message_type() {
        let (_dir, pool) = shop_pool();
        assert_eq!(service_method("https://api.example.com/shop.Shop/Get"), Some(("shop.Shop".into(), "Get".into())));
        assert_eq!(service_method("https://api.example.com/v1/items"), None);
        let m = service_method("http://h/shop.Shop/Get");
        let (d, label) = message_type(&pool, m.as_ref(), Part::Response, None);
        assert_eq!(d.unwrap().full_name(), "shop.Item");
        assert!(label.contains("shop.Shop/Get"), "{label}");
        let (d, label) = message_type(&pool, m.as_ref(), Part::Request, Some("shop.Money"));
        assert_eq!(d.unwrap().full_name(), "shop.Money");
        assert!(label.contains("chosen"));
        let (d, label) = message_type(&pool, service_method("http://h/other.Svc/Get").as_ref(), Part::Request, None);
        assert!(d.is_none() && label.contains("other.Svc"));
        let (d, _) = message_type(&pool, None, Part::Request, None);
        assert!(d.is_none());
    }

    #[test]
    fn compressed_messages_and_grpc_web_trailers() {
        use std::io::Write;
        let (_dir, pool) = shop_pool();
        let desc = pool.get_message_by_name("shop.Item").unwrap();
        let msg = item(&pool);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&msg).unwrap();
        let mut body = frame(1, &gz.finish().unwrap());
        body.extend(frame(0, &msg));
        body.extend(frame(0x80, b"grpc-status: 5\r\ngrpc-message: not found\r\n"));
        let g = decode_frames(&body, Some(&desc), Some("gzip"));
        assert_eq!(g.messages.len(), 2);
        assert!(g.messages[0].compressed);
        assert_eq!(g.messages[0].error, None);
        assert_eq!(g.messages[0].fields[0].name.as_deref(), Some("name"));
        assert_eq!(g.messages[1].message_type.as_deref(), Some("shop.Item"));
        assert_eq!((g.status.as_deref(), g.status_message.as_deref()), (Some("5"), Some("not found")));
        // Compressed without grpc-encoding: said, not guessed.
        let g = decode_frames(&body, Some(&desc), None);
        assert!(g.messages[0].error.as_deref().unwrap().contains("grpc-encoding"));
        // A value that does not fit its schema type is shown as what it is.
        let g = decode_frames(&frame(0, &[0x0a, 0x02, 0xff, 0xfe]), Some(&desc), None);
        assert_eq!(g.messages[0].error, None);
        assert_eq!((g.messages[0].fields[0].name.as_deref(), g.messages[0].fields[0].kind.as_str()), (Some("name"), "bytes"));
    }

    #[test]
    fn grpc_web_text_chunks() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let msg = frame(0, &sample());
        let trailer = frame(0x80, b"grpc-status: 0\r\n");
        // Each frame encoded on its own (with padding), as grpc-web servers send them.
        let text = format!("{}\n{}", b64.encode(&msg), b64.encode(&trailer));
        let (bytes, err) = web_text(text.as_bytes());
        assert_eq!(err, None);
        let g = decode_frames(&bytes, None, None);
        assert_eq!(g.messages.len(), 1);
        assert_eq!(g.status.as_deref(), Some("0"));
        let (_, err) = web_text(b"AAAA!!!!");
        assert!(err.is_some());
    }
}
