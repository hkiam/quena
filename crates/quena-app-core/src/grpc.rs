//! gRPC + protobuf inspector (M16). Decodes gRPC length-prefixed messages and
//! renders protobuf wire format as a field tree without a .proto (schemaless):
//! field number + wire type, with best-effort interpretation (varint as int,
//! length-delimited as nested message / UTF-8 string / bytes).

use crate::AppCore;
use crate::dto::Part;
use quena_body::Body;
use quena_model::SessionId;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub number: u64,
    /// 0=varint,1=i64,2=len,5=i32
    pub wire_type: u8,
    /// Interpretation label, e.g. "int/bool", "string", "message", "bytes", "double".
    pub kind: String,
    pub value: String,
    pub children: Vec<Field>,
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

/// [`decode_message`] within a field budget; when it runs out the fields so far are
/// returned and `truncated` is set.
fn decode_limited(data: &[u8], depth: usize, budget: &mut Budget) -> Option<Vec<Field>> {
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
        let field = match wire {
            0 => {
                let v = r.varint()?;
                // Heuristic: small values may be bool.
                let kind = "varint";
                Field { number, wire_type: 0, kind: kind.into(), value: format!("{v}  (zigzag {})", zigzag(v)), children: vec![] }
            }
            1 => {
                let s = r.take(8)?;
                let u = u64::from_le_bytes(s.try_into().unwrap());
                Field { number, wire_type: 1, kind: "i64/double".into(), value: format!("{u}  ({})", f64::from_bits(u)), children: vec![] }
            }
            5 => {
                let s = r.take(4)?;
                let u = u32::from_le_bytes(s.try_into().unwrap());
                Field { number, wire_type: 5, kind: "i32/float".into(), value: format!("{u}  ({})", f32::from_bits(u)), children: vec![] }
            }
            2 => {
                let len = usize::try_from(r.varint()?).ok()?;
                let bytes = r.take(len)?;
                // Try nested message, then UTF-8 string, else bytes.
                if !bytes.is_empty() {
                    // A failed nested attempt must not use up the budget.
                    let saved = (budget.fields, budget.truncated);
                    let nested = decode_limited(bytes, depth + 1, budget);
                    if nested.is_none() {
                        (budget.fields, budget.truncated) = saved;
                    }
                    if let Some(nested) = nested {
                        Field { number, wire_type: 2, kind: "message".into(), value: format!("{{{} fields}}", nested.len()), children: nested }
                    } else if let Ok(s) = std::str::from_utf8(bytes) {
                        if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t') {
                            Field { number, wire_type: 2, kind: "string".into(), value: cut_string(s, budget), children: vec![] }
                        } else {
                            Field { number, wire_type: 2, kind: "bytes".into(), value: hex_preview(bytes), children: vec![] }
                        }
                    } else {
                        Field { number, wire_type: 2, kind: "bytes".into(), value: hex_preview(bytes), children: vec![] }
                    }
                } else {
                    Field { number, wire_type: 2, kind: "empty".into(), value: String::new(), children: vec![] }
                }
            }
            _ => return None, // 3/4 (groups) deprecated, 6/7 invalid
        };
        fields.push(field);
    }
    Some(fields)
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

/// Decode a gRPC message stream (5-byte prefix framing) from a body.
fn decode_grpc(body: &Body) -> Grpc {
    let mut out = Grpc { is_grpc: true, ..Default::default() };
    let total = body.len();
    let mut pos = 0u64;
    let mut idx = 0;
    let mut fields_left = MAX_FIELDS_TOTAL;
    while pos + 5 <= total {
        if idx >= MAX_MESSAGES || fields_left == 0 {
            out.truncated = true;
            break;
        }
        let mut hdr = [0u8; 5];
        if body.read_at(pos, &mut hdr).unwrap_or(0) < 5 {
            break;
        }
        let compressed = hdr[0] != 0;
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
        let msg_start = pos + 5;
        if msg_start + len as u64 > total {
            out.error = Some("truncated gRPC frame".into());
            break;
        }
        let mut budget = Budget { fields: MAX_FIELDS.min(fields_left), truncated: false };
        let (fields, error) = if compressed {
            (vec![], Some("compressed message (grpc-encoding); decompression not applied".into()))
        } else if len > MAX_MESSAGE {
            (vec![], Some(format!("message of {len} bytes is above the {} MB decode limit; not decoded", MAX_MESSAGE >> 20)))
        } else {
            let data = body.read_range(msg_start, len as usize).unwrap_or_default();
            match decode_limited(&data, 0, &mut budget) {
                Some(f) => (f, None),
                None => (vec![], Some("not valid protobuf".into())),
            }
        };
        fields_left -= MAX_FIELDS.min(fields_left) - budget.fields;
        out.messages.push(GrpcMessage { index: idx, compressed, len, fields, error, truncated: budget.truncated });
        idx += 1;
        pos = msg_start + len as u64;
    }
    out
}

impl AppCore {
    pub fn grpc(&self, id: SessionId, part: Part) -> Option<Grpc> {
        let cap = self.capture();
        let (req, resp) = cap.bodies_of(id)?;
        let d = cap.detail(id)?;
        let (body, headers) = match part {
            Part::Request => (req, d.request.headers),
            Part::Response => (resp, d.response.as_ref().map(|r| r.headers.clone()).unwrap_or_default()),
        };
        let ct = headers.get("content-type").unwrap_or("").to_ascii_lowercase();
        if ct.starts_with("application/grpc") {
            let mut g = decode_grpc(&body);
            // grpc-status may be in response headers (trailers-only) or the session flags.
            if let Some(r) = &d.response {
                g.status = r.headers.get("grpc-status").map(|s| s.to_string());
                g.status_message = r.headers.get("grpc-message").map(|s| s.to_string());
            }
            Some(g)
        } else if ct.contains("protobuf") || ct.contains("x-protobuf") {
            // Raw protobuf (not gRPC framed).
            let data = body.read_range(0, body.len().min(MAX_MESSAGE as u64) as usize).unwrap_or_default();
            let mut budget = Budget { fields: MAX_FIELDS, truncated: body.len() > MAX_MESSAGE as u64 };
            let fields = decode_limited(&data, 0, &mut budget);
            Some(Grpc {
                is_grpc: false,
                truncated: budget.truncated,
                messages: vec![GrpcMessage {
                    index: 0,
                    compressed: false,
                    len: body.len().min(u32::MAX as u64) as u32,
                    error: fields.is_none().then(|| "not valid protobuf".into()),
                    fields: fields.unwrap_or_default(),
                    truncated: budget.truncated,
                }],
                ..Default::default()
            })
        } else {
            None
        }
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
}
