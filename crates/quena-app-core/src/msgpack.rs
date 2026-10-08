//! MessagePack bodies as a tree (`application/msgpack`, `x-msgpack`, `vnd.msgpack`):
//! maps, arrays and scalars like the JSON view, plus what JSON cannot show (binary,
//! extension types, timestamps, non-string map keys). Several values in one body (a
//! MessagePack stream) are listed one after the other.

use crate::AppCore;
use crate::dto::Part;
use quena_model::SessionId;
use rmpv::Value;
use serde::Serialize;

/// Bytes of a body that are decoded.
const MAX_BODY: usize = 16 << 20;
const MAX_DEPTH: usize = 64;
/// Nodes per body (each one is a DTO for the UI).
const MAX_NODES: usize = 200_000;
/// Values of a stream listed.
const MAX_VALUES: usize = 1000;
const MAX_STRING: usize = 4096;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MpNode {
    /// Map key or array index (`None` for a top-level value).
    pub key: Option<String>,
    /// `map`, `array`, `string`, `int`, `float`, `bool`, `nil`, `binary`, `ext`, `timestamp`.
    pub kind: String,
    pub value: String,
    pub children: Vec<MpNode>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Msgpack {
    pub values: Vec<MpNode>,
    pub error: Option<String>,
    /// Not everything is listed (size, node or value limit).
    pub truncated: bool,
}

struct Budget {
    nodes: usize,
    truncated: bool,
}

fn cut(s: &str, b: &mut Budget) -> String {
    if s.len() <= MAX_STRING {
        return s.to_string();
    }
    b.truncated = true;
    let mut end = MAX_STRING;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} … ({} bytes)", &s[..end], s.len())
}

fn hex(b: &[u8]) -> String {
    let h: String = b
        .iter()
        .take(64)
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    if b.len() > 64 {
        format!("{h} … ({} bytes)", b.len())
    } else {
        h
    }
}

/// MessagePack timestamp (extension type -1): 32, 64 or 96 bits.
fn timestamp(data: &[u8]) -> Option<String> {
    let (secs, nanos): (i64, u32) = match data.len() {
        4 => (u32::from_be_bytes(data.try_into().ok()?) as i64, 0),
        8 => {
            let v = u64::from_be_bytes(data.try_into().ok()?);
            ((v & 0x3_ffff_ffff) as i64, (v >> 34) as u32)
        }
        12 => (
            i64::from_be_bytes(data[4..12].try_into().ok()?),
            u32::from_be_bytes(data[0..4].try_into().ok()?),
        ),
        _ => return None,
    };
    let t = time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()?
        .replace_nanosecond(nanos)
        .ok()?;
    t.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

fn node(key: Option<String>, v: &Value, b: &mut Budget) -> MpNode {
    if b.nodes == 0 {
        b.truncated = true;
        return MpNode {
            key,
            kind: "…".into(),
            value: String::new(),
            children: vec![],
        };
    }
    b.nodes -= 1;
    let leaf = |kind: &str, value: String| MpNode {
        key: key.clone(),
        kind: kind.into(),
        value,
        children: vec![],
    };
    match v {
        Value::Nil => leaf("nil", "null".into()),
        Value::Boolean(x) => leaf("bool", x.to_string()),
        Value::Integer(i) => leaf("int", i.to_string()),
        Value::F32(f) => leaf("float", f.to_string()),
        Value::F64(f) => leaf("float", f.to_string()),
        Value::String(s) => match s.as_str() {
            Some(t) => leaf("string", cut(t, b)),
            None => leaf("binary", hex(s.as_bytes())),
        },
        Value::Binary(d) => leaf("binary", hex(d)),
        Value::Ext(-1, d) => match timestamp(d) {
            Some(t) => leaf("timestamp", t),
            None => leaf("ext", format!("type -1: {}", hex(d))),
        },
        Value::Ext(ty, d) => leaf("ext", format!("type {ty}: {}", hex(d))),
        Value::Array(items) => {
            let children = items
                .iter()
                .enumerate()
                .map(|(i, x)| node(Some(i.to_string()), x, b))
                .collect::<Vec<_>>();
            MpNode {
                key,
                kind: "array".into(),
                value: format!("[{}]", items.len()),
                children,
            }
        }
        Value::Map(entries) => {
            let children = entries
                .iter()
                .map(|(k, x)| {
                    let name = match k {
                        Value::String(s) => s
                            .as_str()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| hex(s.as_bytes())),
                        other => other.to_string(),
                    };
                    node(Some(name), x, b)
                })
                .collect::<Vec<_>>();
            MpNode {
                key,
                kind: "map".into(),
                value: format!("{{{}}}", entries.len()),
                children,
            }
        }
    }
}

/// Decode the values of a MessagePack body.
pub fn decode(data: &[u8]) -> Msgpack {
    let mut out = Msgpack::default();
    let mut b = Budget {
        nodes: MAX_NODES,
        truncated: false,
    };
    let mut cur = std::io::Cursor::new(data);
    while (cur.position() as usize) < data.len() {
        if out.values.len() >= MAX_VALUES || b.nodes == 0 {
            out.truncated = true;
            break;
        }
        match rmpv::decode::read_value_with_max_depth(&mut cur, MAX_DEPTH) {
            Ok(v) => out.values.push(node(None, &v, &mut b)),
            Err(e) => {
                out.error = Some(if out.values.is_empty() {
                    format!("not valid MessagePack: {e}")
                } else {
                    format!("after {} value(s): {e}", out.values.len())
                });
                break;
            }
        }
    }
    out.truncated |= b.truncated;
    out
}

/// Whether a content type is MessagePack.
pub fn is_msgpack(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.contains("msgpack") || ct.contains("messagepack")
}

impl AppCore {
    /// The MessagePack body of a session as a tree (`None`: not MessagePack).
    pub fn msgpack(&self, id: SessionId, part: Part) -> Option<Msgpack> {
        let cap = self.capture();
        let (req, resp) = cap.bodies_of(id)?;
        let d = cap.detail(id)?;
        let (body, headers) = match part {
            Part::Request => (req, d.request.headers),
            Part::Response => (resp, d.response.map(|r| r.headers).unwrap_or_default()),
        };
        if !is_msgpack(headers.get("content-type").unwrap_or("")) {
            return None;
        }
        let data =
            quena_body::text::decoded_prefix(&body, &crate::dto::spec_of(&headers), MAX_BODY + 1);
        let mut m = decode(&data[..data.len().min(MAX_BODY)]);
        m.truncated |= data.len() > MAX_BODY;
        Some(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, v).unwrap();
        out
    }

    #[test]
    fn maps_arrays_and_what_json_cannot_show() {
        let v = Value::Map(vec![
            (Value::from("name"), Value::from("quena")),
            (Value::from("n"), Value::from(-3)),
            (Value::from(7), Value::Boolean(true)),
            (Value::from("raw"), Value::Binary(vec![1, 2, 255])),
            (
                Value::from("at"),
                Value::Ext(-1, 1_700_000_000u32.to_be_bytes().to_vec()),
            ),
            (
                Value::from("list"),
                Value::Array(vec![Value::Nil, Value::F64(1.5)]),
            ),
        ]);
        let m = decode(&enc(&v));
        assert_eq!(m.error, None);
        let root = &m.values[0];
        assert_eq!((root.kind.as_str(), root.value.as_str()), ("map", "{6}"));
        let get = |k: &str| {
            root.children
                .iter()
                .find(|c| c.key.as_deref() == Some(k))
                .unwrap()
        };
        assert_eq!(get("name").value, "quena");
        assert_eq!(get("n").value, "-3");
        assert_eq!(get("7").kind, "bool");
        assert_eq!(get("raw").value, "01 02 ff");
        assert_eq!(get("at").value, "2023-11-14T22:13:20Z");
        assert_eq!(get("list").children[1].value, "1.5");
    }

    #[test]
    fn streams_and_broken_input() {
        let mut data = enc(&Value::from(1));
        data.extend(enc(&Value::from("two")));
        let m = decode(&data);
        assert_eq!(m.values.len(), 2);
        let m = decode(&[0xdc, 0x00]);
        assert!(m.error.is_some() && m.values.is_empty());
        assert!(
            is_msgpack("application/vnd.msgpack")
                && is_msgpack("application/x-msgpack; charset=binary")
                && !is_msgpack("application/json")
        );
    }
}
