//! Socket.IO on top of Engine.IO: the packets of WebSocket messages and of long-polling
//! bodies, with event names and arguments (protocol v4, and v3 polling payloads).

use crate::AppCore;
use crate::dto::Part;
use quena_model::SessionId;
use serde::Serialize;

/// Longest payload shown.
const MAX_DATA: usize = 64 << 10;
/// Bytes of a polling body read.
const MAX_BODY: usize = 8 << 20;

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SioPacket {
    /// Engine.IO type: `open`, `close`, `ping`, `pong`, `message`, `upgrade`, `noop`.
    pub eio: String,
    /// Socket.IO type of a message: `connect`, `disconnect`, `event`, `ack`,
    /// `connectError`, `binaryEvent`, `binaryAck`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sio: Option<String>,
    /// Namespace other than `/`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack: Option<u64>,
    /// Event name (`event`, `binaryEvent`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    /// Arguments or payload, pretty JSON when it is JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Binary attachments that follow as separate frames.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<u32>,
}

const EIO: [&str; 7] = ["open", "close", "ping", "pong", "message", "upgrade", "noop"];
const SIO: [&str; 7] = ["connect", "disconnect", "event", "ack", "connectError", "binaryEvent", "binaryAck"];

/// Whether a session URL is Socket.IO (`/socket.io/?EIO=4&transport=…`).
pub fn is_socketio(url: &str) -> bool {
    url.contains("/socket.io/") || url.contains("EIO=")
}

fn shown(s: &str) -> String {
    let t = match serde_json::from_str::<serde_json::Value>(s) {
        Ok(v) if v.is_object() || v.is_array() => serde_json::to_string_pretty(&v).unwrap_or_else(|_| s.to_string()),
        _ => s.to_string(),
    };
    if t.len() <= MAX_DATA {
        return t;
    }
    let mut end = MAX_DATA;
    while !t.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} … ({} bytes)", &t[..end], t.len())
}

/// One Engine.IO packet in text form (`4` + Socket.IO packet for messages).
pub fn decode_packet(text: &str) -> Option<SioPacket> {
    let mut chars = text.chars();
    let t = chars.next()?.to_digit(10)? as usize;
    let eio = *EIO.get(t)?;
    let rest = chars.as_str();
    let mut p = SioPacket { eio: eio.into(), ..Default::default() };
    if eio != "message" {
        if !rest.is_empty() {
            p.data = Some(shown(rest));
        }
        return Some(p);
    }
    let Some(st) = rest.chars().next().and_then(|c| c.to_digit(10)).map(|d| d as usize).filter(|d| *d < SIO.len()) else {
        // A plain Engine.IO message (no Socket.IO on top).
        p.data = Some(shown(rest));
        return Some(p);
    };
    p.sio = Some(SIO[st].into());
    let mut r = &rest[1..];
    if st == 5 || st == 6 {
        if let Some((n, tail)) = r.split_once('-')
            && let Ok(n) = n.parse()
        {
            p.attachments = Some(n);
            r = tail;
        }
    }
    if r.starts_with('/') {
        let end = r.find(',').unwrap_or(r.len());
        p.namespace = Some(r[..end].to_string());
        r = r.get(end + 1..).unwrap_or("");
    }
    let digits = r.bytes().take_while(u8::is_ascii_digit).count();
    if digits > 0 {
        p.ack = r[..digits].parse().ok();
        r = &r[digits..];
    }
    if r.is_empty() {
        return Some(p);
    }
    match serde_json::from_str::<serde_json::Value>(r) {
        Ok(serde_json::Value::Array(mut a)) if matches!(st, 2 | 5) && a.first().is_some_and(|x| x.is_string()) => {
            p.event = a.remove(0).as_str().map(str::to_string);
            p.data = (!a.is_empty()).then(|| shown(&serde_json::Value::Array(a).to_string()));
        }
        _ => p.data = Some(shown(r)),
    }
    Some(p)
}

/// The packets of a long-polling body: v4 separates them with `\x1e`, v3 prefixes each
/// with its length (`12:42["hi",1]`).
pub fn decode_polling(body: &str) -> Vec<SioPacket> {
    let b = body.trim_end_matches(['\n', '\r']);
    if b.is_empty() {
        return vec![];
    }
    // v3: length-prefixed, length in characters.
    if let Some((len, _)) = b.split_once(':')
        && !len.is_empty()
        && len.bytes().all(|c| c.is_ascii_digit())
        && !b.contains('\u{1e}')
    {
        let mut out = Vec::new();
        let mut rest = b;
        while let Some((len, tail)) = rest.split_once(':') {
            let Ok(n) = len.parse::<usize>() else { break };
            let end = tail.char_indices().nth(n).map(|(i, _)| i).unwrap_or(tail.len());
            if let Some(p) = decode_packet(&tail[..end]) {
                out.push(p);
            }
            rest = &tail[end..];
            if rest.is_empty() {
                break;
            }
        }
        return out;
    }
    b.split('\u{1e}').filter_map(decode_packet).collect()
}

impl AppCore {
    /// The Socket.IO packets of a long-polling request or response body (`None`: the
    /// session is not Socket.IO polling).
    pub fn socketio_polling(&self, id: SessionId, part: Part) -> Option<Vec<SioPacket>> {
        let cap = self.capture();
        let d = cap.detail(id)?;
        if !is_socketio(&d.request.url) || !d.request.url.contains("transport=polling") {
            return None;
        }
        let (req, resp) = cap.bodies_of(id)?;
        let (body, headers) = match part {
            Part::Request => (req, d.request.headers),
            Part::Response => (resp, d.response.map(|r| r.headers).unwrap_or_default()),
        };
        let data = quena_body::text::decoded_prefix(&body, &crate::dto::spec_of(&headers), MAX_BODY);
        Some(decode_polling(&String::from_utf8_lossy(&data)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_and_socket_packets() {
        let p = decode_packet(r#"0{"sid":"abc","upgrades":["websocket"],"pingInterval":25000}"#).unwrap();
        assert_eq!(p.eio, "open");
        assert!(p.data.unwrap().contains("\"sid\": \"abc\""));
        assert_eq!(decode_packet("2").unwrap().eio, "ping");
        assert_eq!(decode_packet("3probe").unwrap().data.as_deref(), Some("probe"));
        let e = decode_packet(r#"42["chat message",{"text":"hi"},3]"#).unwrap();
        assert_eq!((e.sio.as_deref(), e.event.as_deref()), (Some("event"), Some("chat message")));
        assert!(e.data.unwrap().contains("\"text\": \"hi\""));
        let a = decode_packet(r#"42/admin,17["update",1]"#).unwrap();
        assert_eq!((a.namespace.as_deref(), a.ack, a.event.as_deref()), (Some("/admin"), Some(17), Some("update")));
        let ack = decode_packet(r#"4317["ok"]"#).unwrap();
        assert_eq!((ack.sio.as_deref(), ack.ack, ack.event), (Some("ack"), Some(17), None));
        let c = decode_packet(r#"40/chat,{"token":"x"}"#).unwrap();
        assert_eq!((c.sio.as_deref(), c.namespace.as_deref()), (Some("connect"), Some("/chat")));
        let b = decode_packet(r#"451-["upload",{"_placeholder":true,"num":0}]"#).unwrap();
        assert_eq!((b.sio.as_deref(), b.attachments, b.event.as_deref()), (Some("binaryEvent"), Some(1), Some("upload")));
        assert_eq!(decode_packet("44{\"message\":\"Not authorized\"}").unwrap().sio.as_deref(), Some("connectError"));
        assert!(decode_packet("x").is_none() && decode_packet("").is_none() && decode_packet("9").is_none());
    }

    #[test]
    fn polling_bodies() {
        let v4 = decode_polling("40\u{1e}42[\"a\",1]\u{1e}2");
        assert_eq!(v4.iter().map(|p| p.eio.as_str()).collect::<Vec<_>>(), ["message", "message", "ping"]);
        assert_eq!(v4[1].event.as_deref(), Some("a"));
        let v3 = decode_polling("2:40\u{0}".trim_end_matches('\0'));
        assert_eq!(v3[0].sio.as_deref(), Some("connect"));
        let v3 = decode_polling("9:42[\"ä\",1]2:40");
        assert_eq!(v3.len(), 2);
        assert_eq!(v3[0].event.as_deref(), Some("ä"));
        assert_eq!(v3[1].sio.as_deref(), Some("connect"));
        assert!(is_socketio("https://x.example/socket.io/?EIO=4&transport=websocket"));
        assert!(!is_socketio("https://x.example/ws"));
    }
}
