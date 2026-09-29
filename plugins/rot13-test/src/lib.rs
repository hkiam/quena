//! ROT13 decoder – the smallest possible Quena plugin (PLAN.md M7/M10).
wit_bindgen::generate!({ path: "../../wit/plugin.wit", world: "plugin" });

use exports::quena::plugin::decoder::{Guest, GuestSession, Info, Representation};

struct Rot13;

fn rot13(b: u8) -> u8 {
    match b {
        b'a'..=b'z' => (b - b'a' + 13) % 26 + b'a',
        b'A'..=b'Z' => (b - b'A' + 13) % 26 + b'A',
        _ => b,
    }
}

impl Guest for Rot13 {
    type Session = Session;

    fn get_info() -> Info {
        Info {
            id: "io.github.hkiam.rot13-test".into(),
            name: "ROT13 (test)".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            tab: "ROT13".into(),
            output: Representation::Text,
        }
    }

    fn detect(content_type: Option<String>, _prefix: Vec<u8>) -> u8 {
        match content_type.as_deref().map(|c| c.to_ascii_lowercase()) {
            Some(c) if c.starts_with("text/x-rot13") => 100,
            Some(c) if c.starts_with("text/") => 50,
            _ => 0,
        }
    }
}

struct Session;

impl GuestSession for Session {
    fn new(_content_type: Option<String>) -> Self {
        Session
    }
    fn push(&self, chunk: Vec<u8>) -> Result<Vec<u8>, String> {
        Ok(chunk.into_iter().map(rot13).collect())
    }
    fn finish(&self) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
}

export!(Rot13);
