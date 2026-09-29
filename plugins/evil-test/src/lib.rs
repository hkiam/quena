//! Misbehaving decoder for sandbox tests: traps, loops forever, eats memory.
wit_bindgen::generate!({ path: "../../wit/plugin.wit", world: "plugin" });

use exports::quena::plugin::decoder::{Guest, GuestSession, Info, Representation};

struct Evil;

impl Guest for Evil {
    type Session = Session;
    fn get_info() -> Info {
        Info { id: "io.github.hkiam.evil-test".into(), name: "Evil (test)".into(), version: "0.1.0".into(), tab: "Evil".into(), output: Representation::Text }
    }
    fn detect(_ct: Option<String>, _prefix: Vec<u8>) -> u8 {
        0
    }
}

struct Session {
    mode: String,
}

impl GuestSession for Session {
    fn new(content_type: Option<String>) -> Self {
        Session { mode: content_type.unwrap_or_default() }
    }
    fn push(&self, chunk: Vec<u8>) -> Result<Vec<u8>, String> {
        match self.mode.as_str() {
            "trap" => panic!("evil plugin panics"),
            "loop" => {
                let mut x: u64 = 1;
                loop {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                    if x == 0 {
                        break;
                    }
                }
                Ok(vec![])
            }
            "oom" => {
                let mut v: Vec<Vec<u8>> = Vec::new();
                loop {
                    v.push(vec![1u8; 64 << 20]);
                    if v.len() > 1000 {
                        break;
                    }
                }
                Ok(vec![v.len() as u8])
            }
            "error" => Err("evil decoding error".into()),
            _ => Ok(chunk),
        }
    }
    fn finish(&self) -> Result<Vec<u8>, String> {
        Ok(vec![])
    }
}

export!(Evil);
