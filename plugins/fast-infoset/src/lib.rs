//! Quena plugin: Fast Infoset → XML (streaming).
pub mod fi;

#[cfg(target_arch = "wasm32")]
mod plugin {
    use crate::fi;
    use std::cell::RefCell;

    wit_bindgen::generate!({ path: "../../wit/plugin.wit", world: "plugin" });
    use exports::quena::plugin::decoder::{Guest, GuestSession, Info, Representation};

    struct Fi;

    impl Guest for Fi {
        type Session = Session;
        fn get_info() -> Info {
            Info {
                id: "io.github.hkiam.fast-infoset".into(),
                name: "Fast Infoset".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                tab: "Fast Infoset".into(),
                output: Representation::Xml,
            }
        }
        fn detect(content_type: Option<String>, prefix: Vec<u8>) -> u8 {
            let ct = content_type.unwrap_or_default().to_ascii_lowercase();
            if ct.contains("fastinfoset") {
                return 100;
            }
            if fi::looks_like_fi(&prefix) { 95 } else { 0 }
        }
    }

    struct Session(RefCell<fi::Decoder>);

    impl GuestSession for Session {
        fn new(_ct: Option<String>) -> Self {
            Session(RefCell::new(fi::Decoder::new()))
        }
        fn push(&self, chunk: Vec<u8>) -> Result<Vec<u8>, String> {
            self.0.borrow_mut().push(&chunk).map(String::into_bytes)
        }
        fn finish(&self) -> Result<Vec<u8>, String> {
            self.0.borrow_mut().finish().map(String::into_bytes)
        }
    }

    export!(Fi);
}
