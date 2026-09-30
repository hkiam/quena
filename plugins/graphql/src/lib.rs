//! Quena plugin: GraphQL requests and responses → formatted text.
pub mod gql;
pub mod json;

#[cfg(target_arch = "wasm32")]
mod plugin {
    use crate::gql;
    use std::cell::RefCell;

    wit_bindgen::generate!({ path: "../../wit/plugin.wit", world: "plugin" });
    use exports::quena::plugin::decoder::{Guest, GuestSession, Info, Representation};

    struct GraphQl;

    impl Guest for GraphQl {
        type Session = Session;
        fn get_info() -> Info {
            Info {
                id: "io.github.hkiam.graphql".into(),
                name: "GraphQL".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                tab: "GraphQL".into(),
                output: Representation::Text,
            }
        }
        fn detect(content_type: Option<String>, prefix: Vec<u8>) -> u8 {
            gql::detect(content_type.as_deref(), &prefix)
        }
    }

    struct Session(RefCell<gql::Decoder>);

    impl GuestSession for Session {
        fn new(ct: Option<String>) -> Self {
            Session(RefCell::new(gql::Decoder::new(ct)))
        }
        fn push(&self, chunk: Vec<u8>) -> Result<Vec<u8>, String> {
            self.0.borrow_mut().push(&chunk).map(String::into_bytes)
        }
        fn finish(&self) -> Result<Vec<u8>, String> {
            self.0.borrow_mut().finish().map(String::into_bytes)
        }
    }

    export!(GraphQl);
}
