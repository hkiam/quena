//! Quena plugin: header inspector for JSON Web Tokens (JWS/JWE).
pub mod json;
pub mod jwt;

#[cfg(target_arch = "wasm32")]
mod plugin {
    use crate::jwt;

    wit_bindgen::generate!({ path: "../../wit/plugin.wit", world: "header-plugin" });
    use exports::quena::plugin::header_inspector::{Guest, Info, Node, NodeKind};

    struct Jwt;

    impl Guest for Jwt {
        fn get_info() -> Info {
            Info {
                id: "io.github.hkiam.jwt".into(),
                name: "JWT".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                tab: "JWT".into(),
            }
        }

        fn detect(name: String, value: String) -> u8 {
            if jwt::find(&name, &value).is_empty() { 0 } else { 100 }
        }

        fn inspect(name: String, value: String) -> Result<Vec<Node>, String> {
            let found = jwt::find(&name, &value);
            if found.is_empty() {
                return Err("no JSON Web Token".into());
            }
            Ok(jwt::nodes(&found, jwt::now())
                .into_iter()
                .map(|n| Node {
                    depth: n.depth,
                    kind: match n.kind {
                        jwt::NodeKind::Section => NodeKind::Section,
                        jwt::NodeKind::Field => NodeKind::Field,
                        jwt::NodeKind::Note => NodeKind::Note,
                        jwt::NodeKind::Code => NodeKind::Code,
                    },
                    name: n.name,
                    value: n.value,
                })
                .collect())
        }
    }

    export!(Jwt);
}
