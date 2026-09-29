//! Quena plugin: header inspector for Negotiate/NTLM/Kerberos tokens.
pub mod token;

#[cfg(target_arch = "wasm32")]
mod plugin {
    use crate::token;

    wit_bindgen::generate!({ path: "../../wit/plugin.wit", world: "header-plugin" });
    use exports::quena::plugin::header_inspector::{Guest, Info, Node, NodeKind};

    struct AuthTokens;

    impl Guest for AuthTokens {
        fn get_info() -> Info {
            Info {
                id: "io.github.hkiam.auth-tokens".into(),
                name: "Kerberos / NTLM".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                tab: "Kerberos / NTLM".into(),
            }
        }

        fn detect(_name: String, value: String) -> u8 {
            if token::decode_header_value(&value).is_some() { 100 } else { 0 }
        }

        fn inspect(_name: String, value: String) -> Result<Vec<Node>, String> {
            let d = token::decode_header_value(&value).ok_or("no Negotiate/NTLM/Kerberos token")?;
            Ok(token::nodes(&d)
                .into_iter()
                .map(|n| Node {
                    depth: n.depth,
                    kind: match n.kind {
                        token::NodeKind::Section => NodeKind::Section,
                        token::NodeKind::Field => NodeKind::Field,
                        token::NodeKind::Note => NodeKind::Note,
                        token::NodeKind::Code => NodeKind::Code,
                    },
                    name: n.name,
                    value: n.value,
                })
                .collect())
        }
    }

    export!(AuthTokens);
}
