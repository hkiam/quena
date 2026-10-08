//! Listeners besides the proxy port: reverse proxy entries, a SOCKS port and a port for
//! transparently redirected traffic. They run while the proxy runs.

use crate::reverse::ReverseRoute;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

/// A port of its own (SOCKS, transparent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtraPort {
    pub port: u16,
    /// Listen on all interfaces (clients still have to pass the remote allowlist).
    pub allow_remote: bool,
}

/// What a listener does with its connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listener {
    /// Forward everything to the route's targets.
    Reverse(Arc<ReverseRoute>),
    /// SOCKS5 (and SOCKS4/4a) clients name their target.
    Socks(ExtraPort),
    /// Traffic redirected by the firewall; the target is the original destination, or the
    /// TLS server name or `Host` header.
    Transparent(ExtraPort),
}

/// Name of the SOCKS listener in the Via column.
pub const SOCKS: &str = "SOCKS5";
/// Name of the transparent listener in the Via column.
pub const TRANSPARENT: &str = "transparent";

impl Listener {
    pub fn id(&self) -> String {
        match self {
            Listener::Reverse(r) => r.id.clone(),
            Listener::Socks(_) => "socks".into(),
            Listener::Transparent(_) => "transparent".into(),
        }
    }
    pub fn kind(&self) -> ListenerKind {
        match self {
            Listener::Reverse(_) => ListenerKind::Reverse,
            Listener::Socks(_) => ListenerKind::Socks,
            Listener::Transparent(_) => ListenerKind::Transparent,
        }
    }
    /// What the Via column shows for its sessions.
    pub fn name(&self) -> String {
        match self {
            Listener::Reverse(r) => r.name.clone(),
            Listener::Socks(_) => SOCKS.into(),
            Listener::Transparent(_) => TRANSPARENT.into(),
        }
    }
    pub fn port(&self) -> u16 {
        match self {
            Listener::Reverse(r) => r.port,
            Listener::Socks(p) | Listener::Transparent(p) => p.port,
        }
    }
    pub fn allow_remote(&self) -> bool {
        match self {
            Listener::Reverse(r) => r.allow_remote,
            Listener::Socks(p) | Listener::Transparent(p) => p.allow_remote,
        }
    }
    /// Where it forwards to, for the status.
    pub fn target(&self) -> String {
        match self {
            Listener::Reverse(r) => r.describe(),
            Listener::Socks(_) => "targets named by the clients".into(),
            Listener::Transparent(_) => "original destinations".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum ListenerKind {
    #[default]
    Reverse,
    Socks,
    Transparent,
}

/// State of a listener while capturing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListenerStatus {
    pub id: String,
    pub kind: ListenerKind,
    pub name: String,
    pub port: u16,
    pub target: String,
    /// Addresses it listens on; empty when it could not start.
    pub listen: Vec<String>,
    pub error: Option<String>,
}

/// A running listener.
pub(crate) struct Running {
    pub listener: Arc<Listener>,
    pub addrs: Vec<SocketAddr>,
    pub stop: tokio::sync::watch::Sender<bool>,
    /// The accept loops (one per address).
    pub tasks: Vec<tokio::task::JoinHandle<()>>,
}
