//! Quena scripting (M14) — JavaScript rules on QuickJS, plus
//! PAC (proxy auto-config) evaluation on the same engine.
//!
//! The engine runs on a dedicated OS thread that owns the QuickJS runtime (the
//! runtime is single-threaded and never shared). Hooks are dispatched over a
//! channel; the async proxy pipeline awaits the reply. Scripts run under a wall
//! clock budget (interrupt handler) and a memory limit, and have no access to
//! the filesystem, network or environment — only the host APIs we expose.
//!
//! Per Quena's large-body invariant, scripts operate on heads
//! and metadata only; bodies never pass through the JS engine. Body tampering
//! stays in the streaming Breakpoints/Tamper path.

mod engine;
pub mod pac;

pub use engine::{ScriptEngine, WsDecision, WsMessage};
pub use pac::{PacEngine, ProxyEntry};

use serde::{Deserialize, Serialize};

/// TypeScript definitions shipped to the UI for CodeMirror autocomplete.
pub const TYPES_DTS: &str = include_str!("quena.d.ts");
/// The starter script shown when no rules script exists yet.
pub const DEFAULT_SCRIPT: &str = include_str!("default_rules.js");

/// A log line produced by `console.*` inside a script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine {
    pub level: String,
    pub message: String,
    /// Wall-clock microseconds since the epoch.
    pub ts_us: u64,
}

/// What the host tells the script about a request at `onBeforeRequest`.
#[derive(Debug, Clone, Default)]
pub struct RequestInfo {
    pub id: u64,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub process: String,
    pub client_ip: String,
    pub headers: Vec<(String, String)>,
}

/// What the host tells the script about a response at `onBeforeResponse`.
#[derive(Debug, Clone, Default)]
pub struct ResponseInfo {
    pub id: u64,
    pub url: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

/// Session metadata a script may attach at any hook (comment/color/custom/flags).
#[derive(Debug, Clone, Default)]
pub struct SessionMeta {
    pub comment: Option<String>,
    pub color: Option<String>,
    /// Value for the script-defined Custom column.
    pub custom: Option<String>,
    pub flags: Vec<(String, String)>,
}

impl SessionMeta {
    pub fn is_empty(&self) -> bool {
        self.comment.is_none() && self.color.is_none() && self.custom.is_none() && self.flags.is_empty()
    }
}

/// A per-session update a `registerMenu` handler asks the host to apply.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MenuAction {
    pub id: u64,
    pub comment: Option<String>,
    pub color: Option<String>,
    pub custom: Option<String>,
}

/// The script's decision for a request.
#[derive(Debug, Clone)]
pub enum RequestDecision {
    /// Continue forwarding, with optional edits to method/url/headers.
    Continue {
        method: Option<String>,
        url: Option<String>,
        headers: Option<Vec<(String, String)>>,
        meta: SessionMeta,
    },
    /// Answer locally.
    Respond {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
        meta: SessionMeta,
    },
    /// Drop the connection.
    Abort { meta: SessionMeta },
}

impl Default for RequestDecision {
    fn default() -> Self {
        RequestDecision::Continue { method: None, url: None, headers: None, meta: SessionMeta::default() }
    }
}

/// The script's decision for a response.
#[derive(Debug, Clone)]
pub enum ResponseDecision {
    Continue { status: Option<u16>, headers: Option<Vec<(String, String)>>, meta: SessionMeta },
    Abort { meta: SessionMeta },
}

impl Default for ResponseDecision {
    fn default() -> Self {
        ResponseDecision::Continue { status: None, headers: None, meta: SessionMeta::default() }
    }
}
