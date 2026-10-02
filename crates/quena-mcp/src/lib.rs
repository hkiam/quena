//! MCP server: lets AI agents (Claude Code and other MCP clients) inspect and control the
//! running Quena.
//!
//! Transport is Streamable HTTP without server-sent events: `POST /mcp` on `127.0.0.1` with a
//! bearer token; every request is answered with one JSON-RPC response. The server runs on its
//! own small runtime, separate from the proxy, and only calls the same [`AppCore`] API the UI
//! uses, so it adds nothing to the forwarding path. What a client may do follows
//! [`McpAccess`](quena_app_core::settings::McpAccess), read on every call.

mod http;
mod rpc;
mod tools;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use quena_app_core::AppCore;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;

pub use rpc::handle_message;

/// A fresh random bearer token (256 bit, hex).
pub fn generate_token() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

/// Give an enabled server a token if it has none yet (saved in the settings).
pub fn ensure_token(core: &Arc<AppCore>) -> Result<()> {
    let mut s = core.settings();
    if s.mcp.enabled && s.mcp.token.trim().is_empty() {
        s.mcp.token = generate_token();
        core.update_settings(s)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpStatus {
    pub running: bool,
    /// Endpoint URL while running.
    pub url: Option<String>,
    /// Why the server is not running although it is enabled (port in use …).
    pub error: Option<String>,
}

struct Running {
    port: u16,
    addr: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Starts, stops and restarts the server to match the settings.
#[derive(Default)]
pub struct McpService {
    running: Mutex<Option<Running>>,
    error: Mutex<Option<String>>,
}

impl McpService {
    pub fn new() -> Arc<McpService> {
        Arc::new(McpService::default())
    }

    /// Bring the server in line with `core.settings().mcp`. A server that cannot start (port
    /// in use) is reported in [`McpService::status`] and the log, never as a panic.
    pub fn apply(&self, core: &Arc<AppCore>) {
        if let Err(e) = ensure_token(core) {
            tracing::warn!(target: "quena", "MCP: could not save a token: {e:#}");
        }
        let s = core.settings().mcp;
        let mut running = self.running.lock();
        let want = s.enabled && !s.token.trim().is_empty();
        if want && running.as_ref().is_some_and(|r| r.port == s.port) {
            return;
        }
        if let Some(r) = running.take() {
            tracing::info!(target: "quena", "MCP server on {} stopped", r.addr);
            drop(r);
        }
        *self.error.lock() = None;
        if !want {
            return;
        }
        match start(core, s.port) {
            Ok(r) => {
                tracing::info!(target: "quena", "MCP server listening on http://{}/mcp", r.addr);
                *running = Some(r);
            }
            Err(e) => {
                tracing::error!(target: "quena", "MCP server could not start: {e:#}");
                *self.error.lock() = Some(format!("{e:#}"));
            }
        }
    }

    pub fn stop(&self) {
        self.running.lock().take();
    }

    pub fn status(&self) -> McpStatus {
        let r = self.running.lock();
        McpStatus {
            running: r.is_some(),
            url: r.as_ref().map(|r| format!("http://{}/mcp", r.addr)),
            error: self.error.lock().clone(),
        }
    }

    /// Address while running (tests).
    pub fn addr(&self) -> Option<SocketAddr> {
        self.running.lock().as_ref().map(|r| r.addr)
    }
}

fn start(core: &Arc<AppCore>, port: u16) -> Result<Running> {
    // Bind here, synchronously, so a port in use is reported to the caller.
    let listener = std::net::TcpListener::bind(("127.0.0.1", port)).with_context(|| format!("listen on 127.0.0.1:{port}"))?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let weak = Arc::downgrade(core);
    let thread = std::thread::Builder::new().name("quena-mcp".into()).spawn(move || {
        // Its own runtime: agent calls never compete with the proxy's workers.
        let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(1).max_blocking_threads(4).thread_name("quena-mcp").enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!(target: "quena", "MCP runtime: {e}");
                return;
            }
        };
        rt.block_on(http::serve(listener, weak, stop_rx));
        // A tool call still running (a long wait) must not hold up a restart.
        rt.shutdown_timeout(std::time::Duration::from_secs(2));
    })?;
    Ok(Running { port, addr, stop: Some(stop_tx), thread: Some(thread) })
}
