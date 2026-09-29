// Piper desktop shell: binds piper-app-core to Tauri (commands, events,
// `piper://` body protocol, native menu). No business logic lives here.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod menu;
mod protocol;

use piper_app_core::{AppCore, EventSink, Paths};
use std::sync::Arc;
use tauri::{Emitter, Manager};

struct TauriSink(tauri::AppHandle);

impl EventSink for TauriSink {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        if let Err(e) = self.0.emit(event, payload) {
            tracing::debug!("emit {event}: {e}");
        }
    }
}

pub type Core = Arc<AppCore>;

fn main() {
    let log = piper_app_core::init_tracing();
    let core = AppCore::new(Paths::default_paths(), log).expect("initialise Piper core");
    let engine = piper_app_core::engine::ProxyEngine::new(&core).expect("initialise capture engine");
    core.set_proxy_engine(engine.clone());
    if core.settings().proxy.capture_on_startup {
        if let Err(e) = core.start_capture() {
            tracing::error!(target: "piper", "could not start capturing: {e}");
        }
    }
    tracing::info!(target: "piper", "Piper {} started, data in {}", env!("CARGO_PKG_VERSION"), core.paths.data.display());

    install_signal_handlers(core.clone());
    let exit_core = core.clone();
    let proto_core = core.clone();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(core.clone())
        .manage(engine.clone())
        .register_asynchronous_uri_scheme_protocol("piper", move |_ctx, request, responder| {
            let core = proto_core.clone();
            std::thread::spawn(move || responder.respond(protocol::handle(&core, request)));
        })
        .setup(move |app| {
            let handle = app.handle().clone();
            // Bundled plugins live in the app resources; dev builds use plugins/dist.
            let bundled = app
                .path()
                .resource_dir()
                .ok()
                .map(|d| d.join("plugins"))
                .filter(|d| d.exists())
                .or_else(|| Some(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/dist")).filter(|d| d.exists()));
            if let Err(e) = core.init_plugins(bundled) {
                tracing::error!(target: "piper", "plugin host: {e:#}");
            }
            core.set_sink(Arc::new(TauriSink(handle.clone())));
            core.start_ticker();
            // Load the rules script if scripting was left enabled.
            if core.settings().scripting_enabled {
                if let Some(r) = core.rules.clone() {
                    tauri::async_runtime::spawn(async move {
                        if let Err(err) = r.set_script_enabled(true).await {
                            tracing::error!(target: "piper", "rules script failed to load: {err}");
                        }
                    });
                }
            }
            let m = menu::build(&handle)?;
            app.set_menu(m)?;
            app.on_menu_event(|app, ev| {
                let _ = app.emit("menu", ev.id().0.clone());
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                if window.label() == "main" {
                    let core: tauri::State<Core> = window.state();
                    core.shutdown();
                }
            }
        })
        .invoke_handler(commands::handler())
        .build(tauri::generate_context!())
        .expect("error while building Piper")
        .run(move |_app, event| {
            // Cmd+Q, dock "Quit", logout: always shut down cleanly (restores the system proxy).
            if let tauri::RunEvent::Exit = event {
                exit_core.shutdown();
            }
        });
}

/// SIGTERM/SIGINT/SIGHUP (e.g. `kill`, system shutdown, dev-mode restarts): shut down
/// cleanly so the system proxy is restored and the capture is not reported as crashed.
#[cfg(unix)]
fn install_signal_handlers(core: Core) {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    let Ok(mut signals) = signal_hook::iterator::Signals::new([SIGTERM, SIGINT, SIGHUP]) else { return };
    std::thread::Builder::new()
        .name("piper-signals".into())
        .spawn(move || {
            if let Some(sig) = signals.forever().next() {
                tracing::info!(target: "piper", "signal {sig} received, shutting down");
                core.shutdown();
                std::process::exit(0);
            }
        })
        .ok();
}

#[cfg(not(unix))]
fn install_signal_handlers(_core: Core) {}
