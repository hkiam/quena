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
        .run(tauri::generate_context!())
        .expect("error while running Piper");
}
