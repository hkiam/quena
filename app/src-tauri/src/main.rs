// Quena desktop shell: binds quena-app-core to Tauri (commands, events,
// `quena://` body protocol, native menu). No business logic lives here.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod menu;
mod protocol;

use quena_app_core::{AppCore, EventSink, Paths};
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
    let log = quena_app_core::init_tracing();
    let paths = Paths::default_paths();
    // One instance per data directory: a second one would run crash recovery and restore
    // (i.e. undo) the system proxy the running instance set.
    let _instance = match lock_instance(&paths.data) {
        Some(l) => l,
        None => {
            tracing::warn!(target: "quena", "Quena is already running with data in {}; exiting", paths.data.display());
            eprintln!("Quena is already running (data directory {}).", paths.data.display());
            return;
        }
    };
    let core = AppCore::new(paths, log).expect("initialise Quena core");
    quena_app_core::engine::install_panic_hook(&core.paths.data);
    let engine = quena_app_core::engine::ProxyEngine::new(&core).expect("initialise capture engine");
    core.set_proxy_engine(engine.clone());
    tracing::info!(target: "quena", "Quena {} started, data in {}", env!("CARGO_PKG_VERSION"), core.paths.data.display());

    install_signal_handlers(core.clone());
    // Archives given on the command line (Windows/Linux file associations use argv).
    let initial_files: Vec<String> = std::env::args_os().skip(1).filter_map(|a| archive_path(std::path::Path::new(&a))).collect();
    let exit_core = core.clone();
    let proto_core = core.clone();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(core.clone())
        .manage(commands::OpenFiles(parking_lot::Mutex::new(initial_files)))
        .manage(engine.clone())
        .register_asynchronous_uri_scheme_protocol("quena", move |_ctx, request, responder| {
            let core = proto_core.clone();
            std::thread::spawn(move || responder.respond(protocol::handle(&core, request)));
        })
        .setup(move |app| {
            let handle = app.handle().clone();
            core.set_sink(Arc::new(TauriSink(handle.clone())));
            core.start_ticker();
            // Load the rules script if scripting was left enabled.
            if core.settings().scripting_enabled {
                if let Some(r) = core.rules.clone() {
                    tauri::async_runtime::spawn(async move {
                        if let Err(err) = r.set_script_enabled(true).await {
                            tracing::error!(target: "quena", "rules script failed to load: {err}");
                        }
                    });
                }
            }
            let m = menu::build(&handle)?;
            app.set_menu(m)?;
            app.on_menu_event(|app, ev| {
                let _ = app.emit("menu", ev.id().0.clone());
            });
            // The main window is created here (not from the config) so that a portable
            // installation keeps the web view's own data (cache, local storage) beside the
            // app as well, instead of in the user profile.
            let cfg = app.config().app.windows.iter().find(|w| w.label == "main").cloned().ok_or("no main window in tauri.conf.json")?;
            let mut builder = tauri::WebviewWindowBuilder::from_config(&handle, &cfg)?;
            if core.paths.is_portable() {
                builder = builder.data_directory(core.paths.data.join("webview"));
            }
            let _w = builder.build()?;
            #[cfg(windows)]
            disable_browser_accelerators(&_w);
            // Bundled plugins live in the app resources, or next to the executable in a
            // portable folder; dev builds use plugins/dist.
            let exe_dir = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf()));
            let bundled = app
                .path()
                .resource_dir()
                .ok()
                .map(|d| d.join("plugins"))
                .filter(|d| d.exists())
                .or_else(|| exe_dir.map(|d| d.join("plugins")).filter(|d| d.exists()))
                .or_else(|| Some(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/dist")).filter(|d| d.exists()));
            // Start capturing once the window is up: setting the system proxy (dozens of
            // `networksetup` calls on a Mac with many network services) and loading a PAC
            // file can take seconds, and the UI shows the progress through status events.
            if core.settings().proxy.capture_on_startup {
                let ccore = core.clone();
                std::thread::Builder::new()
                    .name("quena-capture-start".into())
                    .spawn(move || {
                        if let Err(e) = ccore.start_capture() {
                            tracing::error!(target: "quena", "could not start capturing: {e}");
                        }
                    })
                    .ok();
            }
            // Compiling plugins takes a moment on a cold cache: never make the window wait.
            let pcore = core.clone();
            std::thread::Builder::new()
                .name("quena-plugins".into())
                .spawn(move || {
                    if let Err(e) = pcore.init_plugins(bundled) {
                        tracing::error!(target: "quena", "plugin host: {e:#}");
                    }
                })
                .ok();
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
        .expect("error while building Quena")
        .run(move |app, event| match event {
            // Cmd+Q, dock "Quit", logout: always shut down cleanly (restores the system proxy).
            tauri::RunEvent::Exit => exit_core.shutdown(),
            // macOS delivers "Open With" / double-clicked archives as an event.
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Opened { urls } => {
                let files: Vec<String> = urls.iter().filter_map(|u| u.to_file_path().ok()).filter_map(|p| archive_path(&p)).collect();
                if !files.is_empty() {
                    app.state::<commands::OpenFiles>().0.lock().extend(files);
                    let _ = app.emit("open-files", ());
                }
            }
            _ => {
                let _ = app;
            }
        });
}

/// WebView2 handles browser shortcuts itself (Ctrl+F opens its page search, Ctrl+R/F5
/// reload, Ctrl+P print) before the app sees them. Turn them off so Quena's own shortcuts
/// work; editing keys (copy, paste, undo) are not affected.
#[cfg(windows)]
fn disable_browser_accelerators(w: &tauri::WebviewWindow) {
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Settings3;
    use windows_core::Interface;
    let res = w.with_webview(|pw| {
        let r = unsafe {
            pw.controller()
                .CoreWebView2()
                .and_then(|wv| wv.Settings())
                .and_then(|s| s.cast::<ICoreWebView2Settings3>())
                .and_then(|s3| s3.SetAreBrowserAcceleratorKeysEnabled(false))
        };
        if let Err(e) = r {
            tracing::warn!(target: "quena", "could not disable WebView2 browser shortcuts: {e}");
        }
    });
    if let Err(e) = res {
        tracing::warn!(target: "quena", "webview not available: {e}");
    }
}

/// A session archive Quena can import (`.saz`, `.har`) as an absolute path string.
fn archive_path(p: &std::path::Path) -> Option<String> {
    let ext = p.extension()?.to_string_lossy().to_ascii_lowercase();
    if (ext == "saz" || ext == "har") && p.is_file() {
        Some(std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()).to_string_lossy().into_owned())
    } else {
        None
    }
}

/// Hold an exclusive lock on `<data>/instance.lock` for the life of the process (the OS
/// releases it on exit or crash). `None` if another process holds it.
fn lock_instance(data: &std::path::Path) -> Option<Option<std::fs::File>> {
    let _ = std::fs::create_dir_all(data);
    let f = match std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(data.join("instance.lock")) {
        Ok(f) => f,
        // Can't create the lock file (read-only location…): don't block startup.
        Err(_) => return Some(None),
    };
    match f.try_lock() {
        Ok(()) => Some(Some(f)),
        Err(std::fs::TryLockError::WouldBlock) => None,
        Err(_) => Some(None),
    }
}

/// SIGTERM/SIGINT/SIGHUP (e.g. `kill`, system shutdown, dev-mode restarts): shut down
/// cleanly so the system proxy is restored and the capture is not reported as crashed.
#[cfg(unix)]
fn install_signal_handlers(core: Core) {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    let Ok(mut signals) = signal_hook::iterator::Signals::new([SIGTERM, SIGINT, SIGHUP]) else { return };
    std::thread::Builder::new()
        .name("quena-signals".into())
        .spawn(move || {
            if let Some(sig) = signals.forever().next() {
                tracing::info!(target: "quena", "signal {sig} received, shutting down");
                core.shutdown();
                std::process::exit(0);
            }
        })
        .ok();
}

#[cfg(not(unix))]
fn install_signal_handlers(_core: Core) {}
