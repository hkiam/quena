//! Native menu (Fiddler Classic layout). Menu clicks are forwarded to the UI
//! as `menu` events carrying the item id.
//!
//! Shortcuts that collide with text editing (Ctrl/Cmd+X, Del, R, M …) are
//! handled in the web view when the session list has focus, not here.

use tauri::menu::{AboutMetadata, CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::{AppHandle, Wry};

fn item(app: &AppHandle, id: &str, text: &str, accel: Option<&str>) -> tauri::Result<MenuItem<Wry>> {
    MenuItem::with_id(app, id, text, true, accel)
}

pub fn build(app: &AppHandle) -> tauri::Result<Menu<Wry>> {
    let sep = || PredefinedMenuItem::separator(app);
    let about = PredefinedMenuItem::about(
        app,
        Some("About Piper"),
        Some(AboutMetadata { name: Some("Piper".into()), version: Some(env!("CARGO_PKG_VERSION").into()), copyright: Some("© 2026 Maik Hofmann".into()), ..Default::default() }),
    )?;

    #[cfg(target_os = "macos")]
    let app_menu = Submenu::with_items(
        app,
        "Piper",
        true,
        &[
            &about,
            &sep()?,
            &item(app, "tools.options", "Settings…", Some("CmdOrCtrl+,"))?,
            &sep()?,
            &PredefinedMenuItem::services(app, None)?,
            &sep()?,
            &PredefinedMenuItem::hide(app, None)?,
            &PredefinedMenuItem::hide_others(app, None)?,
            &PredefinedMenuItem::show_all(app, None)?,
            &sep()?,
            &PredefinedMenuItem::quit(app, None)?,
        ],
    )?;

    let file = Submenu::with_items(
        app,
        "File",
        true,
        &[
            &CheckMenuItem::with_id(app, "file.capture", "Capture Traffic", true, false, Some("F12"))?,
            &sep()?,
            &item(app, "file.new-viewer", "New Viewer", None)?,
            &item(app, "file.load", "Load Archive…", Some("CmdOrCtrl+O"))?,
            &item(app, "file.recover", "Recover Previous Capture…", None)?,
            &sep()?,
            &Submenu::with_items(
                app,
                "Save",
                true,
                &[
                    &item(app, "file.save-all", "All Sessions…", Some("CmdOrCtrl+S"))?,
                    &item(app, "file.save-selected", "Selected Sessions…", None)?,
                    &item(app, "file.save-response-body", "Response Body…", None)?,
                    &item(app, "file.save-request-body", "Request Body…", None)?,
                ],
            )?,
            &Submenu::with_items(
                app,
                "Import Sessions",
                true,
                &[&item(app, "file.import-har", "HTTP Archive (HAR)…", None)?, &item(app, "file.import-saz", "Fiddler Archive (SAZ)…", None)?],
            )?,
            &Submenu::with_items(
                app,
                "Export Sessions",
                true,
                &[
                    &item(app, "file.export-har", "HTTP Archive (HAR)…", None)?,
                    &item(app, "file.export-saz", "Fiddler Archive (SAZ)…", None)?,
                    &item(app, "file.export-curl", "cURL Script…", None)?,
                ],
            )?,
            #[cfg(not(target_os = "macos"))]
            &sep()?,
            #[cfg(not(target_os = "macos"))]
            &PredefinedMenuItem::quit(app, Some("Exit"))?,
        ],
    )?;

    let edit = Submenu::with_items(
        app,
        "Edit",
        true,
        &[
            &PredefinedMenuItem::undo(app, None)?,
            &PredefinedMenuItem::redo(app, None)?,
            &sep()?,
            &PredefinedMenuItem::cut(app, None)?,
            &PredefinedMenuItem::copy(app, None)?,
            &PredefinedMenuItem::paste(app, None)?,
            &PredefinedMenuItem::select_all(app, None)?,
            &sep()?,
            &Submenu::with_items(
                app,
                "Copy Session",
                true,
                &[
                    &item(app, "edit.copy-url", "URL", None)?,
                    &item(app, "edit.copy-summary", "Summary", None)?,
                    &item(app, "edit.copy-headers", "Headers Only", None)?,
                    &item(app, "edit.copy-full", "Full Session", None)?,
                    &item(app, "edit.copy-curl", "As cURL", None)?,
                ],
            )?,
            &Submenu::with_items(
                app,
                "Remove",
                true,
                &[
                    &item(app, "edit.remove-selected", "Selected Sessions", None)?,
                    &item(app, "edit.remove-unselected", "Unselected Sessions", None)?,
                    &item(app, "edit.remove-all", "All Sessions", None)?,
                ],
            )?,
            &Submenu::with_items(
                app,
                "Mark",
                true,
                &[
                    &item(app, "edit.mark-red", "Red", None)?,
                    &item(app, "edit.mark-blue", "Blue", None)?,
                    &item(app, "edit.mark-gold", "Gold", None)?,
                    &item(app, "edit.mark-green", "Green", None)?,
                    &item(app, "edit.mark-orange", "Orange", None)?,
                    &item(app, "edit.mark-purple", "Purple", None)?,
                    &sep()?,
                    &item(app, "edit.unmark", "Unmark", None)?,
                ],
            )?,
            &item(app, "edit.comment", "Comment…", None)?,
            &sep()?,
            &item(app, "edit.find", "Find Sessions…", Some("CmdOrCtrl+F"))?,
        ],
    )?;

    let rules = Submenu::with_items(
        app,
        "Rules",
        true,
        &[
            &Submenu::with_items(
                app,
                "Automatic Breakpoints",
                true,
                &[
                    &item(app, "rules.bp-before", "Before Requests", Some("F11"))?,
                    &item(app, "rules.bp-after", "After Responses", Some("Alt+F11"))?,
                    &item(app, "rules.bp-off", "Disabled", Some("Shift+F11"))?,
                ],
            )?,
            &sep()?,
            &item(app, "rules.customize", "Customize Rules…", Some("CmdOrCtrl+R"))?,
            &sep()?,
            &item(app, "rules.hide-connects", "Hide CONNECTs", None)?,
            &item(app, "rules.hide-images", "Hide Image Requests", None)?,
            &item(app, "rules.hide-304", "Hide 304s", None)?,
        ],
    )?;

    let tools = Submenu::with_items(
        app,
        "Tools",
        true,
        &[
            #[cfg(not(target_os = "macos"))]
            &item(app, "tools.options", "Options…", None)?,
            &item(app, "tools.https", "HTTPS Settings…", None)?,
            &item(app, "tools.connect-device", "Connect Device…", None)?,
            &sep()?,
            &item(app, "tools.textwizard", "TextWizard…", Some("CmdOrCtrl+E"))?,
            &item(app, "tools.composer", "Composer", Some("F9"))?,
            &sep()?,
            &item(app, "tools.plugins", "Plugins…", None)?,
        ],
    )?;

    let view = Submenu::with_items(
        app,
        "View",
        true,
        &[
            &item(app, "view.statistics", "Statistics", Some("F7"))?,
            &item(app, "view.inspectors", "Inspectors", Some("F8"))?,
            &item(app, "view.autoresponder", "AutoResponder", None)?,
            &item(app, "view.composer", "Composer", None)?,
            &item(app, "view.filters", "Filters", None)?,
            &item(app, "view.log", "Log", None)?,
            &item(app, "view.timeline", "Timeline", None)?,
            &sep()?,
            &item(app, "view.stacked", "Stacked Layout", None)?,
            &item(app, "view.wide", "Wide Layout", None)?,
            &item(app, "view.tearoff", "Tear off Inspectors", None)?,
            &sep()?,
            &item(app, "view.minimize-to-quickexec", "Focus QuickExec", Some("Alt+Q"))?,
            &item(app, "view.jobs", "Jobs", None)?,
            &sep()?,
            &Submenu::with_items(
                app,
                "Developer",
                true,
                &[
                    &item(app, "dev.mock-1k", "Generate 1,000 mock sessions", None)?,
                    &item(app, "dev.mock-100k", "Generate 100,000 mock sessions", None)?,
                    &item(app, "dev.mock-500k", "Generate 500,000 mock sessions", None)?,
                    &item(app, "dev.mock-stream", "Mock traffic 5,000/s (continuous)", None)?,
                    &item(app, "dev.mock-stop", "Stop mock traffic", None)?,
                    &sep()?,
                    &item(app, "dev.mock-big", "Generate large bodies (≈1.4 GB)", None)?,
                    &item(app, "dev.mock-huge", "Generate huge bodies (≈14 GB)", None)?,
                    &sep()?,
                    &item(app, "dev.overlay", "Performance Overlay", Some("CmdOrCtrl+Shift+P"))?,
                    &item(app, "dev.reload", "Reload UI", None)?,
                ],
            )?,
        ],
    )?;

    let help = Submenu::with_items(
        app,
        "Help",
        true,
        &[
            &item(app, "help.quickexec", "QuickExec Commands", None)?,
            &item(app, "help.shortcuts", "Keyboard Shortcuts", None)?,
            #[cfg(not(target_os = "macos"))]
            &about,
        ],
    )?;

    #[cfg(target_os = "macos")]
    return Menu::with_items(app, &[&app_menu, &file, &edit, &rules, &tools, &view, &help]);
    #[cfg(not(target_os = "macos"))]
    Menu::with_items(app, &[&file, &edit, &rules, &tools, &view, &help])
}
