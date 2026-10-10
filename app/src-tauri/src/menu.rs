//! Native menu. Menu clicks are forwarded to the UI
//! as `menu` events carrying the item id.
//!
//! Shortcuts that collide with text editing (Ctrl/Cmd+X, Del, R, M …) are
//! handled in the web view when the session list has focus, not here.

use tauri::menu::{AboutMetadata, CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use crate::i18n::tr;
use tauri::{AppHandle, Wry};

fn item(app: &AppHandle, id: &str, text: &str, accel: Option<&str>) -> tauri::Result<MenuItem<Wry>> {
    MenuItem::with_id(app, id, tr(text), true, accel)
}

pub fn build(app: &AppHandle) -> tauri::Result<Menu<Wry>> {
    let sep = || PredefinedMenuItem::separator(app);
    let about = PredefinedMenuItem::about(
        app,
        Some(tr("About Quena")),
        Some(AboutMetadata { name: Some("Quena".into()), version: Some(env!("CARGO_PKG_VERSION").into()), copyright: Some("© 2026 Maik Hofmann".into()), ..Default::default() }),
    )?;

    #[cfg(target_os = "macos")]
    let app_menu = Submenu::with_items(
        app,
        tr("Quena"),
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
        tr("File"),
        true,
        &[
            &item(app, "file.new-viewer", "New Viewer", None)?,
            &item(app, "file.load", "Load Archive…", Some("CmdOrCtrl+O"))?,
            &item(app, "file.recover", "Recover Previous Capture…", None)?,
            &sep()?,
            &Submenu::with_items(
                app,
                tr("Save"),
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
                tr("Import Sessions"),
                true,
                &[
                    &item(app, "file.import-har", "HTTP Archive (HAR)…", None)?,
                    &item(app, "file.import-saz", "SAZ Archive…", None)?,
                    &item(app, "file.import-pcap", "Packet Capture (pcap, pcapng)…", None)?,
                    &item(app, "file.import-netxml", "Internet Explorer NetXML…", None)?,
                ],
            )?,
            &Submenu::with_items(
                app,
                tr("Export Sessions"),
                true,
                &[
                    &item(app, "file.export-har", "HTTP Archive (HAR)…", None)?,
                    &item(app, "file.export-saz", "SAZ Archive…", None)?,
                    &item(app, "file.export-saz-protected", "SAZ Archive with Password…", None)?,
                    &item(app, "file.export-curl", "cURL Script…", None)?,
                    &item(app, "file.export-wcat", "WCAT Script…", None)?,
                    &item(app, "file.export-sanitized", "Sanitized for Sharing (SAZ/HAR)…", None)?,
                    &item(app, "file.export-mocks", "Mocks…", None)?,
                ],
            )?,
            #[cfg(not(target_os = "macos"))]
            &sep()?,
            #[cfg(not(target_os = "macos"))]
            &PredefinedMenuItem::quit(app, Some(tr("Exit")))?,
        ],
    )?;

    let edit = Submenu::with_items(
        app,
        tr("Edit"),
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
                tr("Copy Session"),
                true,
                &[
                    &item(app, "edit.copy-url", "URL", None)?,
                    &item(app, "edit.copy-summary", "Summary", None)?,
                    &item(app, "edit.copy-headers", "Headers Only", None)?,
                    &item(app, "edit.copy-full", "Full Session", None)?,
                    &item(app, "edit.copy-curl", "As cURL", None)?,
                    &item(app, "edit.copy-fetch", "As fetch (JavaScript)", None)?,
                    &item(app, "edit.copy-powershell", "As PowerShell", None)?,
                    &item(app, "edit.copy-python", "As Python requests", None)?,
                ],
            )?,
            &Submenu::with_items(
                app,
                tr("Remove"),
                true,
                &[
                    &item(app, "edit.remove-selected", "Selected Sessions", None)?,
                    &item(app, "edit.remove-unselected", "Unselected Sessions", None)?,
                    &item(app, "edit.remove-all", "All Sessions", None)?,
                ],
            )?,
            &Submenu::with_items(
                app,
                tr("Mark"),
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

    let capture = Submenu::with_items(
        app,
        tr("Capture"),
        true,
        &[
            &CheckMenuItem::with_id(app, "file.capture", tr("Capture Traffic"), true, false, Some("F12"))?,
            &item(app, "tools.https", "HTTPS Settings…", None)?,
            &item(app, "tools.connect-device", "Connect Device…", None)?,
            &item(app, "tools.reverse-proxy", "Reverse Proxy…", None)?,
            &item(app, "tools.host-remap", "Host Remapping…", None)?,
            &item(app, "tools.launch-browser", "Start Browser…", None)?,
            &item(app, "tools.open-terminal", "Open Terminal", None)?,
            &sep()?,
            &Submenu::with_items(
                app,
                tr("Breakpoints"),
                true,
                &[
                    &item(app, "rules.bp-before", "Before Requests", Some("F11"))?,
                    &item(app, "rules.bp-after", "After Responses", Some("Alt+F11"))?,
                    &item(app, "rules.bp-off", "Off", Some("Shift+F11"))?,
                ],
            )?,
            &item(app, "view.autoresponder", "Mock Rules", None)?,
            &item(app, "rules.customize", "Rules Script…", Some("CmdOrCtrl+R"))?,
            &sep()?,
            &item(app, "rules.auto-auth", "Enable Automatic Authentication", None)?,
        ],
    )?;

    let tools = Submenu::with_items(
        app,
        tr("Tools"),
        true,
        &[
            #[cfg(not(target_os = "macos"))]
            &item(app, "tools.options", "Options…", None)?,
            &item(app, "tools.textwizard", "Text Tools…", Some("CmdOrCtrl+E"))?,
            &item(app, "tools.composer", "Composer", Some("F9"))?,
            &item(app, "tools.compare-captures", "Compare Captures…", None)?,
            &sep()?,
            &item(app, "tools.plugins", "Plugins…", None)?,
        ],
    )?;

    let view = Submenu::with_items(
        app,
        tr("View"),
        true,
        &[
            &item(app, "view.palette", "Command Palette…", Some("CmdOrCtrl+K"))?,
            &item(app, "view.minimize-to-quickexec", "Focus Command Field", Some("Alt+Q"))?,
            &sep()?,
            &item(app, "view.inspectors", "Inspect", Some("F8"))?,
            &item(app, "view.composer", "Composer", None)?,
            &item(app, "view.statistics", "Statistics", Some("F7"))?,
            &item(app, "view.filters", "Filters", None)?,
            &item(app, "view.log", "Log", None)?,
            &item(app, "view.timeline", "Timeline", None)?,
            &item(app, "view.diagnostics", "Diagnostics", None)?,
            &sep()?,
            &item(app, "view.navigator", "Navigator", Some("CmdOrCtrl+Alt+N"))?,
            &item(app, "view.groups", "Navigator: Groups", None)?,
            &item(app, "view.structure", "Navigator: Structure", None)?,
            &sep()?,
            &Submenu::with_items(
                app,
                tr("Hide in List"),
                true,
                &[
                    &item(app, "rules.hide-connects", "Tunnels (CONNECT)", None)?,
                    &item(app, "rules.hide-images", "Image Requests", None)?,
                    &item(app, "rules.hide-304", "304 Not Modified", None)?,
                ],
            )?,
            &sep()?,
            &item(app, "view.stacked", "Request Above Response", None)?,
            &item(app, "view.wide", "Request Beside Response", None)?,
            &item(app, "view.tearoff", "Tear off Inspectors", None)?,
            &sep()?,
            &item(app, "view.jobs", "Jobs", None)?,
            &item(app, "dev.overlay", "Performance Overlay", Some("CmdOrCtrl+Shift+P"))?,
            // Mock data and reloading the UI are for developing Quena: debug builds only.
            #[cfg(debug_assertions)]
            &sep()?,
            #[cfg(debug_assertions)]
            &Submenu::with_items(
                app,
                tr("Developer"),
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
                    &item(app, "dev.reload", "Reload UI", None)?,
                ],
            )?,
        ],
    )?;

    let help = Submenu::with_items(
        app,
        tr("Help"),
        true,
        &[
            &item(app, "help.quickexec", "Command Syntax", None)?,
            &item(app, "help.shortcuts", "Keyboard Shortcuts", None)?,
            &item(app, "help.coming-from", "Coming from Fiddler Classic…", None)?,
            #[cfg(not(target_os = "macos"))]
            &about,
        ],
    )?;

    #[cfg(target_os = "macos")]
    return Menu::with_items(app, &[&app_menu, &file, &edit, &capture, &view, &tools, &help]);
    #[cfg(not(target_os = "macos"))]
    Menu::with_items(app, &[&file, &edit, &capture, &view, &tools, &help])
}
