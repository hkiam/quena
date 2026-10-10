//! Language of the native menu (the web view translates itself, see app/ui/src/i18n).
//!
//! The preference comes from the UI settings (`ui.layout.language`: "system", "en", "de");
//! "system" follows the OS language.

use std::sync::atomic::{AtomicBool, Ordering};

static GERMAN: AtomicBool = AtomicBool::new(false);

/// The language to use for a preference: "en" or "de".
pub fn resolve(pref: &str) -> &'static str {
    match pref {
        "de" => "de",
        "en" => "en",
        _ => {
            let sys = sys_locale::get_locale().unwrap_or_default().to_ascii_lowercase();
            if sys.starts_with("de") { "de" } else { "en" }
        }
    }
}

/// The preference saved in the UI settings.
pub fn saved_pref(ui: &serde_json::Value) -> String {
    ui.pointer("/layout/language").and_then(|v| v.as_str()).unwrap_or("system").to_string()
}

pub fn set(lang: &str) {
    GERMAN.store(lang == "de", Ordering::Relaxed);
}

/// Menu label in the current language (English if there is no translation).
pub fn tr(en: &str) -> &str {
    if !GERMAN.load(Ordering::Relaxed) {
        return en;
    }
    de(en).unwrap_or(en)
}

fn de(en: &str) -> Option<&'static str> {
    Some(match en {
        "Settings…" => "Einstellungen…",
        "New Viewer" => "Neues Fenster",
        "Load Archive…" => "Archiv laden…",
        "Recover Previous Capture…" => "Vorherige Aufzeichnung wiederherstellen…",
        "All Sessions…" => "Alle Sessions…",
        "Selected Sessions…" => "Ausgewählte Sessions…",
        "Response Body…" => "Response-Body…",
        "Request Body…" => "Request-Body…",
        "HTTP Archive (HAR)…" => "HTTP-Archiv (HAR)…",
        "SAZ Archive…" => "SAZ-Archiv…",
        "SAZ Archive with Password…" => "SAZ-Archiv mit Passwort…",
        "Packet Capture (pcap, pcapng)…" => "Paketmitschnitt (pcap, pcapng)…",
        "cURL Script…" => "cURL-Skript…",
        "WCAT Script…" => "WCAT-Skript…",
        "Snapshot Library…" => "Snapshot-Bibliothek…",
        "Internet Explorer NetXML…" => "Internet-Explorer-NetXML…",
        "Sanitized for Sharing (SAZ/HAR)…" => "Bereinigt zum Weitergeben (SAZ/HAR)…",
        "Mocks…" => "Mocks…",
        "URL" => "URL",
        "Summary" => "Zusammenfassung",
        "Headers Only" => "Nur Header",
        "Full Session" => "Vollständige Session",
        "As cURL" => "Als cURL",
        "As fetch (JavaScript)" => "Als fetch (JavaScript)",
        "As PowerShell" => "Als PowerShell",
        "As Python requests" => "Als Python requests",
        "Selected Sessions" => "Ausgewählte Sessions",
        "Unselected Sessions" => "Nicht ausgewählte Sessions",
        "All Sessions" => "Alle Sessions",
        "Red" => "Rot",
        "Blue" => "Blau",
        "Gold" => "Gold",
        "Green" => "Grün",
        "Orange" => "Orange",
        "Purple" => "Lila",
        "Unmark" => "Markierung entfernen",
        "Comment…" => "Kommentar…",
        "Find Sessions…" => "Sessions suchen…",
        "HTTPS Settings…" => "HTTPS-Einstellungen…",
        "Connect Device…" => "Gerät verbinden…",
        "Reverse Proxy…" => "Reverse Proxy…",
        "Start Browser…" => "Browser starten…",
        "Host Remapping…" => "Host-Umleitung…",
        "Open Terminal" => "Terminal öffnen",
        "Start Agent…" => "Agent starten…",
        "Before Requests" => "Vor Requests",
        "Before LLM Requests" => "Vor LLM-Requests",
        "After Responses" => "Nach Responses",
        "Off" => "Aus",
        "Mock Rules" => "Mock-Regeln",
        "Rules Script…" => "Regel-Skript…",
        "Enable Automatic Authentication" => "Automatische Anmeldung aktivieren",
        "Options…" => "Optionen…",
        "Text Tools…" => "Text-Werkzeuge…",
        "Composer" => "Composer",
        "Compare Captures…" => "Mitschnitte vergleichen…",
        "Plugins…" => "Plugins…",
        "Command Palette…" => "Befehlspalette…",
        "Focus Command Field" => "Befehlsfeld fokussieren",
        "Inspect" => "Inspektor",
        "Statistics" => "Statistik",
        "Filters" => "Filter",
        "Log" => "Protokoll",
        "Timeline" => "Zeitachse",
        "Navigator" => "Navigator",
        "Navigator: Groups" => "Navigator: Gruppen",
        "Navigator: Structure" => "Navigator: Struktur",
        "Diagnostics" => "Diagnose",
        "Agents" => "Agenten",
        "Tunnels (CONNECT)" => "Tunnel (CONNECT)",
        "Image Requests" => "Bild-Requests",
        "304 Not Modified" => "304 Not Modified",
        "Request Above Response" => "Request über Response",
        "Request Beside Response" => "Request neben Response",
        "Tear off Inspectors" => "Inspektoren abkoppeln",
        "Jobs" => "Aufgaben",
        "Generate 1,000 mock sessions" => "1.000 Test-Sessions erzeugen",
        "Generate 100,000 mock sessions" => "100.000 Test-Sessions erzeugen",
        "Generate 500,000 mock sessions" => "500.000 Test-Sessions erzeugen",
        "Mock traffic 5,000/s (continuous)" => "Testverkehr 5.000/s (fortlaufend)",
        "Stop mock traffic" => "Testverkehr stoppen",
        "Generate large bodies (≈1.4 GB)" => "Große Bodies erzeugen (≈1,4 GB)",
        "Generate huge bodies (≈14 GB)" => "Riesige Bodies erzeugen (≈14 GB)",
        "Performance Overlay" => "Performance-Anzeige",
        "Reload UI" => "Oberfläche neu laden",
        "Command Syntax" => "Befehlssyntax",
        "Keyboard Shortcuts" => "Tastenkürzel",
        "Coming from Fiddler Classic…" => "Umstieg von Fiddler Classic…",
        "Capture Traffic" => "Verkehr aufzeichnen",
        "Quena" => "Quena",
        "File" => "Datei",
        "Save" => "Speichern",
        "Import Sessions" => "Sessions importieren",
        "Export Sessions" => "Sessions exportieren",
        "Edit" => "Bearbeiten",
        "Copy Session" => "Session kopieren",
        "Remove" => "Entfernen",
        "Mark" => "Markieren",
        "Capture" => "Aufzeichnung",
        "Breakpoints" => "Haltepunkte",
        "Tools" => "Werkzeuge",
        "View" => "Ansicht",
        "Hide in List" => "In Liste ausblenden",
        "Developer" => "Entwickler",
        "Help" => "Hilfe",
        "About Quena" => "Über Quena",
        "Exit" => "Beenden",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    /// The string literal following `after` (skipping whitespace, commas and one id literal
    /// when `skip_id`).
    fn labels(src: &str, after: &str, skip_id: bool) -> Vec<String> {
        let mut out = vec![];
        for (i, _) in src.match_indices(after) {
            let mut rest = &src[i + after.len()..];
            let mut lit = || {
                let start = rest.find('"')? + 1;
                let len = rest[start..].find('"')?;
                let l = rest[start..start + len].to_string();
                rest = &rest[start + len + 1..];
                Some(l)
            };
            if skip_id {
                lit();
            }
            if let Some(l) = lit() {
                out.push(l);
            }
        }
        out
    }

    /// Every label in menu.rs has a German translation.
    #[test]
    fn menu_is_translated() {
        let src = include_str!("menu.rs");
        let mut all = labels(src, "item(app, ", true);
        all.extend(labels(src, "CheckMenuItem::with_id(app, ", true));
        all.extend(labels(src, "Submenu::with_items(", false));
        all.extend(labels(src, "PredefinedMenuItem::quit(app, Some(tr(", false));
        assert!(all.len() > 80, "found only {} labels", all.len());
        let missing: Vec<_> = all.iter().filter(|l| super::de(l).is_none()).collect();
        assert!(missing.is_empty(), "untranslated menu labels: {missing:?}");
    }
}
