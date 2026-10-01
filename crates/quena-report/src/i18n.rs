//! Frame texts of the exports. The English text is the key, as in the UI; the German texts
//! are those of `app/ui/src/i18n/de` (report texts themselves come localized from the analyzer).

use crate::Lang;

/// Translate an English frame text.
pub(crate) fn t(lang: Lang, en: &'static str) -> &'static str {
    if lang == Lang::En {
        return en;
    }
    match en {
        "Diagnostics report" => "Diagnosebericht",
        "Analyzer" => "Analyse-Plugin",
        "Scope" => "Umfang",
        "Sessions" => "Sessions",
        "Time range" => "Zeitraum",
        "Generated" => "Erstellt",
        "Summary" => "Zusammenfassung",
        "Critical" => "Kritisch",
        "Warning" => "Warnung",
        "Info" => "Hinweis",
        "Key metrics" => "Kennzahlen",
        "Metric" => "Kennzahl",
        "Metrics" => "Kennzahlen",
        "Value" => "Wert",
        "Findings" => "Befunde",
        "{n} more findings of this severity not shown." => {
            "{n} weitere Befunde dieses Schweregrads nicht dargestellt."
        }
        "Operations" => "Vorgänge",
        "Operation" => "Operation",
        "Duration" => "Dauer",
        "{n} more operations not shown." => "{n} weitere Vorgänge nicht dargestellt.",
        "High confidence" => "Hohe Sicherheit",
        "Medium confidence" => "Mittlere Sicherheit",
        "Low confidence" => "Geringe Sicherheit",
        "Estimate" => "Schätzung",
        "Categories" => "Kategorien",
        "Observation" => "Beobachtung",
        "Fact" => "Merkmal",
        "Impact" => "Auswirkung",
        "Hypotheses (not verified)" => "Hypothesen (nicht überprüft)",
        "Recommendations" => "Empfehlungen",
        "Next steps" => "Nächste Schritte",
        "Threshold" => "Schwelle",
        "Affected sessions" => "Betroffene Sessions",
        "Selected sessions" => "Ausgewählte Sessions",
        "Visible sessions" => "Sichtbare Sessions",
        "Process: {list}" => "Prozess: {list}",
        "Host: {list}" => "Host: {list}",
        // Comparison
        "Comparison with baseline" => "Vergleich mit der Baseline",
        "Severity" => "Schweregrad",
        "Before" => "Vorher",
        "After" => "Nachher",
        "Change" => "Änderung",
        "Trend" => "Tendenz",
        "better" => "besser",
        "worse" => "schlechter",
        "unchanged" => "unverändert",
        "New findings" => "Neue Befunde",
        "Resolved findings" => "Behobene Befunde",
        "Changed severity" => "Geänderter Schweregrad",
        "None" => "Keine",
        "{n} finding unchanged." => "{n} Befund unverändert.",
        "{n} findings unchanged." => "{n} Befunde unverändert.",
        // Quality gate
        "Quality gate: passed ✅" => "Qualitätsschranke: bestanden ✅",
        "Quality gate: FAILED ❌" => "Qualitätsschranke: NICHT bestanden ❌",
        "Findings do not fail the gate." => "Befunde lassen die Schranke nicht scheitern.",
        "{n} finding at {severity} or above." => "{n} Befund ab Schweregrad {severity}.",
        "{n} findings at {severity} or above." => "{n} Befunde ab Schweregrad {severity}.",
        "No findings at {severity} or above." => "Keine Befunde ab Schweregrad {severity}.",
        "{n} new or worsened finding at {severity} or above." => {
            "{n} neuer oder verschlechterter Befund ab Schweregrad {severity}."
        }
        "{n} new or worsened findings at {severity} or above." => {
            "{n} neue oder verschlechterte Befunde ab Schweregrad {severity}."
        }
        "No new or worsened findings at {severity} or above." => {
            "Keine neuen oder verschlechterten Befunde ab Schweregrad {severity}."
        }
        "{n} finding ignored by the configuration." => "{n} Befund per Konfiguration ignoriert.",
        "{n} findings ignored by the configuration." => "{n} Befunde per Konfiguration ignoriert.",
        "Budget {key}: {reason}" => "Budget {key}: {reason}",
        "metric not in report" => "Kennzahl nicht im Bericht",
        "metric is not numeric" => "Kennzahl ist nicht numerisch",
        "needs --baseline" => "benötigt --baseline",
        "metric not in baseline" => "Kennzahl nicht in der Baseline",
        "baseline" => "Baseline",
        "Budget" => "Budget",
        "Limit" => "Grenze",
        "Baseline" => "Baseline",
        "Result" => "Ergebnis",
        _ => en,
    }
}

/// Translate and fill `{name}` placeholders.
pub(crate) fn tv(lang: Lang, en: &'static str, vars: &[(&str, &str)]) -> String {
    let src = t(lang, en);
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let var = tail[1..].find('}').and_then(|j| {
            vars.iter()
                .find(|(k, _)| *k == &tail[1..=j])
                .map(|(_, v)| (j, v))
        });
        match var {
            Some((j, v)) => {
                out.push_str(v);
                rest = &tail[j + 2..];
            }
            None => {
                out.push('{');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Singular or plural form by count.
pub(crate) fn plural(lang: Lang, n: usize, one: &'static str, many: &'static str) -> String {
    tv(
        lang,
        if n == 1 { one } else { many },
        &[("n", &n.to_string())],
    )
}
