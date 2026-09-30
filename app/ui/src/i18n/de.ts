// German translations: English UI text → German. Grouped by area of the UI.
//
// Terms (keep consistent): session → Session, request/response → Request/Response,
// header → Header, body → Body, capture → Aufzeichnung/aufzeichnen, Inspect → Inspektor,
// Mock Rules → Mock-Regeln, breakpoint → Haltepunkt, filter → Filter, settings → Einstellungen,
// command field → Befehlsfeld, command palette → Befehlspalette, Text Tools → Text-Werkzeuge,
// Timeline → Zeitachse, Structure → Struktur, Statistics → Statistik, Log → Protokoll,
// plugin → Plugin, proxy → Proxy, certificate → Zertifikat, host → Host, path → Pfad.
// Style: neutral and short, no "Sie"/"du" where it can be avoided ("Sessions auswählen",
// "Datei wählen"); keep technical terms, shortcuts, commands and placeholders unchanged.
import { components } from "./de/components";
import { core } from "./de/core";
import { inspectors } from "./de/inspectors";
import { panels } from "./de/panels";

export const de: Record<string, string> = {
  ...core,
  ...components,
  ...inspectors,
  ...panels,
};
