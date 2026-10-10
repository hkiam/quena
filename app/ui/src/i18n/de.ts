// German translations: English UI text → German. Grouped by area of the UI.
//
// Terms (keep consistent): session → Session, request/response → Request/Response,
// header → Header, body → Body, capture → Aufzeichnung/aufzeichnen, Inspect → Inspektor,
// Mock Rules → Mock-Regeln, breakpoint → Haltepunkt, filter → Filter, settings → Einstellungen,
// command field → Befehlsfeld, command palette → Befehlspalette, Text Tools → Text-Werkzeuge,
// Timeline → Zeitachse, Structure → Struktur, Statistics → Statistik, Log → Protokoll,
// plugin → Plugin, proxy → Proxy, certificate → Zertifikat, host → Host, path → Pfad.
// Agents: conversation → Konversation, turn → Turn, side call → Nebenaufruf, tool call →
// Tool-Aufruf, agent cache → Agent-Cache, prompt cache → Prompt-Cache, input/output →
// Input/Output, cache miss → Cache verfehlt, cache mark (cache_control) → Cache-Marke.
// Style: neutral and short, no "Sie"/"du" where it can be avoided ("Sessions auswählen",
// "Datei wählen"); keep technical terms, shortcuts, commands and placeholders unchanged.
import { agents } from "./de/agents";
import { components } from "./de/components";
import { core } from "./de/core";
import { diagnostics } from "./de/diagnostics";
import { inspectors } from "./de/inspectors";
import { mocks } from "./de/mocks";
import { panels } from "./de/panels";
import { sanitize } from "./de/sanitize";

export const de: Record<string, string> = {
  ...core,
  ...components,
  ...inspectors,
  ...panels,
  ...diagnostics,
  ...mocks,
  ...sanitize,
  ...agents,
};
