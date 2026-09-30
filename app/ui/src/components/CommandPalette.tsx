// Command palette (Cmd/Ctrl+K): every menu command by name, plus running the typed text
// as a command-field command.
import { useEffect, useMemo, useRef, useState } from "react";
import { CornerDownLeft } from "lucide-react";
import { actions } from "../actions";
import { set, useStore } from "../store";
import { t } from "../i18n";
import { de } from "../i18n/de";

// The English names match as well when the UI is in another language.
const ENGLISH = new Map(Object.entries(de).map(([en, tr]) => [tr, en]));

interface Cmd {
  id: string;
  label: string;
  group: string;
  keys?: string;
}

const COMMANDS: Cmd[] = [
  { id: "file.capture", label: t("Start / stop capturing"), group: t("Capture"), keys: "F12" },
  { id: "rules.bp-before", label: t("Break before requests"), group: t("Capture"), keys: "F11" },
  { id: "rules.bp-after", label: t("Break after responses"), group: t("Capture"), keys: "Alt F11" },
  { id: "rules.bp-off", label: t("Breakpoints off"), group: t("Capture"), keys: "Shift F11" },
  { id: "tools.https", label: t("HTTPS settings"), group: t("Capture") },
  { id: "tools.connect-device", label: t("Connect a device"), group: t("Capture") },
  { id: "rules.auto-auth", label: t("Toggle automatic authentication"), group: t("Capture") },
  { id: "rules.customize", label: t("Edit rules script"), group: t("Capture") },
  { id: "file.load", label: t("Open archive"), group: t("File") },
  { id: "file.save-all", label: t("Save all sessions"), group: t("File") },
  { id: "file.save-selected", label: t("Save selected sessions"), group: t("File") },
  { id: "file.import-har", label: t("Import HAR"), group: t("File") },
  { id: "file.import-saz", label: t("Import SAZ archive"), group: t("File") },
  { id: "file.export-har", label: t("Export HAR"), group: t("File") },
  { id: "file.export-saz", label: t("Export SAZ archive"), group: t("File") },
  { id: "file.export-curl", label: t("Export as cURL script"), group: t("File") },
  { id: "file.recover", label: t("Recover previous capture"), group: t("File") },
  { id: "edit.copy-url", label: t("Copy URL"), group: t("Sessions") },
  { id: "edit.copy-curl", label: t("Copy as cURL"), group: t("Sessions") },
  { id: "edit.copy-fetch", label: t("Copy as fetch (JavaScript)"), group: t("Sessions") },
  { id: "edit.copy-powershell", label: t("Copy as PowerShell"), group: t("Sessions") },
  { id: "edit.copy-python", label: t("Copy as Python requests"), group: t("Sessions") },
  { id: "edit.copy-full", label: t("Copy full session"), group: t("Sessions") },
  { id: "edit.comment", label: t("Comment"), group: t("Sessions"), keys: "M" },
  { id: "edit.remove-selected", label: t("Remove selected"), group: t("Sessions"), keys: "Del" },
  { id: "edit.remove-unselected", label: t("Remove unselected"), group: t("Sessions") },
  { id: "edit.remove-all", label: t("Remove all"), group: t("Sessions") },
  { id: "edit.find", label: t("Find sessions"), group: t("Sessions") },
  { id: "rules.hide-connects", label: t("Hide tunnels (CONNECT)"), group: t("List") },
  { id: "rules.hide-images", label: t("Hide image requests"), group: t("List") },
  { id: "rules.hide-304", label: t("Hide 304s"), group: t("List") },
  { id: "view.inspectors", label: t("Show Inspect"), group: t("View"), keys: "F8" },
  { id: "view.composer", label: t("Show Composer"), group: t("View"), keys: "F9" },
  { id: "view.autoresponder", label: t("Show Mock Rules"), group: t("View") },
  { id: "view.filters", label: t("Show Filters"), group: t("View") },
  { id: "view.timeline", label: t("Show Timeline"), group: t("View") },
  { id: "view.structure", label: t("Show Structure (hosts and paths)"), group: t("View") },
  { id: "view.diagnostics", label: t("Show Diagnostics (analyze performance and errors)"), group: t("View") },
  { id: "view.statistics", label: t("Show Statistics"), group: t("View"), keys: "F7" },
  { id: "view.log", label: t("Show Log"), group: t("View") },
  { id: "view.stacked", label: t("Request above response"), group: t("View") },
  { id: "view.wide", label: t("Request beside response"), group: t("View") },
  { id: "view.reset-columns", label: t("Reset columns"), group: t("View") },
  { id: "view.jobs", label: t("Background jobs"), group: t("View") },
  { id: "tools.textwizard", label: t("Text tools"), group: t("Tools") },
  { id: "tools.plugins", label: t("Plugins"), group: t("Tools") },
  { id: "tools.options", label: t("Settings"), group: t("Tools") },
  { id: "help.quickexec", label: t("Command syntax"), group: t("Help") },
  { id: "help.shortcuts", label: t("Keyboard shortcuts"), group: t("Help") },
  { id: "help.coming-from", label: t("Coming from Fiddler Classic"), group: t("Help") },
];

/** Subsequence match; lower is better, -1 = no match. */
function score(label: string, q: string): number {
  const l = label.toLowerCase();
  const direct = l.indexOf(q);
  if (direct >= 0) return direct;
  let pos = -1;
  let gaps = 0;
  for (const ch of q) {
    const next = l.indexOf(ch, pos + 1);
    if (next < 0) return -1;
    gaps += next - pos - 1;
    pos = next;
  }
  return 100 + gaps;
}

export function CommandPalette() {
  const scriptMenus = useStore((s) => s.scriptMenus);
  const [q, setQ] = useState("");
  const [cur, setCur] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);
  const all = useMemo<Cmd[]>(
    () => [...COMMANDS, ...scriptMenus.map((label, i) => ({ id: `script:${i}`, label, group: t("Script") }))],
    [scriptMenus],
  );
  const needle = q.trim().toLowerCase();
  const items = useMemo(() => {
    const hits = needle
      ? all
          .map((c) => ({ c, s: score(`${c.label} ${c.group} ${ENGLISH.get(c.label) ?? ""}`, needle) }))
          .filter((x) => x.s >= 0)
          .sort((a, b) => a.s - b.s)
          .map((x) => x.c)
      : all;
    return needle ? [...hits, { id: "run", label: t("Run “{text}” as command", { text: q.trim() }), group: t("Command") }] : hits;
  }, [all, needle, q]);
  useEffect(() => setCur(0), [needle]);
  useEffect(() => {
    listRef.current?.querySelector(".pal-item.cur")?.scrollIntoView({ block: "nearest" });
  }, [cur]);

  const run = (c: Cmd | undefined) => {
    if (!c) return;
    set({ dialog: null });
    if (c.id === "run") void actions.quickexec(q.trim());
    else if (c.id.startsWith("script:")) void actions.runScriptMenu(Number(c.id.slice(7)));
    else void actions.menu(c.id);
  };

  return (
    <div className="modal-back pal-back" onMouseDown={() => set({ dialog: null })}>
      <div className="palette" onMouseDown={(e) => e.stopPropagation()}>
        <input
          autoFocus
          className="pal-input"
          placeholder={t("Type a command, or a filter like =404 or @host")}
          value={q}
          spellCheck={false}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") setCur((c) => Math.min(items.length - 1, c + 1));
            else if (e.key === "ArrowUp") setCur((c) => Math.max(0, c - 1));
            else if (e.key === "Enter") run(items[cur]);
            else return;
            e.preventDefault();
          }}
        />
        <div className="pal-list" ref={listRef}>
          {items.map((c, i) => (
            <div key={c.id} className={`pal-item ${i === cur ? "cur" : ""}`} onMouseEnter={() => setCur(i)} onClick={() => run(c)}>
              <span className="pal-group">{c.group}</span>
              <span className="pal-label">{c.label}</span>
              {c.keys && <kbd>{c.keys}</kbd>}
              {i === cur && <CornerDownLeft size={13} className="pal-enter" />}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
