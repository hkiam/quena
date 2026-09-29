// Command palette (Cmd/Ctrl+K): every menu command by name, plus running the typed text
// as a command-field command.
import { useEffect, useMemo, useRef, useState } from "react";
import { CornerDownLeft } from "lucide-react";
import { actions } from "../actions";
import { set, useStore } from "../store";

interface Cmd {
  id: string;
  label: string;
  group: string;
  keys?: string;
}

const COMMANDS: Cmd[] = [
  { id: "file.capture", label: "Start / stop capturing", group: "Capture", keys: "F12" },
  { id: "rules.bp-before", label: "Break before requests", group: "Capture", keys: "F11" },
  { id: "rules.bp-after", label: "Break after responses", group: "Capture", keys: "Alt F11" },
  { id: "rules.bp-off", label: "Breakpoints off", group: "Capture", keys: "Shift F11" },
  { id: "tools.https", label: "HTTPS settings", group: "Capture" },
  { id: "tools.connect-device", label: "Connect a device", group: "Capture" },
  { id: "rules.auto-auth", label: "Toggle automatic authentication", group: "Capture" },
  { id: "rules.customize", label: "Edit rules script", group: "Capture" },
  { id: "file.load", label: "Open archive", group: "File" },
  { id: "file.save-all", label: "Save all sessions", group: "File" },
  { id: "file.save-selected", label: "Save selected sessions", group: "File" },
  { id: "file.import-har", label: "Import HAR", group: "File" },
  { id: "file.import-saz", label: "Import SAZ archive", group: "File" },
  { id: "file.export-har", label: "Export HAR", group: "File" },
  { id: "file.export-saz", label: "Export SAZ archive", group: "File" },
  { id: "file.export-curl", label: "Export as cURL script", group: "File" },
  { id: "file.recover", label: "Recover previous capture", group: "File" },
  { id: "edit.copy-url", label: "Copy URL", group: "Sessions" },
  { id: "edit.copy-curl", label: "Copy as cURL", group: "Sessions" },
  { id: "edit.copy-full", label: "Copy full session", group: "Sessions" },
  { id: "edit.comment", label: "Comment", group: "Sessions", keys: "M" },
  { id: "edit.remove-selected", label: "Remove selected", group: "Sessions", keys: "Del" },
  { id: "edit.remove-unselected", label: "Remove unselected", group: "Sessions" },
  { id: "edit.remove-all", label: "Remove all", group: "Sessions" },
  { id: "edit.find", label: "Find sessions", group: "Sessions" },
  { id: "rules.hide-connects", label: "Hide tunnels (CONNECT)", group: "List" },
  { id: "rules.hide-images", label: "Hide image requests", group: "List" },
  { id: "rules.hide-304", label: "Hide 304s", group: "List" },
  { id: "view.inspectors", label: "Show Inspect", group: "View", keys: "F8" },
  { id: "view.composer", label: "Show Composer", group: "View", keys: "F9" },
  { id: "view.autoresponder", label: "Show Mock Rules", group: "View" },
  { id: "view.filters", label: "Show Filters", group: "View" },
  { id: "view.timeline", label: "Show Timeline", group: "View" },
  { id: "view.statistics", label: "Show Statistics", group: "View", keys: "F7" },
  { id: "view.log", label: "Show Log", group: "View" },
  { id: "view.stacked", label: "Request above response", group: "View" },
  { id: "view.wide", label: "Request beside response", group: "View" },
  { id: "view.reset-columns", label: "Reset columns", group: "View" },
  { id: "view.jobs", label: "Background jobs", group: "View" },
  { id: "tools.textwizard", label: "Text tools", group: "Tools" },
  { id: "tools.plugins", label: "Plugins", group: "Tools" },
  { id: "tools.options", label: "Settings", group: "Tools" },
  { id: "help.quickexec", label: "Command syntax", group: "Help" },
  { id: "help.shortcuts", label: "Keyboard shortcuts", group: "Help" },
  { id: "help.coming-from", label: "Coming from Fiddler Classic", group: "Help" },
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
    () => [...COMMANDS, ...scriptMenus.map((label, i) => ({ id: `script:${i}`, label, group: "Script" }))],
    [scriptMenus],
  );
  const needle = q.trim().toLowerCase();
  const items = useMemo(() => {
    const hits = needle
      ? all
          .map((c) => ({ c, s: score(`${c.label} ${c.group}`, needle) }))
          .filter((x) => x.s >= 0)
          .sort((a, b) => a.s - b.s)
          .map((x) => x.c)
      : all;
    return needle ? [...hits, { id: "run", label: `Run “${q.trim()}” as command`, group: "Command" }] : hits;
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
          placeholder="Type a command, or a filter like =404 or @host"
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
