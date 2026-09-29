import { api } from "../api";
import { actions } from "../actions";
import { set, useStore } from "../store";
import { patchSettings } from "../settingsActions";
import { showContextMenu } from "./ContextMenu";

function Btn({ icon, label, onClick, active, title, disabled, menu }: { icon: string; label?: string; onClick?: (e: React.MouseEvent) => void; active?: boolean; title?: string; disabled?: boolean; menu?: boolean }) {
  return (
    <button className={`tb-btn ${active ? "active" : ""}`} onClick={onClick} title={title ?? label} disabled={disabled}>
      <span className="tb-icon">{icon}</span>
      {label && <span className="tb-label">{label}</span>}
      {menu && <span className="tb-caret">▾</span>}
    </button>
  );
}

export function Toolbar() {
  const capturing = useStore((s) => s.status?.engine.capturing ?? false);
  const settings = useStore((s) => s.settings);
  const paused = useStore((s) => s.status?.engine.paused ?? 0);
  const keep = settings?.keepSessions ?? 0;

  return (
    <div className="toolbar">
      <Btn icon={capturing ? "●" : "○"} label={capturing ? "Capturing" : "Capture"} active={capturing} title="Capture Traffic (F12)" onClick={() => actions.toggleCapture()} />
      <div className="tb-sep" />
      <Btn
        icon="↻"
        label="Replay"
        menu
        title="Replay (R)"
        onClick={(e) =>
          showContextMenu(e.clientX, e.clientY + 8, [
            { label: "Replay Requests", shortcut: "R", action: () => import("../replay").then((m) => m.replaySelected({})) },
            { label: "Replay Unconditionally", shortcut: "U", action: () => import("../replay").then((m) => m.replaySelected({ unconditional: true })) },
            { label: "Replay and Edit", action: () => import("../replay").then((m) => m.replaySelected({ breakpoint: true })) },
            { label: "Replay from Composer", action: () => import("../replay").then((m) => m.toComposer()) },
          ])
        }
      />
      <Btn
        icon="✕"
        label="Remove"
        menu
        title="Remove sessions"
        onClick={(e) =>
          showContextMenu(e.clientX, e.clientY + 8, [
            { label: "Remove all", shortcut: "Ctrl+X", action: () => actions.removeAll() },
            { label: "Images", action: () => api.removeWhere("type ~ image") },
            { label: "CONNECTs", action: () => api.removeWhere("kind == tunnel") },
            { label: "Non-200s", action: () => api.removeWhere("status != 200") },
            { label: "Complete & Unmarked", action: () => api.removeWhere("color == '' and not kind == tunnel") },
            { separator: true },
            { label: "Selected", shortcut: "Del", action: () => actions.removeSelected() },
            { label: "Unselected", shortcut: "Shift+Del", action: () => actions.removeUnselected() },
          ])
        }
      />
      <Btn icon="▶" label="Resume" disabled={!paused} title="Resume all paused sessions (G)" onClick={() => import("../breakpoints").then((m) => m.goAll())} />
      <div className="tb-sep" />
      <Btn icon="⇶" label="Stream" active={settings?.stream ?? true} title="Stream responses to the client instead of buffering" onClick={() => patchSettings((s) => (s.stream = !s.stream))} />
      <Btn icon="⧉" label="Decode" active={settings?.decode ?? true} title="Show bodies decoded (gzip/br/zstd/deflate)" onClick={() => patchSettings((s) => (s.decode = !s.decode))} />
      <div className="tb-keep">
        <span>Keep</span>
        <select value={keep} onChange={(e) => patchSettings((s) => (s.keepSessions = Number(e.target.value)))}>
          <option value={0}>All sessions</option>
          <option value={100}>100 sessions</option>
          <option value={200}>200 sessions</option>
          <option value={500}>500 sessions</option>
          <option value={1000}>1000 sessions</option>
          <option value={10000}>10000 sessions</option>
        </select>
      </div>
      <Btn icon="⊕" label="Process Filter" title="Filter by process (drag onto a window – coming later; use Filters tab)" onClick={() => actions.showTab("filters")} />
      <div className="tb-sep" />
      <Btn icon="🔍︎" label="Find" title="Find Sessions (⌘F)" onClick={() => set({ dialog: { kind: "find" } })} />
      <Btn icon="💾︎" label="Save" title="Save all sessions (⌘S)" onClick={() => actions.menu("file.save-all")} />
      <Btn icon="✎" label="Comment" onClick={() => actions.comment()} title="Comment (M)" />
      <Btn icon="✦" label="Text Tools" title="Text Tools (⌘E)" onClick={() => set({ dialog: { kind: "textwizard" } })} />
      <div className="tb-spacer" />
      <Btn icon="⚙︎" title="Settings" onClick={() => set({ dialog: { kind: "options" } })} />
    </div>
  );
}
