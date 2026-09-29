import type { LucideIcon } from "lucide-react";
import { AppWindow, ChevronDown, FileArchive, History, MessageSquareText, Play, RotateCw, Save, Search, Settings, Trash2, Waves, WandSparkles } from "lucide-react";
import { api } from "../api";
import { actions } from "../actions";
import { set, useStore } from "../store";
import { patchSettings } from "../settingsActions";
import { showContextMenu } from "./ContextMenu";
import { CommandField } from "./CommandField";

function Btn({ icon: Icon, label, onClick, active, title, disabled, menu }: { icon: LucideIcon; label?: string; onClick?: (e: React.MouseEvent) => void; active?: boolean; title?: string; disabled?: boolean; menu?: boolean }) {
  return (
    <button className={`tb-btn ${active ? "active" : ""} ${label ? "" : "icon-only"}`} onClick={onClick} title={title ?? label} disabled={disabled}>
      <Icon size={15} strokeWidth={1.8} className="tb-icon" />
      {label && <span className="tb-label">{label}</span>}
      {menu && <ChevronDown size={11} className="tb-caret" />}
    </button>
  );
}

/** The capture switch: a labelled toggle, the most important control in the window. */
function CaptureSwitch() {
  const capturing = useStore((s) => s.status?.engine.capturing ?? false);
  return (
    <button className={`capture-switch ${capturing ? "on" : ""}`} title="Capture traffic (F12)" onClick={() => actions.toggleCapture()}>
      <span className="cs-track">
        <span className="cs-knob" />
      </span>
      <span className="cs-label">{capturing ? "Capturing" : "Paused"}</span>
    </button>
  );
}

export function Toolbar() {
  const settings = useStore((s) => s.settings);
  const paused = useStore((s) => s.status?.engine.paused ?? 0);
  const keep = settings?.keepSessions ?? 0;

  return (
    <div className="toolbar">
      <CaptureSwitch />
      <div className="tb-group">
        <Btn
          icon={RotateCw}
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
          icon={Trash2}
          menu
          title="Remove sessions"
          onClick={(e) =>
            showContextMenu(e.clientX, e.clientY + 8, [
              { label: "Remove all", shortcut: "Ctrl+X", action: () => actions.removeAll() },
              { label: "Images", action: () => api.removeWhere("type ~ image") },
              { label: "Tunnels (CONNECT)", action: () => api.removeWhere("kind == tunnel") },
              { label: "Non-200s", action: () => api.removeWhere("status != 200") },
              { label: "Complete & Unmarked", action: () => api.removeWhere("color == '' and not kind == tunnel") },
              { separator: true },
              { label: "Selected", shortcut: "Del", action: () => actions.removeSelected() },
              { label: "Unselected", shortcut: "Shift+Del", action: () => actions.removeUnselected() },
            ])
          }
        />
        <Btn icon={Play} label={paused ? `Resume ${paused}` : undefined} active={!!paused} disabled={!paused} title="Resume all paused sessions (G)" onClick={() => import("../breakpoints").then((m) => m.goAll())} />
      </div>
      <div className="tb-group">
        <Btn icon={Waves} active={settings?.stream ?? true} title="Stream responses to the client instead of buffering them" onClick={() => patchSettings((s) => (s.stream = !s.stream))} />
        <Btn icon={FileArchive} active={settings?.decode ?? true} title="Show bodies decoded (gzip/br/zstd/deflate)" onClick={() => patchSettings((s) => (s.decode = !s.decode))} />
        <Btn
          icon={History}
          menu
          title={keep ? `Keep the newest ${keep} sessions` : "Keep all sessions"}
          active={keep > 0}
          onClick={(e) =>
            showContextMenu(
              e.clientX,
              e.clientY + 8,
              [0, 100, 200, 500, 1000, 10000].map((n) => ({
                label: n ? `Keep newest ${n}` : "Keep all sessions",
                checked: keep === n,
                action: () => patchSettings((s) => (s.keepSessions = n)),
              })),
            )
          }
        />
        <Btn icon={AppWindow} title="Filter by process (Filters tab)" onClick={() => actions.showTab("filters")} />
      </div>
      <CommandField />
      <div className="tb-group">
        <Btn icon={Search} title="Find sessions (⌘F)" onClick={() => set({ dialog: { kind: "find" } })} />
        <Btn icon={Save} title="Save all sessions (⌘S)" onClick={() => actions.menu("file.save-all")} />
        <Btn icon={MessageSquareText} onClick={() => actions.comment()} title="Comment (M)" />
        <Btn icon={WandSparkles} title="Text tools (⌘E)" onClick={() => set({ dialog: { kind: "textwizard" } })} />
      </div>
      <Btn icon={Settings} title="Settings" onClick={() => set({ dialog: { kind: "options" } })} />
    </div>
  );
}
