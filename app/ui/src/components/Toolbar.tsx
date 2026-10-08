import type { LucideIcon } from "lucide-react";
import { AppWindow, ChevronDown, Globe, PanelLeft, FileArchive, History, MessageSquareText, Play, RotateCw, Save, Search, Settings, Trash2, Waves, WandSparkles } from "lucide-react";
import { api } from "../api";
import { actions } from "../actions";
import { set, useStore } from "../store";
import { patchSettings } from "../settingsActions";
import { showContextMenu } from "./ContextMenu";
import { CommandField } from "./CommandField";
import { t } from "../i18n";

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
  const busy = useStore((s) => s.captureBusy);
  // While switching, show the state being switched to.
  const on = busy ? busy === "starting" : capturing;
  const label = busy === "starting" ? t("Starting…") : busy === "stopping" ? t("Stopping…") : capturing ? t("Capturing") : t("Paused");
  return (
    <button className={`capture-switch ${on ? "on" : ""} ${busy ? "busy" : ""}`} title={t("Capture traffic (F12)")} aria-busy={!!busy} onClick={() => actions.toggleCapture()}>
      <span className="cs-track">
        <span className="cs-knob" />
      </span>
      <span className="cs-label">{label}</span>
    </button>
  );
}

export function Toolbar() {
  const settings = useStore((s) => s.settings);
  const paused = useStore((s) => s.status?.engine.paused ?? 0);
  const keep = settings?.keepSessions ?? 0;
  const navOpen = useStore((s) => !!s.layout.navOpen);

  return (
    <div className="toolbar">
      <Btn icon={PanelLeft} active={navOpen} title={t("Navigator: narrow the list to a group or path")} onClick={() => actions.showNavigator(!navOpen)} />
      <CaptureSwitch />
      <Btn icon={Globe} menu title={t("Start a browser or terminal that uses Quena")} onClick={(e) => void import("./LaunchDialog").then((m) => m.launchMenu(e.clientX, e.clientY + 8))} />
      <div className="tb-group">
        <Btn
          icon={RotateCw}
          menu
          title={t("Replay (R)")}
          onClick={(e) =>
            showContextMenu(e.clientX, e.clientY + 8, [
              { label: t("Replay Requests"), shortcut: "R", action: () => import("../replay").then((m) => m.replaySelected({})) },
              { label: t("Replay Unconditionally"), shortcut: "U", action: () => import("../replay").then((m) => m.replaySelected({ unconditional: true })) },
              { label: t("Replay and Edit"), action: () => import("../replay").then((m) => m.replaySelected({ breakpoint: true })) },
              { label: t("Replay from Composer"), action: () => import("../replay").then((m) => m.toComposer()) },
            ])
          }
        />
        <Btn
          icon={Trash2}
          menu
          title={t("Remove sessions")}
          onClick={(e) =>
            showContextMenu(e.clientX, e.clientY + 8, [
              { label: t("Remove all"), shortcut: "Ctrl+X", action: () => actions.removeAll() },
              { label: t("Images"), action: () => api.removeWhere("type ~ image") },
              { label: t("Tunnels (CONNECT)"), action: () => api.removeWhere("kind == tunnel") },
              { label: t("Non-200s"), action: () => api.removeWhere("status != 200") },
              { label: t("Complete & Unmarked"), action: () => api.removeWhere("color == '' and not kind == tunnel") },
              { separator: true },
              { label: t("Selected"), shortcut: "Del", action: () => actions.removeSelected() },
              { label: t("Unselected"), shortcut: "Shift+Del", action: () => actions.removeUnselected() },
            ])
          }
        />
        <Btn icon={Play} label={paused ? t("Resume {n}", { n: paused }) : undefined} active={!!paused} disabled={!paused} title={t("Resume all paused sessions (G)")} onClick={() => import("../breakpoints").then((m) => m.goAll())} />
      </div>
      <div className="tb-group">
        <Btn icon={Waves} active={settings?.stream ?? true} title={t("Stream responses to the client instead of buffering them")} onClick={() => patchSettings((s) => (s.stream = !s.stream))} />
        <Btn icon={FileArchive} active={settings?.decode ?? true} title={t("Show bodies decoded (gzip/br/zstd/deflate)")} onClick={() => patchSettings((s) => (s.decode = !s.decode))} />
        <Btn
          icon={History}
          menu
          title={keep ? t("Keep the newest {n} sessions", { n: keep }) : t("Keep all sessions")}
          active={keep > 0}
          onClick={(e) =>
            showContextMenu(
              e.clientX,
              e.clientY + 8,
              [0, 100, 200, 500, 1000, 10000].map((n) => ({
                label: n ? t("Keep newest {n}", { n }) : t("Keep all sessions"),
                checked: keep === n,
                action: () => patchSettings((s) => (s.keepSessions = n)),
              })),
            )
          }
        />
        <Btn icon={AppWindow} title={t("Filter by process (Filters tab)")} onClick={() => actions.showTab("filters")} />
      </div>
      <CommandField />
      <div className="tb-group">
        <Btn icon={Search} title={t("Find sessions (⌘F)")} onClick={() => set({ dialog: { kind: "find" } })} />
        <Btn icon={Save} title={t("Save all sessions (⌘S)")} onClick={() => actions.menu("file.save-all")} />
        <Btn icon={MessageSquareText} onClick={() => actions.comment()} title={t("Comment (M)")} />
        <Btn icon={WandSparkles} title={t("Text tools (⌘E)")} onClick={() => set({ dialog: { kind: "textwizard" } })} />
      </div>
      <Btn icon={Settings} title={t("Settings")} onClick={() => set({ dialog: { kind: "options" } })} />
    </div>
  );
}
