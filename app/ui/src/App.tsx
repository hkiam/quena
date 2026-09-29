import { useEffect, useRef } from "react";
import { api, isTauri, on, type JobInfo, type LogEntry, type Status } from "./api";
import { actions } from "./actions";
import { ContextMenuHost } from "./components/ContextMenu";
import { Dialogs } from "./components/Dialogs";
import { PerfOverlay } from "./components/PerfOverlay";
import { QuickExec } from "./components/QuickExec";
import { StatusBar } from "./components/StatusBar";
import { Toolbar } from "./components/Toolbar";
import { SessionGrid } from "./grid/SessionGrid";
import { RightPane } from "./panels/RightPane";
import { DEFAULT_LAYOUT, get, set, useStore, type Layout } from "./store";
import { installGlobalKeys } from "./keys";

function useBoot() {
  useEffect(() => {
    if (!isTauri) return;
    const unlisten: Promise<() => void>[] = [];
    unlisten.push(
      on<{ version: number; total: number; count: number }>("list", (e) =>
        set({ listVersion: e.version, listTotal: e.total, listCount: e.count }),
      ),
    );
    unlisten.push(on<Status>("status", (s) => set({ status: s })));
    unlisten.push(on<JobInfo[]>("jobs", (j) => set({ jobs: j })));
    unlisten.push(
      on<LogEntry[]>("log", (entries) => {
        const log = [...get().log, ...entries];
        set({ log: log.length > 5000 ? log.slice(log.length - 5000) : log });
      }),
    );
    unlisten.push(on<string>("menu", (id) => actions.menu(id)));
    unlisten.push(
      on<{ id: number; phase: string; url: string }>("breakpoint", (b) => {
        // Fiddler behaviour: jump to the paused session.
        actions.selectIds([b.id]);
        actions.showTab("inspectors");
      }),
    );
    (async () => {
      const settings = await api.settingsGet();
      const ui = (settings.ui ?? {}) as { layout?: Partial<Layout> };
      const layout = { ...DEFAULT_LAYOUT, ...(ui.layout ?? {}) };
      // Columns added in newer versions are appended.
      const known = new Set(layout.columns.map((c) => c.key));
      layout.columns = [...layout.columns, ...DEFAULT_LAYOUT.columns.filter((c) => !known.has(c.key))];
      set({ settings, layout, filters: await api.getFilters(), status: await api.status(), log: await api.logSince(0) });
      // Load any script-registered menu commands (if scripting was left enabled).
      void actions.refreshScriptMenus();
      if (settings.offerRecovery !== false) {
        const rec = await api.recoverable();
        if (rec.length) set({ dialog: { kind: "recover" } });
      }
      const w = await api.rows(0, 0);
      set({ listVersion: w.version, listTotal: w.total });
    })();
    const uninstall = installGlobalKeys();
    return () => {
      unlisten.forEach((p) => p.then((u) => u()));
      uninstall();
    };
  }, []);
}

function Splitter({ onDrag, vertical }: { onDrag: (fraction: number) => void; vertical?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const down = (e: React.PointerEvent) => {
    e.preventDefault();
    const parent = ref.current!.parentElement!;
    const rect = parent.getBoundingClientRect();
    const move = (ev: PointerEvent) => {
      const f = vertical ? (ev.clientY - rect.top) / rect.height : (ev.clientX - rect.left) / rect.width;
      onDrag(Math.min(0.9, Math.max(0.1, f)));
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      actions.saveLayout();
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };
  return <div ref={ref} className={vertical ? "splitter-h" : "splitter-v"} onPointerDown={down} />;
}

export { Splitter };

export function App() {
  useBoot();
  const leftWidth = useStore((s) => s.layout.leftWidth);
  const overlay = useStore((s) => s.overlay);
  if (!isTauri) {
    return <div className="not-tauri">Piper UI must run inside the Piper app (npm run tauri dev).</div>;
  }
  return (
    <div className="app">
      <Toolbar />
      <div className="main" style={{ gridTemplateColumns: `${leftWidth * 100}% 5px 1fr` }}>
        <div className="left">
          <SessionGrid />
          <QuickExec />
        </div>
        <Splitter onDrag={(f) => set((s) => ({ layout: { ...s.layout, leftWidth: f } }))} />
        <RightPane />
      </div>
      <StatusBar />
      <ContextMenuHost />
      <Dialogs />
      {overlay && <PerfOverlay />}
    </div>
  );
}
