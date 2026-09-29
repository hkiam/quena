import { useEffect, useRef } from "react";
import { api, isTauri, on, type JobInfo, type LogEntry, type Status } from "./api";
import { actions } from "./actions";
import { ContextMenuHost } from "./components/ContextMenu";
import { Dialogs } from "./components/Dialogs";
import { PerfOverlay } from "./components/PerfOverlay";
import { StatusBar } from "./components/StatusBar";
import { Toolbar } from "./components/Toolbar";
import { SessionGrid } from "./grid/SessionGrid";
import { RightPane } from "./panels/RightPane";
import { get, restoreLayout, say, set, useStore, type Layout } from "./store";
import { installGlobalKeys } from "./keys";

async function importOpenFiles() {
  for (const path of await api.takeOpenFiles()) {
    try {
      await api.importArchive(path);
      say(`Loading ${path}`);
    } catch (e) {
      say(String(e), "error");
    }
  }
}

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
    // Archives opened from the file manager / "Open With" while running.
    unlisten.push(on("open-files", () => void importOpenFiles()));
    unlisten.push(
      on<{ id: number; phase: string; url: string }>("breakpoint", (b) => {
        // Jump to the paused session.
        actions.selectIds([b.id]);
        actions.showTab("inspectors");
      }),
    );
    (async () => {
      const settings = await api.settingsGet();
      const ui = (settings.ui ?? {}) as { layout?: Partial<Layout> };
      const layout = restoreLayout(ui.layout);
      set({ settings, layout, filters: await api.getFilters(), status: await api.status(), log: await api.logSince(0) });
      // Load any script-registered menu commands (if scripting was left enabled).
      void actions.refreshScriptMenus();
      let recovering = false;
      if (settings.offerRecovery !== false) {
        const rec = await api.recoverable();
        if (rec.length) {
          set({ dialog: { kind: "recover" } });
          recovering = true;
        }
      }
      // First run: let the user pick the layout once (the recovery dialog wins; ask next time).
      if (!recovering && !layout.presetChosen) set({ dialog: { kind: "choose-layout" } });
      const w = await api.rows(0, 0);
      set({ listVersion: w.version, listTotal: w.total });
      // Archives Quena was started with (double-click, command line).
      void importOpenFiles();
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
    return <div className="not-tauri">Quena UI must run inside the Quena app (npm exec --prefix app/ui -- tauri dev).</div>;
  }
  return (
    <div className="app">
      <Toolbar />
      <div className="main" style={{ gridTemplateColumns: `${leftWidth * 100}% 8px 1fr` }}>
        <div className="left">
          <SessionGrid />
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
