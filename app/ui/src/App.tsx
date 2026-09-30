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
import { installFileDrop } from "./lib/dropImport";
import { t } from "./i18n";

async function importOpenFiles() {
  for (const path of await api.takeOpenFiles()) {
    try {
      await api.importArchive(path);
      say(t("Loading {path}", { path }));
    } catch (e) {
      say(String(e), "error");
    }
  }
}

function useBoot() {
  useEffect(() => {
    // Lets end-to-end tests run menu commands (the native menu is outside the web view).
    (window as unknown as { __quena?: object }).__quena = {
      menu: (id: string) => actions.menu(id),
      setLayout: (patch: Partial<Layout>) => set((s) => ({ layout: { ...s.layout, ...patch } })),
      // Load an archive by path (on Windows the WebDriver cannot pass command-line arguments).
      load: (path: string) => api.importArchive(path),
    };
    if (!isTauri) return;
    const unlisten: Promise<() => void>[] = [];
    unlisten.push(
      on<{ version: number; total: number; count: number }>("list", (e) =>
        set({ listVersion: e.version, listTotal: e.total, listCount: e.count }),
      ),
    );
    unlisten.push(
      on<Status>("status", (s) => {
        // Capture started on its background thread after launch.
        set(get().captureBusy === "starting" && s.engine.capturing ? { status: s, captureBusy: null } : { status: s });
      }),
    );
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
      const status = await api.status();
      set({ settings, layout, filters: await api.getFilters(), status, log: await api.logSince(0) });
      // Capture starts in the background after launch: show that instead of "Paused".
      if (settings.proxy.captureOnStartup && !status.engine.capturing) {
        set({ captureBusy: "starting" });
        window.setTimeout(() => get().captureBusy === "starting" && set({ captureBusy: null }), 15000);
      }
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
    const uninstallDrop = installFileDrop();
    return () => {
      unlisten.forEach((p) => p.then((u) => u()));
      uninstall();
      uninstallDrop();
    };
  }, []);
}

/** `min` = smallest size in px of the areas before and after the splitter, so dragging can
 * never squeeze one of them into something unusable. */
function Splitter({ onDrag, vertical, min = [120, 120] }: { onDrag: (fraction: number) => void; vertical?: boolean; min?: [number, number] }) {
  const ref = useRef<HTMLDivElement>(null);
  const down = (e: React.PointerEvent) => {
    e.preventDefault();
    const parent = ref.current!.parentElement!;
    const rect = parent.getBoundingClientRect();
    const move = (ev: PointerEvent) => {
      const size = vertical ? rect.height : rect.width;
      const f = vertical ? (ev.clientY - rect.top) / size : (ev.clientX - rect.left) / size;
      const lo = Math.min(0.5, min[0] / size);
      const hi = Math.max(0.5, 1 - min[1] / size);
      onDrag(Math.min(hi, Math.max(lo, f)));
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

/** Apply the chosen theme to the document (CSS tokens switch on `data-theme`). */
function useTheme() {
  const theme = useStore((s) => s.layout.theme ?? "system");
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") delete root.dataset.theme;
    else root.dataset.theme = theme;
    // Title bar and native controls follow as well.
    if (isTauri) import("@tauri-apps/api/window").then((w) => w.getCurrentWindow().setTheme(theme === "system" ? null : theme)).catch(() => {});
  }, [theme]);
}

export function App() {
  useBoot();
  useTheme();
  const leftWidth = useStore((s) => s.layout.leftWidth);
  const overlay = useStore((s) => s.overlay);
  if (!isTauri) {
    return <div className="not-tauri">{t("Quena UI must run inside the Quena app ({command}).", { command: "npm exec --prefix app/ui -- tauri dev" })}</div>;
  }
  return (
    <div className="app">
      <Toolbar />
      <div className="main" style={{ gridTemplateColumns: `minmax(280px, ${leftWidth * 100}%) 8px minmax(380px, 1fr)` }}>
        <div className="left">
          <SessionGrid />
        </div>
        <Splitter min={[320, 420]} onDrag={(f) => set((s) => ({ layout: { ...s.layout, leftWidth: f } }))} />
        <RightPane />
      </div>
      <StatusBar />
      <ContextMenuHost />
      <Dialogs />
      {overlay && <PerfOverlay />}
    </div>
  );
}
