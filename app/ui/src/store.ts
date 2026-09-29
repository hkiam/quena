import { create } from "zustand";
import type { FilterSettings, JobInfo, LogEntry, SessionId, Settings, Sort, Status } from "./api";

export type RightTab = "statistics" | "inspectors" | "autoresponder" | "composer" | "filters" | "log" | "timeline";

export type ColumnKey =
  | "id"
  | "result"
  | "protocol"
  | "host"
  | "url"
  | "body"
  | "caching"
  | "contentType"
  | "process"
  | "comments"
  | "custom"
  | "method"
  | "duration"
  | "started";

export interface ColumnConf {
  key: ColumnKey;
  title: string;
  width: number;
  visible: boolean;
  align?: "left" | "right";
}

/** Column titles come from the key (not the saved layout), so renames apply everywhere. */
export const COLUMN_TITLES: Record<ColumnKey, string> = {
  id: "#",
  result: "Status",
  protocol: "Protocol",
  host: "Host",
  url: "Path",
  body: "Size",
  caching: "Caching",
  contentType: "Type",
  process: "Process",
  comments: "Comments",
  custom: "Custom",
  method: "Method",
  duration: "Duration",
  started: "Started",
};

const col = (key: ColumnKey, width: number, visible: boolean, align?: "left" | "right"): ColumnConf => ({
  key,
  title: COLUMN_TITLES[key],
  width,
  visible,
  ...(align ? { align } : {}),
});

/** Quena's default columns: what, where, outcome, size, time. */
export const DEFAULT_COLUMNS: ColumnConf[] = [
  col("id", 56, true, "left"),
  col("method", 64, true),
  col("result", 56, true, "right"),
  col("host", 160, true),
  col("url", 250, true),
  col("contentType", 120, true),
  col("body", 76, true, "right"),
  col("duration", 76, true, "right"),
  col("process", 90, true),
  col("protocol", 70, false),
  col("comments", 120, false),
  col("custom", 90, false),
  col("caching", 90, false),
  col("started", 90, false),
];

/** Classic: a dense list with more columns, for long-time proxy users. */
export const CLASSIC_COLUMNS: ColumnConf[] = [
  col("id", 74, true, "left"),
  col("result", 52, true, "right"),
  col("protocol", 62, true),
  col("host", 170, true),
  col("url", 300, true),
  col("body", 80, true, "right"),
  col("caching", 90, true),
  col("contentType", 130, true),
  col("process", 90, true),
  col("comments", 120, true),
  col("custom", 80, true),
  col("method", 60, false),
  col("duration", 70, false, "right"),
  col("started", 90, false),
];

export type LayoutPreset = "quena" | "classic";

export interface Layout {
  leftWidth: number; // fraction of window width
  inspectorSplit: number; // fraction of inspector height for the request
  stacked: boolean; // request/response left/right (false) or top/bottom (true = stacked)
  columns: ColumnConf[];
  requestTab: string;
  responseTab: string;
  /** Arrangement preset the layout started from. */
  preset: LayoutPreset;
  /** The user picked a preset (first-run choice done). */
  presetChosen: boolean;
}

type PresetParts = Pick<Layout, "leftWidth" | "inspectorSplit" | "stacked" | "columns">;

export const PRESETS: Record<LayoutPreset, PresetParts> = {
  // List left, request and response side by side.
  quena: { leftWidth: 0.42, inspectorSplit: 0.5, stacked: false, columns: DEFAULT_COLUMNS },
  // Dense list, request above response.
  classic: { leftWidth: 0.52, inspectorSplit: 0.42, stacked: true, columns: CLASSIC_COLUMNS },
};

export const DEFAULT_LAYOUT: Layout = {
  ...PRESETS.quena,
  requestTab: "headers",
  responseTab: "headers",
  preset: "quena",
  presetChosen: false,
};

/** Merge a saved layout (possibly from an older version) with the current defaults. */
export function restoreLayout(saved: Partial<Layout> | undefined): Layout {
  if (!saved) return { ...DEFAULT_LAYOUT, columns: [...DEFAULT_COLUMNS] };
  // Layouts saved before presets existed: stacked inspectors meant the classic arrangement.
  const preset: LayoutPreset = saved.preset ?? (saved.stacked === false ? "quena" : "classic");
  const base = PRESETS[preset];
  const layout: Layout = { ...DEFAULT_LAYOUT, ...base, ...saved, preset, presetChosen: saved.presetChosen ?? false };
  // Titles from the key; columns added in newer versions are appended (hidden if unknown to the preset).
  const known = new Set(layout.columns.map((c) => c.key));
  layout.columns = [...layout.columns, ...base.columns.filter((c) => !known.has(c.key))]
    .filter((c) => c.key in COLUMN_TITLES)
    .map((c) => ({ ...c, title: COLUMN_TITLES[c.key] }));
  return layout;
}

export interface Message {
  text: string;
  kind: "info" | "error";
  at: number;
}

export type Dialog =
  | { kind: "comment"; ids: SessionId[]; initial: string }
  | { kind: "help"; topic: "quickexec" | "shortcuts" }
  | { kind: "options" }
  | { kind: "recover" }
  | { kind: "find" }
  | { kind: "jobs" }
  | { kind: "about" }
  | { kind: "text"; title: string; text: string }
  | { kind: "connect-device" }
  | { kind: "textwizard"; text?: string }
  | { kind: "https" }
  | { kind: "plugins" }
  | { kind: "rules" }
  | { kind: "choose-layout" }
  | { kind: "compare"; a: string; b: string; titleA: string; titleB: string }
  | { kind: "prompt"; title: string; label: string; initial: string; resolve: (v: string | null) => void };

export interface AppState {
  status: Status | null;
  listVersion: number;
  listTotal: number;
  listCount: number;
  sort: Sort;
  selection: Set<SessionId>;
  focusIndex: number | null;
  focusId: SessionId | null;
  anchorIndex: number | null;
  activeTab: RightTab;
  jobs: JobInfo[];
  log: LogEntry[];
  message: Message | null;
  filters: FilterSettings | null;
  settings: Settings | null;
  layout: Layout;
  overlay: boolean;
  dialog: Dialog | null;
  /** Bumped to force the grid to refetch rows (e.g. after marking). */
  gridNonce: number;
  /** Request to load a session into the Composer. */
  composerLoad: { id: SessionId; nonce: number } | null;
  /** Bumped when AutoResponder rules change outside the panel. */
  arNonce: number;
  /** Menu commands the active rules script registered (Quena.registerMenu). */
  scriptMenus: string[];
}

export const useStore = create<AppState>(() => ({
  status: null,
  listVersion: 0,
  listTotal: 0,
  listCount: 0,
  sort: { column: "id", descending: false },
  selection: new Set(),
  focusIndex: null,
  focusId: null,
  anchorIndex: null,
  activeTab: "inspectors",
  jobs: [],
  log: [],
  message: null,
  filters: null,
  settings: null,
  layout: DEFAULT_LAYOUT,
  overlay: false,
  dialog: null,
  gridNonce: 0,
  composerLoad: null,
  arNonce: 0,
  scriptMenus: [],
}));

export const set = useStore.setState;
export const get = useStore.getState;

export function say(text: string, kind: "info" | "error" = "info") {
  set({ message: { text, kind, at: Date.now() } });
}

export function selectedIds(): SessionId[] {
  return [...get().selection];
}

let prefsTimer: number | undefined;
export function saveLayoutSoon(save: (layout: Layout) => void) {
  window.clearTimeout(prefsTimer);
  prefsTimer = window.setTimeout(() => save(get().layout), 500);
}

/** In-app replacement for window.prompt (which blocks the web view). */
export function promptText(title: string, label: string, initial = ""): Promise<string | null> {
  return new Promise((resolve) => set({ dialog: { kind: "prompt", title, label, initial, resolve } }));
}
