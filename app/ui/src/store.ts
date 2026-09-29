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

export const DEFAULT_COLUMNS: ColumnConf[] = [
  { key: "id", title: "#", width: 74, visible: true, align: "left" },
  { key: "result", title: "Result", width: 52, visible: true, align: "right" },
  { key: "protocol", title: "Protocol", width: 62, visible: true },
  { key: "host", title: "Host", width: 170, visible: true },
  { key: "url", title: "URL", width: 300, visible: true },
  { key: "body", title: "Body", width: 80, visible: true, align: "right" },
  { key: "caching", title: "Caching", width: 90, visible: true },
  { key: "contentType", title: "Content-Type", width: 130, visible: true },
  { key: "process", title: "Process", width: 90, visible: true },
  { key: "comments", title: "Comments", width: 120, visible: true },
  { key: "custom", title: "Custom", width: 80, visible: true },
  { key: "method", title: "Method", width: 60, visible: false },
  { key: "duration", title: "Duration", width: 70, visible: false, align: "right" },
  { key: "started", title: "Started", width: 90, visible: false },
];

export interface Layout {
  leftWidth: number; // fraction of window width
  inspectorSplit: number; // fraction of inspector height for the request
  stacked: boolean; // request/response left/right (false) or top/bottom (true = stacked)
  columns: ColumnConf[];
  requestTab: string;
  responseTab: string;
}

export const DEFAULT_LAYOUT: Layout = {
  leftWidth: 0.52,
  inspectorSplit: 0.42,
  stacked: true,
  columns: DEFAULT_COLUMNS,
  requestTab: "headers",
  responseTab: "headers",
};

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
  /** Menu commands the active rules script registered (Piper.registerMenu). */
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
