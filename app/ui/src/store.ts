import { create } from "zustand";
import type { NetworkProfile } from "./lib/diagReport";
import type { FilterSettings, JobInfo, LogEntry, SanitizedExport, SessionId, Settings, Sort, Status } from "./api";
import { t } from "./i18n";

export type RightTab = "statistics" | "inspectors" | "autoresponder" | "composer" | "filters" | "log" | "timeline" | "structure" | "diagnostics";

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
  result: t("Status"),
  protocol: t("Protocol"),
  host: t("Host"),
  url: t("Path"),
  body: t("Size"),
  caching: t("Caching"),
  contentType: t("Type"),
  process: t("Process"),
  comments: t("Comments"),
  custom: t("Custom"),
  method: t("Method"),
  duration: t("Duration"),
  started: t("Started"),
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
  col("id", 44, true, "left"),
  col("method", 72, true),
  col("result", 54, true),
  col("host", 136, true),
  col("url", 176, true),
  col("contentType", 92, true),
  col("body", 62, true, "right"),
  col("duration", 62, true, "right"),
  col("process", 90, false),
  col("protocol", 70, false),
  col("comments", 120, false),
  col("custom", 90, false),
  col("caching", 90, false),
  col("started", 90, false),
];

/** Classic: a dense list with more columns, for long-time proxy users. */
export const CLASSIC_COLUMNS: ColumnConf[] = [
  col("id", 52, true, "left"),
  col("method", 72, true),
  col("result", 52, true),
  col("protocol", 58, true),
  col("host", 160, true),
  col("url", 280, true),
  col("contentType", 120, true),
  col("body", 80, true, "right"),
  col("duration", 64, true, "right"),
  col("caching", 90, true),
  col("process", 90, true),
  col("comments", 120, true),
  col("custom", 80, false),
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
  /** Colour theme: follow the OS, or force light/dark. */
  theme?: "system" | "light" | "dark";
  /** UI language: follow the OS, or English/German (switching reloads the UI). */
  language?: "system" | "en" | "de";
  /** Keep the chosen inspector view per request/response and kind of content. */
  rememberViews?: boolean;
  /** `request:json` → `syntaxview`, `response:soap` → `xml`, … */
  viewByType?: Record<string, string>;
  /** Arrangement preset the layout started from. */
  preset: LayoutPreset;
  /** The user picked a preset (first-run choice done). */
  presetChosen: boolean;
  /** Diagnostics panel: last analyzer, profile, scope and option overrides. */
  diag?: DiagPrefs;
  /** Timeline columns: order of the visible ones and their widths. */
  timeline?: import("./lib/timelineScale").TlLayout;
}

export interface DiagPrefs {
  analyzer?: string;
  profile?: string;
  scope?: "visible" | "selection";
  /** Narrow the analysis to these processes / target hosts (empty = all). */
  processes?: string[];
  hosts?: string[];
  /** Overrides of the analyzer's default options (merged with describe()). */
  options?: Partial<{ slowMs: number; ttfbMs: number; largeResponseBytes: number; operationGapMs: number; networks: NetworkProfile[] }>;
}

type PresetParts = Pick<Layout, "leftWidth" | "inspectorSplit" | "stacked" | "columns">;

export const PRESETS: Record<LayoutPreset, PresetParts> = {
  // List left, request and response side by side.
  quena: { leftWidth: 0.5, inspectorSplit: 0.5, stacked: false, columns: DEFAULT_COLUMNS },
  // Dense list, request above response.
  classic: { leftWidth: 0.52, inspectorSplit: 0.42, stacked: true, columns: CLASSIC_COLUMNS },
};

export const DEFAULT_LAYOUT: Layout = {
  ...PRESETS.quena,
  requestTab: "headers",
  responseTab: "headers",
  rememberViews: true,
  theme: "system",
  language: "system",
  viewByType: {},
  preset: "quena",
  presetChosen: false,
};

/** Merge a saved layout (possibly from an older version) with the current defaults. */
export function restoreLayout(saved: Partial<Layout> | undefined): Layout {
  if (!saved) return { ...DEFAULT_LAYOUT, columns: [...DEFAULT_COLUMNS] };
  // Layouts saved before presets existed: stacked inspectors meant the classic arrangement.
  // Unknown/legacy preset names (e.g. from before the rename) fall back by arrangement.
  const preset: LayoutPreset =
    saved.preset && saved.preset in PRESETS ? saved.preset : saved.stacked === false ? "quena" : "classic";
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
  /** A button next to the message (e.g. "Show redaction log"). */
  action?: { label: string; run: () => void };
}

export type Dialog =
  | { kind: "comment"; ids: SessionId[]; initial: string }
  | { kind: "help"; topic: "quickexec" | "shortcuts" }
  | { kind: "options" }
  | { kind: "recover" }
  | { kind: "find" }
  | { kind: "palette" }
  | { kind: "jobs" }
  | { kind: "about" }
  | { kind: "text"; title: string; text: string }
  | { kind: "connect-device" }
  | { kind: "textwizard"; text?: string }
  | { kind: "https" }
  | { kind: "plugins" }
  | { kind: "rules" }
  /** Mocks from sessions; the dialog offers the selected or the visible sessions. */
  | { kind: "mocks"; selected: SessionId[]; target?: "apply" | "package" | "wiremock" }
  /** Sanitized export: the selected sessions or all in the list (`scope` is what the dialog
   *  starts with; it can switch while there is a selection), and its redaction log afterwards. */
  | { kind: "sanitize"; selected: SessionId[]; scope: "selected" | "all" }
  | { kind: "sanitize-result"; result: SanitizedExport }
  | { kind: "choose-layout" }
  | { kind: "compare"; a: string; b: string; titleA: string; titleB: string }
  | { kind: "prompt"; title: string; label: string; initial: string; resolve: (v: string | null) => void }
  | { kind: "confirm"; title: string; message: string; confirm: string; resolve: (ok: boolean) => void };

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
  /** Capture is being switched on/off (the system proxy can take a moment). */
  captureBusy: "starting" | "stopping" | null;
  /** Visible width of the session list (the flexible column fills it). */
  gridWidth: number;
  /** Charsets chosen by the user for the bodies of one session (`request`, `response`,
   * `response:part3` …); belongs to session `id` and is dropped with the next session. */
  charsetOverrides: { id: SessionId | null; map: Record<string, string> };
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
  captureBusy: null,
  gridWidth: 0,
  charsetOverrides: { id: null, map: {} },
}));

export const set = useStore.setState;
export const get = useStore.getState;

export function say(text: string, kind: "info" | "error" = "info", action?: Message["action"]) {
  set({ message: { text, kind, at: Date.now(), action } });
}

/** Yes/no question in the app's confirm dialog. Focus returns to where it was (usually the
 *  session list), so the keyboard keeps working. */
export function confirmAsk(title: string, message: string, confirm: string): Promise<boolean> {
  const back = document.activeElement as HTMLElement | null;
  return new Promise((resolve) =>
    set({
      dialog: {
        kind: "confirm",
        title,
        message,
        confirm,
        resolve: (ok) => {
          resolve(ok);
          setTimeout(() => back?.focus?.(), 0);
        },
      },
    }),
  );
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
