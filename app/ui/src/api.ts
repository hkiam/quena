// Typed bindings to the Quena core (Tauri commands + events).
// Bodies are never transferred through invoke – see bodyUrl().
import { invoke as tauriInvoke, convertFileSrc } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { perf } from "./lib/perf";

export type SessionId = number;
export type MarkColor = "red" | "blue" | "gold" | "green" | "orange" | "purple";
export type SessionKind = "http" | "tunnel" | "webSocket" | "synthetic";
export type SessionState =
  | "requestHeaders"
  | "sendingRequest"
  | "breakpointRequest"
  | "awaitingResponse"
  | "receivingResponse"
  | "breakpointResponse"
  | "done"
  | "aborted";

export const Flags = {
  REPLAYED: 1 << 0,
  AUTO_RESPONDED: 1 << 1,
  BREAKPOINTED: 1 << 2,
  TAMPERED: 1 << 3,
  REQUEST_TRUNCATED: 1 << 4,
  RESPONSE_TRUNCATED: 1 << 5,
  DECRYPTED: 1 << 6,
  REMOTE_CLIENT: 1 << 7,
  IMPORTED: 1 << 8,
  STREAMED: 1 << 9,
  CLIENT_ABORTED: 1 << 10,
  SERVER_ABORTED: 1 << 11,
  COMPOSED: 1 << 12,
} as const;

export interface SessionSummary {
  id: SessionId;
  kind: SessionKind;
  state: SessionState;
  flags: number;
  color: MarkColor | null;
  method: string;
  protocol: string;
  host: string;
  url: string;
  status: number;
  requestBodyLen: number;
  responseBodyLen: number;
  contentType: string;
  caching: string;
  process: string;
  comment: string;
  custom: string;
  startedAt: number;
  durationMs: number | null;
  clientIp: string;
}

export type Headers = [string, string][];
export type HttpVersion = "HTTP/0.9" | "HTTP/1.0" | "HTTP/1.1" | "HTTP/2" | "HTTP/3";

export interface RequestHead {
  method: string;
  url: string;
  version: HttpVersion;
  headers: Headers;
}
export interface ResponseHead {
  status: number;
  reason: string;
  version: HttpVersion;
  headers: Headers;
}
export type Variant = "raw" | "decoded" | "pretty" | `plugin:${number}`;
export type Part = "request" | "response";

export interface BodyInfo {
  bodyId: number;
  len: number;
  wireLen: number;
  complete: boolean;
  truncated: boolean;
  contentType: string | null;
  contentEncoding: string | null;
  transferEncoding: string | null;
  isText: boolean;
  isImage: boolean;
  variants: Variant[];
  plugins: { variant: Variant; tab: string; confidence: number; output: "text" | "xml" | "json" }[];
}

export interface PluginInfo {
  index: number;
  id: string;
  name: string;
  version: string;
  tab: string;
  output: "text" | "xml" | "json";
  enabled: boolean;
  status: string;
  error: string | null;
  path: string;
  kind: "decoder" | "headerInspector";
  mimeTypes: string[];
  /** Header names of a header inspector. */
  headers: string[];
}

/** One line of a header inspection; the tree is flattened, `depth` is the nesting level. */
export interface InspectNode {
  depth: number;
  kind: "section" | "field" | "note" | "code";
  name: string;
  value: string;
}

export interface HeaderInspection {
  pluginId: string;
  tab: string;
  confidence: number;
  nodes: InspectNode[];
  error: string | null;
}

export interface TreeNode {
  name: string;
  count: number;
  errors: number;
  bytes: number;
  hasChildren: boolean;
}

export interface Timers {
  clientConnected?: number | null;
  clientBeginRequest?: number | null;
  gotRequestHeaders?: number | null;
  clientDoneRequest?: number | null;
  serverConnectStart?: number | null;
  serverConnected?: number | null;
  serverBeginRequest?: number | null;
  serverDoneRequest?: number | null;
  serverGotFirstByte?: number | null;
  gotResponseHeaders?: number | null;
  serverDoneResponse?: number | null;
  clientBeginResponse?: number | null;
  clientDoneResponse?: number | null;
  dnsMs?: number | null;
  tcpConnectMs?: number | null;
  tlsHandshakeMs?: number | null;
  gatewayMs?: number | null;
}

export interface TlsInfo {
  version: string;
  cipher: string;
  sni: string | null;
  alpn: string | null;
  serverChainPem: string[];
}

export interface ConnectionInfo {
  clientAddr: string | null;
  serverAddr: string | null;
  clientConnId: number | null;
  serverConnReused: boolean;
  clientTls: TlsInfo | null;
  serverTls: TlsInfo | null;
  gateway: string | null;
  streamId: number | null;
}

export interface Detail {
  summary: SessionSummary;
  request: RequestHead;
  response: ResponseHead | null;
  requestBody: BodyInfo;
  responseBody: BodyInfo;
  timers: Timers;
  connection: ConnectionInfo;
  process: { pid: number; name: string } | null;
  error: string | null;
  extraFlags: [string, string][];
}

export interface RowWindow {
  version: number;
  total: number;
  start: number;
  rows: SessionSummary[];
}

export interface EngineStatus {
  capturing: boolean;
  listen: string[];
  systemProxy: boolean;
  decrypting: boolean;
  upstream: string | null;
  error: string | null;
  breakpoints: string[];
  paused: number;
  autoresponder: boolean;
}

export interface Status {
  engine: EngineStatus;
  sessions: number;
  visible: number;
  jobsActive: number;
  usedBytes: number;
  freeBytes: number | null;
  recordingSuspended: boolean;
  filterActive: boolean;
  captureDir: string;
  uptimeS: number;
  mockRunning: boolean;
}

export interface JobInfo {
  id: number;
  key: string;
  title: string;
  status: "queued" | "running" | "done" | "failed" | "cancelled";
  done: number;
  total: number;
  error: string | null;
  elapsedMs: number | null;
}

export interface BodyView {
  len: number;
  complete: boolean;
  variant: Variant;
  job: number | null;
  lineJob: number | null;
  lines: number;
  linesDone: boolean;
  scanned: number;
  error: string | null;
}

export interface LinesDto {
  start: number;
  lines: string[];
  view: BodyView;
}

export interface SearchResult {
  hits: { offset: number; line: number }[];
  done: boolean;
  truncated: boolean;
}

export interface QuickExecResult {
  message: string | null;
  error: string | null;
  select: SessionId[] | null;
  action: string | null;
  engineCommand: string | null;
}

export interface LogEntry {
  seq: number;
  time: number;
  level: string;
  target: string;
  message: string;
}

export type Column =
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

export interface Sort {
  column: Column;
  descending: boolean;
}

export interface FilterSettings {
  enabled: boolean;
  hostMode: "noFilter" | "showOnly" | "hide";
  hosts: string;
  processMode: "all" | "browsers" | "nonBrowsers" | "remote";
  processOnly: string;
  hideProcesses: string;
  urlShowOnly: string;
  urlHide: string;
  hideConnects: boolean;
  hideSuccess: boolean;
  hideNonSuccess: boolean;
  hideAuth: boolean;
  hideRedirects: boolean;
  hideNotModified: boolean;
  hideImages: boolean;
  hideCss: boolean;
  hideScripts: boolean;
  hideFonts: boolean;
  contentTypeShowOnly: string;
  contentTypeHide: string;
  minSize: number | null;
  maxSize: number | null;
  minDurationMs: number | null;
  expression: string;
}

export interface Statistics {
  sessions: number;
  requestBytes: number;
  responseBytes: number;
  firstRequest: number | null;
  lastResponse: number | null;
  aggregateMs: number;
  statusCodes: Record<string, number>;
  contentTypes: [string, number, number][];
  hosts: [string, number, number][];
  processes: [string, number][];
  aborted: number;
  inFlight: number;
}

export interface Settings {
  proxy: {
    port: number;
    allowRemote: boolean;
    remoteAllowlist: string;
    actAsSystemProxy: boolean;
    captureOnStartup: boolean;
    useSystemUpstream: boolean;
    manualUpstream: string;
    upstreamBypass: string;
    useSystemPac: boolean;
    pacUrl: string;
  };
  https: {
    decrypt: boolean;
    scope: "all" | "browsers" | "nonBrowsers" | "remote";
    skipDecryption: string;
    ignoreCertErrors: boolean;
    ignoreCertErrorsHosts: string;
    enableHttp2: boolean;
    http2DowngradeHosts: string;
    clientCerts: { host: string; certPath: string; keyPath: string }[];
  };
  bodies: {
    inlineLimitKb: number;
    maxRecordedBodyMb: number;
    quotaGb: number;
    minFreeSpaceGb: number;
    maxDerivedGb: number;
    maxRatio: number;
  };
  keepSessions: number;
  stream: boolean;
  decode: boolean;
  headersOnlyHosts: string;
  headersOnlyTypes: string;
  losslessRecording: boolean;
  keepCaptures: boolean;
  offerRecovery: boolean;
  auth: AuthSettings;
  scriptingEnabled: boolean;
  throttleKbps: number;
  throttleLatencyMs: number;
  ui: unknown;
}

export interface FindOptions {
  text: string;
  matchCase: boolean;
  regex: boolean;
  scope: "all" | "requests" | "responses" | "urls";
  examine: "all" | "headers" | "bodies";
  ids: SessionId[];
  decode: boolean;
  maxBodyMb: number;
  mark: MarkColor | null;
}

export interface FindResult {
  ids: SessionId[];
  examined: number;
  total: number;
  done: boolean;
}

export interface CredentialRef {
  host: string;
  user: string;
  domain: string;
  hasPassword: boolean;
}

export interface AuthSettings {
  enabled: boolean;
  hosts: string;
  upstream: boolean;
  useCurrentIdentity: boolean;
  prefer: string;
  credentials: CredentialRef[];
}

export interface Recoverable {
  dir: string;
  sessions: number;
  modified: number | null;
}

export interface ComposeRequest {
  method: string;
  url: string;
  headers: string;
  body: string;
  bodyFromSession?: SessionId | null;
  bodyFile?: string | null;
  fixContentLength: boolean;
  breakpoint?: boolean;
}

export interface ArRule {
  id: number;
  enabled: boolean;
  match: string;
  action: string;
  latencyMs: number;
  matchOnce: boolean;
  comment: string;
  hits: number;
}

export interface ArState {
  enabled: boolean;
  unmatchedPassthrough: boolean;
  enableLatency: boolean;
  rules: ArRule[];
}

export interface BpState {
  allRequests: boolean;
  allResponses: boolean;
  requestUrl: string | null;
  responseUrl: string | null;
  status: number | null;
  method: string | null;
  timeoutS: number;
}

export interface Resume {
  action: "continue" | "breakOnResponse" | "abort" | "respond";
  headText?: string | null;
  bodyText?: string | null;
  bodyFile?: string | null;
  status?: number | null;
}

export interface WsFrame {
  seq: number;
  dir: number;
  opcode: number;
  opcodeName: string;
  fin: boolean;
  time: number;
  len: number;
  text: string | null;
  preview: string | null;
  offset: number;
}
export interface WsMessages {
  total: number;
  frames: WsFrame[];
  complete: boolean;
  truncated: boolean;
}

export interface MultipartPart {
  index: number;
  headers: [string, string][];
  contentType: string;
  contentId: string;
  name: string;
  filename: string;
  encoding: string;
  offset: number;
  len: number;
  isText: boolean;
  preview: string | null;
}
export interface Multipart {
  boundary: string;
  subtype: string;
  rootType: string;
  start: string;
  parts: MultipartPart[];
  error: string | null;
}

export interface PbField {
  number: number;
  wireType: number;
  kind: string;
  value: string;
  children: PbField[];
}
export interface GrpcMessage {
  index: number;
  compressed: boolean;
  len: number;
  fields: PbField[];
  error: string | null;
}
export interface Grpc {
  isGrpc: boolean;
  messages: GrpcMessage[];
  status: string | null;
  statusMessage: string | null;
  error: string | null;
}

export interface CaInfo {
  exists: boolean;
  trusted: boolean;
  sha256: string;
  path: string;
  pem: string;
}

export interface DeviceInfo {
  port: number;
  allowRemote: boolean;
  listening: boolean;
  addresses: [string, string][];
  caSha256: string | null;
}

export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const t0 = performance.now();
  try {
    return await tauriInvoke<T>(cmd, args);
  } finally {
    perf.ipc(cmd, performance.now() - t0);
  }
}

export const api = {
  status: () => invoke<Status>("status"),
  appInfo: () => invoke<{ version: string; dataDir: string; captureDir: string; platform: string }>("app_info"),
  rows: (start: number, count: number) => invoke<RowWindow>("rows", { start, count }),
  viewIds: (start: number, count: number) => invoke<SessionId[]>("view_ids", { start, count }),
  positionOf: (id: SessionId) => invoke<number | null>("position_of", { id }),
  setSort: (sort: Sort) => invoke<void>("set_sort", { sort }),
  getFilters: () => invoke<FilterSettings>("get_filters"),
  setFilters: (filters: FilterSettings) => invoke<void>("set_filters", { filters }),
  quickexec: (input: string) => invoke<QuickExecResult>("quickexec", { input }),
  remove: (ids: SessionId[]) => invoke<void>("remove", { ids }),
  removeAll: () => invoke<void>("remove_all"),
  removeWhere: (expr: string) => invoke<number>("remove_where", { expr }),
  summaries: (ids: SessionId[]) => invoke<SessionSummary[]>("summaries", { ids }),
  removeExcept: (ids: SessionId[]) => invoke<void>("remove_except", { ids }),
  mark: (ids: SessionId[], color: MarkColor | null) => invoke<void>("mark", { ids, color }),
  comment: (ids: SessionId[], text: string) => invoke<void>("comment", { ids, text }),
  detail: (id: SessionId) => invoke<Detail | null>("detail", { id }),
  bodyOpen: (id: SessionId, part: Part, variant: Variant) => invoke<BodyView>("body_open", { id, part, variant }),
  bodyLines: (id: SessionId, part: Part, variant: Variant, start: number, count: number) =>
    invoke<LinesDto>("body_lines", { id, part, variant, start, count }),
  bodySearch: (id: SessionId, part: Part, variant: Variant, needle: string, ignoreCase: boolean) =>
    invoke<number>("body_search", { id, part, variant, needle, ignoreCase }),
  searchResult: (job: number) => invoke<SearchResult | null>("search_result", { job }),
  saveBody: (id: SessionId, part: Part, variant: Variant, path: string) => invoke<number>("save_body", { id, part, variant, path }),
  findSessions: (options: FindOptions) => invoke<number>("find_sessions", { options }),
  findResult: (job: number) => invoke<FindResult | null>("find_result", { job }),
  statistics: (ids: SessionId[]) => invoke<Statistics>("statistics", { ids }),
  jobs: () => invoke<JobInfo[]>("jobs"),
  cancelJob: (id: number) => invoke<boolean>("cancel_job", { id }),
  settingsGet: () => invoke<Settings>("settings_get"),
  settingsSet: (settings: Settings) => invoke<void>("settings_set", { settings }),
  saveUiPrefs: (prefs: unknown) => invoke<void>("save_ui_prefs", { prefs }),
  logSince: (seq: number) => invoke<LogEntry[]>("log_since", { seq }),
  logClear: () => invoke<void>("log_clear"),
  mockStart: (rate: number, total: number) => invoke<void>("mock_start", { rate, total }),
  mockStop: () => invoke<void>("mock_stop"),
  mockBig: (scale: number) => invoke<void>("mock_big", { scale }),
  toggleCapture: () => invoke<boolean>("toggle_capture"),
  recoverable: () => invoke<Recoverable[]>("recoverable"),
  recover: (dir: string) => invoke<void>("recover", { dir }),
  discard: (dir: string) => invoke<void>("discard", { dir }),
  discardAll: () => invoke<number>("discard_all"),
  authSetCredential: (host: string, user: string, domain: string, password: string | null) =>
    invoke<void>("auth_set_credential", { host, user, domain, password }),
  authRemoveCredential: (host: string) => invoke<void>("auth_remove_credential", { host }),
  caInfo: () => invoke<CaInfo>("ca_info"),
  caTrust: () => invoke<CaInfo>("ca_trust"),
  caRemove: () => invoke<CaInfo>("ca_remove"),
  caRegenerate: () => invoke<CaInfo>("ca_regenerate"),
  caExport: (path: string, der: boolean) => invoke<void>("ca_export", { path, der }),
  exportArchive: (ids: SessionId[], path: string) => invoke<number>("export_archive", { ids, path }),
  importArchive: (path: string) => invoke<number>("import_archive", { path }),
  dropChunk: (id: string, name: string, offset: number, data: Uint8Array, last: boolean) =>
    tauriInvoke<number | null>("drop_chunk", data, {
      headers: { "quena-drop-id": id, "quena-drop-name": encodeURIComponent(name), "quena-drop-offset": String(offset), "quena-drop-last": last ? "1" : "0" },
    }),
  timers: (ids: SessionId[]) => invoke<{ id: SessionId; timers: Timers }[]>("timers", { ids }),
  structure: (host: string | null, prefix: string) => invoke<{ nodes: TreeNode[]; truncated: boolean }>("structure", { host, prefix }),
  structureIds: (host: string, path: string) => invoke<SessionId[]>("structure_ids", { host, path }),
  uiLanguage: () => invoke<string>("ui_language"),
  setLanguage: (pref: string) => invoke<string>("set_language", { pref }),
  takeOpenFiles: () => invoke<string[]>("take_open_files"),
  writeTextFile: (path: string, text: string) => invoke<void>("write_text_file", { path, text }),
  arGet: () => invoke<ArState>("ar_get"),
  arSet: (state: ArState) => invoke<void>("ar_set", { state }),
  arAddSessions: (ids: SessionId[], exact: boolean) => invoke<number>("ar_add_sessions", { ids, exact }),
  arImportFarx: (path: string) => invoke<ArState>("ar_import_farx", { path }),
  arExportFarx: (path: string) => invoke<void>("ar_export_farx", { path }),
  bpGet: () => invoke<BpState>("bp_get"),
  bpSet: (state: BpState) => invoke<void>("bp_set", { state }),
  bpPaused: () => invoke<{ id: SessionId; phase: string; url: string; since: number }[]>("bp_paused"),
  bpResume: (id: SessionId, resume: Resume) => invoke<void>("bp_resume", { id, resume }),
  bpGo: () => invoke<number>("bp_go"),
  pluginsList: () => invoke<PluginInfo[]>("plugins_list"),
  pluginSetEnabled: (id: string, enabled: boolean) => invoke<void>("plugin_set_enabled", { id, enabled }),
  pluginsRescan: () => invoke<PluginInfo[]>("plugins_rescan"),
  pluginsInspectHeader: (name: string, value: string) => invoke<HeaderInspection[]>("plugins_inspect_header", { name, value }),
  pluginsReveal: () => invoke<void>("plugins_reveal"),
  saveBodyRange: (id: SessionId, part: Part, offset: number, len: number, path: string) =>
    invoke<number>("save_body_range", { id, part, offset, len, path }),
  grpc: (id: SessionId, part: Part) => invoke<Grpc | null>("grpc", { id, part }),
  multipart: (id: SessionId, part: Part) => invoke<Multipart | null>("multipart", { id, part }),
  wsFrames: (id: SessionId, start: number, count: number) => invoke<WsMessages>("ws_frames", { id, start, count }),
  deviceInfo: () => invoke<DeviceInfo>("device_info"),
  replay: (ids: SessionId[], options: { unconditional?: boolean; count?: number; breakpoint?: boolean; sequential?: boolean }) =>
    invoke<number>("replay", { ids, options }),
  compose: (request: ComposeRequest) => invoke<SessionId>("compose", { request }),
  parseRawRequest: (raw: string) => invoke<{ method: string; url: string; version: string; headers: string; body: string }>("parse_raw_request", { raw }),
  parseCurl: (cmd: string) => invoke<{ method: string; url: string; version: string; headers: string; body: string }>("parse_curl", { cmd }),
  scriptGet: () => invoke<ScriptState>("script_get"),
  scriptSet: (source: string) => invoke<ScriptState>("script_set", { source }),
  scriptSetEnabled: (enabled: boolean) => invoke<ScriptState>("script_set_enabled", { enabled }),
  scriptLogs: () => invoke<ScriptLog[]>("script_logs"),
  scriptClearLogs: () => invoke<void>("script_clear_logs"),
  scriptMenus: () => invoke<string[]>("script_menus"),
  scriptRunMenu: (index: number, ids: SessionId[]) => invoke<number>("script_run_menu", { index, ids }),
};

export interface ScriptState {
  source: string;
  enabled: boolean;
  loaded: boolean;
  error: string | null;
  types: string;
  menus: string[];
  columnTitle: string | null;
}

export interface ScriptLog {
  level: string;
  message: string;
  tsUs: number;
}

/** URL of a body variant served by the `quena://` protocol (supports Range). */
export function bodyUrl(id: SessionId, part: Part, variant: Variant): string {
  return convertFileSrc(`body/${id}/${part}/${variant}`, "quena");
}

/** Fetch a byte range of a body. */
export async function fetchBody(
  id: SessionId,
  part: Part,
  variant: Variant,
  offset: number,
  length: number,
  signal?: AbortSignal,
): Promise<{ data: Uint8Array; total: number; complete: boolean }> {
  const t0 = performance.now();
  const end = offset + Math.max(0, length) - 1;
  const res = await fetch(bodyUrl(id, part, variant), {
    headers: { Range: `bytes=${offset}-${end}` },
    signal,
  });
  const buf = new Uint8Array(await res.arrayBuffer());
  perf.ipc("body-range", performance.now() - t0);
  return {
    data: buf,
    total: Number(res.headers.get("X-Quena-Total") ?? buf.length),
    complete: res.headers.get("X-Quena-Complete") === "1",
  };
}

export function on<T>(event: string, cb: (payload: T) => void): Promise<UnlistenFn> {
  return listen<T>(event, (e) => cb(e.payload));
}
