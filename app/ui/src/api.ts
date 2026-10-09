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
  /** Client connection (keep-alive, HTTP/2); 0: unknown. */
  conn: number;
  /** Trace or correlation id of the request. */
  trace?: string;
  /** Session cookie as `NAME #hash`. */
  session?: string;
  /** Reverse proxy entry the request came through. */
  via?: string;
  /** End of validity of the server certificate (Unix seconds). */
  certExpires?: number | null;
  /** LLM API call: `provider/model`, tokens, estimated cost in millionths of a dollar. */
  llm?: string;
  llmTokens?: number | null;
  llmCostMicros?: number | null;
}

/** "Group by" of the session list (crates/quena-index). */
export type GroupBy = "none" | "connection" | "host" | "process" | "trace" | "session" | "custom" | "via" | "llm";

export interface RowGroup {
  start: boolean;
  hue: number;
  size: number;
  collapsed: boolean;
  /** The group's first session. */
  first: SessionId;
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
/** Body representations; `text:<charset>` is the decoded body transcoded from that charset
 * to UTF-8 (for charsets the viewer cannot process byte-wise, like UTF-16). */
export type Variant = "raw" | "decoded" | "pretty" | `plugin:${number}` | `text:${string}`;

/** The charset of a text and where it came from (see quena_body::charset). */
export interface Charset {
  /** WHATWG name (UTF-8, windows-1252, UTF-16LE …). */
  name: string;
  source: "bom" | "header" | "document" | "default";
  /** charset parameter of the Content-Type, as sent. */
  header?: string;
  /** Declaration inside the document (XML declaration, HTML meta), as written. */
  document?: string;
}
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
  /** Effective charset of a text body (null for binary bodies). */
  charset: Charset | null;
  /** What a text body is, from its start: json, odata-json, soap, atom, edmx, xml, html. */
  shape?: "json" | "odata-json" | "soap" | "atom" | "edmx" | "xml" | "html" | null;
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
  kind: "decoder" | "headerInspector" | "analyzer";
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
  /** Server certificate: end of validity (Unix seconds), subject, issuer, expiry warning. */
  notAfter?: number | null;
  subject?: string | null;
  issuer?: string | null;
  warning?: string | null;
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
  /** Per row, while the list is grouped (null: the row has no group). */
  groups?: (RowGroup | null)[];
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
  rewrite: boolean;
  /** Listeners besides the proxy port while capturing: reverse proxy entries, SOCKS, transparent. */
  listeners: ListenerStatus[];
}

/** A browser that can be started with Quena as proxy (crates/quena-platform/src/launch.rs). */
export interface BrowserInfo {
  kind: string;
  name: string;
  exe: string;
  family: "chromium" | "firefox";
}

/** A listener while capturing (crates/quena-proxy/src/listener.rs). */
export interface ListenerStatus {
  id: string;
  kind: "reverse" | "socks" | "transparent";
  name: string;
  port: number;
  target: string;
  /** Addresses it listens on; empty when it could not start. */
  listen: string[];
  error: string | null;
}

export type ClientProtocol = "auto" | "http" | "https";

/** One reverse proxy entry (Capture → Reverse Proxy…). */
export interface ReverseProxyEntry {
  id: string;
  name: string;
  enabled: boolean;
  listenPort: number;
  allowRemote: boolean;
  clientProtocol: ClientProtocol;
  /** `http(s)://host[:port][/base path]` */
  target: string;
  preserveHost: boolean;
  /** Certificate name for TLS clients without SNI ("" = localhost). */
  tlsHost: string;
  rewriteLocation: boolean;
  rewriteCookieDomain: boolean;
  forwardedHeaders: boolean;
  /** Other targets for some paths; the longest matching prefix wins. */
  paths: ReversePathEntry[];
}

export interface ReversePathEntry {
  /** `/auth`, `/api/v2` … */
  prefix: string;
  target: string;
  /** Drop the prefix from the forwarded path. */
  stripPrefix: boolean;
}

/** Host remapping entry (Capture → Host Remapping…). */
export interface HostRemapEntry {
  id: string;
  enabled: boolean;
  /** `api.example.com`, `*.example.com` */
  host: string;
  /** `host`, `ip`, `host:port` */
  target: string;
  /** Keep Host and TLS name of the original (only the connection moves). */
  keepHost: boolean;
  comment: string;
}

/** SOCKS or transparent port (listening while capturing). */
export interface ListenerSettings {
  enabled: boolean;
  port: number;
  allowRemote: boolean;
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
  /** Charset of the variant's bytes when the variant fixes it (UTF-8 for transcoded text). */
  charset: string | null;
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
  | "started"
  | "via"
  | "cert"
  | "llm"
  | "tokens"
  | "cost";

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
  /** LLM calls: [provider/model, calls, tokens, estimated USD]. */
  llmModels: [string, number, number, number][];
  llmTokens: number;
  llmCost: number;
}

export type DiffSource = { kind: "live" } | { kind: "archive"; name: string } | { kind: "ids"; name: SessionId[] };
export interface DiffSourceInfo {
  source: DiffSource;
  label: string;
  sessions: number;
}
export interface DiffEntry {
  kind: "changed" | "added" | "removed" | "same";
  method: string;
  key: string;
  idA: SessionId | null;
  idB: SessionId | null;
  urlA: string | null;
  urlB: string | null;
  statusA: number | null;
  statusB: number | null;
  sizeA: number | null;
  sizeB: number | null;
  msA: number | null;
  msB: number | null;
  changes: string[];
}
export interface CaptureDiff {
  sessionsA: number;
  sessionsB: number;
  counts: { changed: number; added: number; removed: number; same: number; newErrors: number };
  entries: DiffEntry[];
}

export interface LlmPart {
  kind: "text" | "image" | "toolCall" | "toolResult" | "thinking" | "other";
  text: string;
  name?: string;
  id?: string;
}
export interface LlmCall {
  provider: string;
  api: "chat" | "responses" | "messages" | "gemini" | "ollamaChat" | "ollamaGenerate" | "embeddings";
  model: string;
  stream: boolean;
  system: string[];
  messages: { role: string; parts: LlmPart[] }[];
  tools: { name: string; description: string }[];
  params: [string, string][];
  output: LlmPart[];
  stopReason: string | null;
  usage: { input: number; output: number; cacheRead: number; cacheWrite: number; reasoning: number } | null;
  cost: { usd: number; price: string } | null;
  error: string | null;
  notes: string[];
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
  /** Reverse proxy ports: each forwards everything to one target (while capturing). */
  reverseProxy: { enabled: boolean; entries: ReverseProxyEntry[] };
  /** Host remapping: connections to a host go elsewhere. */
  hostRemap: { enabled: boolean; entries: HostRemapEntry[] };
  /** SOCKS5/4 port. */
  socks: ListenerSettings;
  /** Port for transparently redirected traffic. */
  transparent: ListenerSettings;
  https: {
    decrypt: boolean;
    scope: "all" | "browsers" | "nonBrowsers" | "remote";
    skipDecryption: string;
    ignoreCertErrors: boolean;
    ignoreCertErrorsHosts: string;
    enableHttp2: boolean;
    http2DowngradeHosts: string;
    clientCerts: { host: string; certPath: string; keyPath: string }[];
    /** TLS key log (SSLKEYLOGFILE) for decrypting packet captures; "" = none. */
    tlsKeyLogFile: string;
    /** Flag sessions whose server certificate expires within this many days (0: off). */
    certWarnDays: number;
  };
  /** Protobuf schemas for gRPC/protobuf bodies: .proto files or folders, import paths, server reflection. */
  protobuf: { protoPaths: string[]; includePaths: string[]; reflection: boolean };
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
  /** Save the capture to an archive every few minutes (only when it changed). */
  autosave: { enabled: boolean; intervalMin: number; folder: string; keep: number };
  offerRecovery: boolean;
  auth: AuthSettings;
  scriptingEnabled: boolean;
  throttleKbps: number;
  throttleLatencyMs: number;
  /** Last options of the sanitized export. */
  sanitize?: SanitizeExportSettings;
  /** MCP server for AI agents (crates/quena-mcp). */
  mcp: McpSettings;
  /** Importing into a non-empty list: ask, or remove or keep its sessions. */
  importExisting?: "ask" | "remove" | "keep";
  ui: unknown;
}

/** Rewrite rules (crates/quena-app-core/src/rewrite.rs); `ops` are edited by agents (MCP) for now. */
export interface RwRule {
  id: number;
  enabled: boolean;
  match: string;
  phase: "request" | "response" | "webSocket";
  /** With phase webSocket: which messages. */
  direction?: "both" | "up" | "down";
  status: string;
  contentType: string;
  ops: RwOp[];
  comment: string;
  /** Named group, switched on and off together ("" = none). */
  group: string;
  hits: number;
}

/** One change of a rewrite rule (crates/quena-app-core/src/rewrite.rs `Op`). */
export type RwOp =
  | { op: "jsonSet"; path: string; value: unknown }
  | { op: "jsonRemove"; path: string }
  | { op: "jsonAppend"; path: string; value?: unknown }
  | { op: "jsonAppendAll"; value?: unknown }
  | { op: "regexReplace"; pattern: string; replacement: string }
  | { op: "setHeader"; name: string; value: string }
  | { op: "removeHeader"; name: string }
  | { op: "setStatus"; code: number };

/** A rewrite rule tried on a captured session. */
export interface RwPreview {
  matched: boolean;
  changed: boolean;
  part: "request" | "response";
  notes: string[];
  statusBefore: number | null;
  statusAfter: number | null;
  headersBefore: [string, string][];
  headersAfter: [string, string][];
  before: string;
  after: string;
}

/** What the navigator narrows the session list to (crates/quena-app-core/src/navigator.rs). */
export type NavScope = { kind: "group"; by: GroupBy; key: string } | { kind: "path"; host: string; path: string; exact: boolean };

export interface NavGroup {
  key: string;
  label: string;
  count: number;
  errors: number;
  bytes: number;
  first: SessionId;
}

export interface NavGroups {
  groups: NavGroup[];
  total: number;
  ungrouped: number;
  truncated: boolean;
}

export interface RwState {
  enabled: boolean;
  maxBodyKb: number;
  rules: RwRule[];
  /** Groups whose rules are off. */
  disabledGroups: string[];
}

export interface McpSettings {
  enabled: boolean;
  port: number;
  access: "readOnly" | "full";
  token: string;
  /** Hand captured credentials to agents unredacted. */
  includeSecrets: boolean;
  /** The only folder agents may read and write files in; empty: `mcp-files` in the data folder. */
  filesDir: string;
}

export interface McpStatus {
  running: boolean;
  url: string | null;
  error: string | null;
}

/** What the sanitized export replaces (crates/quena-app-core/src/sanitize.rs). */
export interface SanitizeOptions {
  preset: "support" | "gdpr" | "credentials" | "custom";
  authorization: boolean;
  cookies: boolean;
  secretHeaders: boolean;
  urlSecrets: boolean;
  bodySecrets: boolean;
  emails: boolean;
  payment: boolean;
  phones: boolean;
  ips: boolean;
  personalFields: boolean;
  nationalIds: boolean;
  process: boolean;
  bodies: "keep" | "truncate" | "placeholder" | "drop";
  truncateKib: number;
  binary: "keep" | "placeholder";
  pseudonyms: boolean;
  extraHeaders: string[];
  extraParams: string[];
  extraFields: string[];
  patterns: string[];
}

export interface SanitizeExportSettings {
  options: SanitizeOptions;
  format: "saz" | "har";
}

/** What was replaced, without the values. */
export interface RedactionLog {
  preset: string;
  sessions: number;
  /** Session numbers (original capture) with replacements. */
  touched: number[];
  total: number;
  byCategory: Record<string, number>;
  byLocation: Record<string, number>;
  counts: { category: string; location: string; count: number }[];
  distinctValues: number;
  numbersAsStrings: number;
  wsMessages: number;
  notes: string[];
}

/** Event `pcap-import`: what a packet capture import found. */
export interface CaptureImport {
  /** The file read (a temporary copy for dropped files) and its name for messages. */
  path: string;
  name: string;
  sessions: number;
  tls: number;
  decrypted: number;
  /** TLS connections without secrets in the key logs. */
  noKeys: number;
  /** The new sessions, and the session numbering they belong to. */
  ids: SessionId[];
  numbering: number;
}

/** Payload of the `export-sanitized` event. */
export interface SanitizedExport {
  path: string;
  format: "saz" | "har";
  log: RedactionLog;
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
  /** Charset the body text was shown in (the text is encoded in the declared charset, else this one). */
  bodyCharset?: string | null;
  bodyFromSession?: SessionId | null;
  bodyFile?: string | null;
  fixContentLength: boolean;
  breakpoint?: boolean;
  /** Force `HTTP/1.1` or `HTTP/2`; absent: as negotiated. */
  version?: "HTTP/1.1" | "HTTP/2" | null;
}

export interface CollectionInfo {
  name: string;
  path: string;
  requests: number;
}
/** A request of a collection, as the Composer edits it. */
export interface CollectionRequest {
  name: string;
  method: string;
  url: string;
  /** `HTTP/1.1`, `HTTP/2`; empty: automatic. */
  version: string;
  headers: string;
  body: string;
  /** Body from this file (relative to the collections folder or absolute). */
  bodyFile: string;
  /** Substitute variables in the body file. */
  bodyTemplate: boolean;
}
export interface Collection {
  name: string;
  variables: [string, string][];
  requests: CollectionRequest[];
  warnings?: string[];
  environments?: string[];
}
export interface HttpRunResult {
  name: string | null;
  line: number;
  method: string;
  url: string;
  session: SessionId | null;
  status: number | null;
  durationMs: number | null;
  pending: boolean;
  error: string | null;
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

/** Options for mocks from sessions (crates/quena-app-core/src/mockgen.rs). */
export interface MockOptions {
  hosts: string[];
  includeStatic: boolean;
  query: "exact" | "ignore";
  ignoreParams: string[];
  repeats: "last" | "sequence";
  matchBody: boolean;
  latency: boolean;
  includePreflight: boolean;
  includeErrors: boolean;
  /** Sanitize preset ("credentials" = only credentials and tokens); null = as recorded. */
  sanitize: "credentials" | "support" | "gdpr" | null;
  keepSetCookie: boolean;
}

export type MockSkipReason =
  | "noResponse"
  | "incomplete"
  | "truncated"
  | "tunnel"
  | "webSocket"
  | "host"
  | "static"
  | "preflight"
  | "errorStatus"
  | "notModified"
  | "superseded"
  | "duplicate"
  | "tooLarge"
  | "undecodable";

export interface MockSequence {
  group: number;
  index: number;
  len: number;
}

export interface MockPreview {
  sessions: number;
  mappings: number;
  sequences: number;
  hosts: string[];
  skippedByReason: Partial<Record<MockSkipReason, number>>;
  skipped: { id: SessionId; method: string; url: string; reason: MockSkipReason }[];
  entries: { session: SessionId; method: string; url: string; status: number; bodyMatch: boolean; sequence: MockSequence | null }[];
}

export interface MockPackage {
  name: string;
  dir: string;
  rules: number;
  rejected: number;
  /** Hosts the package's rules answer for (sorted). */
  hosts: string[];
  created: number | null;
}

/** Event `mocks`: a mock job finished. */
export interface MockJobResult {
  job: number;
  target: "wiremock" | "package" | "apply";
  path: string;
  name: string | null;
  mappings: number;
  sequences: number;
  skipped: number;
  /** Mappings that did not become rules (unsafe or invalid); 0 normally. */
  rejected: number;
  /** Recorded response headers left out as invalid. */
  droppedHeaders: number;
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
  /** Charset the edited body text was shown in. */
  bodyCharset?: string | null;
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
  /** Changed on the way by a rule or the rules script. */
  edited?: boolean;
  /** Not sent (dropped by the rules script). */
  dropped?: boolean;
  /** Socket.IO packet (Socket.IO sessions). */
  sio?: SioPacket;
}
export interface SioPacket {
  eio: string;
  sio?: string;
  namespace?: string;
  ack?: number;
  event?: string;
  data?: string;
  attachments?: number;
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
  charset: Charset | null;
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
  /** Field name from the schema. */
  name?: string | null;
  /** Message or enum type from the schema. */
  typeName?: string | null;
}
export interface GrpcMessage {
  index: number;
  compressed: boolean;
  len: number;
  fields: PbField[];
  error: string | null;
  truncated?: boolean;
  /** Schema type the message was decoded with. */
  messageType?: string | null;
}
export interface Grpc {
  isGrpc: boolean;
  messages: GrpcMessage[];
  status: string | null;
  statusMessage: string | null;
  error: string | null;
  truncated?: boolean;
  /** `pkg.Service/Method` from the path. */
  method?: string | null;
  /** Where the schema came from, or why there is none. */
  schema?: string | null;
}
export interface MpNode {
  key: string | null;
  kind: string;
  value: string;
  children: MpNode[];
}
export interface Msgpack {
  values: MpNode[];
  error: string | null;
  truncated: boolean;
}
/** LLM prices: own file, fetched list, built-in list. */
export interface LlmPricesInfo {
  path: string;
  exists: boolean;
  custom: number;
  customError: string | null;
  fetched: number;
  /** Unix seconds. */
  fetchedAt: number | null;
  source: string;
  builtIn: number;
}
export interface SchemaStatus {
  files: number;
  messages: number;
  services: string[];
  messageTypes: string[];
  reflected: string[];
  error: string | null;
}

export interface CaInfo {
  exists: boolean;
  trusted: boolean;
  sha256: string;
  path: string;
  pem: string;
  name: string;
  issuer: string;
  /** End of validity (Unix seconds). */
  notAfter: number;
  /** Certificates above the CA (imported intermediate). */
  chain: number;
  /** Created by Quena (not imported). */
  generated: boolean;
}
export interface CaImport {
  certPath?: string;
  keyPath?: string;
  p12Path?: string;
  password?: string;
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
  setGroup: (group: GroupBy) => invoke<void>("set_group", { group }),
  toggleGroup: (id: SessionId) => invoke<boolean | null>("toggle_group", { id }),
  collapseGroups: (collapse: boolean) => invoke<void>("collapse_groups", { collapse }),
  groupIds: (id: SessionId) => invoke<SessionId[]>("group_ids", { id }),
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
  /** Lines of a variant, decoded from `charset` (default: the body's; ignored when the variant fixes it). */
  bodyLines: (id: SessionId, part: Part, variant: Variant, start: number, count: number, charset?: string | null) =>
    invoke<LinesDto>("body_lines", { id, part, variant, start, count, charset: charset ?? null }),
  bodySearch: (id: SessionId, part: Part, variant: Variant, needle: string, ignoreCase: boolean, charset?: string | null) =>
    invoke<number>("body_search", { id, part, variant, needle, ignoreCase, charset: charset ?? null }),
  searchResult: (job: number) => invoke<SearchResult | null>("search_result", { job }),
  saveBody: (id: SessionId, part: Part, variant: Variant, path: string) => invoke<number>("save_body", { id, part, variant, path }),
  findSessions: (options: FindOptions) => invoke<number>("find_sessions", { options }),
  findResult: (job: number) => invoke<FindResult | null>("find_result", { job }),
  statistics: (ids: SessionId[]) => invoke<Statistics>("statistics", { ids }),
  jobs: () => invoke<JobInfo[]>("jobs"),
  cancelJob: (id: number) => invoke<boolean>("cancel_job", { id }),
  browsersList: () => invoke<BrowserInfo[]>("browsers_list"),
  hostsFileImport: () => invoke<HostRemapEntry[]>("hosts_file_import"),
  launchBrowser: (kind: string, url?: string) => invoke<string>("launch_browser", { kind, url }),
  openTerminal: () => invoke<void>("open_terminal"),
  settingsGet: () => invoke<Settings>("settings_get"),
  settingsSet: (settings: Settings) => invoke<void>("settings_set", { settings }),
  mcpStatus: () => invoke<McpStatus>("mcp_status"),
  mcpNewToken: () => invoke<string>("mcp_new_token"),
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
  caExport: (path: string, format: "pem" | "der" | "p12", password?: string) => invoke<void>("ca_export", { path, format, password: password ?? null }),
  caImport: (source: CaImport) => invoke<CaInfo>("ca_import", { source }),
  exportArchive: (ids: SessionId[], path: string, password?: string) => invoke<number>("export_archive", { ids, path, password: password ?? null }),
  importArchive: (path: string, password?: string) => invoke<number>("import_archive", { path, password: password ?? null }),
  importDropped: (id: string, name: string, password: string) => invoke<number>("import_dropped", { id, name, password }),
  autosaveNow: () => invoke<string | null>("autosave_now"),
  mcpSetupClient: (client: "claudeCode" | "vsCode" | "cursor" | "codex") => invoke<string>("mcp_setup_client", { client }),
  mcpInstallSkill: (target: "claudeCode" | "codex") => invoke<string>("mcp_install_skill", { target }),
  llmPricesInfo: () => invoke<LlmPricesInfo>("llm_prices_info"),
  llmPricesUpdate: () => invoke<LlmPricesInfo>("llm_prices_update"),
  llmPricesForget: () => invoke<LlmPricesInfo>("llm_prices_forget"),
  llmPricesOpen: () => invoke<void>("llm_prices_open"),
  autosaveReveal: () => invoke<void>("autosave_reveal"),
  /** A packet capture again with a TLS key log, replacing the sessions of its first import
   *  (unless numbering restarted since, e.g. after Remove All). */
  importCapture: (path: string, name: string, keylog: string, replace: SessionId[], numbering: number) =>
    invoke<number>("import_capture", { path, name, keylog, replace, numbering }),
  /** Job id; the event `export-sanitized` follows when it is done. */
  exportSanitized: (ids: SessionId[], path: string, format: "saz" | "har", options: SanitizeOptions) =>
    invoke<number>("export_sanitized", { ids, path, format, options }),
  revealPath: (path: string) => invoke<void>("reveal_path", { path }),
  /** [support, gdpr] */
  sanitizePresets: () => invoke<SanitizeOptions[]>("sanitize_presets"),
  /** Rejects with the first invalid pattern. */
  sanitizeValidate: (options: SanitizeOptions) => invoke<void>("sanitize_validate", { options }),
  dropChunk: (id: string, name: string, offset: number, data: Uint8Array, last: boolean) =>
    tauriInvoke<number | null>("drop_chunk", data, {
      headers: { "quena-drop-id": id, "quena-drop-name": encodeURIComponent(name), "quena-drop-offset": String(offset), "quena-drop-last": last ? "1" : "0" },
    }),
  timers: (ids: SessionId[]) => invoke<{ id: SessionId; timers: Timers }[]>("timers", { ids }),
  /** Several tree levels in one backend pass (`host: null` = the list of hosts). */
  structure: (levels: { host: string | null; prefix: string }[]) => invoke<{ nodes: TreeNode[]; truncated: boolean }[]>("structure", { levels }),
  /** Sessions of a node; `exact` for "(this path)": that path only, nothing below it. */
  structureIds: (host: string, path: string, exact = false) => invoke<SessionId[]>("structure_ids", { host, path, exact }),
  uiLanguage: () => invoke<string>("ui_language"),
  setLanguage: (pref: string) => invoke<string>("set_language", { pref }),
  takeOpenFiles: () => invoke<string[]>("take_open_files"),
  writeTextFile: (path: string, text: string) => invoke<void>("write_text_file", { path, text }),
  arGet: () => invoke<ArState>("ar_get"),
  navGroups: (by: GroupBy) => invoke<NavGroups>("nav_groups", { by }),
  setScope: (scope: NavScope | null) => invoke<void>("set_scope", { scope }),
  navIds: (scope: NavScope) => invoke<SessionId[]>("nav_ids", { scope }),
  rwGet: () => invoke<RwState>("rw_get"),
  rwSet: (state: RwState) => invoke<RwState>("rw_set", { state }),
  rwUpdate: (rule: RwRule) => invoke<RwState>("rw_update", { rule }),
  rwPreview: (rule: RwRule, id: SessionId) => invoke<RwPreview>("rw_preview", { rule, id }),
  rwApply: (ids: SessionId[], ruleIds?: number[], group?: string) => invoke<{ created: SessionId[]; unchanged: number }>("rw_apply", { ids, ruleIds, group }),
  arSet: (state: ArState) => invoke<void>("ar_set", { state }),
  arAddSessions: (ids: SessionId[], exact: boolean) => invoke<number>("ar_add_sessions", { ids, exact }),
  arImportFarx: (path: string) => invoke<ArState>("ar_import_farx", { path }),
  arExportFarx: (path: string) => invoke<void>("ar_export_farx", { path }),
  mockPreview: (ids: SessionId[], opts: MockOptions) => invoke<MockPreview>("mock_preview", { ids, opts }),
  mockExportWiremock: (ids: SessionId[], path: string, opts: MockOptions) => invoke<number>("mock_export_wiremock", { ids, path, opts }),
  mockExportPackage: (ids: SessionId[], path: string, opts: MockOptions) => invoke<number>("mock_export_package", { ids, path, opts }),
  mockApply: (ids: SessionId[], opts: MockOptions, name: string) => invoke<number>("mock_apply", { ids, opts, name }),
  mockImportPackage: (path: string, replace: boolean) => invoke<MockPackage>("mock_import_package", { path, replace }),
  mockImportPackageData: (name: string, data: Uint8Array, replace: boolean) =>
    tauriInvoke<MockPackage>("mock_import_package_data", data, { headers: { "quena-mock-name": encodeURIComponent(name), "quena-mock-replace": replace ? "1" : "0" } }),
  mockRemovePackage: (name: string) => invoke<number>("mock_remove_package", { name }),
  /** Sequences of the package start again with their first response; the number of rules reset. */
  mockResetSequences: (name: string) => invoke<number>("mock_reset_sequences", { name }),
  mockPackages: () => invoke<MockPackage[]>("mock_packages"),
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
  grpc: (id: SessionId, part: Part, typeName?: string) => invoke<Grpc | null>("grpc", { id, part, typeName: typeName ?? null }),
  compareSources: () => invoke<DiffSourceInfo[]>("compare_sources"),
  compareCaptures: (a: DiffSource, b: DiffSource, options?: { ignoreHost?: boolean }) => invoke<CaptureDiff>("compare_captures", { a, b, options }),
  llmCall: (id: SessionId) => invoke<LlmCall | null>("llm_call", { id }),
  socketioPolling: (id: SessionId, part: Part) => invoke<SioPacket[] | null>("socketio_polling", { id, part }),
  msgpack: (id: SessionId, part: Part) => invoke<Msgpack | null>("msgpack", { id, part }),
  protobufStatus: () => invoke<SchemaStatus>("protobuf_status"),
  grpcReflect: (id: SessionId) => invoke<{ service: string; files: string[] }>("grpc_reflect", { id }),
  multipart: (id: SessionId, part: Part) => invoke<Multipart | null>("multipart", { id, part }),
  wsFrames: (id: SessionId, start: number, count: number) => invoke<WsMessages>("ws_frames", { id, start, count }),
  deviceInfo: () => invoke<DeviceInfo>("device_info"),
  replay: (ids: SessionId[], options: { unconditional?: boolean; count?: number; breakpoint?: boolean; sequential?: boolean }) =>
    invoke<number>("replay", { ids, options }),
  compose: (request: ComposeRequest) => invoke<SessionId>("compose", { request }),
  collectionsList: () => invoke<CollectionInfo[]>("collections_list"),
  collectionRead: (name: string) => invoke<Collection>("collection_read", { name }),
  collectionSave: (collection: Collection) => invoke<CollectionInfo>("collection_save", { collection }),
  collectionRename: (from: string, to: string) => invoke<void>("collection_rename", { from, to }),
  collectionDelete: (name: string) => invoke<void>("collection_delete", { name }),
  collectionImport: (path: string) => invoke<string>("collection_import", { path }),
  collectionRun: (name: string, names: string[], env: string) => invoke<HttpRunResult[]>("collection_run", { name, names, env }),
  collectionSend: (name: string | null, request: CollectionRequest, env: string) => invoke<HttpRunResult>("collection_send", { name, request, env }),
  collectionsReveal: () => invoke<void>("collections_reveal"),
  parseRawRequest: (raw: string) => invoke<{ method: string; url: string; version: string; headers: string; body: string }>("parse_raw_request", { raw }),
  parseCurl: (cmd: string) => invoke<{ method: string; url: string; version: string; headers: string; body: string }>("parse_curl", { cmd }),
  scriptGet: () => invoke<ScriptState>("script_get"),
  scriptSet: (source: string) => invoke<ScriptState>("script_set", { source }),
  scriptSetEnabled: (enabled: boolean) => invoke<ScriptState>("script_set_enabled", { enabled }),
  scriptLogs: () => invoke<ScriptLog[]>("script_logs"),
  scriptClearLogs: () => invoke<void>("script_clear_logs"),
  scriptMenus: () => invoke<string[]>("script_menus"),
  scriptRunMenu: (index: number, ids: SessionId[]) => invoke<number>("script_run_menu", { index, ids }),
  diagAnalyzers: () => invoke<{ index: number; id: string; name: string; title: string; version: string }[]>("diag_analyzers"),
  diagDescribe: (index: number, lang: string) => invoke<string>("diag_describe", { index, lang }),
  diagRun: (index: number, options: string, ids: number[] | null, filter: { processes: string[]; hosts: string[] }) =>
    invoke<number>("diag_run", { index, options, ids, filter }),
  pluginsReady: () => invoke<boolean>("plugins_ready"),
  diagScopeOptions: () => invoke<{ processes: [string, number][]; hosts: [string, number][] }>("diag_scope_options"),
  diagReport: () => invoke<string | null>("diag_report"),
  readTextFile: (path: string) => invoke<string>("read_text_file", { path }),
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
): Promise<{ data: Uint8Array; total: number; complete: boolean; charset: string | null }> {
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
    // Set when the variant fixes the charset of its bytes (transcoded text: UTF-8).
    charset: res.headers.get("X-Quena-Charset"),
  };
}

export function on<T>(event: string, cb: (payload: T) => void): Promise<UnlistenFn> {
  return listen<T>(event, (e) => cb(e.payload));
}
