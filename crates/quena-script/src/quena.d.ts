// Type definitions for Quena rules scripts (M14). Loaded by the editor for
// autocomplete; not evaluated at runtime.

/** An ordered, case-insensitive collection of HTTP headers. */
interface QuenaHeaders {
  /** First value for `name`, or null. */
  get(name: string): string | null;
  /** All values for `name`. */
  getAll(name: string): string[];
  has(name: string): boolean;
  /** Set `name` to `value`, removing any duplicates. */
  set(name: string, value: string): QuenaHeaders;
  /** Append a value without removing existing ones. */
  add(name: string, value: string): QuenaHeaders;
  remove(name: string): QuenaHeaders;
  names(): string[];
  toArray(): [string, string][];
}

/** The session handed to request/response hooks. Mutate it in place. */
interface QuenaSession {
  readonly id: number;
  readonly process: string;
  readonly clientIp: string;
  readonly phase: 'request' | 'response';

  // Request phase
  method?: string;
  host?: string;
  path?: string;
  requestHeaders?: QuenaHeaders;

  // Response phase
  status?: number;
  reason?: string;
  responseHeaders?: QuenaHeaders;

  /** Full URL (request phase: editable to redirect). */
  url: string;

  /** Attach a comment (shown in the Comments column). */
  comment(text: string): QuenaSession;
  /** Colour the row. One of: red, blue, gold, green, orange, purple. */
  color(color: string): QuenaSession;
  /** Set the value shown in the script's Custom column (see Quena.registerColumn). */
  custom(value: string): QuenaSession;
  /** Attach an arbitrary flag to the session. */
  flag(key: string, value: string): QuenaSession;

  /** Request phase: redirect to another URL. */
  redirect(url: string): void;
  /** Drop the connection (request phase) / cut the response (response phase). */
  abort(): void;
  /** Request phase: answer locally without contacting the server. */
  respond(status: number, body?: string, headers?: Record<string, string>): void;
}

interface QuenaSummary {
  id: number;
  method: string;
  url: string;
  status: number;
}

declare const console: {
  log(...args: any[]): void;
  info(...args: any[]): void;
  warn(...args: any[]): void;
  error(...args: any[]): void;
  debug(...args: any[]): void;
};

/** A session as passed to a registerMenu handler. */
interface QuenaMenuSession {
  id: number;
  method: string;
  url: string;
  status: number;
  host: string;
  process: string;
  comment: string;
  contentType: string;
}

/** A per-session update a registerMenu handler may return to apply. */
interface QuenaMenuAction {
  id: number;
  comment?: string;
  color?: string;
  custom?: string;
}

/** Script-extensibility namespace: custom menu commands and a custom column. */
declare const Quena: {
  /**
   * Add a command to the session context menu (Scripts submenu). The handler
   * receives the selected sessions and may return an array of updates to apply.
   */
  registerMenu(label: string, handler: (sessions: QuenaMenuSession[]) => QuenaMenuAction[] | void): void;
  /**
   * Define the Custom column. Its value is set per session via session.custom(),
   * or computed by the optional fn(session) at response time.
   */
  registerColumn(title: string, fn?: (session: QuenaSession) => string): void;
  log(...args: any[]): void;
};

declare function onBoot(): void;
declare function onBeforeRequest(session: QuenaSession): void;
declare function onBeforeResponse(session: QuenaSession): void;
declare function onSessionComplete(summary: QuenaSummary): void;

/** A WebSocket message on its way (whole, uncompressed messages up to 1 MB). */
interface QuenaWsMessage {
  /** Session id of the WebSocket. */
  readonly id: number;
  /** URL of the upgrade request. */
  readonly url: string;
  /** `up`: client → server, `down`: server → client. */
  readonly direction: "up" | "down";
  readonly isBinary: boolean;
  readonly size: number;
  /** Text of a text message; assign to send other text. `null` for binary messages. */
  text: string | null;
  /** Do not send this message. */
  drop(): void;
}
declare function onWebSocketMessage(msg: QuenaWsMessage): void;
