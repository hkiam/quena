// Type definitions for Piper rules scripts (M14). Loaded by the editor for
// autocomplete; not evaluated at runtime.

/** An ordered, case-insensitive collection of HTTP headers. */
interface PiperHeaders {
  /** First value for `name`, or null. */
  get(name: string): string | null;
  /** All values for `name`. */
  getAll(name: string): string[];
  has(name: string): boolean;
  /** Set `name` to `value`, removing any duplicates. */
  set(name: string, value: string): PiperHeaders;
  /** Append a value without removing existing ones. */
  add(name: string, value: string): PiperHeaders;
  remove(name: string): PiperHeaders;
  names(): string[];
  toArray(): [string, string][];
}

/** The session handed to request/response hooks. Mutate it in place. */
interface PiperSession {
  readonly id: number;
  readonly process: string;
  readonly clientIp: string;
  readonly phase: 'request' | 'response';

  // Request phase
  method?: string;
  host?: string;
  path?: string;
  requestHeaders?: PiperHeaders;

  // Response phase
  status?: number;
  reason?: string;
  responseHeaders?: PiperHeaders;

  /** Full URL (request phase: editable to redirect). */
  url: string;

  /** Attach a comment (shown in the Comments column). */
  comment(text: string): PiperSession;
  /** Colour the row. One of: red, blue, gold, green, orange, purple. */
  color(color: string): PiperSession;
  /** Set the value shown in the script's Custom column (see Piper.registerColumn). */
  custom(value: string): PiperSession;
  /** Attach an arbitrary flag to the session. */
  flag(key: string, value: string): PiperSession;

  /** Request phase: redirect to another URL. */
  redirect(url: string): void;
  /** Drop the connection (request phase) / cut the response (response phase). */
  abort(): void;
  /** Request phase: answer locally without contacting the server. */
  respond(status: number, body?: string, headers?: Record<string, string>): void;
}

interface PiperSummary {
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
interface PiperMenuSession {
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
interface PiperMenuAction {
  id: number;
  comment?: string;
  color?: string;
  custom?: string;
}

/** Script-extensibility namespace (Fiddler's registerMenu/registerColumn). */
declare const Piper: {
  /**
   * Add a command to the session context menu (Scripts submenu). The handler
   * receives the selected sessions and may return an array of updates to apply.
   */
  registerMenu(label: string, handler: (sessions: PiperMenuSession[]) => PiperMenuAction[] | void): void;
  /**
   * Define the Custom column. Its value is set per session via session.custom(),
   * or computed by the optional fn(session) at response time.
   */
  registerColumn(title: string, fn?: (session: PiperSession) => string): void;
  log(...args: any[]): void;
};

declare function onBoot(): void;
declare function onBeforeRequest(session: PiperSession): void;
declare function onBeforeResponse(session: PiperSession): void;
declare function onSessionComplete(summary: PiperSummary): void;
