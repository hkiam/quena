// The Composer's request draft and its conversions (raw text, collection requests).
import type { CollectionRequest } from "../api";

export interface Draft {
  method: string;
  url: string;
  headers: string;
  body: string;
  bodyFromSession: number | null;
  bodyFromSessionLen: number;
  bodyFile: string | null;
  /** Charset the body text was loaded in (from a session); edits are encoded in the
   * declared charset, else in this one. */
  bodyCharset?: string | null;
  /** `HTTP/1.1` or `HTTP/2` forced; empty: as negotiated. */
  version?: string;
  /** Substitute variables in the body file (collections: `<@ file`). */
  bodyTemplate?: boolean;
  /** The collection request this draft was loaded from (saved back there). */
  coll?: { name: string; index: number; title: string } | null;
  /** Query parameters switched off in the Params table (`name=value` as in the URL). */
  offParams?: string[];
}

export const EMPTY: Draft = {
  method: "GET",
  url: "https://",
  headers: "User-Agent: Quena\nAccept: */*",
  body: "",
  bodyFromSession: null,
  bodyFromSessionLen: 0,
  bodyFile: null,
  version: "",
  coll: null,
};

export const VERSIONS = ["", "HTTP/1.1", "HTTP/2"] as const;

/** The draft as a raw HTTP request. */
export function toRaw(d: Draft): string {
  const u = (() => {
    try {
      return new URL(d.url);
    } catch {
      return null;
    }
  })();
  const path = u ? u.pathname + u.search : d.url;
  const headers = activeHeaders(d.headers);
  const hasHost = /^host\s*:/im.test(headers);
  return `${d.method} ${u ? d.url : path} ${d.version || "HTTP/1.1"}\n${hasHost || !u ? "" : `Host: ${u.host}\n`}${headers.trim()}\n\n${d.body}`;
}

/** `{{name}}` somewhere: the request needs a collection's variables or an environment. */
export function hasVariables(d: Pick<Draft, "url" | "headers" | "body">): boolean {
  return /\{\{.+?\}\}/.test(`${d.url}\n${d.headers}\n${d.body}`);
}

export function toCollectionRequest(d: Draft, name: string): CollectionRequest {
  return {
    name,
    method: d.method,
    url: d.url,
    version: d.version ?? "",
    headers: activeHeaders(d.headers),
    body: d.bodyFile ? "" : d.body,
    bodyFile: d.bodyFile ?? "",
    bodyTemplate: !!d.bodyFile && !!d.bodyTemplate,
  };
}

export function fromCollectionRequest(r: CollectionRequest, coll: string, index: number): Draft {
  return {
    method: r.method,
    url: r.url,
    headers: r.headers,
    body: r.body,
    bodyFromSession: null,
    bodyFromSessionLen: 0,
    bodyFile: r.bodyFile || null,
    bodyTemplate: r.bodyTemplate,
    bodyCharset: null,
    version: r.version,
    coll: { name: coll, index, title: r.name },
  };
}

/** A name for a request without one: method and path. */
export function defaultName(d: Pick<Draft, "method" | "url">): string {
  const path = d.url.replace(/^[a-z]+:\/\/[^/]*/i, "").split("?")[0] || "/";
  return `${d.method} ${path}`.slice(0, 80);
}

/** Move element `i` by `dir` places; a new array, or the same if it cannot move. */
export function moved<T>(list: T[], i: number, dir: -1 | 1): T[] {
  const j = i + dir;
  if (j < 0 || j >= list.length) return list;
  const next = [...list];
  [next[i], next[j]] = [next[j], next[i]];
  return next;
}

// ---- Header and parameter tables ----

export interface Row {
  on: boolean;
  name: string;
  value: string;
  /** Query parameters: the pair as written in the URL, sent unchanged while name and value are. */
  raw?: string;
}

/** Header lines that are on (`#` turns one off). */
export function activeHeaders(text: string): string {
  return text
    .split("\n")
    .filter((l) => !l.trimStart().startsWith("#"))
    .join("\n");
}

/** The header text as table rows. */
export function headerRows(text: string): Row[] {
  return text
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => {
      const off = l.trimStart().startsWith("#");
      const line = off ? l.trimStart().replace(/^#\s?/, "") : l;
      const i = line.indexOf(":");
      // The value keeps trailing spaces (typed one after the other in the table).
      return { on: !off, name: (i < 0 ? line : line.slice(0, i)).trim(), value: i < 0 ? "" : line.slice(i + 1).trimStart() };
    });
}

/** Table rows as header text (rows switched off as `# Name: value`, empty rows left out). */
export function headerText(rows: Row[]): string {
  return rows
    .filter((r) => r.name.trim() || r.value.trim())
    .map((r) => `${r.on ? "" : "# "}${r.name.trim()}: ${r.value}`)
    .join("\n");
}

/** Percent-encoded, `{{variables}}` left as they are (a collection substitutes them). */
const enc = (s: string) =>
  s
    .split(/(\{\{[^}]*\}\})/)
    .map((part) => (part.startsWith("{{") && part.endsWith("}}") ? part : encodeURIComponent(part).replace(/%20/g, "+")))
    .join("");
const dec = (s: string) => {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
};

/** The query parameters of `url` (on) and those switched off, decoded. */
export function queryRows(url: string, off: string[] = []): Row[] {
  const q = url.split("#")[0].split("?").slice(1).join("?");
  const pair = (p: string, on: boolean): Row => {
    const i = p.indexOf("=");
    return { on, name: dec(i < 0 ? p : p.slice(0, i)), value: i < 0 ? "" : dec(p.slice(i + 1)), raw: p };
  };
  return [...q.split("&").filter(Boolean).map((p) => pair(p, true)), ...off.map((p) => pair(p, false))];
}

/** `url` with the query of the rows that are on; the others as `offParams`. */
export function withQuery(url: string, rows: Row[]): { url: string; offParams: string[] } {
  const [beforeHash, ...hash] = url.split("#");
  const base = beforeHash.split("?")[0];
  // A pair as it was written while unchanged (its encoding stays: `%20`, `%7E`, signatures).
  const encode = (r: Row) => {
    if (r.raw != null) {
      const i = r.raw.indexOf("=");
      const same = dec(i < 0 ? r.raw : r.raw.slice(0, i)) === r.name && (i < 0 ? "" : dec(r.raw.slice(i + 1))) === r.value;
      if (same) return r.raw;
    }
    return r.value === "" && !r.name.includes("=") ? enc(r.name) : `${enc(r.name)}=${enc(r.value)}`;
  };
  const used = rows.filter((r) => r.name.trim() || r.value.trim());
  const on = used.filter((r) => r.on).map(encode);
  return { url: `${base}${on.length ? `?${on.join("&")}` : ""}${hash.length ? `#${hash.join("#")}` : ""}`, offParams: used.filter((r) => !r.on).map(encode) };
}
