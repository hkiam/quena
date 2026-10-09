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
  const hasHost = /^host\s*:/im.test(d.headers);
  return `${d.method} ${u ? d.url : path} ${d.version || "HTTP/1.1"}\n${hasHost || !u ? "" : `Host: ${u.host}\n`}${d.headers.trim()}\n\n${d.body}`;
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
    headers: d.headers,
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
