import type { Detail } from "../api";
import { latin1ToUtf8 } from "./format";

export function requestLine(d: Detail): string {
  const r = d.request;
  if (d.summary.kind === "tunnel") return `CONNECT ${r.url} ${r.version}`;
  return `${r.method} ${r.url} ${r.version === "HTTP/2" ? "HTTP/2" : r.version}`;
}

export function rawRequestText(d: Detail, body: string): string {
  const lines = [requestLine(d), ...d.request.headers.map(([k, v]) => `${k}: ${latin1ToUtf8(v)}`)];
  return lines.join("\r\n") + "\r\n\r\n" + body;
}

export function rawResponseHead(d: Detail): string {
  const r = d.response;
  if (!r) return "";
  const lines = [`${r.version} ${r.status} ${r.reason}`, ...r.headers.map(([k, v]) => `${k}: ${latin1ToUtf8(v)}`)];
  return lines.join("\r\n") + "\r\n\r\n";
}

/**
 * Quote a string as one word for a POSIX-style shell (sh/bash/zsh). Everything
 * inside '…' is literal (including `$`, backticks, `!`, `|`, newlines and
 * non-ASCII); an embedded `'` becomes `'\''`. Control characters other than
 * tab and newline are emitted as `$'\xHH'` pieces (bash/zsh ANSI-C quoting) so
 * nothing invisible reaches the terminal; NUL cannot be carried by a shell
 * argument at all and is dropped (bodies with NUL are referenced via @file).
 */
function shq(s: string): string {
  let out = "";
  let lit = "";
  const flush = () => {
    if (lit) out += `'${lit.replace(/'/g, `'\\''`)}'`;
    lit = "";
  };
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (c === 0) continue;
    if ((c < 0x20 && c !== 0x09 && c !== 0x0a) || c === 0x7f) {
      flush();
      out += `$'\\x${c.toString(16).padStart(2, "0")}'`;
    } else lit += ch;
  }
  flush();
  return out || "''";
}

const SKIP_CURL = new Set(["content-length", "host", "connection", "proxy-connection", "accept-encoding", "transfer-encoding"]);

/** cURL for a POSIX-style shell (sh/bash/zsh); every value is shell-quoted. */
export function buildCurl(d: Detail, body: string | null): string {
  const parts = ["curl"];
  if (d.request.method !== "GET" || (body && d.request.method === "GET")) parts.push("-X " + shq(d.request.method));
  // A leading "-" would make curl read the URL as an option.
  if (d.request.url.startsWith("-")) parts.push("--url " + shq(d.request.url));
  else parts.push(shq(d.request.url));
  for (const [k, v] of d.request.headers) {
    if (SKIP_CURL.has(k.toLowerCase()) || k.startsWith(":")) continue;
    parts.push("-H " + shq(`${k}: ${latin1ToUtf8(v)}`));
  }
  if (d.request.headers.some(([k]) => k.toLowerCase() === "accept-encoding")) parts.push("--compressed");
  // A NUL cannot travel in a shell argument; such bodies go through the file like binary ones.
  if (body != null && body.length && !body.includes("\0")) parts.push("--data-binary " + shq(body));
  else if (d.requestBody.len > 0 || (body != null && body.length)) parts.push("--data-binary " + shq(`@body-${d.summary.id}.bin`));
  if (d.request.version === "HTTP/2") parts.push("--http2");
  return parts.join(" \\\n  ");
}

export function parseQuery(q: string): [string, string][] {
  if (!q) return [];
  return q
    .replace(/^\?/, "")
    .split("&")
    .filter(Boolean)
    .map((kv) => {
      const i = kv.indexOf("=");
      const dec = (s: string) => {
        try {
          return decodeURIComponent(s.replace(/\+/g, " "));
        } catch {
          return s;
        }
      };
      return i < 0 ? [dec(kv), ""] : [dec(kv.slice(0, i)), dec(kv.slice(i + 1))];
    });
}

export function parseCookies(v: string): [string, string][] {
  return v
    .split(";")
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      const i = p.indexOf("=");
      return i < 0 ? [p, ""] : [p.slice(0, i), p.slice(i + 1)];
    });
}

export function b64decode(s: string): string {
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "="));
    return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  } catch {
    return "(invalid base64)";
  }
}

/** Request headers worth reproducing in a snippet (no hop-by-hop or computed ones). */
function snippetHeaders(d: Detail): [string, string][] {
  return d.request.headers.filter(([k]) => !SKIP_CURL.has(k.toLowerCase()) && !k.startsWith(":")).map(([k, v]) => [k, latin1ToUtf8(v)]);
}

/**
 * Snippet headers with repeated names (case-insensitive) merged into one entry,
 * as dictionary/hashtable literals can hold each name only once. Values are
 * joined with ", " (RFC 9110 list syntax), Cookie with "; ". The first
 * spelling of the name is kept.
 */
function mergedHeaders(d: Detail): [string, string][] {
  const out: [string, string][] = [];
  const at = new Map<string, number>();
  for (const [k, v] of snippetHeaders(d)) {
    const lk = k.toLowerCase();
    const i = at.get(lk);
    if (i === undefined) {
      at.set(lk, out.length);
      out.push([k, v]);
    } else out[i][1] += (lk === "cookie" ? "; " : ", ") + v;
  }
  return out;
}

/** JavaScript `fetch` (browser DevTools console or Node 18+). */
export function buildFetch(d: Detail, body: string | null): string {
  const opts: string[] = [`  method: ${JSON.stringify(d.request.method)},`];
  const hs = mergedHeaders(d);
  if (hs.length) opts.push(`  headers: {\n${hs.map(([k, v]) => `    ${JSON.stringify(k)}: ${JSON.stringify(v)},`).join("\n")}\n  },`);
  if (body != null && body.length) opts.push(`  body: ${JSON.stringify(body)},`);
  else if (d.requestBody.len > 0) opts.push(`  // body: ${d.requestBody.len} bytes (binary or large, not included)`);
  return `await fetch(${JSON.stringify(d.request.url)}, {\n${opts.join("\n")}\n});`;
}

/**
 * PowerShell string literal. Inside '…' only quote characters are special, and
 * PowerShell accepts ASCII ' as well as U+2018 U+2019 U+201A U+201B as single
 * quotes: all of them are doubled. Control characters other than tab/newline
 * are spliced in as [char]N so the literal stays visible and paste-safe.
 */
function psq(s: string): string {
  const q = (t: string) => `'${t.replace(/['\u2018\u2019\u201A\u201B]/g, "$&$&")}'`;
  const pieces: string[] = [];
  let lit = "";
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if ((c < 0x20 && c !== 0x09 && c !== 0x0a) || c === 0x7f) {
      if (lit || !pieces.length) pieces.push(q(lit));
      lit = "";
      pieces.push(`[char]${c}`);
    } else lit += ch;
  }
  if (lit || !pieces.length) pieces.push(q(lit));
  return pieces.length === 1 ? pieces[0] : `(${pieces.join(" + ")})`;
}

/** Methods `Invoke-WebRequest -Method` takes by name (WebRequestMethod); anything else is -CustomMethod. */
const PS_METHODS = /^(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH|TRACE|MERGE)$/i;

/** PowerShell `Invoke-WebRequest`. */
export function buildPowerShell(d: Detail, body: string | null): string {
  const hs = mergedHeaders(d);
  const ct = hs.find(([k]) => k.toLowerCase() === "content-type")?.[1];
  const ua = hs.find(([k]) => k.toLowerCase() === "user-agent")?.[1];
  // Content-Type and User-Agent must go through their own parameters.
  const rest = hs.filter(([k]) => !["content-type", "user-agent"].includes(k.toLowerCase()));
  const m = d.request.method;
  const method = PS_METHODS.test(m) ? `-Method ${m.toUpperCase()}` : `-CustomMethod ${psq(m)}`;
  const lines = [`Invoke-WebRequest -Uri ${psq(d.request.url)} ${method}`];
  if (rest.length) lines.push(`  -Headers @{\n${rest.map(([k, v]) => `    ${psq(k)} = ${psq(v)}`).join("\n")}\n  }`);
  if (ct) lines.push(`  -ContentType ${psq(ct)}`);
  if (ua) lines.push(`  -UserAgent ${psq(ua)}`);
  if (body != null && body.length) lines.push(`  -Body ${psq(body)}`);
  else if (d.requestBody.len > 0) lines.push(`  -InFile ${psq(`body-${d.summary.id}.bin`)}`);
  return lines.join(" `\n");
}

/** Python `requests`. JSON string literals are valid Python string literals. */
export function buildPython(d: Detail, body: string | null): string {
  const hs = mergedHeaders(d);
  const lines = ["import requests", ""];
  lines.push(`response = requests.request(`);
  lines.push(`    ${JSON.stringify(d.request.method)},`);
  lines.push(`    ${JSON.stringify(d.request.url)},`);
  if (hs.length) lines.push(`    headers={\n${hs.map(([k, v]) => `        ${JSON.stringify(k)}: ${JSON.stringify(v)},`).join("\n")}\n    },`);
  if (body != null && body.length) lines.push(`    data=${JSON.stringify(body)}.encode("utf-8"),`);
  else if (d.requestBody.len > 0) lines.push(`    data=open(${JSON.stringify(`body-${d.summary.id}.bin`)}, "rb"),`);
  lines.push(`)`, `print(response.status_code, response.text[:500])`);
  return lines.join("\n");
}
