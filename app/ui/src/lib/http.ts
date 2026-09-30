import type { Charset, Detail } from "../api";
import { latin1ToUtf8 } from "./format";
import { CHARSETS, canonical, decodeBytes, sameCharset } from "./bodytext";

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

/** Bytes as a bash/zsh ANSI-C string (`$'…'`): printable ASCII literally, the rest as \xHH. */
function shBytes(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b >= 0x20 && b < 0x7f && b !== 0x27 && b !== 0x5c ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, "0")}`;
  return `$'${s}'`;
}

/**
 * The snippet builders take the body as text; `bytes` is given when that text is not what
 * goes over the wire in UTF-8 (a windows-1252 body, a UTF-8 BOM, invalid sequences). The
 * snippets then carry those exact bytes, so they send the same body as the session.
 */
type Bytes = Uint8Array | undefined;

/** cURL for a POSIX-style shell (sh/bash/zsh); every value is shell-quoted. */
export function buildCurl(d: Detail, body: string | null, bytes?: Bytes): string {
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
  if (bytes && bytes.length && !bytes.includes(0)) parts.push("--data-binary " + shBytes(bytes));
  else if (!bytes && body != null && body.length && !body.includes("\0")) parts.push("--data-binary " + shq(body));
  else if (d.requestBody.len > 0 || (body != null && body.length)) parts.push("--data-binary " + shq(`@body-${d.summary.id}.bin`));
  if (d.request.version === "HTTP/2") parts.push("--http2");
  return parts.join(" \\\n  ");
}

const hex = (b: number) => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66);

/** Percent-decode bytes (`+` as space if `plus`). */
function percentDecode(bytes: Uint8Array, plus: boolean): Uint8Array {
  const out = new Uint8Array(bytes.length);
  let n = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0x25 && i + 2 < bytes.length && hex(bytes[i + 1]) && hex(bytes[i + 2])) {
      out[n++] = parseInt(String.fromCharCode(bytes[i + 1], bytes[i + 2]), 16);
      i += 2;
    } else out[n++] = b === 0x2b && plus ? 0x20 : b;
  }
  return out.subarray(0, n);
}

/** Percent-decode a string into bytes; characters outside ASCII count as their UTF-8 bytes. */
function percentBytes(s: string, plus: boolean): Uint8Array {
  return percentDecode(new TextEncoder().encode(s), plus);
}

/** Percent-decode text (`+` as space) whose bytes are in `charset`. */
export function percentDecodeText(s: string, charset: string): string {
  return decodeBytes(percentBytes(s, true), charset);
}

/** Percent-encode bytes like encodeURIComponent (which does it for UTF-8 only). */
export function percentEncodeBytes(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += /[A-Za-z0-9\-_.!~*'()]/.test(String.fromCharCode(b)) && b < 0x80 ? String.fromCharCode(b) : `%${b.toString(16).toUpperCase().padStart(2, "0")}`;
  return out;
}

/** Percent-encoded bytes as text: UTF-8, or windows-1252 when they are not valid UTF-8
 * (legacy pages encode query strings in their own charset). */
function utf8OrLegacy(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return decodeBytes(bytes, "windows-1252");
  }
}

/** Name/value pairs of a query string. */
export function parseQuery(q: string): [string, string][] {
  if (!q) return [];
  return q
    .replace(/^\?/, "")
    .split("&")
    .filter(Boolean)
    .map((kv) => {
      const i = kv.indexOf("=");
      const dec = (s: string) => utf8OrLegacy(percentBytes(s, true));
      return i < 0 ? [dec(kv), ""] : [dec(kv.slice(0, i)), dec(kv.slice(i + 1))];
    });
}

/**
 * Name/value pairs of an application/x-www-form-urlencoded body (WHATWG URL §5.1, on the
 * bytes): percent-decoded bytes are text in the form's charset, which the page chose when it
 * submitted the form.
 */
export function parseForm(body: Uint8Array, charset: string): [string, string][] {
  const out: [string, string][] = [];
  let start = 0;
  const piece = (a: number, b: number) => decodeBytes(percentDecode(body.subarray(a, b), true), charset);
  for (let i = 0; i <= body.length; i++) {
    if (i < body.length && body[i] !== 0x26) continue;
    if (i > start) {
      let eq = body.indexOf(0x3d, start);
      if (eq < 0 || eq > i) eq = i;
      out.push([piece(start, eq), eq < i ? piece(eq + 1, i) : ""]);
    }
    start = i + 1;
  }
  return out;
}

/** The charset of a form body: the Content-Type's charset parameter, else a `_charset_` field
 * (HTML §4.10.21.8), else UTF-8. */
export function formCharset(contentType: string, body: Uint8Array): Charset {
  const header = /;\s*charset\s*=\s*"?([^";\s]+)/i.exec(contentType)?.[1];
  if (header && canonical(header)) return { name: canonicalName(header), source: "header", header };
  const field = parseForm(body, "utf-8").find(([k]) => k === "_charset_")?.[1];
  if (field && canonical(field)) return { name: canonicalName(field), source: "document", document: field };
  return { name: "UTF-8", source: "default" };
}

/** Display name of a charset label: as in the override menu, else the WHATWG name. */
function canonicalName(label: string): string {
  return CHARSETS.find((c) => sameCharset(c, label)) ?? canonical(label) ?? label;
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

/**
 * Base64 (or base64url) to text. Without a charset: UTF-8 (JWT, RFC 7617 `charset="UTF-8"`),
 * or ISO-8859-1/windows-1252 when the bytes are not valid UTF-8 (legacy Basic credentials).
 */
export function b64decode(s: string, charset?: string): string {
  let bytes: Uint8Array;
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "="));
    bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return "(invalid base64)";
  }
  return charset ? decodeBytes(bytes, charset) : utf8OrLegacy(bytes);
}

/**
 * Parameters in the RFC 8187 form `name*=charset'language'percent-encoded` (e.g.
 * `filename*=UTF-8''%E2%82%AC%20rates.pdf` in Content-Disposition), decoded.
 */
export function extParams(value: string): { name: string; value: string; language: string }[] {
  const out: { name: string; value: string; language: string }[] = [];
  for (const m of value.matchAll(/(?:^|;)\s*([!#$&+.^_`|~0-9A-Za-z-]+)\*\s*=\s*([^';\s]*)'([^']*)'([^;\s]*)/g)) {
    const cs = m[2] || "UTF-8";
    if (!canonical(cs)) continue;
    out.push({ name: m[1], language: m[3], value: decodeBytes(percentBytes(m[4], false), cs) });
  }
  return out;
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
export function buildFetch(d: Detail, body: string | null, bytes?: Bytes): string {
  const opts: string[] = [`  method: ${JSON.stringify(d.request.method)},`];
  const hs = mergedHeaders(d);
  if (hs.length) opts.push(`  headers: {\n${hs.map(([k, v]) => `    ${JSON.stringify(k)}: ${JSON.stringify(v)},`).join("\n")}\n  },`);
  if (bytes && bytes.length) opts.push(`  body: new Uint8Array([${bytes.join(", ")}]),`);
  else if (body != null && body.length) opts.push(`  body: ${JSON.stringify(body)},`);
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
export function buildPowerShell(d: Detail, body: string | null, bytes?: Bytes): string {
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
  if (bytes && bytes.length) lines.push(`  -Body ([byte[]](${bytes.join(",")}))`);
  else if (body != null && body.length) lines.push(`  -Body ${psq(body)}`);
  else if (d.requestBody.len > 0) lines.push(`  -InFile ${psq(`body-${d.summary.id}.bin`)}`);
  return lines.join(" `\n");
}

/** Python `requests`. JSON string literals are valid Python string literals. */
/** Bytes as a Python bytes literal. */
function pyBytes(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b >= 0x20 && b < 0x7f && b !== 0x22 && b !== 0x5c ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, "0")}`;
  return `b"${s}"`;
}

export function buildPython(d: Detail, body: string | null, bytes?: Bytes): string {
  const hs = mergedHeaders(d);
  const lines = ["import requests", ""];
  lines.push(`response = requests.request(`);
  lines.push(`    ${JSON.stringify(d.request.method)},`);
  lines.push(`    ${JSON.stringify(d.request.url)},`);
  if (hs.length) lines.push(`    headers={\n${hs.map(([k, v]) => `        ${JSON.stringify(k)}: ${JSON.stringify(v)},`).join("\n")}\n    },`);
  if (bytes && bytes.length) lines.push(`    data=${pyBytes(bytes)},`);
  else if (body != null && body.length) lines.push(`    data=${JSON.stringify(body)}.encode("utf-8"),`);
  else if (d.requestBody.len > 0) lines.push(`    data=open(${JSON.stringify(`body-${d.summary.id}.bin`)}, "rb"),`);
  lines.push(`)`, `print(response.status_code, response.text[:500])`);
  return lines.join("\n");
}
