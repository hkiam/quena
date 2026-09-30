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

function shq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

const SKIP_CURL = new Set(["content-length", "host", "connection", "proxy-connection", "accept-encoding", "transfer-encoding"]);

export function buildCurl(d: Detail, body: string | null): string {
  const parts = ["curl"];
  if (d.request.method !== "GET" || (body && d.request.method === "GET")) parts.push("-X", d.request.method);
  parts.push(shq(d.request.url));
  for (const [k, v] of d.request.headers) {
    if (SKIP_CURL.has(k.toLowerCase()) || k.startsWith(":")) continue;
    parts.push("-H", shq(`${k}: ${latin1ToUtf8(v)}`));
  }
  if (d.request.headers.some(([k]) => k.toLowerCase() === "accept-encoding")) parts.push("--compressed");
  if (body != null && body.length) parts.push("--data-binary", shq(body));
  else if (d.requestBody.len > 0) parts.push("--data-binary", `@body-${d.summary.id}.bin`);
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

/** JavaScript `fetch` (browser DevTools console or Node 18+). */
export function buildFetch(d: Detail, body: string | null): string {
  const opts: string[] = [`  method: ${JSON.stringify(d.request.method)},`];
  const hs = snippetHeaders(d);
  if (hs.length) opts.push(`  headers: {\n${hs.map(([k, v]) => `    ${JSON.stringify(k)}: ${JSON.stringify(v)},`).join("\n")}\n  },`);
  if (body != null && body.length) opts.push(`  body: ${JSON.stringify(body)},`);
  else if (d.requestBody.len > 0) opts.push(`  // body: ${d.requestBody.len} bytes (binary or large, not included)`);
  return `await fetch(${JSON.stringify(d.request.url)}, {\n${opts.join("\n")}\n});`;
}

function psq(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}

/** PowerShell `Invoke-WebRequest`. */
export function buildPowerShell(d: Detail, body: string | null): string {
  const hs = snippetHeaders(d);
  const ct = hs.find(([k]) => k.toLowerCase() === "content-type")?.[1];
  const ua = hs.find(([k]) => k.toLowerCase() === "user-agent")?.[1];
  // Content-Type and User-Agent must go through their own parameters.
  const rest = hs.filter(([k]) => !["content-type", "user-agent"].includes(k.toLowerCase()));
  const lines = [`Invoke-WebRequest -Uri ${psq(d.request.url)} -Method ${d.request.method}`];
  if (rest.length) lines.push(`  -Headers @{\n${rest.map(([k, v]) => `    ${psq(k)} = ${psq(v)}`).join("\n")}\n  }`);
  if (ct) lines.push(`  -ContentType ${psq(ct)}`);
  if (ua) lines.push(`  -UserAgent ${psq(ua)}`);
  if (body != null && body.length) lines.push(`  -Body ${psq(body)}`);
  else if (d.requestBody.len > 0) lines.push(`  -InFile ${psq(`body-${d.summary.id}.bin`)}`);
  return lines.join(" `\n");
}

/** Python `requests`. */
export function buildPython(d: Detail, body: string | null): string {
  const hs = snippetHeaders(d);
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
