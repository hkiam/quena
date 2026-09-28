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
