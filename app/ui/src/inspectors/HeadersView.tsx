// Fiddler-style headers inspector: request/status line, headers grouped by category.
import { useState } from "react";
import type { Detail, Part } from "../api";
import { latin1ToUtf8 } from "../lib/format";
import { requestLine } from "../lib/http";
import { CodeView } from "./CodeView";

const GROUPS: [string, string[]][] = [
  ["Cache", ["cache-control", "expires", "pragma", "if-modified-since", "if-none-match", "etag", "last-modified", "age", "vary", "date", "if-match", "if-unmodified-since"]],
  ["Client", ["accept", "accept-encoding", "accept-language", "accept-charset", "user-agent", "dnt", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "priority"]],
  ["Cookies / Login", ["cookie", "set-cookie", "authorization", "proxy-authorization", "www-authenticate", "proxy-authenticate"]],
  ["Entity", ["content-type", "content-length", "content-encoding", "content-language", "content-disposition", "content-range", "content-md5", "content-location"]],
  ["Security", ["origin", "referer", "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-headers", "access-control-allow-methods", "access-control-expose-headers", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user", "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy"]],
  ["Transport", ["host", "connection", "proxy-connection", "transfer-encoding", "keep-alive", "upgrade", "te", "trailer", "via", "alt-svc", "location", "server", "x-forwarded-for", "forwarded"]],
];

function category(name: string): string {
  const n = name.toLowerCase();
  if (n.startsWith(":")) return "Pseudo-Headers";
  for (const [g, names] of GROUPS) if (names.includes(n)) return g;
  if (n.startsWith("sec-") || n.startsWith("access-control-")) return "Security";
  if (n.startsWith("x-") || n.startsWith("cf-")) return "Miscellaneous";
  return "Miscellaneous";
}

export function HeadersView({ detail, part }: { detail: Detail; part: Part }) {
  const [raw, setRaw] = useState(false);
  const head = part === "request" ? detail.request : detail.response;
  if (!head) return <div className="placeholder">{detail.summary.state === "aborted" ? "No response (session aborted)" : "Waiting for response…"}</div>;
  const first = part === "request" ? requestLine(detail) : `${detail.response!.version} ${detail.response!.status} ${detail.response!.reason}`;
  if (raw) {
    const text = [first, ...head.headers.map(([k, v]) => `${k}: ${latin1ToUtf8(v)}`)].join("\n");
    return (
      <div className="headers-view">
        <div className="hv-bar">
          <button onClick={() => setRaw(false)}>Grouped</button>
        </div>
        <CodeView text={text} wrap />
      </div>
    );
  }
  const groups = new Map<string, [string, string][]>();
  for (const [k, v] of head.headers) {
    const g = category(k);
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g)!.push([k, v]);
  }
  const order = ["Pseudo-Headers", "Cache", "Client", "Cookies / Login", "Entity", "Miscellaneous", "Security", "Transport"];
  return (
    <div className="headers-view">
      <div className="hv-bar">
        <span className="hv-title">{part === "request" ? "Request Headers" : "Response Headers"}</span>
        <button onClick={() => setRaw(true)}>Raw</button>
        <button onClick={() => navigator.clipboard.writeText([first, ...head.headers.map(([k, v]) => `${k}: ${latin1ToUtf8(v)}`)].join("\r\n"))}>Copy</button>
      </div>
      <div className="hv-scroll">
        <div className="hv-first">{first}</div>
        {order
          .filter((g) => groups.has(g))
          .map((g) => (
            <details key={g} open className="hv-group">
              <summary>{g}</summary>
              {groups
                .get(g)!
                .slice()
                .sort((a, b) => a[0].localeCompare(b[0]))
                .map(([k, v], i) => (
                  <div className="hv-row" key={i} title="Double-click to copy" onDoubleClick={() => navigator.clipboard.writeText(`${k}: ${latin1ToUtf8(v)}`)}>
                    <span className="hv-name">{k}</span>: <span className="hv-value">{latin1ToUtf8(v)}</span>
                  </div>
                ))}
            </details>
          ))}
        {head.headers.length === 0 && <div className="placeholder">No headers</div>}
      </div>
    </div>
  );
}
