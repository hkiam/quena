// Headers inspector: start line plus a name/value table in wire order, with a filter,
// optional A–Z sorting and a topic tag per header.
import { useMemo, useState } from "react";
import type { Detail, Part } from "../api";
import { latin1ToUtf8 } from "../lib/format";
import { extParams, requestLine } from "../lib/http";
import { CodeView } from "./CodeView";
import { plural, t } from "../i18n";
import { copyText } from "../actions";
import { openMenu, withSelection } from "../components/contextMenus";
import { copyItem } from "./inspectMenus";
import { addHeaderColumn } from "../headerColumns";
import { api } from "../api";
import { get, say, set } from "../store";
import { addClause, clause } from "../lib/columnFilter";

/** Narrow the list to sessions with the same header value. */
async function filterByHeader(response: boolean, name: string, value: string) {
  const f = get().filters;
  const c = clause(`${response ? "resheader" : "reqheader"}.${name.toLowerCase()}`, `== ${JSON.stringify(value)}`);
  if (!f || !c) return;
  const next = { ...f, enabled: true, expression: addClause(f.enabled ? f.expression : "", c) };
  try {
    await api.setFilters(next);
    set({ filters: next });
    say(t("Filter: {expr}", { expr: next.expression }));
  } catch (e) {
    say(String(e), "error");
  }
}

type Topic = "auth" | "cookie" | "cache" | "cors" | "content" | "conn" | "fetch" | "policy";

const TOPIC_LABEL: Record<Topic, string> = {
  auth: "auth",
  cookie: "cookie",
  cache: "cache",
  cors: "cors",
  content: "body",
  conn: "conn",
  fetch: "fetch",
  policy: "policy",
};

const EXACT: Record<string, Topic> = {
  authorization: "auth",
  "proxy-authorization": "auth",
  "www-authenticate": "auth",
  "proxy-authenticate": "auth",
  cookie: "cookie",
  "set-cookie": "cookie",
  "cache-control": "cache",
  expires: "cache",
  pragma: "cache",
  etag: "cache",
  "last-modified": "cache",
  "if-modified-since": "cache",
  "if-none-match": "cache",
  "if-match": "cache",
  "if-unmodified-since": "cache",
  age: "cache",
  vary: "cache",
  origin: "cors",
  "content-type": "content",
  "content-length": "content",
  "content-encoding": "content",
  "content-language": "content",
  "content-disposition": "content",
  "content-range": "content",
  "accept-ranges": "content",
  "transfer-encoding": "content",
  host: "conn",
  connection: "conn",
  "proxy-connection": "conn",
  "keep-alive": "conn",
  upgrade: "conn",
  te: "conn",
  via: "conn",
  "alt-svc": "conn",
  forwarded: "conn",
  "x-forwarded-for": "conn",
  "strict-transport-security": "policy",
  "content-security-policy": "policy",
  "x-frame-options": "policy",
  "x-content-type-options": "policy",
  "referrer-policy": "policy",
  "permissions-policy": "policy",
};

function topic(name: string): Topic | null {
  const n = name.toLowerCase();
  if (EXACT[n]) return EXACT[n];
  if (n.startsWith("access-control-")) return "cors";
  if (n.startsWith("sec-fetch-") || n.startsWith("sec-ch-")) return "fetch";
  if (n.startsWith("cross-origin-")) return "policy";
  return null;
}

export function HeadersView({ detail, part }: { detail: Detail; part: Part }) {
  const [raw, setRaw] = useState(false);
  const [sorted, setSorted] = useState(false);
  const [filter, setFilter] = useState("");
  const head = part === "request" ? detail.request : detail.response;
  const rows = useMemo(() => {
    if (!head) return [];
    const q = filter.trim().toLowerCase();
    const all = head.headers.map(([k, v]) => ({ k, v: latin1ToUtf8(v), t: topic(k) }));
    const hit = q ? all.filter((h) => h.k.toLowerCase().includes(q) || h.v.toLowerCase().includes(q) || (h.t && TOPIC_LABEL[h.t] === q)) : all;
    return sorted ? [...hit].sort((a, b) => a.k.localeCompare(b.k)) : hit;
  }, [head, filter, sorted]);
  if (!head) return <div className="placeholder">{detail.summary.state === "aborted" ? t("No response (session aborted)") : t("Waiting for response…")}</div>;
  const first = part === "request" ? requestLine(detail) : `${detail.response!.version} ${detail.response!.status} ${detail.response!.reason}`;
  const text = (sep: string) => [first, ...head.headers.map(([k, v]) => `${k}: ${latin1ToUtf8(v)}`)].join(sep);
  if (raw) {
    return (
      <div className="headers-view">
        <div className="hv-bar">
          <span className="hv-title">{plural(head.headers.length, "{n} header", "{n} headers")}</span>
          <button onClick={() => setRaw(false)}>{t("Table")}</button>
        </div>
        <CodeView text={text("\n")} wrap />
      </div>
    );
  }
  return (
    <div className="headers-view">
      <div className="hv-bar">
        <input className="hv-filter" placeholder={t("Filter headers…")} value={filter} spellCheck={false} onChange={(e) => setFilter(e.target.value)} />
        <span className="muted small">{filter ? `${rows.length} / ${head.headers.length}` : head.headers.length}</span>
        <span className="tp-spacer" />
        <button className={sorted ? "on" : ""} title={t("Sort by name (otherwise wire order)")} onClick={() => setSorted(!sorted)}>
          A–Z
        </button>
        <button onClick={() => setRaw(true)}>{t("Raw")}</button>
        <button onClick={() => void copyText(text("\r\n"))}>{t("Copy")}</button>
      </div>
      <div className="hv-scroll">
        <div className="hv-first">{first}</div>
        <table className="hv-table">
          <tbody>
            {rows.map((h, i) => (
              <tr
                key={i}
                title={t("Double-click to copy")}
                onDoubleClick={() => void copyText(`${h.k}: ${h.v}`)}
                onContextMenu={(e) =>
                  openMenu(
                    e,
                    withSelection(
                      [
                        copyItem(t("Copy Value"), h.v),
                        copyItem(t("Copy Name"), h.k),
                        copyItem(t("Copy Header"), `${h.k}: ${h.v}`),
                        copyItem(t("Copy All Headers"), text("\r\n")),
                        { separator: true },
                        { label: t("Show Only {name}", { name: h.k }), action: () => setFilter(h.k) },
                        { label: t("Add {name} as a Column", { name: h.k }), action: () => void addHeaderColumn(part === "response", h.k) },
                        { label: t("Filter Sessions with this {name}", { name: h.k }), action: () => void filterByHeader(part === "response", h.k, h.v) },
                      ],
                      e.target as Element,
                    ),
                  )
                }
              >
                <td className="hv-name">{h.k}</td>
                <td className="hv-value">
                  {h.v}
                  {extParams(h.v).map((p, j) => (
                    <div key={j} className="hv-ext" title={t("RFC 8187 encoded parameter, decoded")}>
                      {p.name}* = {p.value}
                      {p.language && <span className="muted"> ({p.language})</span>}
                    </div>
                  ))}
                </td>
                <td className="hv-tag">{h.t && <span className={`tag tag-${h.t}`} onClick={() => setFilter(TOPIC_LABEL[h.t!])}>{TOPIC_LABEL[h.t]}</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {head.headers.length === 0 && <div className="placeholder">{t("No headers")}</div>}
      </div>
    </div>
  );
}
