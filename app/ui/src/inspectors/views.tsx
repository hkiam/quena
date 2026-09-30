// Smaller inspectors: WebForms, Auth, Cookies, Caching, Image, WebView,
// Transformer, Raw, JSON and XML trees.
import { useEffect, useMemo, useState } from "react";
import { api, bodyUrl, type Detail, type HeaderInspection, type Part, type Variant } from "../api";
import { fmtBytes, fmtInt, headerValue, latin1ToUtf8 } from "../lib/format";
import { b64decode, parseCookies, parseQuery, rawResponseHead, requestLine } from "../lib/http";
import { loadText } from "../lib/bodytext";
import { nodesToTree, type InspectSection } from "../lib/inspect";
import { BodyText } from "./BodyText";
import { get } from "../store";
import { parseXml } from "../lib/xml";
import { plural, t } from "../i18n";

const TREE_LIMIT = 5 << 20;
/** Rows / children rendered before a "more" control (hostile bodies can have millions). */
export const ROW_CAP = 1000;

/** "… N more" control for capped lists. */
export function MoreRows({ shown, total, onMore, step = ROW_CAP }: { shown: number; total: number; onMore: (n: number) => void; step?: number }) {
  if (total <= shown) return null;
  return (
    <div className="j-more" onClick={() => onMore(shown + step)}>
      … {t("{n} more (show {step})", { n: fmtInt(total - shown), step: fmtInt(Math.min(step, total - shown)) })}
    </div>
  );
}

function Table({ rows, head = [t("Name"), t("Value")] }: { rows: (string | React.ReactNode)[][]; head?: string[] }) {
  const [limit, setLimit] = useState(ROW_CAP);
  return (
    <>
      <table className="kv">
        <thead>
          <tr>
            {head.map((h) => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, limit).map((r, i) => (
            <tr key={i}>
              {r.map((c, j) => (
                <td key={j}>{c}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      <MoreRows shown={limit} total={rows.length} onMore={setLimit} />
    </>
  );
}

function useBodyText(detail: Detail, part: Part, limit: number) {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    setText(null);
    setError(null);
    if (info.len === 0) {
      setText("");
      return;
    }
    if (info.len > limit && !info.variants.includes("decoded")) {
      setText(null);
      return;
    }
    loadText(detail.summary.id, part, info, limit).then(
      (s) => alive && setText(s),
      (e) => alive && setError(t("Could not load the body: {error}", { error: String(e) })),
    );
    return () => {
      alive = false;
    };
  }, [detail.summary.id, part, info.len, info.complete]);
  return { text, info, error };
}

export function WebFormsView({ detail }: { detail: Detail }) {
  const query = useMemo(() => {
    const i = detail.request.url.indexOf("?");
    return i < 0 ? [] : parseQuery(detail.request.url.slice(i + 1));
  }, [detail.request.url]);
  const ct = headerValue(detail.request.headers, "content-type") ?? "";
  const { text } = useBodyText(detail, "request", 1 << 20);
  const form = ct.includes("x-www-form-urlencoded") && text ? parseQuery(text) : [];
  return (
    <div className="scroll pad">
      <h4>QueryString</h4>
      {query.length ? <Table rows={query} /> : <div className="muted">{t("No query string")}</div>}
      <h4>{t("Body")}</h4>
      {ct.includes("multipart/form-data") ? (
        <div className="muted">{t("multipart/form-data – see Plain Text / Raw ({size})", { size: fmtBytes(detail.requestBody.len) })}</div>
      ) : form.length ? (
        <Table rows={form} />
      ) : (
        <div className="muted">{detail.requestBody.len ? t("Body is not form-urlencoded ({type})", { type: ct || t("no content type") }) : t("No body")}</div>
      )}
    </div>
  );
}

function jwt(token: string): React.ReactNode {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const pretty = (s: string) => {
    try {
      return JSON.stringify(JSON.parse(b64decode(s)), null, 2);
    } catch {
      return b64decode(s);
    }
  };
  return (
    <div>
      <div className="muted">JSON Web Token</div>
      <b>Header</b>
      <pre>{pretty(parts[0])}</pre>
      <b>Payload</b>
      <pre>{pretty(parts[1])}</pre>
    </div>
  );
}

function authValue(v: string): React.ReactNode {
  const [scheme, ...rest] = v.split(" ");
  const cred = rest.join(" ").trim();
  switch (scheme.toLowerCase()) {
    case "basic":
      return (
        <>
          <div>{t("Basic authentication")}</div>
          <pre>{b64decode(cred)}</pre>
        </>
      );
    case "bearer":
      return (
        <>
          <div>{t("Bearer token")}</div>
          {jwt(cred) ?? <pre>{cred}</pre>}
        </>
      );
    case "ntlm":
    case "negotiate":
      return <div>{scheme} ({plural(cred.length, "{n} char", "{n} chars")}, {cred.startsWith("TlRMTVNTUAAB") ? t("Type {n}", { n: 1 }) : cred.startsWith("TlRMTVNTUAAC") ? t("Type {n}", { n: 2 }) : cred.startsWith("TlRMTVNTUAAD") ? t("Type {n}", { n: 3 }) : t("token")})</div>;
    default:
      return <pre>{v}</pre>;
  }
}

function InspectSectionView({ s }: { s: InspectSection }) {
  return (
    <div className="auth-token">
      {s.title && <b>{s.title}</b>}
      {s.fields.length > 0 && <Table rows={s.fields} />}
      {s.notes.map((n, i) => (
        <div key={i} className="muted">
          {n}
        </div>
      ))}
      {s.children.map((c, i) => (
        <InspectSectionView key={i} s={c} />
      ))}
      {s.code.map((c, i) => (
        <details key={i}>
          <summary>{c.caption}</summary>
          <pre>{c.text}</pre>
        </details>
      ))}
    </div>
  );
}

/**
 * A header value as seen by the header inspector plugins (e.g. Kerberos / NTLM);
 * `fallback` is shown while they run and when none applies.
 */
/** One header in the Auth view, decoded by the header-inspector plugins that recognise it.
 *  An `optional` header (cookie, token header …) only shows when a plugin found something. */
function PluginHeader({ name, value, fallback, optional }: { name: string; value: string; fallback: React.ReactNode; optional?: boolean }) {
  const [res, setRes] = useState<HeaderInspection[] | null>(null);
  useEffect(() => {
    let alive = true;
    setRes(null);
    api
      .pluginsInspectHeader(name, value)
      .then((r) => alive && setRes(r))
      .catch(() => alive && setRes([]));
    return () => {
      alive = false;
    };
  }, [name, value]);
  const ok = (res ?? []).filter((r) => !r.error && r.nodes.length);
  const failed = (res ?? []).filter((r) => r.error);
  if (optional && !ok.length && !failed.length) return null;
  return (
    <div className="auth-item">
      <h4>{name}</h4>
      {ok.length === 0 && fallback}
      {ok.map((r) => (
        <div key={r.pluginId}>
          <div className="muted small">{t("Plugin: {name}", { name: r.tab })}</div>
          {nodesToTree(r.nodes).map((s, i) => (
            <InspectSectionView key={i} s={s} />
          ))}
        </div>
      ))}
      {failed.map((r) => (
        <div key={r.pluginId} className="err small">
          {t("Plugin {name}: {error}", { name: r.tab, error: r.error ?? "" })}
        </div>
      ))}
    </div>
  );
}

// Header names the enabled header-inspector plugins look at (besides the auth headers).
let inspectorHeaders: Promise<Set<string>> | null = null;
export function forgetInspectorHeaders() {
  inspectorHeaders = null;
}
function useInspectorHeaders(): Set<string> {
  const [names, setNames] = useState<Set<string>>(new Set());
  useEffect(() => {
    let alive = true;
    inspectorHeaders ??= api
      .pluginsList()
      .then((l) => new Set(l.filter((p) => p.kind === "headerInspector" && p.enabled).flatMap((p) => p.headers.map((h) => h.toLowerCase()))))
      .catch(() => new Set<string>());
    inspectorHeaders.then((n) => alive && setNames(n));
    return () => {
      alive = false;
    };
  }, []);
  return names;
}

export function AuthView({ detail, part }: { detail: Detail; part: Part }) {
  const h = part === "request" ? detail.request.headers : detail.response?.headers ?? [];
  const names = part === "request" ? ["authorization", "proxy-authorization"] : ["www-authenticate", "proxy-authenticate"];
  const extra = useInspectorHeaders();
  const found = h.filter(([k]) => names.includes(k.toLowerCase()));
  // Tokens elsewhere (JWT in a cookie or an X-Access-Token header …), shown when recognised.
  const more = h.filter(([k]) => !names.includes(k.toLowerCase()) && extra.has(k.toLowerCase()));
  return (
    <div className="scroll pad">
      {found.length === 0 && <div className="muted">{t("No {header} headers are present.", { header: part === "request" ? "Authorization" : "WWW-Authenticate" })}</div>}
      {found.map(([k, v], i) => {
        const value = latin1ToUtf8(v);
        return <PluginHeader key={i} name={k} value={value} fallback={part === "request" ? authValue(value) : <pre>{value}</pre>} />;
      })}
      {more.map(([k, v], i) => (
        <PluginHeader key={`m${i}`} name={k} value={latin1ToUtf8(v)} fallback={null} optional />
      ))}
    </div>
  );
}

export function CookiesView({ detail, part }: { detail: Detail; part: Part }) {
  if (part === "request") {
    const rows = detail.request.headers.filter(([k]) => k.toLowerCase() === "cookie").flatMap(([, v]) => parseCookies(latin1ToUtf8(v)));
    return <div className="scroll pad">{rows.length ? <Table rows={rows} /> : <div className="muted">{t("This request did not send any cookie data.")}</div>}</div>;
  }
  const sets = (detail.response?.headers ?? []).filter(([k]) => k.toLowerCase() === "set-cookie").map(([, v]) => latin1ToUtf8(v));
  const rows = sets.map((s) => {
    const [nv, ...attrs] = s.split(";").map((x) => x.trim());
    const i = nv.indexOf("=");
    return [nv.slice(0, Math.max(0, i)), nv.slice(i + 1), attrs.join("; ")];
  });
  return <div className="scroll pad">{rows.length ? <Table head={[t("Name"), t("Value"), t("Attributes")]} rows={rows} /> : <div className="muted">{t("This response did not set any cookies.")}</div>}</div>;
}

export function CachingView({ detail }: { detail: Detail }) {
  const r = detail.response;
  if (!r) return <div className="placeholder">{t("No response")}</div>;
  const h = r.headers;
  const cc = headerValue(h, "cache-control");
  const notes: string[] = [];
  if (r.status === 304) notes.push(t("304 Not Modified: the client's cached copy was revalidated."));
  if (cc) {
    for (const d of cc.split(",").map((x) => x.trim().toLowerCase())) {
      if (d === "no-store") notes.push(t("no-store: must not be stored in any cache."));
      else if (d === "no-cache") notes.push(t("no-cache: may be stored, but must be revalidated before every use."));
      else if (d === "private") notes.push(t("private: only the browser cache may store it (no shared caches)."));
      else if (d === "public") notes.push(t("public: may be stored by shared caches."));
      else if (d.startsWith("max-age=")) notes.push(t("max-age: fresh for {n} seconds.", { n: fmtInt(Number(d.slice(8))) }));
      else if (d.startsWith("s-maxage=")) notes.push(t("s-maxage: shared caches keep it fresh for {n} seconds.", { n: d.slice(9) }));
      else if (d === "must-revalidate") notes.push(t("must-revalidate: stale copies must be revalidated."));
      else if (d === "immutable") notes.push(t("immutable: will not change during its freshness lifetime."));
    }
  } else notes.push(t("No Cache-Control header present."));
  const exp = headerValue(h, "expires");
  const date = headerValue(h, "date");
  const lm = headerValue(h, "last-modified");
  if (exp) notes.push(`Expires: ${exp}${date ? ` (Date: ${date})` : ""}`);
  if (!cc && !exp && lm && date) {
    const age = (Date.parse(date) - Date.parse(lm)) / 1000;
    if (age > 0) notes.push(t("Heuristic freshness (10% of Date − Last-Modified): ~{n} seconds.", { n: fmtInt(Math.round(age / 10)) }));
  }
  const etag = headerValue(h, "etag");
  if (etag) notes.push(t("ETag {etag} allows conditional revalidation (If-None-Match).", { etag }));
  if (lm) notes.push(t("Last-Modified {date} allows conditional revalidation (If-Modified-Since).", { date: lm }));
  const vary = headerValue(h, "vary");
  if (vary) notes.push(t("Vary: {vary} – cached per value of these request headers.", { vary }));
  const pragma = headerValue(h, "pragma");
  if (pragma) notes.push(t("Pragma: {pragma} (HTTP/1.0 legacy).", { pragma }));
  return (
    <div className="scroll pad">
      <h4>{t("Response Caching Information")}</h4>
      <ul className="notes">
        {notes.map((n, i) => (
          <li key={i}>{n}</li>
        ))}
      </ul>
    </div>
  );
}

export function ImageView({ detail }: { detail: Detail }) {
  const info = detail.responseBody;
  const [dim, setDim] = useState<string>("");
  if (!info.len) return <div className="placeholder">{t("No body")}</div>;
  const v: Variant = info.variants.includes("decoded") ? "decoded" : "raw";
  return (
    <div className="imageview">
      <div className="lt-bar">
        <span className="lt-info">
          {info.contentType} · {fmtBytes(info.len)} {dim && `· ${dim}`}
        </span>
      </div>
      <div className="img-wrap checker">
        <img
          src={bodyUrl(detail.summary.id, "response", v)}
          onLoad={(e) => setDim(`${(e.target as HTMLImageElement).naturalWidth} × ${(e.target as HTMLImageElement).naturalHeight}`)}
          onError={() => setDim(t("not a displayable image"))}
        />
      </div>
    </div>
  );
}

export function WebViewPane({ detail }: { detail: Detail }) {
  const info = detail.responseBody;
  const [on, setOn] = useState(false);
  if (!info.len) return <div className="placeholder">{t("No body")}</div>;
  const v: Variant = info.variants.includes("decoded") ? "decoded" : "raw";
  if (!on) {
    return (
      <div className="placeholder">
        <p>{t("Renders the response in a sandboxed frame without scripts, forms or network access to the page's origin.")}</p>
        <button onClick={() => setOn(true)}>{t("Render")}</button>
      </div>
    );
  }
  return <iframe className="webview" sandbox="" referrerPolicy="no-referrer" src={bodyUrl(detail.summary.id, "response", v)} />;
}

export function TransformerView({ detail }: { detail: Detail }) {
  const info = detail.responseBody;
  const decode = get().settings?.decode;
  return (
    <div className="scroll pad">
      <h4>{t("Response body encoding")}</h4>
      <Table
        rows={[
          ["Transfer-Encoding", info.transferEncoding ?? t("(none) – chunking is removed while recording")],
          ["Content-Encoding", info.contentEncoding ?? t("(none)")],
          [t("Bytes on the wire"), fmtInt(info.wireLen)],
          [t("Bytes stored"), fmtInt(info.len) + (info.truncated ? ` ${t("(truncated: recording limit reached)")}` : "")],
          [t("Complete"), info.complete ? t("yes") : t("no (still receiving)")],
          [t("Decoded view"), info.variants.includes("decoded") ? (decode ? t("on (toolbar ‘Decode’)") : t("off – enable ‘Decode’ in the toolbar")) : t("not needed")],
        ]}
      />
      <p className="muted">{t("Quena never modifies the recorded body; decoded and formatted views are derived caches (Raw Traffic = Source of Truth).")}</p>
    </div>
  );
}

export function RawView({ detail, part, wrap }: { detail: Detail; part: Part; wrap: boolean }) {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const head = part === "request" ? [requestLine(detail), ...detail.request.headers.map(([k, v]) => `${k}: ${latin1ToUtf8(v)}`)].join("\n") : detail.response ? rawResponseHead(detail).trimEnd() : "";
  if (part === "response" && !detail.response) return <div className="placeholder">{t("No response")}</div>;
  const textBody = info.len > 0 && (info.isText || info.variants.includes("decoded"));
  // Without a text body the head gets the whole pane; the binary hint is one line below it.
  return (
    <div className={textBody ? "rawview" : "rawview head-only"}>
      <pre className="raw-head">
        {head}
        {info.len > 0 && !textBody && <span className="raw-binary">{`\n\n${t("Binary body ({size}) – see Hex", { size: fmtBytes(info.len) })}`}</span>}
      </pre>
      {textBody && (
        <div className="raw-body">
          <BodyText id={detail.summary.id} part={part} info={info} variant="raw" highlight={false} wrap={wrap} />
        </div>
      )}
    </div>
  );
}

// ------------------------------------------------------------------ trees

type J = unknown;

function JNode({ k, v, depth }: { k: string | null; v: J; depth: number }) {
  const [open, setOpen] = useState(depth < 2);
  const [limit, setLimit] = useState(500);
  const isObj = v !== null && typeof v === "object";
  if (!isObj) {
    const cls = typeof v === "string" ? "j-str" : typeof v === "number" ? "j-num" : "j-lit";
    return (
      <div className="j-row">
        {k !== null && <span className="j-key">{k}: </span>}
        <span className={cls}>{typeof v === "string" ? JSON.stringify(v) : String(v)}</span>
      </div>
    );
  }
  const entries: [string, J][] = Array.isArray(v) ? v.map((x, i) => [String(i), x]) : Object.entries(v as Record<string, J>);
  return (
    <div className="j-row">
      <span className="j-toggle" onClick={() => setOpen(!open)}>
        {open ? "▾" : "▸"}
      </span>
      {k !== null && <span className="j-key">{k}: </span>}
      <span className="j-meta">{Array.isArray(v) ? `[${entries.length}]` : `{${entries.length}}`}</span>
      {open && (
        <div className="j-children">
          {entries.slice(0, limit).map(([ck, cv]) => (
            <JNode key={ck} k={ck} v={cv} depth={depth + 1} />
          ))}
          {entries.length > limit && (
            <div className="j-more" onClick={() => setLimit(limit + 1000)}>
              … {t("{n} more", { n: fmtInt(entries.length - limit) })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function JsonView({ detail, part }: { detail: Detail; part: Part }) {
  const { text, info, error } = useBodyText(detail, part, TREE_LIMIT);
  const parsed = useMemo(() => {
    if (text == null) return { err: null, v: undefined };
    const s = text.trim();
    try {
      return { err: null, v: JSON.parse(s) as J };
    } catch (e) {
      // NDJSON / JSONP
      const lines = s.split("\n").filter(Boolean);
      if (lines.length > 1) {
        try {
          return { err: null, v: lines.slice(0, 10000).map((l) => JSON.parse(l)) };
        } catch {
          /* fall through */
        }
      }
      const m = s.match(/^[\w$.]+\(([\s\S]*)\);?$/);
      if (m) {
        try {
          return { err: null, v: JSON.parse(m[1]) };
        } catch {
          /* ignore */
        }
      }
      return { err: String(e), v: undefined };
    }
  }, [text]);
  if (!info.len) return <div className="placeholder">{t("No body")}</div>;
  if (info.len > TREE_LIMIT) return <div className="placeholder">{t("Body is {size} – too large for the tree view. Use Body (formatted) instead.", { size: fmtBytes(info.len) })}</div>;
  if (error) return <div className="placeholder">{error}</div>;
  if (text == null) return <div className="placeholder">{t("Loading…")}</div>;
  if (parsed.err) return <div className="placeholder">{t("Not valid JSON: {error}", { error: parsed.err })}</div>;
  return (
    <div className="scroll pad mono">
      <JNode k={null} v={parsed.v} depth={0} />
    </div>
  );
}

export function XNode({ n, depth }: { n: Element; depth: number }) {
  const [open, setOpen] = useState(depth < 3);
  const [limit, setLimit] = useState(ROW_CAP);
  const kids = Array.from(n.childNodes).filter((c) => c.nodeType === 1 || (c.nodeType === 3 && (c.textContent ?? "").trim()) || c.nodeType === 4);
  const allAttrs = n.attributes;
  const attrs = Array.from(allAttrs).slice(0, 200);
  const onlyText = kids.length === 1 && kids[0].nodeType !== 1;
  return (
    <div className="j-row">
      {!onlyText && kids.length > 0 ? (
        <span className="j-toggle" onClick={() => setOpen(!open)}>
          {open ? "▾" : "▸"}
        </span>
      ) : (
        <span className="j-toggle" />
      )}
      <span className="x-tag">{n.nodeName}</span>
      {attrs.map((a) => (
        <span key={a.name} className="x-attr">
          {" "}
          {a.name}=<span className="j-str">"{a.value}"</span>
        </span>
      ))}
      {allAttrs.length > attrs.length && <span className="muted"> … {t("{n} more attributes", { n: fmtInt(allAttrs.length - attrs.length) })}</span>}
      {onlyText && <span className="x-text"> {kids[0].textContent}</span>}
      {open && !onlyText && (
        <div className="j-children">
          {kids.slice(0, limit).map((c, i) =>
            c.nodeType === 1 ? (
              <XNode key={i} n={c as Element} depth={depth + 1} />
            ) : (
              <div key={i} className="x-text">
                {c.textContent}
              </div>
            ),
          )}
          <MoreRows shown={limit} total={kids.length} onMore={setLimit} />
        </div>
      )}
    </div>
  );
}

export function XmlView({ detail, part }: { detail: Detail; part: Part }) {
  const { text, info, error } = useBodyText(detail, part, TREE_LIMIT);
  const doc = useMemo(() => (text == null ? null : parseXml(text)), [text]);
  if (!info.len) return <div className="placeholder">{t("No body")}</div>;
  if (info.len > TREE_LIMIT) return <div className="placeholder">{t("Body is {size} – too large for the tree view. Use Body (formatted) instead.", { size: fmtBytes(info.len) })}</div>;
  if (error) return <div className="placeholder">{error}</div>;
  if (!doc) return <div className="placeholder">{t("Loading…")}</div>;
  if ("error" in doc) return <div className="placeholder">{doc.error}</div>;
  return (
    <div className="scroll pad mono">
      <XNode n={doc.root} depth={0} />
    </div>
  );
}
