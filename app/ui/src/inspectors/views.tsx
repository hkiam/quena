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

const TREE_LIMIT = 5 << 20;
/** Rows / children rendered before a "more" control (hostile bodies can have millions). */
export const ROW_CAP = 1000;

/** "… N more" control for capped lists. */
export function MoreRows({ shown, total, onMore, step = ROW_CAP }: { shown: number; total: number; onMore: (n: number) => void; step?: number }) {
  if (total <= shown) return null;
  return (
    <div className="j-more" onClick={() => onMore(shown + step)}>
      … {fmtInt(total - shown)} more (show {fmtInt(Math.min(step, total - shown))})
    </div>
  );
}

function Table({ rows, head = ["Name", "Value"] }: { rows: (string | React.ReactNode)[][]; head?: string[] }) {
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
      (t) => alive && setText(t),
      (e) => alive && setError(`Could not load the body: ${String(e)}`),
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
      {query.length ? <Table rows={query} /> : <div className="muted">No query string</div>}
      <h4>Body</h4>
      {ct.includes("multipart/form-data") ? (
        <div className="muted">multipart/form-data – see TextView / Raw ({fmtBytes(detail.requestBody.len)})</div>
      ) : form.length ? (
        <Table rows={form} />
      ) : (
        <div className="muted">{detail.requestBody.len ? `Body is not form-urlencoded (${ct || "no content type"})` : "No body"}</div>
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
          <div>Basic authentication</div>
          <pre>{b64decode(cred)}</pre>
        </>
      );
    case "bearer":
      return (
        <>
          <div>Bearer token</div>
          {jwt(cred) ?? <pre>{cred}</pre>}
        </>
      );
    case "ntlm":
    case "negotiate":
      return <div>{scheme} ({cred.length} chars, {cred.startsWith("TlRMTVNTUAAB") ? "Type 1" : cred.startsWith("TlRMTVNTUAAC") ? "Type 2" : cred.startsWith("TlRMTVNTUAAD") ? "Type 3" : "token"})</div>;
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
function PluginHeader({ name, value, fallback }: { name: string; value: string; fallback: React.ReactNode }) {
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
  const ok = (res ?? []).filter((r) => !r.error);
  const failed = (res ?? []).filter((r) => r.error);
  return (
    <>
      {ok.length === 0 && fallback}
      {ok.map((r) => (
        <div key={r.pluginId}>
          <div className="muted small">Plugin: {r.tab}</div>
          {nodesToTree(r.nodes).map((s, i) => (
            <InspectSectionView key={i} s={s} />
          ))}
        </div>
      ))}
      {failed.map((r) => (
        <div key={r.pluginId} className="err small">
          Plugin {r.tab}: {r.error}
        </div>
      ))}
    </>
  );
}

export function AuthView({ detail, part }: { detail: Detail; part: Part }) {
  const h = part === "request" ? detail.request.headers : detail.response?.headers ?? [];
  const names = part === "request" ? ["authorization", "proxy-authorization"] : ["www-authenticate", "proxy-authenticate"];
  const found = h.filter(([k]) => names.includes(k.toLowerCase()));
  return (
    <div className="scroll pad">
      {found.length === 0 && <div className="muted">No {part === "request" ? "Authorization" : "WWW-Authenticate"} headers are present.</div>}
      {found.map(([k, v], i) => {
        const value = latin1ToUtf8(v);
        return (
          <div key={i} className="auth-item">
            <h4>{k}</h4>
            <PluginHeader name={k} value={value} fallback={part === "request" ? authValue(value) : <pre>{value}</pre>} />
          </div>
        );
      })}
    </div>
  );
}

export function CookiesView({ detail, part }: { detail: Detail; part: Part }) {
  if (part === "request") {
    const rows = detail.request.headers.filter(([k]) => k.toLowerCase() === "cookie").flatMap(([, v]) => parseCookies(latin1ToUtf8(v)));
    return <div className="scroll pad">{rows.length ? <Table rows={rows} /> : <div className="muted">This request did not send any cookie data.</div>}</div>;
  }
  const sets = (detail.response?.headers ?? []).filter(([k]) => k.toLowerCase() === "set-cookie").map(([, v]) => latin1ToUtf8(v));
  const rows = sets.map((s) => {
    const [nv, ...attrs] = s.split(";").map((x) => x.trim());
    const i = nv.indexOf("=");
    return [nv.slice(0, Math.max(0, i)), nv.slice(i + 1), attrs.join("; ")];
  });
  return <div className="scroll pad">{rows.length ? <Table head={["Name", "Value", "Attributes"]} rows={rows} /> : <div className="muted">This response did not set any cookies.</div>}</div>;
}

export function CachingView({ detail }: { detail: Detail }) {
  const r = detail.response;
  if (!r) return <div className="placeholder">No response</div>;
  const h = r.headers;
  const cc = headerValue(h, "cache-control");
  const notes: string[] = [];
  if (r.status === 304) notes.push("304 Not Modified: the client's cached copy was revalidated.");
  if (cc) {
    for (const d of cc.split(",").map((x) => x.trim().toLowerCase())) {
      if (d === "no-store") notes.push("no-store: must not be stored in any cache.");
      else if (d === "no-cache") notes.push("no-cache: may be stored, but must be revalidated before every use.");
      else if (d === "private") notes.push("private: only the browser cache may store it (no shared caches).");
      else if (d === "public") notes.push("public: may be stored by shared caches.");
      else if (d.startsWith("max-age=")) notes.push(`max-age: fresh for ${fmtInt(Number(d.slice(8)))} seconds.`);
      else if (d.startsWith("s-maxage=")) notes.push(`s-maxage: shared caches keep it fresh for ${d.slice(9)} seconds.`);
      else if (d === "must-revalidate") notes.push("must-revalidate: stale copies must be revalidated.");
      else if (d === "immutable") notes.push("immutable: will not change during its freshness lifetime.");
    }
  } else notes.push("No Cache-Control header present.");
  const exp = headerValue(h, "expires");
  const date = headerValue(h, "date");
  const lm = headerValue(h, "last-modified");
  if (exp) notes.push(`Expires: ${exp}${date ? ` (Date: ${date})` : ""}`);
  if (!cc && !exp && lm && date) {
    const age = (Date.parse(date) - Date.parse(lm)) / 1000;
    if (age > 0) notes.push(`Heuristic freshness (10% of Date − Last-Modified): ~${fmtInt(Math.round(age / 10))} seconds.`);
  }
  const etag = headerValue(h, "etag");
  if (etag) notes.push(`ETag ${etag} allows conditional revalidation (If-None-Match).`);
  if (lm) notes.push(`Last-Modified ${lm} allows conditional revalidation (If-Modified-Since).`);
  const vary = headerValue(h, "vary");
  if (vary) notes.push(`Vary: ${vary} – cached per value of these request headers.`);
  const pragma = headerValue(h, "pragma");
  if (pragma) notes.push(`Pragma: ${pragma} (HTTP/1.0 legacy).`);
  return (
    <div className="scroll pad">
      <h4>Response Caching Information</h4>
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
  if (!info.len) return <div className="placeholder">No body</div>;
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
          onError={() => setDim("not a displayable image")}
        />
      </div>
    </div>
  );
}

export function WebViewPane({ detail }: { detail: Detail }) {
  const info = detail.responseBody;
  const [on, setOn] = useState(false);
  if (!info.len) return <div className="placeholder">No body</div>;
  const v: Variant = info.variants.includes("decoded") ? "decoded" : "raw";
  if (!on) {
    return (
      <div className="placeholder">
        <p>Renders the response in a sandboxed frame without scripts, forms or network access to the page's origin.</p>
        <button onClick={() => setOn(true)}>Render</button>
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
      <h4>Response body encoding</h4>
      <Table
        rows={[
          ["Transfer-Encoding", info.transferEncoding ?? "(none) – chunking is removed while recording"],
          ["Content-Encoding", info.contentEncoding ?? "(none)"],
          ["Bytes on the wire", fmtInt(info.wireLen)],
          ["Bytes stored", fmtInt(info.len) + (info.truncated ? " (truncated: recording limit reached)" : "")],
          ["Complete", info.complete ? "yes" : "no (still receiving)"],
          ["Decoded view", info.variants.includes("decoded") ? (decode ? "on (toolbar ‘Decode’)" : "off – enable ‘Decode’ in the toolbar") : "not needed"],
        ]}
      />
      <p className="muted">Quena never modifies the recorded body; decoded and formatted views are derived caches (Raw Traffic = Source of Truth).</p>
    </div>
  );
}

export function RawView({ detail, part, wrap }: { detail: Detail; part: Part; wrap: boolean }) {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const head = part === "request" ? [requestLine(detail), ...detail.request.headers.map(([k, v]) => `${k}: ${latin1ToUtf8(v)}`)].join("\n") : detail.response ? rawResponseHead(detail).trimEnd() : "";
  if (part === "response" && !detail.response) return <div className="placeholder">No response</div>;
  return (
    <div className="rawview">
      <pre className="raw-head">{head}</pre>
      {info.len > 0 &&
        (info.isText || info.variants.includes("decoded") ? (
          <div className="raw-body">
            <BodyText id={detail.summary.id} part={part} info={info} variant="raw" highlight={false} wrap={wrap} />
          </div>
        ) : (
          <div className="placeholder">Binary body ({fmtBytes(info.len)}) – see HexView</div>
        ))}
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
              … {fmtInt(entries.length - limit)} more
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
    const t = text.trim();
    try {
      return { err: null, v: JSON.parse(t) as J };
    } catch (e) {
      // NDJSON / JSONP
      const lines = t.split("\n").filter(Boolean);
      if (lines.length > 1) {
        try {
          return { err: null, v: lines.slice(0, 10000).map((l) => JSON.parse(l)) };
        } catch {
          /* fall through */
        }
      }
      const m = t.match(/^[\w$.]+\(([\s\S]*)\);?$/);
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
  if (!info.len) return <div className="placeholder">No body</div>;
  if (info.len > TREE_LIMIT) return <div className="placeholder">Body is {fmtBytes(info.len)} – too large for the tree view. Use TextView (formatted) instead.</div>;
  if (error) return <div className="placeholder">{error}</div>;
  if (text == null) return <div className="placeholder">Loading…</div>;
  if (parsed.err) return <div className="placeholder">Not valid JSON: {parsed.err}</div>;
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
      {allAttrs.length > attrs.length && <span className="muted"> … {fmtInt(allAttrs.length - attrs.length)} more attributes</span>}
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
  if (!info.len) return <div className="placeholder">No body</div>;
  if (info.len > TREE_LIMIT) return <div className="placeholder">Body is {fmtBytes(info.len)} – too large for the tree view. Use TextView (formatted) instead.</div>;
  if (error) return <div className="placeholder">{error}</div>;
  if (!doc) return <div className="placeholder">Loading…</div>;
  if ("error" in doc) return <div className="placeholder">{doc.error}</div>;
  return (
    <div className="scroll pad mono">
      <XNode n={doc.root} depth={0} />
    </div>
  );
}
