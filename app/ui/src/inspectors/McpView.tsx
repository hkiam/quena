// MCP inspector: an exchange with an MCP server (Model Context Protocol) — the tool called with
// its arguments and result, the tools a server offers with what they cost in tokens, the
// server and protocol, and the way of a tool call from the model's answer to the next request.
import { useEffect, useState } from "react";
import { api, type Detail, type McpExchange, type SessionId, type ToolTrail } from "../api";
import { actions } from "../actions";
import { fmtInt } from "../lib/format";
import { useAgentStamp, useListVersion } from "../lib/useSettled";
import { t } from "../i18n";

/** Whether a session may be an MCP exchange (mirrors the core's cheap check). */
export function mcpCandidate(detail: Detail): boolean {
  if (detail.summary.mcp) return true;
  const url = detail.request.url;
  if (url.startsWith("stdio://")) return true;
  const hasHeader = (h: [string, string][] | undefined) => (h ?? []).some(([n]) => /^mcp-(session-id|protocol-version)$/i.test(n));
  if (hasHeader(detail.request.headers) || hasHeader(detail.response?.headers)) return true;
  const m = detail.request.method.toUpperCase();
  if (m !== "POST" && m !== "GET") return false;
  let path = "";
  try {
    path = new URL(url).pathname.replace(/\/+$/, "").toLowerCase();
  } catch {
    return false;
  }
  return /\/mcp$|\/mcp\/|\/sse$|\/messages?$/.test(path);
}

function Go({ id, children }: { id: SessionId; children: React.ReactNode }) {
  return (
    <button type="button" className="linklike" onClick={() => void actions.selectIds([id])}>
      {children}
    </button>
  );
}

export function TrailView({ tr }: { tr: ToolTrail }) {
  return (
    <ul className="mcp-trail small">
      {tr.requestedBy != null ? (
        <li>
          {t("Asked for by the model in")} <Go id={tr.requestedBy}>#{tr.requestedBy}</Go>
        </li>
      ) : (
        <li className="muted">{t("No LLM call in the capture asked for this tool shortly before.")}</li>
      )}
      {tr.mcp != null && (
        <li>
          {t("Run by the MCP server in")} <Go id={tr.mcp}>#{tr.mcp}</Go>
        </li>
      )}
      {tr.resultIn != null && (
        <li>
          {t("Its result goes back to the model in")} <Go id={tr.resultIn}>#{tr.resultIn}</Go>
        </li>
      )}
      {tr.offered > 0 && <li className="muted">{t("Offered in {n} LLM requests; its definition costs ≈ {tokens} tokens in each.", { n: tr.offered, tokens: fmtInt(tr.defTokens) })}</li>}
    </ul>
  );
}

export function McpView({ detail }: { detail: Detail }) {
  const id = detail.summary.id;
  const state = detail.summary.state;
  const [ex, setEx] = useState<McpExchange | null | undefined>(undefined);
  const [trail, setTrail] = useState<ToolTrail | null>(null);
  // The mark and the request that carries the result come later: look again as sessions arrive.
  const version = useListVersion();
  const stamp = useAgentStamp();
  const mark = detail.summary.mcp ?? "";
  // The older SSE transport answers on its stream, later; a stream still open grows.
  const pending = ex?.transport === "sse" && (state !== "done" || (!!ex.call && ex.call.content.length === 0));
  useEffect(() => {
    setEx(undefined);
    setTrail(null);
  }, [id]);
  useEffect(() => {
    let alive = true;
    api.mcpExchange(id).then((r) => alive && setEx(r), () => alive && setEx(null));
    return () => {
      alive = false;
    };
  }, [id, state, pending ? version : 0]);
  useEffect(() => {
    let alive = true;
    if (mark.startsWith("tools/call") && trail?.resultIn == null) api.mcpTrail(id).then((x) => alive && setTrail(x), () => {});
    return () => {
      alive = false;
    };
  }, [id, mark, trail?.resultIn == null ? stamp : 0]);
  if (ex === undefined) return <div className="placeholder">{t("Decoding…")}</div>;
  if (ex === null) return <div className="placeholder">{t("Not an exchange with an MCP server.")}</div>;
  const toolTokens = (ex.tools ?? []).reduce((a, x) => a + x.tokens, 0);
  return (
    <div className="scroll pad mcp">
      <div className="llm-head">
        <span className="pill pill-violet">{ex.transport === "stdio" ? "stdio" : ex.transport === "sse" ? "HTTP+SSE" : "Streamable HTTP"}</span>
        <b className="mono">{ex.label}</b>
        {(ex.server?.[0] || detail.summary.mcpServer) && (
          <span>
            {ex.server?.[0] || detail.summary.mcpServer} {ex.server?.[1] && <span className="muted small">{ex.server[1]}</span>}
          </span>
        )}
        <span className="tp-spacer" />
        {ex.protocol && <span className="muted small">{t("protocol version {v}", { v: ex.protocol })}</span>}
        {ex.session && <span className="muted small mono" title={t("MCP session id")}>{ex.session}</span>}
      </div>
      {ex.error && <div className="mocks-error">{ex.error}</div>}
      {ex.call && (
        <>
          <h4>{t("Arguments")}</h4>
          <pre className="llm-text mono">{ex.call.arguments || "{}"}</pre>
          <h4>
            {t("Result")} {ex.call.isError && <span className="pill pill-err">{t("error")}</span>}{" "}
            <span className="muted small">{t("≈ {n} tokens in the agent's next request", { n: fmtInt(ex.call.tokens) })}</span>
          </h4>
          {ex.call.content.length === 0 && <div className="muted small">{t("no content")}</div>}
          {ex.call.content.map((c, i) => (
            <div key={i} className="llm-part">
              {c.kind !== "text" && <div className="muted small">{c.kind}</div>}
              <pre className="llm-text">{c.text}</pre>
            </div>
          ))}
          {trail && (
            <>
              <h4>{t("Tool call trail")}</h4>
              <TrailView tr={trail} />
            </>
          )}
        </>
      )}
      {ex.tools && ex.tools.length > 0 && (
        <>
          <h4>
            {t("Tools offered")} ({ex.tools.length}){" "}
            <span className="muted small">{t("≈ {n} tokens in every LLM request that offers them all", { n: fmtInt(toolTokens) })}</span>
          </h4>
          <table className="kv">
            <tbody>
              {[...ex.tools]
                .sort((a, b) => b.tokens - a.tokens)
                .map((x) => (
                  <tr key={x.name}>
                    <td className="mono nowrap">{x.name}</td>
                    <td className="small">{x.description}</td>
                    <td className="num nowrap">{fmtInt(x.tokens)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </>
      )}
      <details className="llm-details" open={!ex.call && !ex.tools?.length}>
        <summary>
          {t("Messages")} ({ex.sent.length + ex.received.length})
        </summary>
        {[...ex.sent.map((m) => ["→", m] as const), ...ex.received.map((m) => ["←", m] as const)].map(([dir, m], i) => (
          <div key={i} className="llm-part">
            <div className="small">
              {dir} <b>{m.method ?? m.kind}</b> {m.id != null && <span className="muted mono">id {m.id}</span>} {m.method && <span className="muted">{m.kind}</span>}
            </div>
            {m.body && <pre className="llm-text mono">{m.body}</pre>}
          </div>
        ))}
      </details>
    </div>
  );
}
