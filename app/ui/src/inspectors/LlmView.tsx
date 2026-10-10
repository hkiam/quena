// LLM inspector: a call to an LLM API as a conversation — system prompt, messages, tool
// calls and results, the answer (assembled from a stream), token usage and estimated cost.
import { useEffect, useState } from "react";
import { api, type CallContext, type Detail, type LlmCall, type LlmPart, type ToolTrail } from "../api";
import { actions } from "../actions";
import { useListVersion } from "../lib/useSettled";
import { fmtInt, fmtUsd } from "../lib/format";
import { t } from "../i18n";
import { confirmAsk, say, set } from "../store";
import { CallContextView } from "../panels/CallContext";

/** URLs of LLM APIs (mirrors the core's recognition; POST only). */
export function llmCandidate(detail: Detail): boolean {
  if (detail.summary.llm) return true;
  if (detail.request.method.toUpperCase() !== "POST") return false;
  let path = "";
  try {
    path = new URL(detail.request.url).pathname.replace(/\/+$/, "");
  } catch {
    return false;
  }
  return /\/chat\/completions$|\/responses$|\/v1\/messages$|:(stream)?generateContent|\/api\/(chat|generate)$/i.test(path);
}

const ROLE: Record<string, string> = { system: t("System"), user: t("User"), assistant: t("Assistant"), tool: t("Tool"), developer: t("System") };

function PartView({ p }: { p: LlmPart }) {
  const [open, setOpen] = useState(p.kind !== "thinking");
  switch (p.kind) {
    case "toolCall":
      return (
        <div className="llm-part llm-tool">
          <div className="llm-tool-head">
            → {t("calls")} <b className="mono">{p.name ?? "?"}</b>
            {p.id && <span className="muted small mono"> {p.id}</span>}
          </div>
          {p.text && <pre className="llm-text mono">{p.text}</pre>}
        </div>
      );
    case "toolResult":
      return (
        <div className="llm-part llm-tool">
          <div className="llm-tool-head">
            ← {t("result")}
            {p.name && <b className="mono"> {p.name}</b>}
            {p.id && <span className="muted small mono"> {p.id}</span>}
          </div>
          <pre className="llm-text mono">{p.text}</pre>
        </div>
      );
    case "thinking":
      return (
        <div className="llm-part llm-thinking">
          <span className="linklike small" onClick={() => setOpen(!open)}>
            {open ? "▾" : "▸"} {t("Thinking")}
          </span>
          {open && <pre className="llm-text">{p.text}</pre>}
        </div>
      );
    case "image":
    case "other":
      return <div className="llm-part muted small mono">{p.text}</div>;
    default:
      return <pre className="llm-part llm-text">{p.text}</pre>;
  }
}

function Usage({ c }: { c: LlmCall }) {
  const u = c.usage;
  if (!u) return <span className="muted">{t("no token usage in the response")}</span>;
  return (
    <span className="llm-usage">
      <span>{t("in {n}", { n: fmtInt(u.input) })}</span>
      <span>{t("out {n}", { n: fmtInt(u.output) })}</span>
      {u.cacheRead > 0 && <span>{t("cache read {n}", { n: fmtInt(u.cacheRead) })}</span>}
      {u.cacheWrite > 0 && <span>{t("cache write {n}", { n: fmtInt(u.cacheWrite) })}</span>}
      {u.reasoning > 0 && <span>{t("reasoning {n}", { n: fmtInt(u.reasoning) })}</span>}
      {c.cost ? (
        <span title={t("Estimated from {price}. Own prices: llm-prices.json in the data folder.", { price: c.cost.price })}>≈ {fmtUsd(c.cost.usd)}</span>
      ) : (
        <span className="muted" title={t("No price known for this model. Own prices: llm-prices.json in the data folder.")}>
          {t("cost unknown")}
        </span>
      )}
    </span>
  );
}

/** Agent cache: this call answered from the cache, or a switch to cache its answer. */
function CacheBar({ detail }: { detail: Detail }) {
  const id = detail.summary.id;
  const hit = detail.extraFlags.find(([k]) => k === "x-quena-cache")?.[1];
  const [cached, setCached] = useState<boolean | null>(null);
  const done = detail.summary.state === "done" && detail.summary.status >= 200 && detail.summary.status < 300;
  useEffect(() => {
    if (hit || !done) return;
    api.llmCacheSet(id).then(setCached, () => setCached(null));
  }, [id, hit, done]);
  if (hit) return <div className="llm-cache llm-cache-hit">{t("Answered by Quena from the agent cache: {what}", { what: hit })}</div>;
  if (!done || cached === null) return null;
  return (
    <label className="f-check llm-cache" title={t("The same request (URL and JSON body; key order, user and metadata do not count) is then answered by Quena without asking the model. Settings → Bodies & Storage → Agent cache.")}>
      <input
        type="checkbox"
        checked={cached}
        onChange={(e) =>
          api.llmCacheSet(id, e.target.checked).then(setCached, (err) => {
            say(String(err), "error");
          })
        }
      />{" "}
      {t("Cache this answer (agent cache)")}
    </label>
  );
}

/** The call in its conversation: turn, what fills the context, change and cache. */
function ContextBar({ id, state }: { id: number; state: string }) {
  const [c, setC] = useState<CallContext | null>(null);
  useEffect(() => {
    let alive = true;
    setC(null);
    if (state === "done" || state === "aborted") api.llmContext(id).then((r) => alive && setC(r), () => {});
    return () => {
      alive = false;
    };
  }, [id, state]);
  if (!c) return null;
  const miss = c.cache.some((n) => n.code === "miss");
  const tokens = c.breakdown.actual ?? c.breakdown.estimated;
  return (
    <details className="llm-details llm-context">
      <summary>
        {t("Context")}: {t("{n} tokens", { n: fmtInt(tokens) })}
        {c.window ? ` · ${Math.round((tokens * 100) / c.window)} %` : ""}
        {c.key && (
          <>
            {" · "}
            {t("turn {n} of {of}", { n: c.turn, of: c.turns })}{" "}
            <button
              type="button"
              className="linklike"
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                set({ agentConv: c.key, activeTab: "agents" });
              }}
            >
              {t("Show conversation")}
            </button>
          </>
        )}
        {miss && <span className="pill pill-warn">{t("cache missed")}</span>}
      </summary>
      <CallContextView c={c} />
    </details>
  );
}

/** Prompt playground: send the call again with another system prompt, fewer tools, another
 * model or output limit, and compare answer and tokens. */
function Playground({ detail, c, onClose }: { detail: Detail; c: LlmCall; onClose: () => void }) {
  const original = c.system.join("\n\n");
  const limitParam = c.params.find(([k]) => k === "max_tokens" || k === "max_completion_tokens" || k === "max_output_tokens" || k === "maxOutputTokens");
  const [system, setSystem] = useState(original);
  const [model, setModel] = useState(c.model);
  const [limit, setLimit] = useState(limitParam?.[1] ?? "");
  const [off, setOff] = useState<Set<string>>(new Set());
  const [sent, setSent] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [variant, setVariant] = useState<LlmCall | null>(null);
  const version = useListVersion();
  useEffect(() => {
    if (sent == null || variant?.usage) return;
    let alive = true;
    api.llmCall(sent).then((r) => alive && r && setVariant(r), () => {});
    return () => {
      alive = false;
    };
  }, [sent, version]);
  let host = "";
  try {
    host = new URL(detail.request.url).host;
  } catch {
    /* shown without host */
  }
  const send = async () => {
    if (!(await confirmAsk(t("Send the variant?"), t("It goes to {host} with the original request's headers, its credentials included, and costs tokens like any call.", { host }), t("Send")))) return;
    setBusy(true);
    try {
      const n = Number(limit);
      const id = await api.llmVariant(detail.summary.id, {
        system: system !== original ? system : null,
        dropTools: [...off],
        model: model !== c.model ? model : null,
        maxTokens: limit !== (limitParam?.[1] ?? "") && Number.isFinite(n) && n > 0 ? n : null,
      });
      setSent(id);
      setVariant(null);
    } catch (e) {
      say(String(e), "error");
    } finally {
      setBusy(false);
    }
  };
  const usage = (x: LlmCall) => (x.usage ? `${t("in {n}", { n: fmtInt(x.usage.input) })} · ${t("out {n}", { n: fmtInt(x.usage.output) })}${x.cost ? ` · ≈ ${fmtUsd(x.cost.usd)}` : ""}` : t("no token usage in the response"));
  const answer = (x: LlmCall) => x.output.filter((p) => p.kind === "text").map((p) => p.text).join("\n");
  return (
    <div className="llm-playground">
      <div className="lt-bar">
        <b>{t("Variant")}</b>
        <span className="tp-spacer" />
        <button type="button" className="linklike" onClick={onClose}>
          {t("Close")}
        </button>
      </div>
      <label className="small">{t("System prompt")}</label>
      <textarea className="mono" rows={6} value={system} onChange={(e) => setSystem(e.target.value)} spellCheck={false} />
      <div className="llm-play-line">
        <label className="small">
          {t("Model")} <input className="mono" value={model} onChange={(e) => setModel(e.target.value)} spellCheck={false} />
        </label>
        <label className="small">
          {t("Output limit")} <input className="mono" value={limit} onChange={(e) => setLimit(e.target.value)} placeholder="max_tokens" />
        </label>
      </div>
      {c.tools.length > 0 && (
        <details>
          <summary className="small">
            {t("Tools")} ({c.tools.length - off.size} / {c.tools.length})
          </summary>
          <div className="llm-play-tools">
            {c.tools.map((x) => (
              <label key={x.name} className="f-check small">
                <input
                  type="checkbox"
                  checked={!off.has(x.name)}
                  onChange={(e) => {
                    const n = new Set(off);
                    if (e.target.checked) n.delete(x.name);
                    else n.add(x.name);
                    setOff(n);
                  }}
                />{" "}
                <span className="mono">{x.name}</span> <span className="muted">≈ {fmtInt(x.tokens)}</span>
              </label>
            ))}
          </div>
        </details>
      )}
      <div className="llm-play-line">
        <button className="primary" disabled={busy} onClick={() => void send()}>
          ▶ {t("Send variant")}
        </button>
        {sent != null && (
          <span className="small">
            {t("Sent as")}{" "}
            <button type="button" className="linklike" onClick={() => void actions.selectIds([sent])}>
              #{sent}
            </button>
          </span>
        )}
      </div>
      {sent != null && (
        <table className="kv small">
          <tbody>
            <tr>
              <td>{t("Original")}</td>
              <td>{usage(c)}</td>
            </tr>
            <tr>
              <td>{t("Variant")}</td>
              <td>{variant ? usage(variant) : t("waiting for the answer…")}</td>
            </tr>
            {variant && (
              <tr>
                <td>{t("Answer")}</td>
                <td>
                  <pre className="llm-text">{answer(variant) || variant.output.map((p) => `→ ${p.name ?? p.kind}`).join("\n")}</pre>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  );
}

/** The MCP exchanges that ran the tool calls of the answer. */
function ToolTrails({ id, state }: { id: number; state: string }) {
  const [trails, setTrails] = useState<ToolTrail[]>([]);
  // The MCP exchanges come after the answer: look again as sessions arrive.
  const version = useListVersion();
  useEffect(() => setTrails([]), [id]);
  useEffect(() => {
    let alive = true;
    if (state === "done" || state === "aborted") api.llmToolTrails(id).then((r) => alive && setTrails(r), () => {});
    return () => {
      alive = false;
    };
  }, [id, state, version]);
  const ran = trails.filter((x) => x.mcp != null);
  if (!ran.length) return null;
  return (
    <div className="small llm-trails">
      {ran.map((x, i) => (
        <div key={i}>
          → <span className="mono">{x.tool}</span> {t("run by the MCP server in")}{" "}
          <button type="button" className="linklike" onClick={() => void actions.selectIds([x.mcp as number])}>
            #{x.mcp}
          </button>
        </div>
      ))}
    </div>
  );
}

export function LlmView({ detail }: { detail: Detail }) {
  const [c, setC] = useState<LlmCall | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [play, setPlay] = useState(false);
  const id = detail.summary.id;
  const state = detail.summary.state;
  useEffect(() => {
    let alive = true;
    setError(null);
    api.llmCall(id).then(
      (r) => alive && setC(r),
      (e) => alive && setError(String(e)),
    );
    return () => {
      alive = false;
    };
  }, [id, state]);
  if (error) return <div className="placeholder">{t("Could not decode: {error}", { error })}</div>;
  if (c === undefined) return <div className="placeholder">{t("Decoding…")}</div>;
  if (c === null) return <div className="placeholder">{t("Not a call to an LLM API.")}</div>;
  return (
    <div className="scroll pad llm">
      <div className="llm-head">
        <b>{c.provider}</b>
        <span className="mono">{c.model || "?"}</span>
        {c.stream && <span className="muted small">{t("streamed")}</span>}
        {c.stopReason && <span className="muted small">{t("stop: {reason}", { reason: c.stopReason })}</span>}
        <span className="tp-spacer" />
        <Usage c={c} />
        {c.api !== "embeddings" && (
          <button type="button" className="linklike small" title={t("Send this call again with another system prompt, fewer tools, another model or output limit")} onClick={() => setPlay(!play)}>
            {t("Try a variant…")}
          </button>
        )}
      </div>
      {play && <Playground detail={detail} c={c} onClose={() => setPlay(false)} />}
      <CacheBar detail={detail} />
      <ContextBar id={id} state={state} />
      {c.error && <div className="mocks-error">{c.error}</div>}
      {c.notes.map((n) => (
        <div key={n} className="muted small">
          {n}
        </div>
      ))}
      {c.system.length > 0 && (
        <div className="llm-msg llm-system">
          <div className="llm-role">{ROLE.system}</div>
          {c.system.map((s, i) => (
            <pre key={i} className="llm-part llm-text">
              {s}
            </pre>
          ))}
        </div>
      )}
      {c.messages.map((m, i) => (
        <div key={i} className={`llm-msg llm-${m.role}`}>
          <div className="llm-role">{ROLE[m.role] ?? m.role}</div>
          {m.parts.map((p, j) => (
            <PartView key={j} p={p} />
          ))}
        </div>
      ))}
      <div className="llm-msg llm-answer">
        <div className="llm-role">{t("Answer")}</div>
        {c.output.length === 0 ? <div className="muted small">{state === "done" || state === "aborted" ? t("no answer") : t("waiting for the answer…")}</div> : c.output.map((p, j) => <PartView key={j} p={p} />)}
        <ToolTrails id={id} state={state} />
      </div>
      {(c.tools.length > 0 || c.params.length > 0) && (
        <details className="llm-details">
          <summary>
            {t("Tools and parameters")} ({c.tools.length + c.params.length})
          </summary>
          <table className="kv">
            <tbody>
              {c.tools.map((tool) => (
                <tr key={`t:${tool.name}`}>
                  <td className="mono">{tool.name}</td>
                  <td className="small">{tool.description}</td>
                </tr>
              ))}
              {c.params.map(([k, v]) => (
                <tr key={`p:${k}`}>
                  <td className="mono muted">{k}</td>
                  <td className="mono small">{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </div>
  );
}
