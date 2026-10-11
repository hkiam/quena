// LLM inspector: a call to an LLM API as a conversation — system prompt, messages, tool
// calls and results, the answer (assembled from a stream), token usage and estimated cost.
import { useEffect, useMemo, useRef, useState } from "react";
import { api, type CallContext, type Detail, type LlmCall, type LlmPart, type LlmSection, type ToolTrail } from "../api";
import { actions, copyText } from "../actions";
import { useAgentStamp, useListVersion } from "../lib/useSettled";
import { fmtInt, fmtUsd } from "../lib/format";
import { t } from "../i18n";
import { confirmAsk, say, set } from "../store";
import { CallContextView } from "../panels/CallContext";
import { KIND, cutAt, preview, sectionTitle } from "../lib/llmSections";

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
  return /\/chat\/completions$|\/responses$|\/v1\/messages$|:(stream)?generateContent|:(stream)?rawPredict$|\/api\/(chat|generate)$|\/model\/[^/]+\/(invoke|invoke-with-response-stream|converse|converse-stream)$/i.test(path);
}

const ROLE: Record<string, string> = { system: t("System"), user: t("User"), assistant: t("Assistant"), tool: t("Tool"), developer: t("System (developer)") };
const ICON: Record<string, string> = { system: "⚙", developer: "⚙", user: "◉", assistant: "✦", tool: "⚒", answer: "✦" };

function LongText({ text, mono }: { text: string; mono?: boolean }) {
  const [all, setAll] = useState(false);
  const cut = useMemo(() => cutAt(text), [text]);
  const short = !all && cut != null && cut < text.length;
  return (
    <>
      <pre className={mono ? "llm-text mono" : "llm-text"}>{short ? text.slice(0, cut) : text}</pre>
      {short && (
        <button type="button" className="linklike small" onClick={() => setAll(true)}>
          {t("Show all ({n} more characters)", { n: fmtInt(text.length - cut) })}
        </button>
      )}
    </>
  );
}

function CopyButton({ text }: { text: string }) {
  return (
    <button
      type="button"
      className="llm-copy"
      title={t("Copy")}
      onClick={(e) => {
        e.stopPropagation();
        void copyText(text).then(() => say(t("Copied"), "info"));
      }}
    >
      ⧉
    </button>
  );
}

/** Sections the user opened: they stay open in the next call of the conversation. */
const opened = new Set<string>();

/** "Expand all" / "Collapse all" of a block: a counter, so the same choice twice applies again. */
type Force = { open: boolean; n: number } | null;

function SectionView({ s, force }: { s: LlmSection; force: Force }) {
  const title = sectionTitle(s);
  const key = `${s.kind}|${s.label || title}`;
  const [open, setOpen] = useState(() => opened.has(key));
  useEffect(() => {
    if (force) setOpen(force.open);
  }, [force]);
  useEffect(() => {
    if (open) opened.add(key);
    else opened.delete(key);
  }, [open, key]);
  if (s.kind === "text") return <LongText text={s.text} />;
  return (
    <div className={`llm-sec llm-sec-${s.kind}`}>
      <div
        className="llm-sec-head"
        role="button"
        tabIndex={0}
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setOpen(!open);
          }
        }}
        title={open ? t("Collapse") : t("Expand")}
      >
        <span className="llm-sec-arrow">{open ? "▾" : "▸"}</span>
        <b className="llm-sec-title">{title}</b>
        <span className={`llm-kind llm-kind-${s.kind}`}>{KIND[s.kind]}</span>
        <span className="muted small llm-sec-size">
          {t("{n} characters", { n: fmtInt(s.text.length) })} · ≈ {t("{n} tokens", { n: fmtInt(s.tokens) })}
        </span>
        {!open && <span className="muted small llm-sec-preview">{s.kind === "prompt" ? "" : preview(s, title)}</span>}
        <span className="tp-spacer" />
        <CopyButton text={s.text} />
      </div>
      {open && <LongText text={s.text} mono={s.kind !== "base" && s.kind !== "prompt"} />}
    </div>
  );
}

/** The sections of one text or block with "Expand all" when several can be opened. */
function useForce(): [Force, (open: boolean) => void] {
  const [force, setForce] = useState<Force>(null);
  return [force, (open) => setForce((f) => ({ open, n: (f?.n ?? 0) + 1 }))];
}

function ExpandAll({ count, onSet }: { count: number; onSet: (open: boolean) => void }) {
  if (count < 2) return null;
  return (
    <span className="llm-expand">
      <button type="button" className="linklike" onClick={() => onSet(true)}>
        {t("Expand all")}
      </button>
      {" · "}
      <button type="button" className="linklike" onClick={() => onSet(false)}>
        {t("Collapse all")}
      </button>
    </span>
  );
}

function RoleHead({ role, label, extra, children }: { role: string; label: string; extra?: string; children?: React.ReactNode }) {
  return (
    <div className="llm-role">
      <span className="llm-role-icon">{ICON[role] ?? "•"}</span> {label}
      {extra && <span className="llm-role-extra"> · {extra}</span>}
      {children}
    </div>
  );
}

function SystemBlock({ c, at }: { c: LlmCall; at: React.Ref<HTMLDivElement> }) {
  const [force, setForce] = useForce();
  const secs: LlmSection[] = c.systemSections ?? c.system.map((text, i) => ({ kind: i === 0 ? "base" : "prompt", label: "", text, tokens: Math.ceil(text.length / 4) }));
  const tokens = secs.reduce((n, s) => n + s.tokens, 0);
  const role = c.systemRole && c.systemRole !== "system" ? c.systemRole : "system";
  const label = role === "system" ? t("System") : t("System ({role})", { role });
  return (
    <div className="llm-msg llm-system" ref={at}>
      <RoleHead role={role} label={label} extra={`${secs.length === 1 ? t("1 part") : t("{n} parts", { n: secs.length })} · ≈ ${t("{n} tokens", { n: fmtInt(tokens) })}`}>
        <ExpandAll count={secs.length} onSet={setForce} />
      </RoleHead>
      {secs.map((s, i) => (
        <SectionView key={i} s={s} force={force} />
      ))}
    </div>
  );
}

function MessageView({ m, sections, at }: { m: LlmCall["messages"][number]; sections: Map<number, LlmSection[]>; at?: React.Ref<HTMLDivElement> }) {
  const [force, setForce] = useForce();
  const openable = [...sections.values()].reduce((n, secs) => n + secs.filter((s) => s.kind !== "text").length, 0);
  return (
    <div className={`llm-msg llm-${m.role}`} ref={at}>
      <RoleHead role={m.role} label={ROLE[m.role] ?? m.role}>
        <ExpandAll count={openable} onSet={setForce} />
      </RoleHead>
      {m.parts.map((p, j) => {
        const secs = sections.get(j);
        return secs ? secs.map((s, k) => <SectionView key={`${j}:${k}`} s={s} force={force} />) : <PartView key={j} p={p} />;
      })}
    </div>
  );
}

function PartView({ p }: { p: LlmPart }) {
  const [open, setOpen] = useState(p.kind !== "thinking");
  switch (p.kind) {
    case "toolCall":
      return (
        <div className="llm-part llm-tool">
          <div className="llm-tool-head">
            → {t("calls")} <b className="mono">{p.name ?? "?"}</b>
            {p.id && <span className="muted small mono"> {p.id}</span>}
            {p.text && <CopyButton text={p.text} />}
          </div>
          {p.text && <LongText text={p.text} mono />}
        </div>
      );
    case "toolResult":
      return (
        <div className="llm-part llm-tool">
          <div className="llm-tool-head">
            ← {t("result")}
            {p.name && <b className="mono"> {p.name}</b>}
            {p.id && <span className="muted small mono"> {p.id}</span>}
            <CopyButton text={p.text} />
          </div>
          <LongText text={p.text} mono />
        </div>
      );
    case "thinking":
      return (
        <div className="llm-part llm-thinking">
          <span className="linklike small" onClick={() => setOpen(!open)}>
            {open ? "▾" : "▸"} {t("Thinking")}
          </span>
          {open && <LongText text={p.text} />}
        </div>
      );
    case "image":
    case "other":
      return <div className="llm-part muted small mono">{p.text}</div>;
    default:
      return (
        <div className="llm-part llm-plain">
          <CopyButton text={p.text} />
          <LongText text={p.text} />
        </div>
      );
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
    <label className="f-check llm-cache" title={t("The same request (URL, credentials and JSON body; what changes with every request, like key order, user, metadata, Claude Code's attribution block or cache marks, does not count) is then answered by Quena without asking the model. Settings → Bodies & Storage → Agent cache.")}>
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
        {c.window ? <span title={t("Of the model's context window ({n} tokens)", { n: fmtInt(c.window) })}> · {Math.round((tokens * 100) / c.window)} %</span> : ""}
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
                set({ agentConv: c.key, agentView: "convs", activeTab: "agents" });
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
  // A shortened text cannot be sent back as the system prompt.
  const shortened = c.system.some((s) => / … \(\d+ characters\)$/.test(s));
  const limitParam = c.params.find(([k]) => k === "max_tokens" || k === "max_completion_tokens" || k === "max_output_tokens" || k === "maxOutputTokens");
  const [system, setSystem] = useState(original);
  const [model, setModel] = useState(c.model);
  const [limit, setLimit] = useState(limitParam?.[1] ?? "");
  const [off, setOff] = useState<Set<string>>(new Set());
  const [sent, setSent] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [variant, setVariant] = useState<LlmCall | null>(null);
  const version = useListVersion();
  // Looked at again as sessions arrive, until the variant's session is done or aborted.
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (sent == null || done) return;
    let alive = true;
    void Promise.all([api.detail(sent), api.llmCall(sent)]).then(
      ([d, r]) => {
        if (!alive) return;
        if (r) setVariant(r);
        if (d && (d.summary.state === "done" || d.summary.state === "aborted")) setDone(true);
      },
      () => {},
    );
    return () => {
      alive = false;
    };
  }, [sent, version, done]);
  let host = detail.request.url;
  try {
    host = new URL(detail.request.url).host;
  } catch {
    /* the URL as it is */
  }
  const send = async () => {
    const text = detail.summary.archive
      ? t("It goes to {host} with the original request's headers. The session comes from {archive}: these are the credentials of whoever recorded it, and the call costs tokens on their account.", { host, archive: detail.summary.archive })
      : t("It goes to {host} with the original request's headers, its credentials included, and costs tokens like any call.", { host });
    if (!(await confirmAsk(t("Send the variant?"), text, t("Send")))) return;
    let maxTokens: number | null = null;
    if (limit.trim() !== (limitParam?.[1] ?? "")) {
      const m = /^(\d+(?:\.\d+)?)\s*([km]?)$/i.exec(limit.trim());
      const n = m ? Math.round(Number(m[1]) * (m[2].toLowerCase() === "k" ? 1e3 : m[2].toLowerCase() === "m" ? 1e6 : 1)) : NaN;
      if (!Number.isInteger(n) || n <= 0) return say(t("The output limit is a whole number of tokens, e.g. 1000 or 4k"), "error");
      maxTokens = n;
    }
    setBusy(true);
    try {
      const id = await api.llmVariant(detail.summary.id, {
        system: system !== original ? system : null,
        dropTools: [...off],
        model: model !== c.model ? model : null,
        maxTokens,
      });
      setSent(id);
      setVariant(null);
      setDone(false);
    } catch (e) {
      say(String(e), "error");
    } finally {
      setBusy(false);
    }
  };
  const usage = (x: LlmCall) => (x.usage ? `${t("Input {n}", { n: fmtInt(x.usage.input) })} · ${t("Output {n}", { n: fmtInt(x.usage.output) })}${x.cost ? ` · ≈ ${fmtUsd(x.cost.usd)}` : ""}` : t("no token usage in the response"));
  const answer = (x: LlmCall) =>
    x.output
      .filter((p) => p.kind === "text" || p.kind === "toolCall")
      .map((p) => (p.kind === "toolCall" ? `→ ${p.name ?? "?"} ${p.text}` : p.text))
      .join("\n");
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
      <textarea className="mono" rows={6} value={system} disabled={shortened} onChange={(e) => setSystem(e.target.value)} spellCheck={false} />
      <div className="muted small">
        {shortened ? t("The system prompt is too long to edit here; it is sent as it was.") : t("A changed system prompt is sent as one text: cache marks (and Claude Code's attribution block) are left out, so the provider's cache starts over.")}
      </div>
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
            {t("Tools offered")} ({c.tools.length - off.size} / {c.tools.length})
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
        <button className="primary" disabled={busy || !model.trim()} title={!model.trim() ? t("Enter a model") : undefined} onClick={() => void send()}>
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
            {variant?.error && (
              <tr>
                <td />
                <td className="mocks-error">{variant.error}</td>
              </tr>
            )}
            {variant && (
              <tr>
                <td>{t("Answer")}</td>
                <td>
                  <pre className="llm-text">{answer(variant)}</pre>
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
  const [trails, setTrails] = useState<ToolTrail[] | null>(null);
  // The MCP exchanges come after the answer: look again as agent traffic arrives, until every
  // call has its exchange and the next request.
  const stamp = useAgentStamp();
  const complete = !!trails && trails.every((x) => x.mcp != null && x.resultIn != null);
  useEffect(() => {
    if (complete) return;
    let alive = true;
    if (state === "done" || state === "aborted") api.llmToolTrails(id).then((r) => alive && setTrails(r), () => {});
    return () => {
      alive = false;
    };
  }, [id, state, complete ? "" : stamp]);
  const ran = (trails ?? []).filter((x) => x.mcp != null);
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

const NONE = new Map<number, LlmSection[]>();

/** Links to the parts of a long call. */
function JumpBar({ targets }: { targets: [string, React.RefObject<HTMLElement | null> | null][] }) {
  return (
    <div className="llm-jump small">
      <span className="muted">{t("Go to")}</span>
      {targets
        .filter(([, r]) => r)
        .map(([label, r]) => (
          <button
            key={label}
            type="button"
            className="linklike"
            onClick={() => {
              const el = r!.current;
              if (el instanceof HTMLDetailsElement) el.open = true;
              el?.scrollIntoView({ block: "start", behavior: "smooth" });
            }}
          >
            {label}
          </button>
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
  const systemAt = useRef<HTMLDivElement>(null);
  const historyAt = useRef<HTMLDivElement>(null);
  const answerAt = useRef<HTMLDivElement>(null);
  const toolsAt = useRef<HTMLDetailsElement>(null);
  const sectionsOf = useMemo(() => {
    const m = new Map<number, Map<number, LlmSection[]>>();
    for (const [i, j, secs] of c?.partSections ?? []) {
      if (!m.has(i)) m.set(i, new Map());
      m.get(i)!.set(j, secs);
    }
    return m;
  }, [c]);
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
      <JumpBar
        targets={[
          [t("System"), c.system.length > 0 ? systemAt : null],
          [t("History ({n})", { n: c.messages.length }), c.messages.length > 0 ? historyAt : null],
          [t("Answer"), answerAt],
          [t("Tools and parameters"), c.tools.length + c.params.length > 0 ? toolsAt : null],
        ]}
      />
      {play && <Playground detail={detail} c={c} onClose={() => setPlay(false)} />}
      <CacheBar detail={detail} />
      <ContextBar id={id} state={state} />
      {c.error && <div className="mocks-error">{c.error}</div>}
      {c.notes.map((n) => (
        <div key={n} className="muted small">
          {n}
        </div>
      ))}
      {c.system.length > 0 && <SystemBlock c={c} at={systemAt} />}
      {c.messages.map((m, i) => (
        <MessageView key={i} m={m} sections={sectionsOf.get(i) ?? NONE} at={i === 0 ? historyAt : undefined} />
      ))}
      <div className="llm-msg llm-answer" ref={answerAt}>
        <RoleHead role="answer" label={t("Answer")} />
        {c.output.length === 0 ? <div className="muted small">{state === "done" || state === "aborted" ? t("no answer") : t("waiting for the answer…")}</div> : c.output.map((p, j) => <PartView key={j} p={p} />)}
        <ToolTrails id={id} state={state} />
      </div>
      {(c.tools.length > 0 || c.params.length > 0) && (
        <details className="llm-details" ref={toolsAt}>
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
