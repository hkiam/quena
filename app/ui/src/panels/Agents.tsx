// Agents: the conversations of AI agents in the capture (each run of Claude Code, Codex, an
// app), with their turns, what fills the context, where the prompt cache missed and why, and
// hints where tokens go to waste.
import { Fragment, memo, useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, type CallContext, type ConvDetail, type ConvSide, type ConvSummary, type ConvTurn, type SessionId } from "../api";
import { actions } from "../actions";
import { fmtDuration, fmtInt, fmtMs, fmtTime, fmtUsd } from "../lib/format";
import { CATEGORIES, breaksCache, cacheText, convTree, diffText, hintText, hintTokens } from "../lib/agentText";
import { CallContextView } from "./CallContext";
import { AgentTools } from "./AgentTools";
import { useAgentStamp } from "../lib/useSettled";
import { confirmAsk, say, set, useStore } from "../store";
import { plural, t } from "../i18n";
import { ContextMap } from "./ContextMap";

const tokens = (c: { input: number; output: number }) => c.input + c.output;
const cacheShare = (read: number, input: number) => (input > 0 ? Math.round((read * 100) / input) : 0);
/** Turns shown at first in long runs (the rest on request). */
const TURN_ROWS = 1000;

/** Keyboard on a list row: Enter or Space selects, Shift+Enter opens the session, arrows move. */
function rowKeys(e: React.KeyboardEvent<HTMLTableRowElement>, select: () => void, open: () => void) {
  if (e.key === "Enter" && e.shiftKey) {
    e.preventDefault();
    open();
  } else if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    select();
  } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    const next = (e.key === "ArrowDown" ? e.currentTarget.nextElementSibling : e.currentTarget.previousElementSibling) as HTMLElement | null;
    next?.focus();
  }
}

export default function AgentsPanel() {
  const stamp = useAgentStamp();
  const view = useStore((s) => s.agentView);
  const sel = useStore((s) => s.agentConv);
  const [list, setList] = useState<ConvSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    // The tools view asks for its own report.
    if (view === "tools") return;
    let alive = true;
    api.llmConversations().then(
      (r) => {
        if (!alive) return;
        setList(r);
        setError(null);
        // Nothing chosen yet: the newest conversation.
        if (r.length && !useStore.getState().agentConv) set({ agentConv: r[0].key });
      },
      (e) => alive && setError(String(e)),
    );
    return () => {
      alive = false;
    };
  }, [stamp, tick, view]);
  const tree = useMemo(() => convTree(list ?? []), [list]);
  const switcher = (
    <span className="tabs-inline agents-switch" role="tablist">
      <button type="button" role="tab" aria-selected={view === "convs"} className={`insp-tab ${view === "convs" ? "active" : ""}`} onClick={() => set({ agentView: "convs" })}>
        {t("Conversations")}
      </button>
      <button type="button" role="tab" aria-selected={view === "tools"} className={`insp-tab ${view === "tools" ? "active" : ""}`} onClick={() => set({ agentView: "tools" })}>
        {t("Tools & skills")}
      </button>
    </span>
  );
  const refresh = (
    <button className="icon-btn" title={t("Refresh")} onClick={() => setTick(tick + 1)}>
      <RefreshCw size={13} />
    </button>
  );
  const bar = (extra?: React.ReactNode) => (
    <div className="lt-bar">
      {switcher}
      {extra}
      <span className="tp-spacer" />
      {refresh}
    </div>
  );
  if (view === "tools")
    return (
      <div className="agents-tools-wrap">
        {bar()}
        <AgentTools refresh={`${stamp}:${tick}`} />
      </div>
    );
  if (!list || !list.length)
    return (
      <div className="agents-tools-wrap">
        {bar()}
        <div className="placeholder">
          {error ?? (!list ? t("Computing…") : t("No LLM calls in the capture. Start an agent (Claude Code, Codex …) through Quena; each of its runs shows here as a conversation."))}
        </div>
      </div>
    );
  // A conversation opened from the LLM view may not be in the list yet: it loads on its own.
  const shown = sel;
  return (
    <div className="agents">
      <div className="agents-list">
        {bar(
          <>
            <span className="muted small">{plural(list.length, "{n} conversation", "{n} conversations")}</span>
            {error && <span className="mocks-error small">{error}</span>}
          </>,
        )}
        <div className="scroll">
          <table className="agt-table agents-table">
            <thead>
              <tr>
                <th>{t("Conversation")}</th>
                <th>{t("Started")}</th>
                <th>{t("Agent")}</th>
                <th className="num">{t("Turns")}</th>
                <th className="num" title={t("Input (cached tokens included) plus output")}>
                  {t("Tokens")}
                </th>
                <th className="num" title={t("Share of the input served from the provider's prompt cache")}>
                  {t("Cached")}
                </th>
                <th className="num" title={t("Estimated, for the turns whose model has a known price")}>
                  {t("Cost")}
                </th>
              </tr>
            </thead>
            <tbody>
              {tree.map(({ c, depth }) => (
                <tr
                  key={c.key}
                  tabIndex={0}
                  aria-selected={c.key === shown}
                  className={c.key === shown ? "selected" : ""}
                  onClick={() => set({ agentConv: c.key })}
                  onDoubleClick={() => void actions.selectIds([c.first])}
                  onKeyDown={(e) => rowKeys(e, () => set({ agentConv: c.key }), () => void actions.selectIds([c.first]))}
                  title={`${c.title}\n${c.models.join(", ")}\n${t("Double-click: select its first session")}`}
                >
                  <td className="agt-title-cell">
                    <div className="agt-title" style={{ paddingLeft: depth * 14 }}>
                      {depth > 0 && <span className="muted">↳</span>}
                      <span className="agt-title-text">{c.title}</span>
                      {c.cacheMisses > 0 && (
                        <span className="pill pill-warn" title={t("The cache missed in {n} turns", { n: c.cacheMisses })}>
                          {c.cacheMisses}
                        </span>
                      )}
                      {c.errors > 0 && (
                        <span className="pill pill-err" title={t("Calls that failed")}>
                          {c.errors}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="small">{fmtTime(c.started)}</td>
                  <td className="small agt-agent">{c.agent || c.provider}</td>
                  <td className="num">{c.turns}</td>
                  <td className="num">{fmtInt(tokens(c))}</td>
                  <td className="num">{c.cacheRead > 0 || c.cacheMisses > 0 ? `${cacheShare(c.cacheRead, c.input)} %` : "–"}</td>
                  <td className="num">{c.cost != null ? fmtUsd(c.cost) : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div className="agents-detail scroll pad">{shown ? <Conversation key={shown} convKey={shown} refresh={`${stamp}:${tick}`} list={list} /> : <div className="placeholder">{t("Choose a conversation.")}</div>}</div>
    </div>
  );
}

/** A conversation's label in lists: title, start time, turns (runs often share the title). */
const convLabel = (c: ConvSummary) => `${c.title.slice(0, 50)} · ${fmtTime(c.started)} · ${plural(c.turns, "{n} turn", "{n} turns")}`;

function Conversation({ convKey, refresh, list }: { convKey: string; refresh: string; list: ConvSummary[] }) {
  const [d, setD] = useState<ConvDetail | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [turnId, setTurnId] = useState<SessionId | null>(null);
  const [other, setOther] = useState<string | null>(null);
  const [all, setAll] = useState(false);
  useEffect(() => {
    let alive = true;
    api.llmConversation(convKey).then(
      (r) => alive && (setD(r), setError(null)),
      // An error keeps what is shown.
      (e) => alive && setError(String(e)),
    );
    return () => {
      alive = false;
    };
  }, [convKey, refresh]);
  const index = useMemo(() => new Map((d?.turns ?? []).map((x, i) => [x.id, i])), [d]);
  if (d === undefined) return <div className="placeholder">{error ?? t("Computing…")}</div>;
  if (d === null) return <div className="placeholder">{t("The conversation is no longer in the capture.")}</div>;
  const s = d.summary;
  const span = Math.max(1, s.ended - s.started);
  const titleOf = (k: string) => list.find((c) => c.key === k)?.title ?? k;
  const turnAt = turnId != null ? (index.get(turnId) ?? -1) : -1;
  const exportAs = async (format: "markdown" | "jsonl" | "otel") => {
    const ext = format === "markdown" ? "md" : format === "jsonl" ? "jsonl" : "otel.json";
    const name = format === "markdown" ? t("Markdown") : format === "jsonl" ? t("JSON lines") : t("OpenTelemetry (OTLP JSON)");
    try {
      const path = await save({ defaultPath: `conversation-${convKey}.${ext}`, filters: [{ name, extensions: [ext.split(".").pop() ?? ext] }] });
      if (!path) return;
      const n = await api.llmExport(convKey, format, path);
      say(plural(n, "{n} turn exported", "{n} turns exported"));
    } catch (e) {
      say(String(e), "error");
    }
  };
  const freeze = async () => {
    if (!(await confirmAsk(t("Freeze this conversation?"), t("Its answered turns and those of the subagents it started go into the agent cache: the agent run again gets the same answers from Quena without asking the model, until it asks something else. The new run then shows where it left the recording."), t("Freeze")))) return;
    try {
      const f = await api.llmFreeze(convKey);
      const msg = plural(f.added, "{n} turn added to the agent cache", "{n} turns added to the agent cache");
      const subs = f.conversations > 1 ? ` ${plural(f.conversations - 1, "(with {n} subagent)", "(with {n} subagents)")}` : "";
      const skipped = f.skipped ? ` ${plural(f.skipped, "{n} turn could not be kept (cut off or too large).", "{n} turns could not be kept (cut off or too large).")}` : "";
      say(msg + subs + skipped);
    } catch (e) {
      say(String(e), "error");
    }
  };
  const rows = all ? d.turns : d.turns.slice(0, TURN_ROWS);
  return (
    <div className="conv">
      {error && <div className="mocks-error small">{error}</div>}
      <div className="conv-head">
        <b>{s.title}</b>
        <span className="muted small mono">{s.key}</span>
      </div>
      <div className="conv-facts small">
        <span>{s.agent || s.provider}</span>
        <span className="mono">{s.models.join(", ")}</span>
        <span>
          {plural(s.turns, "{n} turn", "{n} turns")}
          {s.side > 0 && ` (${plural(s.side, "{n} side call", "{n} side calls")})`}
        </span>
        {s.hits > 0 && <span>{plural(s.hits, "{n} from the agent cache", "{n} from the agent cache")}</span>}
        <span title={t("From the first call's start to the last call's end")}>{fmtDuration(span / 1000)}</span>
        <span>{t("Input {n}", { n: fmtInt(s.input) })}</span>
        <span>{t("Output {n}", { n: fmtInt(s.output) })}</span>
        <span title={t("Share of the input served from the provider's prompt cache")}>{t("cached {pct} %", { pct: cacheShare(s.cacheRead, s.input) })}</span>
        {s.cost != null && <span title={t("Estimated, for the turns whose model has a known price")}>≈ {fmtUsd(s.cost)}</span>}
        {s.window ? (
          <span title={t("The last request's input of the model's context window")}>
            {t("context {pct} %", { pct: Math.round((s.lastInput * 100) / s.window) })}
          </span>
        ) : null}
        {s.ttfbMs != null && <span title={t("Median time from sending to the response headers")}>{t("headers after {t}", { t: fmtMs(s.ttfbMs) })}</span>}
        {s.tokensPerS != null && <span title={t("Median output tokens per second of streamed answers")}>{t("{n} tokens/s", { n: Math.round(s.tokensPerS) })}</span>}
        {s.limited > 0 && <span className="warn">{plural(s.limited, "{n} refused (rate limit)", "{n} refused (rate limit)")}</span>}
        {s.retries > 0 && <span>{plural(s.retries, "{n} retry", "{n} retries")}</span>}
        {s.divergedAt != null && <span className="warn" title={t("Answered from the agent cache until this turn: here the run asked something the recording did not have")}>{t("left the frozen run at turn {n}", { n: s.divergedAt })}</span>}
      </div>
      <div className="conv-actions small">
        <button type="button" className="linklike" onClick={() => void freeze()} title={t("Put the answered turns into the agent cache, to run the agent again against them")}>
          {t("Freeze for replays…")}
        </button>
        <span>
          {t("Export:")}{" "}
          <button type="button" className="linklike" onClick={() => void exportAs("markdown")} title={t("Each turn with what it added and the answer, to read or share")}>
            Markdown
          </button>{" "}
          ·{" "}
          <button type="button" className="linklike" onClick={() => void exportAs("jsonl")} title={t("One call per line, as the LLM view takes it apart, with the messages each turn added: for evaluations")}>
            JSONL
          </button>{" "}
          ·{" "}
          <button type="button" className="linklike" onClick={() => void exportAs("otel")} title={t("Spans after the OpenTelemetry GenAI conventions (models, tokens, no content), for Langfuse, Phoenix and other tracing tools")}>
            OpenTelemetry
          </button>
        </span>
        <label className="conv-compare-pick">
          {t("Compare with")}{" "}
          <select value={other ?? ""} onChange={(e) => setOther(e.target.value || null)}>
            <option value="">–</option>
            {list
              .filter((c) => c.key !== convKey)
              .map((c) => (
                <option key={c.key} value={c.key}>
                  {convLabel(c)}
                </option>
              ))}
          </select>
        </label>
      </div>
      {other && <CompareView a={convKey} b={other} refresh={refresh} />}
      {s.parent && (
        <div className="small">
          {t("Started by")}{" "}
          <button type="button" className="linklike" onClick={() => set({ agentConv: s.parent ?? null })}>
            {titleOf(s.parent)}
          </button>
        </div>
      )}
      {d.children.length > 0 && (
        <div className="small">
          {t("Subagents:")}{" "}
          {d.children.map((k, i) => (
            <Fragment key={k}>
              {i > 0 && ", "}
              <button type="button" className="linklike" onClick={() => set({ agentConv: k })}>
                {titleOf(k)}
              </button>
            </Fragment>
          ))}
        </div>
      )}
      {d.hints.length > 0 && (
        <>
          <h4>{t("Hints")}</h4>
          <ul className="conv-hints">
            {d.hints.map((h, i) => (
              <li key={i}>
                {hintText(h)} <span className="muted small">— {hintTokens(h)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      <h4>{t("Turns")}</h4>
      <div className="muted small conv-legend">{t("One row per LLM call, in the order they started. Click a row for its context; double-click (or Shift+Enter) selects its session. Orange: the change broke the cached prefix, or the cache missed.")}</div>
      <table className="agt-table conv-turns">
        <thead>
          <tr>
            <th className="num">#</th>
            <th>{t("Time")}</th>
            <th className="conv-bar-col" title={t("When the call ran, on the run's time axis")} />
            <th className="num" title={t("Input tokens, cached ones included")}>
              {t("In")}
            </th>
            <th className="num" title={t("Read from the prompt cache")}>
              {t("Cached")}
            </th>
            <th className="num">{t("Out")}</th>
            <th className="num">{t("Cost")}</th>
            <th className="num" title={t("Time from sending to the response headers (with connecting on a new connection)")}>
              {t("Headers")}
            </th>
            <th className="num" title={t("Output tokens per second of a streamed answer, from its first byte")}>
              {t("tok/s")}
            </th>
            <th>{t("Change")}</th>
            <th>{t("Tool calls")}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((x, i) => (
            <TurnRow key={x.id} x={x} i={i} prevIndex={x.prev != null ? index.get(x.prev) : undefined} start={s.started} span={span} selected={turnId === x.id} onSelect={setTurnId} />
          ))}
        </tbody>
      </table>
      {!all && d.turns.length > TURN_ROWS && (
        <button type="button" className="linklike small" onClick={() => setAll(true)}>
          {t("Show all {n} turns", { n: fmtInt(d.turns.length) })}
        </button>
      )}
      {turnAt >= 0 ? (
        <TurnContext key={d.turns[turnAt].id} id={d.turns[turnAt].id} index={turnAt + 1} refresh={refresh} />
      ) : (
        d.breakdown && (
          <>
            <h4>{t("Context of the last request")}</h4>
            <ContextMap b={d.breakdown} />
          </>
        )
      )}
    </div>
  );
}

const TurnRow = memo(function TurnRow({ x, i, prevIndex, start, span, selected, onSelect }: { x: ConvTurn; i: number; prevIndex: number | undefined; start: number; span: number; selected: boolean; onSelect: (id: SessionId) => void }) {
  const miss = x.cache.some((c) => c.code === "miss");
  const left = ((x.started - start) * 100) / span;
  const width = ((x.durationMs ?? 0) * 1000 * 100) / span;
  const open = () => void actions.selectIds([x.id]);
  return (
    <tr
      tabIndex={0}
      aria-selected={selected}
      className={`${selected ? "selected" : ""} ${x.error ? "err" : ""} ${x.side ? "side" : ""}`}
      onClick={() => onSelect(x.id)}
      onDoubleClick={open}
      onKeyDown={(e) => rowKeys(e, () => onSelect(x.id), open)}
      title={[...x.cache.map(cacheText), t("Double-click: select the session")].join("\n")}
    >
      <td className="num" title={prevIndex != null ? t("Continues #{n}", { n: prevIndex + 1 }) : undefined}>
        {i + 1}
      </td>
      <td className="small">{fmtTime(x.started)}</td>
      <td className="conv-bar-col">
        <div className="conv-bar" style={{ left: `${left}%`, width: `max(2px, ${width}%)` }} />
      </td>
      <td className="num">{x.usage ? fmtInt(x.usage.input) : ""}</td>
      <td className={`num ${miss ? "warn" : ""}`}>{x.usage ? `${cacheShare(x.usage.cacheRead, x.usage.input)} %` : ""}</td>
      <td className="num">{x.usage ? fmtInt(x.usage.output) : ""}</td>
      <td className="num">{x.cost != null ? fmtUsd(x.cost) : ""}</td>
      <td className="num">{x.ttfbMs != null ? fmtMs(x.ttfbMs) : ""}</td>
      <td className="num" title={x.rate ? rateText(x.rate) : undefined}>
        {x.tokensPerS != null ? Math.round(x.tokensPerS) : ""}
      </td>
      <td className={`small ${breaksCache(x.diff) ? "warn" : "muted"}`}>
        {x.status >= 400 && (
          <span className="pill pill-err" title={x.rate ? rateText(x.rate) : undefined}>
            {x.status}
          </span>
        )}{" "}
        {diffText(x.diff)}
        {x.diff.modelChanged && <span className="mono"> {x.model}</span>}
      </td>
      <td className="small">
        <div className="agt-ellipsis" title={x.calls.join(", ")}>
          {x.side && (
            <span className="pill pill-muted" title={t("No later turn continues this call: a side call of the agent (a prompt suggestion, a summary …)")}>
              {t("side call")}
            </span>
          )}
          {x.hit && (
            <span className="pill pill-info" title={t("Answered by Quena from the agent cache: nothing was spent")}>
              {t("agent cache")}
            </span>
          )}{" "}
          <span className="mono">{x.calls.join(", ")}</span>
        </div>
      </td>
    </tr>
  );
});

/** A turn: what filled its context, how it differs from the one before, the cache. */
function TurnContext({ id, index, refresh }: { id: SessionId; index: number; refresh: string }) {
  const [c, setC] = useState<CallContext | null | undefined>(undefined);
  // A turn still running is looked at again until its usage is known.
  const settled = c != null && c.breakdown.actual != null;
  useEffect(() => {
    if (settled) return;
    let alive = true;
    api.llmContext(id).then((r) => alive && setC(r), () => alive && setC(null));
    return () => {
      alive = false;
    };
  }, [id, settled ? "" : refresh]);
  return (
    <>
      <h4>{t("Turn {n}", { n: index })}</h4>
      {c === undefined && <div className="muted small">{t("Computing…")}</div>}
      {c === null && <div className="muted small">{t("The request of this turn cannot be read.")}</div>}
      {c && <CallContextView c={c} />}
    </>
  );
}

/** The rate limits a response reported. */
function rateText(r: { tokensLeft?: number; tokensLimit?: number; requestsLeft?: number; requestsLimit?: number; retryAfter?: string }): string {
  const parts: string[] = [];
  if (r.tokensLeft != null) parts.push(t("tokens left: {left} of {limit}", { left: fmtInt(r.tokensLeft), limit: r.tokensLimit != null ? fmtInt(r.tokensLimit) : "?" }));
  if (r.requestsLeft != null) parts.push(t("requests left: {left} of {limit}", { left: fmtInt(r.requestsLeft), limit: r.requestsLimit != null ? fmtInt(r.requestsLimit) : "?" }));
  if (r.retryAfter) parts.push(t("retry after {t}", { t: r.retryAfter }));
  return parts.join("\n");
}

/** Two conversations side by side: an A/B test of a prompt, skill, model or MCP server. */
function CompareView({ a, b, refresh }: { a: string; b: string; refresh: string }) {
  const [c, setC] = useState<{ a: ConvSide; b: ConvSide } | null | undefined>(undefined);
  useEffect(() => {
    let alive = true;
    api.llmCompare(a, b).then((r) => alive && setC(r), () => alive && setC(null));
    return () => {
      alive = false;
    };
  }, [a, b, refresh]);
  if (c === undefined) return <div className="muted small">{t("Computing…")}</div>;
  if (c === null) return <div className="muted small">{t("One of the conversations is no longer in the capture.")}</div>;
  const dur = (s: ConvSummary) => Math.max(0, s.ended - s.started) / 1000;
  // Which way is better: less (tokens, cost …), more (cached share), or neither (turns, calls).
  type Better = "less" | "more" | "none";
  const rows: [string, (x: ConvSide) => number, (n: number) => string, Better][] = [
    [t("Turns"), (x) => x.summary.turns, (n) => String(n), "none"],
    [t("Input tokens"), (x) => x.summary.input, fmtInt, "less"],
    [t("Output tokens"), (x) => x.summary.output, fmtInt, "less"],
    [t("Cached share"), (x) => cacheShare(x.summary.cacheRead, x.summary.input), (n) => `${n} %`, "more"],
    [t("Cost"), (x) => x.summary.cost ?? 0, fmtUsd, "less"],
    [t("Duration"), (x) => dur(x.summary), fmtDuration, "less"],
    [t("Last request"), (x) => x.summary.lastInput, fmtInt, "less"],
    [t("Cache misses"), (x) => x.summary.cacheMisses, (n) => String(n), "less"],
    [t("Errors"), (x) => x.summary.errors, (n) => String(n), "less"],
    [t("Hints"), (x) => x.hints, (n) => String(n), "less"],
  ];
  const keys = (f: (x: ConvSide) => Record<string, number>) => [...new Set([...Object.keys(f(c.a)), ...Object.keys(f(c.b))])].sort((x, y) => (f(c.b)[y] ?? 0) + (f(c.a)[y] ?? 0) - (f(c.b)[x] ?? 0) - (f(c.a)[x] ?? 0));
  const delta = (va: number, vb: number, fmt: (n: number) => string, better: Better = "less", relative = true) => {
    if (va === vb) return <span className="muted">=</span>;
    const pct = relative && va ? Math.round(((vb - va) * 100) / va) : null;
    const cls = better === "none" ? "" : (vb > va) === (better === "more") ? "ok" : "warn";
    return (
      <span className={cls}>
        {vb > va ? "+" : "−"}
        {fmt(Math.abs(vb - va))}
        {pct != null && ` (${pct > 0 ? "+" : ""}${pct} %)`}
      </span>
    );
  };
  return (
    <div className="conv-compare">
      <h4>{t("A/B comparison")}</h4>
      <div className="muted small">
        A: {convLabel(c.a.summary)} — B: {convLabel(c.b.summary)}
      </div>
      <table className="agt-table">
        <thead>
          <tr>
            <th />
            <th className="num" title={c.a.summary.title}>
              A
            </th>
            <th className="num" title={c.b.summary.title}>
              B
            </th>
            <th className="num">B − A</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([label, f, fmt, better]) => (
            <tr key={label}>
              <td>{label}</td>
              <td className="num">{fmt(f(c.a))}</td>
              <td className="num">{fmt(f(c.b))}</td>
              <td className="num">{delta(f(c.a), f(c.b), fmt, better, label !== t("Cached share"))}</td>
            </tr>
          ))}
          <tr>
            <td colSpan={4} className="muted small">
              {t("Context of the last request")}
            </td>
          </tr>
          {keys((x) => x.context).map((k) => (
            <tr key={`c:${k}`}>
              <td>{CATEGORIES[k] ?? k}</td>
              <td className="num">{fmtInt(c.a.context[k] ?? 0)}</td>
              <td className="num">{fmtInt(c.b.context[k] ?? 0)}</td>
              <td className="num">{delta(c.a.context[k] ?? 0, c.b.context[k] ?? 0, fmtInt)}</td>
            </tr>
          ))}
          <tr>
            <td colSpan={4} className="muted small">
              {t("Tool calls")}
            </td>
          </tr>
          {keys((x) => x.tools).map((k) => (
            <tr key={`t:${k}`}>
              <td className="mono">
                <div className="agt-ellipsis" title={k}>
                  {k}
                </div>
              </td>
              <td className="num">{c.a.tools[k] ?? 0}</td>
              <td className="num">{c.b.tools[k] ?? 0}</td>
              <td className="num">{delta(c.a.tools[k] ?? 0, c.b.tools[k] ?? 0, String, "none")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
