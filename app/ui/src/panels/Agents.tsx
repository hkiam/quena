// Agents: the conversations of AI agents in the capture (each run of Claude Code, Codex, an
// app), with their turns, what fills the context, where the prompt cache missed and why, and
// hints where tokens go to waste.
import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { RefreshCw } from "lucide-react";
import { api, type CallContext, type ConvDetail, type ConvSummary, type SessionId } from "../api";
import { actions } from "../actions";
import { fmtInt, fmtMs, fmtTime, fmtUsd } from "../lib/format";
import { breaksCache, cacheText, convTree, diffText, hintText, hintTokens } from "../lib/agentText";
import { CallContextView } from "./CallContext";
import { set, useStore } from "../store";
import { plural, t } from "../i18n";
import { ContextMap } from "./ContextMap";

const tokens = (c: { input: number; output: number }) => c.input + c.output;

/** `value` once it has not changed for `quiet` ms, and at least every `most` ms while it keeps
 * changing (an agent at work changes the list all the time). */
function useSettled<T>(value: T, quiet = 400, most = 3000): T {
  const [settled, setSettled] = useState(value);
  const since = useRef(Date.now());
  useEffect(() => {
    if (Object.is(value, settled)) return;
    const wait = Math.max(0, Math.min(quiet, most - (Date.now() - since.current)));
    const timer = setTimeout(() => {
      since.current = Date.now();
      setSettled(value);
    }, wait);
    return () => clearTimeout(timer);
  }, [value, settled, quiet, most]);
  return settled;
}
const cacheShare = (read: number, input: number) => (input > 0 ? Math.round((read * 100) / input) : 0);

export default function AgentsPanel() {
  const version = useSettled(useStore((s) => s.listVersion));
  const sel = useStore((s) => s.agentConv);
  const [list, setList] = useState<ConvSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    const timer = setTimeout(
      () =>
        api.llmConversations().then(
          (r) => alive && (setList(r), setError(null)),
          (e) => alive && setError(String(e)),
        ),
      0,
    );
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [version, tick]);
  const tree = useMemo(() => convTree(list ?? []), [list]);
  if (error && !list) return <div className="placeholder">{error}</div>;
  if (!list) return <div className="placeholder">{t("Computing…")}</div>;
  if (!list.length)
    return (
      <div className="placeholder">
        {t("No LLM calls in the capture. Start an agent (Claude Code, Codex …) through Quena; each of its runs shows here as a conversation.")}
      </div>
    );
  // A conversation opened from the LLM view may not be in the list yet: it loads on its own.
  const shown = sel;
  return (
    <div className="agents">
      <div className="agents-list scroll">
        <div className="lt-bar">
          <span className="muted small">{plural(list.length, "{n} conversation", "{n} conversations")}</span>
          {error && <span className="mocks-error small">{error}</span>}
          <span className="tp-spacer" />
          <button className="icon-btn" title={t("Refresh")} onClick={() => setTick(tick + 1)}>
            <RefreshCw size={13} />
          </button>
        </div>
        <table className="agt-table agents-table">
          <thead>
            <tr>
              <th>{t("Conversation")}</th>
              <th>{t("Agent")}</th>
              <th className="num">{t("Turns")}</th>
              <th className="num">{t("Tokens")}</th>
              <th className="num" title={t("Share of the input served from the provider's prompt cache")}>
                {t("Cached")}
              </th>
              <th className="num">{t("Cost")}</th>
            </tr>
          </thead>
          <tbody>
            {tree.map(({ c, depth }) => (
              <tr key={c.key} className={c.key === shown ? "selected" : ""} onClick={() => set({ agentConv: c.key })} onDoubleClick={() => void actions.selectIds([c.first])}>
                <td title={`${c.title}\n${c.models.join(", ")}`}>
                  <div className="agt-title" style={{ paddingLeft: depth * 14 }}>
                    {depth > 0 && <span className="muted">↳</span>}
                    <span className="agt-title-text">{c.title}</span>
                    {c.cacheMisses > 0 && (
                      <span className="pill pill-warn" title={t("The cache missed in {n} turns", { n: c.cacheMisses })}>
                        {c.cacheMisses}
                      </span>
                    )}
                    {c.errors > 0 && <span className="pill pill-err">{c.errors}</span>}
                  </div>
                </td>
                <td className="mono small">{c.agent || c.provider}</td>
                <td className="num">{c.turns}</td>
                <td className="num">{fmtInt(tokens(c))}</td>
                <td className="num">{cacheShare(c.cacheRead, c.input)} %</td>
                <td className="num">{c.cost != null ? fmtUsd(c.cost) : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="agents-detail scroll pad">{shown ? <Conversation key={shown} convKey={shown} refresh={`${version}:${tick}`} list={list} /> : <div className="placeholder">{t("Choose a conversation.")}</div>}</div>
    </div>
  );
}

function Conversation({ convKey, refresh, list }: { convKey: string; refresh: string; list: ConvSummary[] }) {
  const [d, setD] = useState<ConvDetail | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [turnId, setTurnId] = useState<SessionId | null>(null);
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
  if (d === undefined) return <div className="placeholder">{error ?? t("Computing…")}</div>;
  if (d === null) return <div className="placeholder">{t("The conversation is no longer in the capture.")}</div>;
  const s = d.summary;
  const span = Math.max(1, s.ended - s.started);
  const titleOf = (k: string) => list.find((c) => c.key === k)?.title ?? k;
  const turnAt = d.turns.findIndex((x) => x.id === turnId);
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
        <span>{plural(s.turns, "{n} turn", "{n} turns")}</span>
        {s.side > 0 && <span>{plural(s.side, "{n} side call", "{n} side calls")}</span>}
        {s.hits > 0 && <span>{plural(s.hits, "{n} from the agent cache", "{n} from the agent cache")}</span>}
        <span>{fmtMs(Math.round(span / 1000))}</span>
        <span>{t("in {n}", { n: fmtInt(s.input) })}</span>
        <span>{t("out {n}", { n: fmtInt(s.output) })}</span>
        <span title={t("Share of the input served from the provider's prompt cache")}>{t("cached {pct} %", { pct: cacheShare(s.cacheRead, s.input) })}</span>
        {s.cost != null && <span>≈ {fmtUsd(s.cost)}</span>}
        {s.window ? (
          <span title={t("The last request's input of the model's context window")}>
            {t("context {pct} %", { pct: Math.round((s.lastInput * 100) / s.window) })}
          </span>
        ) : null}
      </div>
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
      <table className="agt-table conv-turns">
        <thead>
          <tr>
            <th className="num">#</th>
            <th>{t("Time")}</th>
            <th className="conv-bar-col" />
            <th className="num">{t("In")}</th>
            <th className="num" title={t("Read from the prompt cache")}>
              {t("Cached")}
            </th>
            <th className="num">{t("Out")}</th>
            <th className="num">{t("Cost")}</th>
            <th>{t("Change")}</th>
            <th>{t("Calls")}</th>
          </tr>
        </thead>
        <tbody>
          {d.turns.map((x, i) => {
            const miss = x.cache.some((c) => c.code === "miss");
            const left = ((x.started - s.started) * 100) / span;
            const width = ((x.durationMs ?? 0) * 1000 * 100) / span;
            return (
              <tr
                key={x.id}
                className={`${turnId === x.id ? "selected" : ""} ${x.error ? "err" : ""} ${x.side ? "side" : ""}`}
                onClick={() => setTurnId(x.id)}
                onDoubleClick={() => void actions.selectIds([x.id])}
                title={[...x.cache.map(cacheText), t("Double-click: select the session")].join("\n")}
              >
                <td className="num" title={x.prev != null ? t("Continues #{n}", { n: d.turns.findIndex((y) => y.id === x.prev) + 1 }) : undefined}>
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
                <td className={`small ${breaksCache(x.diff) ? "warn" : "muted"}`}>
                  {diffText(x.diff)}
                  {x.diff.modelChanged && <span className="mono"> {x.model}</span>}
                </td>
                <td className="small mono">
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
                  {x.calls.join(", ")}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {turnAt >= 0 ? (
        <TurnContext key={d.turns[turnAt].id} id={d.turns[turnAt].id} index={turnAt + 1} />
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

/** A turn: what filled its context, how it differs from the one before, the cache. */
function TurnContext({ id, index }: { id: SessionId; index: number }) {
  const [c, setC] = useState<CallContext | null | undefined>(undefined);
  useEffect(() => {
    let alive = true;
    api.llmContext(id).then((r) => alive && setC(r), () => alive && setC(null));
    return () => {
      alive = false;
    };
  }, [id]);
  return (
    <>
      <h4>{t("Turn {n}", { n: index })}</h4>
      {c === undefined && <div className="muted small">{t("Computing…")}</div>}
      {c === null && <div className="muted small">{t("The request of this turn cannot be read.")}</div>}
      {c && <CallContextView c={c} />}
    </>
  );
}
