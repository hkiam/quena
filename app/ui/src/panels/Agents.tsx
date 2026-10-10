// Agents: the conversations of AI agents in the capture (each run of Claude Code, Codex, an
// app), with their turns, what fills the context, where the prompt cache missed and why, and
// hints where tokens go to waste.
import { Fragment, useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { api, type CallContext, type ConvDetail, type ConvSummary, type ConvTurn } from "../api";
import { actions } from "../actions";
import { fmtInt, fmtMs, fmtTime, fmtUsd } from "../lib/format";
import { breaksCache, cacheText, convTree, diffText, hintText, hintTokens } from "../lib/agentText";
import { set, useStore } from "../store";
import { plural, t } from "../i18n";
import { ContextMap } from "./ContextMap";

const tokens = (c: { input: number; output: number }) => c.input + c.output;
const cacheShare = (read: number, input: number) => (input > 0 ? Math.round((read * 100) / input) : 0);

export default function AgentsPanel() {
  const version = useStore((s) => s.listVersion);
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
      list ? 400 : 0,
    );
    return () => {
      alive = false;
      clearTimeout(timer);
    };
    // A new session shows after a moment; many in a row do not ask each time.
  }, [Math.floor(version / 20), tick]);
  const tree = useMemo(() => convTree(list ?? []), [list]);
  if (error) return <div className="placeholder">{error}</div>;
  if (!list) return <div className="placeholder">{t("Computing…")}</div>;
  if (!list.length)
    return (
      <div className="placeholder">
        {t("No LLM calls in the capture. Start an agent (Claude Code, Codex …) through Quena; each of its runs shows here as a conversation.")}
      </div>
    );
  const shown = sel && list.some((c) => c.key === sel) ? sel : null;
  return (
    <div className="agents">
      <div className="agents-list scroll">
        <div className="lt-bar">
          <span className="muted small">{plural(list.length, "{n} conversation", "{n} conversations")}</span>
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
                  <span style={{ paddingLeft: depth * 14 }}>
                    {depth > 0 && <span className="muted">↳ </span>}
                    {c.title}
                  </span>
                  {c.cacheMisses > 0 && (
                    <span className="pill pill-warn" title={t("The cache missed in {n} turns", { n: c.cacheMisses })}>
                      {c.cacheMisses}
                    </span>
                  )}
                  {c.errors > 0 && <span className="pill pill-err">{c.errors}</span>}
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
      <div className="agents-detail scroll pad">{shown ? <Conversation key={shown} convKey={shown} version={version} list={list} /> : <div className="placeholder">{t("Choose a conversation.")}</div>}</div>
    </div>
  );
}

function Conversation({ convKey, version, list }: { convKey: string; version: number; list: ConvSummary[] }) {
  const [d, setD] = useState<ConvDetail | null | undefined>(undefined);
  const [turn, setTurn] = useState<ConvTurn | null>(null);
  useEffect(() => {
    let alive = true;
    api.llmConversation(convKey).then((r) => alive && setD(r), () => alive && setD(null));
    return () => {
      alive = false;
    };
  }, [convKey, Math.floor(version / 20)]);
  if (d === undefined) return <div className="placeholder">{t("Computing…")}</div>;
  if (d === null) return <div className="placeholder">{t("The conversation is no longer in the capture.")}</div>;
  const s = d.summary;
  const span = Math.max(1, s.ended - s.started);
  const titleOf = (k: string) => list.find((c) => c.key === k)?.title ?? k;
  return (
    <div className="conv">
      <div className="conv-head">
        <b>{s.title}</b>
        <span className="muted small mono">{s.key}</span>
      </div>
      <div className="conv-facts small">
        <span>{s.agent || s.provider}</span>
        <span className="mono">{s.models.join(", ")}</span>
        <span>{plural(s.turns, "{n} turn", "{n} turns")}</span>
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
          <span className="linklike" onClick={() => set({ agentConv: s.parent ?? null })}>
            {titleOf(s.parent)}
          </span>
        </div>
      )}
      {d.children.length > 0 && (
        <div className="small">
          {t("Subagents:")}{" "}
          {d.children.map((k, i) => (
            <Fragment key={k}>
              {i > 0 && ", "}
              <span className="linklike" onClick={() => set({ agentConv: k })}>
                {titleOf(k)}
              </span>
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
            const width = Math.max(0.5, (((x.durationMs ?? 0) * 1000) * 100) / span);
            return (
              <tr
                key={x.id}
                className={`${turn?.id === x.id ? "selected" : ""} ${x.error ? "err" : ""}`}
                onClick={() => {
                  setTurn(x);
                  void actions.selectIds([x.id]);
                }}
                title={x.cache.map(cacheText).join("\n")}
              >
                <td className="num">{i + 1}</td>
                <td className="small">{fmtTime(x.started)}</td>
                <td className="conv-bar-col">
                  <div className="conv-bar" style={{ left: `${left}%`, width: `${width}%` }} />
                </td>
                <td className="num">{x.usage ? fmtInt(x.usage.input) : ""}</td>
                <td className={`num ${miss ? "warn" : ""}`}>{x.usage ? `${cacheShare(x.usage.cacheRead, x.usage.input)} %` : ""}</td>
                <td className="num">{x.usage ? fmtInt(x.usage.output) : ""}</td>
                <td className="num">{x.cost != null ? fmtUsd(x.cost) : ""}</td>
                <td className={`small ${breaksCache(x.diff) ? "warn" : "muted"}`}>
                  {diffText(x.diff)}
                  {x.diff.modelChanged && <span className="mono"> {x.model}</span>}
                </td>
                <td className="small mono">{x.calls.join(", ")}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {turn ? (
        <TurnContext key={turn.id} turn={turn} index={d.turns.indexOf(turn) + 1} />
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
function TurnContext({ turn, index }: { turn: ConvTurn; index: number }) {
  const [c, setC] = useState<CallContext | null | undefined>(undefined);
  useEffect(() => {
    let alive = true;
    api.llmContext(turn.id).then((r) => alive && setC(r), () => alive && setC(null));
    return () => {
      alive = false;
    };
  }, [turn.id]);
  return (
    <>
      <h4>{t("Turn {n}", { n: index })}</h4>
      {c === undefined && <div className="muted small">{t("Computing…")}</div>}
      {c === null && <div className="muted small">{t("The request of this turn cannot be read.")}</div>}
      {c && <CallContextView c={c} />}
    </>
  );
}

/** Change from the previous turn, cache notes and the context map (also in the LLM view). */
export function CallContextView({ c }: { c: CallContext }) {
  return (
    <div className="call-ctx">
      {c.diff && c.diff.kind !== "first" && (
        <div className="small">
          <b>{t("Change from the turn before:")}</b> {diffText(c.diff)}
          {c.diff.gapMs != null && c.diff.gapMs > 0 && <span className="muted"> · {t("{t} after it", { t: fmtMs(c.diff.gapMs) })}</span>}
          {!!c.diff.toolsAdded?.length && <div className="mono small">+ {c.diff.toolsAdded.join(", ")}</div>}
          {!!c.diff.toolsRemoved?.length && <div className="mono small">− {c.diff.toolsRemoved.join(", ")}</div>}
          {!!c.diff.toolsChanged?.length && <div className="mono small">~ {c.diff.toolsChanged.join(", ")}</div>}
        </div>
      )}
      {c.changed && (
        <div className="call-ctx-changed small">
          <div>
            <span className="muted">{t("before:")}</span> <span className="mono">{c.changed[0]}</span>
          </div>
          <div>
            <span className="muted">{t("now:")}</span> <span className="mono">{c.changed[1]}</span>
          </div>
        </div>
      )}
      {c.cache.length > 0 && (
        <ul className="conv-hints warn">
          {c.cache.map((n, i) => (
            <li key={i}>{cacheText(n)}</li>
          ))}
        </ul>
      )}
      <ContextMap b={c.breakdown} />
      {c.window && c.breakdown.actual != null && (
        <div className="muted small">{t("{pct} % of the context window ({window} tokens)", { pct: Math.round((c.breakdown.actual * 100) / c.window), window: fmtInt(c.window) })}</div>
      )}
    </div>
  );
}
