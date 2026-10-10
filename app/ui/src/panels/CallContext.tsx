// One LLM call in its conversation: the change from the turn before, why the prompt cache
// missed, and what fills its context (Agents panel and LLM view).
import type { CallContext } from "../api";
import { fmtInt, fmtMs } from "../lib/format";
import { cacheText, diffText } from "../lib/agentText";
import { t } from "../i18n";
import { ContextMap } from "./ContextMap";

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
