import { useEffect, useState } from "react";
import { api, type SessionSummary, type Timers } from "../api";
import { fmtMs } from "../lib/format";
import { PHASES, phasesOf, type Segment } from "../lib/waterfall";
import { useStore } from "../store";
import { actions } from "../actions";
import { fmtNum, plural, t } from "../i18n";

const MAX = 500;

export function TimelinePanel() {
  const selection = useStore((s) => s.selection);
  const version = useStore((s) => s.listVersion);
  const [rows, setRows] = useState<SessionSummary[]>([]);
  const [timers, setTimers] = useState<Map<number, Timers>>(new Map());
  useEffect(() => {
    const ids = [...selection].sort((a, b) => a - b).slice(0, MAX);
    if (!ids.length) {
      setRows([]);
      setTimers(new Map());
      return;
    }
    let live = true;
    const t = setTimeout(() => {
      api.summaries(ids).then((r) => live && setRows(r));
      api
        .timers(ids)
        .then((ts) => live && setTimers(new Map(ts.map((x) => [x.id, x.timers]))))
        .catch(() => {});
    }, 100);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [selection, Math.floor(version / 15)]);
  if (!rows.length) return <div className="placeholder">{t("Select sessions to see their timeline.")}</div>;

  const segs = new Map<number, Segment[]>(rows.map((r) => [r.id, timers.has(r.id) ? phasesOf(timers.get(r.id)!) : []]));
  const endOf = (r: SessionSummary) => Math.max(r.startedAt + (r.durationMs ?? 0) * 1000, ...(segs.get(r.id) ?? []).map((s) => s.end));
  const startOf = (r: SessionSummary) => Math.min(r.startedAt, ...(segs.get(r.id) ?? []).map((s) => s.start));
  const start = Math.min(...rows.map(startOf));
  const end = Math.max(...rows.map(endOf));
  const span = Math.max(1, end - start);
  const pct = (us: number) => ((us - start) / span) * 100;
  const used = new Set([...segs.values()].flat().map((s) => s.phase));
  return (
    <div className="scroll pad timeline">
      <div className="tl-head">
        <span className="muted">
          {plural(rows.length, "{n} session over {time}", "{n} sessions over {time}", { time: fmtMs(Math.round(span / 1000)) })}
          {selection.size > MAX ? t(" (first {max} of {total})", { max: fmtNum(MAX), total: fmtNum(selection.size) }) : ""}
        </span>
        <span className="tl-legend">
          {PHASES.filter((p) => used.has(p.key)).map((p) => (
            <span key={p.key}>
              <i className={`tl-seg ph-${p.key}`} /> {p.label}
            </span>
          ))}
        </span>
      </div>
      {rows.map((r) => {
        const s = segs.get(r.id) ?? [];
        const tip = [`#${r.id} ${r.method} ${r.host}${r.url} – ${fmtMs(r.durationMs)}`, ...s.map((x) => `${PHASES.find((p) => p.key === x.phase)!.label}: ${fmtMs(Math.round((x.end - x.start) / 1000))}`)].join("\n");
        return (
          <div key={r.id} className="tl-row" onClick={() => actions.selectIds([r.id])} title={tip}>
            <span className="tl-label">
              #{r.id} {r.host}
              {r.url}
            </span>
            <span className="tl-track">
              {s.length ? (
                s.map((x, i) => <span key={i} className={`tl-seg ph-${x.phase}`} style={{ left: `${pct(x.start)}%`, width: `${Math.max(0.15, pct(x.end) - pct(x.start))}%` }} />)
              ) : (
                <span
                  className={`tl-bar ${r.status >= 400 ? "err" : ""} ${r.state !== "done" ? "live" : ""}`}
                  style={{ left: `${pct(r.startedAt)}%`, width: `${Math.max(0.3, (((r.durationMs ?? 0) * 1000) / span) * 100)}%` }}
                />
              )}
              {r.status >= 400 && s.length > 0 && <span className="tl-err-dot" style={{ left: `${pct(endOf(r))}%` }} />}
            </span>
          </div>
        );
      })}
    </div>
  );
}
