import { useEffect, useState } from "react";
import { api, type SessionSummary } from "../api";
import { fmtMs } from "../lib/format";
import { useStore } from "../store";
import { actions } from "../actions";

export function TimelinePanel() {
  const selection = useStore((s) => s.selection);
  const version = useStore((s) => s.listVersion);
  const [rows, setRows] = useState<SessionSummary[]>([]);
  useEffect(() => {
    const ids = [...selection].sort((a, b) => a - b).slice(0, 1000);
    if (!ids.length) {
      setRows([]);
      return;
    }
    const t = setTimeout(() => api.summaries(ids).then(setRows), 100);
    return () => clearTimeout(t);
  }, [selection, Math.floor(version / 15)]);
  if (!rows.length) return <div className="placeholder">Select sessions to see their timeline.</div>;
  const start = Math.min(...rows.map((r) => r.startedAt));
  const end = Math.max(...rows.map((r) => r.startedAt + (r.durationMs ?? 0) * 1000));
  const span = Math.max(1, end - start);
  return (
    <div className="scroll pad timeline">
      <div className="muted">
        {rows.length} sessions over {fmtMs(Math.round(span / 1000))}
      </div>
      {rows.map((r) => {
        const left = ((r.startedAt - start) / span) * 100;
        const width = Math.max(0.3, (((r.durationMs ?? 0) * 1000) / span) * 100);
        return (
          <div key={r.id} className="tl-row" onClick={() => actions.selectIds([r.id])} title={`#${r.id} ${r.method} ${r.host}${r.url} – ${fmtMs(r.durationMs)}`}>
            <span className="tl-label">
              #{r.id} {r.host}
              {r.url}
            </span>
            <span className="tl-track">
              <span className={`tl-bar ${r.status >= 400 ? "err" : ""} ${r.state !== "done" ? "live" : ""}`} style={{ left: `${left}%`, width: `${width}%` }} />
            </span>
          </div>
        );
      })}
    </div>
  );
}
