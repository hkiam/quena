import { useEffect, useState } from "react";
import { api } from "../api";
import { fmtBytes, fmtInt } from "../lib/format";
import { set, useStore } from "../store";
import { showContextMenu } from "./ContextMenu";
import { actions } from "../actions";

export function StatusBar() {
  const status = useStore((s) => s.status);
  const message = useStore((s) => s.message);
  const jobs = useStore((s) => s.jobs);
  const selection = useStore((s) => s.selection);
  const total = useStore((s) => s.listTotal);
  const count = useStore((s) => s.status?.sessions ?? s.listCount);
  const filters = useStore((s) => s.filters);
  const [msgVisible, setMsgVisible] = useState(false);

  useEffect(() => {
    if (!message) return;
    setMsgVisible(true);
    const t = setTimeout(() => setMsgVisible(false), message.kind === "error" ? 8000 : 4000);
    return () => clearTimeout(t);
  }, [message]);

  const running = jobs.filter((j) => j.status === "running" || j.status === "queued");
  const eng = status?.engine;
  const procMode = filters?.enabled ? filters.processMode : "all";
  const procLabel = { all: "All Processes", browsers: "Web Browsers", nonBrowsers: "Non-Browser", remote: "Remote Clients" }[procMode];

  return (
    <div className="statusbar">
      <div className={`sb-cell sb-capture ${eng?.capturing ? "on" : ""}`} onClick={() => actions.toggleCapture()} title={eng?.listen.join(", ") || "Not capturing"}>
        {eng?.capturing ? "● Capturing" : "○ Not capturing"}
        {eng?.systemProxy && <span className="sb-tag">System Proxy</span>}
        {eng?.decrypting && <span className="sb-tag">HTTPS</span>}
      </div>
      <div
        className="sb-cell sb-click"
        onClick={(e) =>
          showContextMenu(
            e.clientX,
            e.clientY - 120,
            (["all", "browsers", "nonBrowsers", "remote"] as const).map((m) => ({
              label: { all: "All Processes", browsers: "Web Browsers", nonBrowsers: "Non-Browser", remote: "Remote Clients" }[m],
              checked: procMode === m,
              action: async () => {
                const f = await api.getFilters();
                const next = { ...f, enabled: true, processMode: m };
                set({ filters: next });
                await api.setFilters(next);
              },
            })),
          )
        }
      >
        {procLabel}
      </div>
      <div className="sb-cell" title="visible / total sessions">
        {selection.size > 1 ? `${fmtInt(selection.size)} selected · ` : ""}
        {fmtInt(total)}
        {count !== total ? ` / ${fmtInt(count)}` : ""}
        {status?.filterActive ? " (filtered)" : ""}
      </div>
      {!!eng?.breakpoints.length && <div className="sb-cell sb-bp">⏸ {eng.breakpoints.join(", ")}</div>}
      {!!eng?.paused && <div className="sb-cell sb-bp">{eng.paused} paused</div>}
      {eng?.autoresponder && <div className="sb-cell sb-ar">⚡ Mock Rules</div>}
      {status?.recordingSuspended && <div className="sb-cell sb-warn">Recording suspended (disk)</div>}
      {status?.mockRunning && <div className="sb-cell sb-warn">Mock traffic</div>}
      <div className="sb-msg">
        {msgVisible && message ? <span className={message.kind === "error" ? "sb-error" : ""}>{message.text}</span> : eng?.error ? <span className="sb-error">{eng.error}</span> : null}
      </div>
      {running.length > 0 && (
        <div className="sb-cell sb-click sb-jobs" onClick={() => set({ dialog: { kind: "jobs" } })} title="Background jobs">
          <span className="spinner" /> {running.length} job{running.length > 1 ? "s" : ""}: {running[0].title}
          {running[0].total > 0 && <span> {Math.floor((running[0].done / running[0].total) * 100)}%</span>}
        </div>
      )}
      <div className="sb-cell" title={status?.captureDir}>
        {status ? `${fmtBytes(status.usedBytes)} stored` : ""}
        {status?.freeBytes != null ? ` · ${fmtBytes(status.freeBytes)} free` : ""}
      </div>
    </div>
  );
}
