import { useEffect, useState } from "react";
import { api } from "../api";
import { fmtBytes, fmtInt } from "../lib/format";
import { set, useStore } from "../store";
import { showContextMenu } from "./ContextMenu";
import { actions } from "../actions";
import { fmtNum, plural, t } from "../i18n";

const PROC_LABELS = {
  all: t("All processes"),
  browsers: t("Browsers only"),
  nonBrowsers: t("Non-browsers"),
  remote: t("Remote clients"),
};

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
    const timer = setTimeout(() => setMsgVisible(false), message.action ? 15000 : message.kind === "error" ? 8000 : 4000);
    return () => clearTimeout(timer);
  }, [message]);

  const running = jobs.filter((j) => j.status === "running" || j.status === "queued");
  const eng = status?.engine;
  const procMode = filters?.enabled ? filters.processMode : "all";
  const procLabel = PROC_LABELS[procMode];

  return (
    <div className="statusbar">
      <div className={`sb-cell sb-capture ${eng?.capturing ? "on" : ""}`} onClick={() => actions.toggleCapture()} title={eng?.listen.join(", ") || t("Not capturing")}>
        <span className="sb-dot" />
        {eng?.capturing ? `Proxy ${eng.listen[0] ?? ""}` : t("Not capturing")}
        {eng?.systemProxy && <span className="sb-tag">{t("system proxy")}</span>}
        {eng?.decrypting && <span className="sb-tag">{t("HTTPS decrypt")}</span>}
      </div>
      <div
        className="sb-cell sb-click"
        onClick={(e) =>
          showContextMenu(
            e.clientX,
            e.clientY - 120,
            (["all", "browsers", "nonBrowsers", "remote"] as const).map((m) => ({
              label: PROC_LABELS[m],
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
      <div className="sb-cell" title={t("visible / total sessions")}>
        {selection.size > 1 ? `${t("{n} selected", { n: fmtInt(selection.size) })} · ` : ""}
        {count !== total ? plural(count, "{shown} of {n} session", "{shown} of {n} sessions", { shown: fmtNum(total) }) : plural(total, "{n} session", "{n} sessions")}
        {status?.filterActive ? <span className="sb-tag">{t("filtered")}</span> : null}
      </div>
      {!!eng?.breakpoints.length && <div className="sb-cell sb-bp">⏸ {eng.breakpoints.join(", ")}</div>}
      {!!eng?.paused && <div className="sb-cell sb-bp">{t("{n} paused", { n: eng.paused })}</div>}
      {eng?.autoresponder && <div className="sb-cell sb-ar">⚡ {t("Mock Rules")}</div>}
      {eng?.rewrite && (
        <div className="sb-cell sb-ar" title={t("Rewrite rules change real requests and responses (list in the Mock Rules tab)")}>
          ✎ {t("Rewrite rules")}
        </div>
      )}
      {status?.recordingSuspended && <div className="sb-cell sb-warn">{t("Recording suspended (disk)")}</div>}
      {status?.mockRunning && <div className="sb-cell sb-warn">{t("Mock traffic")}</div>}
      <div className="sb-msg">
        {msgVisible && message ? (
          <>
            <span className={message.kind === "error" ? "sb-error" : ""}>{message.text}</span>
            {message.action && (
              <button
                className="sb-msg-action linklike"
                onClick={() => {
                  setMsgVisible(false);
                  message.action?.run();
                }}
              >
                {message.action.label}
              </button>
            )}
          </>
        ) : eng?.error ? (
          <span className="sb-error">{eng.error}</span>
        ) : null}
      </div>
      {running.length > 0 && (
        <div className="sb-cell sb-click sb-jobs" onClick={() => set({ dialog: { kind: "jobs" } })} title={t("Background jobs")}>
          <span className="spinner" /> {plural(running.length, "{n} job", "{n} jobs")}: {running[0].title}
          {running[0].total > 0 && <span> {Math.floor((running[0].done / running[0].total) * 100)}%</span>}
        </div>
      )}
      <div className="sb-cell" title={status?.captureDir}>
        {status ? t("{size} stored", { size: fmtBytes(status.usedBytes) }) : ""}
        {status?.freeBytes != null ? ` · ${t("{size} free", { size: fmtBytes(status.freeBytes) })}` : ""}
      </div>
    </div>
  );
}
