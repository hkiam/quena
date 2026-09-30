import { useEffect, useRef } from "react";
import { api } from "../api";
import { fmtTime } from "../lib/format";
import { set, useStore } from "../store";
import { plural, t } from "../i18n";

export function LogPanel() {
  const log = useStore((s) => s.log);
  const ref = useRef<HTMLDivElement>(null);
  const stick = useRef(true);
  useEffect(() => {
    const el = ref.current;
    if (el && stick.current) el.scrollTop = el.scrollHeight;
  }, [log]);
  const shown = log.slice(-2000);
  return (
    <div className="logpanel">
      <div className="lt-bar">
        <span className="lt-info">{plural(log.length, "{n} entry", "{n} entries")}</span>
        <button
          onClick={() => {
            api.logClear();
            set({ log: [] });
          }}
        >
          {t("Clear")}
        </button>
        <button onClick={() => navigator.clipboard.writeText(log.map((l) => `${fmtTime(l.time)} ${l.level} ${l.message}`).join("\n"))}>{t("Copy")}</button>
      </div>
      <div
        className="log-scroll mono"
        ref={ref}
        onScroll={(e) => {
          const el = e.target as HTMLDivElement;
          stick.current = el.scrollTop + el.clientHeight >= el.scrollHeight - 20;
        }}
      >
        {shown.map((l) => (
          <div key={l.seq} className={`log-line lvl-${l.level.toLowerCase()}`}>
            <span className="log-time">{fmtTime(l.time)}</span> <span className="log-lvl">{l.level}</span> {l.message}
          </div>
        ))}
      </div>
    </div>
  );
}
