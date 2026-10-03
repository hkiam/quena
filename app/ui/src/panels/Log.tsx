import { useEffect, useRef } from "react";
import { api } from "../api";
import { fmtTime } from "../lib/format";
import { set, useStore } from "../store";
import { plural, t } from "../i18n";
import { copyText } from "../actions";
import { openMenu, withSelection } from "../components/contextMenus";

const line = (l: { time: number; level: string; message: string }) => `${fmtTime(l.time)} ${l.level} ${l.message}`;

export function LogPanel() {
  const log = useStore((s) => s.log);
  const ref = useRef<HTMLDivElement>(null);
  const stick = useRef(true);
  useEffect(() => {
    const el = ref.current;
    if (el && stick.current) el.scrollTop = el.scrollHeight;
  }, [log]);
  const shown = log.slice(-2000);
  const clear = () => {
    api.logClear();
    set({ log: [] });
  };
  return (
    <div className="logpanel">
      <div className="lt-bar">
        <span className="lt-info">{plural(log.length, "{n} entry", "{n} entries")}</span>
        <button onClick={clear}>{t("Clear")}</button>
        <button onClick={() => void copyText(log.map(line).join("\n"))}>{t("Copy")}</button>
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
          <div
            key={l.seq}
            className={`log-line lvl-${l.level.toLowerCase()}`}
            onContextMenu={(e) =>
              openMenu(
                e,
                withSelection(
                  [
                    { label: t("Copy Line"), action: () => void copyText(line(l)) },
                    { label: t("Copy All"), action: () => void copyText(log.map(line).join("\n")) },
                    { separator: true },
                    { label: t("Clear"), action: clear },
                  ],
                  e.target as Element,
                ),
              )
            }
          >
            <span className="log-time">{fmtTime(l.time)}</span> <span className="log-lvl">{l.level}</span> {l.message}
          </div>
        ))}
      </div>
    </div>
  );
}
