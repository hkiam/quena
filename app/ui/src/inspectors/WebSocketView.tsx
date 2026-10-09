// WebSocket inspector (M15): frame log with direction, opcode, size, payload.
import { useEffect, useRef, useState } from "react";
import { api, type Detail, type SioPacket, type WsFrame } from "../api";
import { fmtBytes, fmtInt, fmtTime } from "../lib/format";
import { CodeView } from "./CodeView";
import { useStore } from "../store";
import { t } from "../i18n";
import { openMenu, withSelection } from "../components/contextMenus";
import { copyItem } from "./inspectMenus";

const PAGE = 500;

/** What a Socket.IO packet is, in a few words: the event, else the packet type. */
export function sioLabel(p: SioPacket): string {
  if (p.event) return p.event;
  if (p.sio) return p.ack != null ? `${p.sio} #${p.ack}` : p.sio;
  return p.eio;
}

/** Engine.IO or WebSocket keep-alive. */
export function isHeartbeat(f: WsFrame): boolean {
  return f.opcode === 9 || f.opcode === 10 || f.sio?.eio === "ping" || f.sio?.eio === "pong";
}

function looksJson(t: string) {
  const s = t.trim();
  return (s.startsWith("{") && s.endsWith("}")) || (s.startsWith("[") && s.endsWith("]"));
}

export function WebSocketView({ detail }: { detail: Detail }) {
  const [frames, setFrames] = useState<WsFrame[]>([]);
  const [total, setTotal] = useState(0);
  const [complete, setComplete] = useState(false);
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sel, setSel] = useState<number | null>(null);
  const [filter, setFilter] = useState<"all" | "text" | "in" | "out">("all");
  const [hideBeats, setHideBeats] = useState(false);
  const [search, setSearch] = useState("");
  const version = useStore((s) => s.listVersion);
  const stick = useRef(true);
  const scroller = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let alive = true;
    let busy = false;
    const load = () => {
      if (busy) return;
      busy = true;
      const start = Math.max(0, total - PAGE);
      api
        .wsFrames(detail.summary.id, complete ? start : Math.max(0, (total || 0) - PAGE), PAGE)
        .then(
          (m) => {
            if (!alive) return;
            setFrames(m.frames);
            setTotal(m.total);
            setComplete(m.complete);
            setTruncated(!!m.truncated);
            setError(null);
          },
          (e) => alive && setError(t("Could not load frames: {error}", { error: String(e) })),
        )
        .finally(() => (busy = false));
    };
    load();
    const timer = detail.summary.state === "done" || detail.summary.state === "aborted" ? null : setInterval(load, 500);
    return () => {
      alive = false;
      if (timer) clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail.summary.id, version]);

  useEffect(() => {
    if (stick.current && scroller.current) scroller.current.scrollTop = scroller.current.scrollHeight;
  }, [frames]);

  const sio = frames.some((f) => f.sio);
  const needle = search.trim().toLowerCase();
  const shown = frames.filter((f) => {
    if (hideBeats && isHeartbeat(f)) return false;
    if (needle && !(f.sio ? sioLabel(f.sio) : (f.text ?? "")).toLowerCase().includes(needle)) return false;
    if (filter === "text") return f.opcode === 1;
    if (filter === "in") return f.dir === 1;
    if (filter === "out") return f.dir === 0;
    return true;
  });
  const selFrame = shown.find((f) => f.seq === sel) ?? null;

  return (
    <div className="wsview">
      <div className="lt-bar">
        <span className="lt-info">
          {total === 1 ? t("{n} frame", { n: fmtInt(total) }) : t("{n} frames", { n: fmtInt(total) })}
          {!complete ? ` · ${t("live")}` : ""}
          {total > frames.length && ` · ${t("last {n} shown", { n: fmtInt(frames.length) })}`}
          {truncated && ` · ${t("truncated (recording limit reached)")}`}
          {error && <span className="err"> · {error}</span>}
        </span>
        <label className="f-check small">
          <input type="checkbox" checked={hideBeats} onChange={(e) => setHideBeats(e.target.checked)} /> {t("Hide ping/pong")}
        </label>
        <input
          className="ws-search"
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
          placeholder={sio ? t("Event…") : t("Text…")}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select value={filter} onChange={(e) => setFilter(e.target.value as typeof filter)}>
          <option value="all">{t("All frames")}</option>
          <option value="text">{t("Text messages")}</option>
          <option value="out">↑ Client → Server</option>
          <option value="in">↓ Server → Client</option>
        </select>
      </div>
      <div className="ws-split">
        <div
          className="ws-list"
          ref={scroller}
          onScroll={(e) => {
            const el = e.target as HTMLDivElement;
            stick.current = el.scrollTop + el.clientHeight >= el.scrollHeight - 20;
          }}
        >
          {shown.map((f) => (
            <div
              key={f.seq}
              className={`ws-frame ${sel === f.seq ? "sel" : ""} op-${f.opcodeName}`}
              onClick={() => setSel(f.seq)}
              onContextMenu={(e) => {
                setSel(f.seq);
                openMenu(e, withSelection([copyItem(f.text != null && f.len <= 4096 ? t("Copy Message") : t("Copy Preview"), f.text ?? f.preview ?? "")], e.target as Element));
              }}
            >
              <span className={`ws-dir ${f.dir === 0 ? "out" : "in"}`}>{f.dir === 0 ? "▲" : "▼"}</span>
              <span className="ws-op" title={f.sio ? `${f.sio.eio}${f.sio.sio ? ` / ${f.sio.sio}` : ""}` : undefined}>
                {f.sio ? sioLabel(f.sio) : f.opcodeName}
              </span>
              {f.dropped ? (
                <span className="ws-mark err" title={t("Not sent: dropped by the rules script")}>
                  ✕
                </span>
              ) : f.edited ? (
                <span className="ws-mark" title={t("Changed on the way by a rule or the rules script")}>
                  ✎
                </span>
              ) : null}
              <span className="ws-time">{fmtTime(f.time)}</span>
              <span className="ws-len">{fmtBytes(f.len)}</span>
              <span className="ws-text">{(f.sio?.event ? (f.sio.data ?? "").replace(/\s+/g, " ") : (f.text ?? f.preview ?? "")).slice(0, 500)}</span>
            </div>
          ))}
          {shown.length === 0 && !error && <div className="placeholder">{total > 0 ? t("No frames match the filter.") : t("No frames yet.")}</div>}
        </div>
        {selFrame && (
          <div className="ws-detail">
            <div className="ws-detail-head">
              {selFrame.dir === 0 ? "Client → Server" : "Server → Client"} · {selFrame.opcodeName} · {fmtBytes(selFrame.len)} · {fmtTime(selFrame.time)}
              {!selFrame.fin && ` · ${t("fragment")}`}
              {selFrame.dropped ? ` · ${t("not sent")}` : selFrame.edited ? ` · ${t("changed by Quena")}` : ""}
            </div>
            {selFrame.sio && (
              <div className="ws-sio small">
                Socket.IO: <b>{selFrame.sio.eio}</b>
                {selFrame.sio.sio && <> · {selFrame.sio.sio}</>}
                {selFrame.sio.namespace && <> · {t("namespace {ns}", { ns: selFrame.sio.namespace })}</>}
                {selFrame.sio.ack != null && <> · ack {selFrame.sio.ack}</>}
                {selFrame.sio.event && (
                  <>
                    {" "}
                    · {t("event")} <b className="mono">{selFrame.sio.event}</b>
                  </>
                )}
                {selFrame.sio.attachments != null && <> · {t("{n} binary attachments", { n: selFrame.sio.attachments })}</>}
              </div>
            )}
            {selFrame.sio?.data != null ? (
              <CodeView text={selFrame.sio.data} lang={looksJson(selFrame.sio.data) ? "json" : "text"} wrap />
            ) : selFrame.text != null ? (
              <CodeView text={selFrame.text} lang={looksJson(selFrame.text) ? "json" : "text"} wrap />
            ) : (
              <pre className="ws-hex">{selFrame.preview ?? t("(no payload)")}</pre>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
