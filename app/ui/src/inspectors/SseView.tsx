// Server-Sent Events inspector (M15): parse text/event-stream into events.
import { useEffect, useRef, useState } from "react";
import { api, fetchBody, type Detail } from "../api";
import { fmtBytes, fmtInt } from "../lib/format";
import { decodeBytes } from "../lib/bodytext";
import { useCharsetOverride } from "./CharsetPicker";
import { useStore } from "../store";
import { t } from "../i18n";
import { openMenu, withSelection } from "../components/contextMenus";
import { copyItem } from "./inspectMenus";

interface Event {
  id?: string;
  event: string;
  data: string;
  retry?: string;
  raw: number;
}

function parse(text: string): { events: Event[]; partial: string } {
  const events: Event[] = [];
  // The spec allows CR, LF and CRLF line endings.
  const blocks = text.replace(/\r\n?/g, "\n").split(/\n\n/);
  const partial = blocks.pop() ?? "";
  for (const block of blocks) {
    if (!block.trim() || block.startsWith(":")) continue;
    let ev: Event = { event: "message", data: "", raw: block.length };
    const data: string[] = [];
    for (const line of block.split("\n")) {
      const c = line.indexOf(":");
      const field = c < 0 ? line : line.slice(0, c);
      let val = c < 0 ? "" : line.slice(c + 1);
      if (val.startsWith(" ")) val = val.slice(1);
      if (field === "event") ev.event = val;
      else if (field === "data") data.push(val);
      else if (field === "id") ev.id = val;
      else if (field === "retry") ev.retry = val;
    }
    ev.data = data.join("\n");
    events.push(ev);
  }
  return { events, partial };
}

const LIMIT = 8 << 20;
/** Events rendered at once (newest); older ones behind "show more". */
const SHOW = 1000;

export function SseView({ detail }: { detail: Detail }) {
  const [events, setEvents] = useState<Event[]>([]);
  const [live, setLive] = useState(false);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [show, setShow] = useState(SHOW);
  const version = useStore((s) => s.listVersion);
  const seen = useRef({ id: -1, len: -1, complete: false, charset: "" });
  // Event streams are always UTF-8 (HTML §9.2.5); a charset chosen in Plain Text still applies.
  const [override] = useCharsetOverride(detail.summary.id, "response");
  const charset = override ?? "UTF-8";
  useEffect(() => {
    let alive = true;
    let busy = false;
    const load = async () => {
      if (busy) return;
      busy = true;
      try {
        const v = await api.bodyOpen(detail.summary.id, "response", "raw");
        if (!alive) return;
        setLive(!v.complete);
        setTotal(v.len);
        // Re-parse only when the stream actually grew (the poll runs every 500 ms).
        const last = seen.current;
        if (last.id === detail.summary.id && last.len === v.len && last.complete === v.complete && last.charset === charset) return;
        const { data } = await fetchBody(detail.summary.id, "response", "raw", 0, Math.min(v.len, LIMIT));
        if (!alive) return;
        seen.current = { id: detail.summary.id, len: v.len, complete: v.complete, charset };
        setEvents(parse(decodeBytes(data, charset)).events);
        setError(null);
      } catch (e) {
        if (alive) setError(t("Could not load the event stream: {error}", { error: String(e) }));
      } finally {
        busy = false;
      }
    };
    load();
    const running = detail.summary.state !== "done" && detail.summary.state !== "aborted";
    const timer = running ? setInterval(load, 500) : null;
    return () => {
      alive = false;
      if (timer) clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail.summary.id, version, charset]);
  useEffect(() => setShow(SHOW), [detail.summary.id]);

  const from = Math.max(0, events.length - show);
  return (
    <div className="scroll pad sse">
      <div className="muted small">
        {events.length === 1 ? t("{n} event", { n: fmtInt(events.length) }) : t("{n} events", { n: fmtInt(events.length) })}
        {live ? ` · ${t("live")}` : ""}
        {total > LIMIT && ` · ${t("first {limit} of {total} parsed", { limit: fmtBytes(LIMIT), total: fmtBytes(total) })}`}
      </div>
      {error && <div className="banner error">{error}</div>}
      {from > 0 && (
        <div className="j-more" onClick={() => setShow(show + SHOW)}>
          … {t("{n} earlier events (show {more} more)", { n: fmtInt(from), more: fmtInt(Math.min(SHOW, from)) })}
        </div>
      )}
      {events.slice(from).map((e, i) => (
        <div
          key={from + i}
          className="sse-event"
          onContextMenu={(ev) =>
            openMenu(
              ev,
              withSelection(
                [copyItem(t("Copy Data"), e.data), copyItem(t("Copy Event"), [`event: ${e.event}`, e.id && `id: ${e.id}`, ...e.data.split("\n").map((l) => `data: ${l}`)].filter(Boolean).join("\n"))],
                ev.target as Element,
              ),
            )
          }
        >
          <div className="sse-head">
            <span className="sse-type">{e.event}</span>
            {e.id && <span className="muted">id: {e.id}</span>}
            {e.retry && <span className="muted">retry: {e.retry}ms</span>}
          </div>
          <pre className="sse-data">{e.data}</pre>
        </div>
      ))}
      {events.length === 0 && !error && <div className="placeholder">{t("No events yet.")}</div>}
    </div>
  );
}
