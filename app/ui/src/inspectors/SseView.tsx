// Server-Sent Events inspector (M15): parse text/event-stream into events.
import { useEffect, useState } from "react";
import { api, fetchBody, type Detail } from "../api";
import { fmtInt } from "../lib/format";
import { decodeText } from "../lib/bodytext";
import { useStore } from "../store";

interface Event {
  id?: string;
  event: string;
  data: string;
  retry?: string;
  raw: number;
}

function parse(text: string): { events: Event[]; partial: string } {
  const events: Event[] = [];
  const blocks = text.split(/\n\n/);
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

export function SseView({ detail }: { detail: Detail }) {
  const [events, setEvents] = useState<Event[]>([]);
  const [live, setLive] = useState(false);
  const version = useStore((s) => s.listVersion);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      const v = await api.bodyOpen(detail.summary.id, "response", "raw");
      const { data } = await fetchBody(detail.summary.id, "response", "raw", 0, Math.min(v.len, LIMIT));
      if (!alive) return;
      const { events } = parse(decodeText(data));
      setEvents(events);
      setLive(!v.complete);
    };
    load();
    const running = detail.summary.state !== "done" && detail.summary.state !== "aborted";
    const t = running ? setInterval(load, 500) : null;
    return () => {
      alive = false;
      if (t) clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail.summary.id, version]);

  return (
    <div className="scroll pad sse">
      <div className="muted small">
        {fmtInt(events.length)} events{live ? " · live" : ""}
      </div>
      {events.map((e, i) => (
        <div key={i} className="sse-event">
          <div className="sse-head">
            <span className="sse-type">{e.event}</span>
            {e.id && <span className="muted">id: {e.id}</span>}
            {e.retry && <span className="muted">retry: {e.retry}ms</span>}
          </div>
          <pre className="sse-data">{e.data}</pre>
        </div>
      ))}
      {events.length === 0 && <div className="placeholder">No events yet.</div>}
    </div>
  );
}
