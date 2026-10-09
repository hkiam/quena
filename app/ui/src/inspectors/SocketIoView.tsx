// Socket.IO long-polling: the Engine.IO / Socket.IO packets of a polling request or
// response body (the WebSocket view decodes them per frame).
import { useEffect, useState } from "react";
import { api, type Detail, type Part, type SioPacket } from "../api";
import { sioLabel } from "./WebSocketView";
import { plural, t } from "../i18n";

export function socketioCandidate(detail: Detail, part: Part): boolean {
  const u = detail.request.url;
  // Polls are GETs without a body; only sends (POST) carry packets in the request.
  if (part === "request" && !detail.requestBody?.len) return false;
  return (u.includes("/socket.io/") || u.includes("EIO=")) && u.includes("transport=polling");
}

export function SocketIoView({ detail, part }: { detail: Detail; part: Part }) {
  const [packets, setPackets] = useState<SioPacket[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const id = detail.summary.id;
  useEffect(() => {
    let alive = true;
    setPackets(null);
    setError(null);
    api.socketioPolling(id, part).then(
      (r) => alive && setPackets(r ?? []),
      (e) => alive && setError(String(e)),
    );
    return () => {
      alive = false;
    };
  }, [id, part]);
  if (error) return <div className="placeholder">{t("Could not decode: {error}", { error })}</div>;
  if (!packets) return <div className="placeholder">{t("Decoding…")}</div>;
  if (packets.length === 0) return <div className="placeholder">{t("No Socket.IO packets in this body.")}</div>;
  return (
    <div className="scroll pad">
      <div className="muted small">Socket.IO · {plural(packets.length, "{n} packet", "{n} packets")}</div>
      {packets.map((p, i) => (
        <div key={i} className="grpc-msg">
          <div className="grpc-msg-head muted">
            <b>{sioLabel(p)}</b>
            {sioLabel(p) !== p.eio && ` · ${p.eio}`}
            {p.sio && sioLabel(p) !== p.sio && ` / ${p.sio}`}
            {p.namespace && ` · ${p.namespace}`}
            {p.ack != null && ` · ack ${p.ack}`}
          </div>
          {p.data != null && <pre className="llm-text mono pad">{p.data}</pre>}
        </div>
      ))}
    </div>
  );
}
