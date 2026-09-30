// Phases of a session for the waterfall: where the time went, from the session timers.
import type { Timers } from "../api";

export type Phase = "request" | "dns" | "connect" | "tls" | "send" | "wait" | "receive";

export const PHASES: { key: Phase; label: string }[] = [
  { key: "request", label: "Request from client" },
  { key: "dns", label: "DNS" },
  { key: "connect", label: "Connect" },
  { key: "tls", label: "TLS" },
  { key: "send", label: "Send" },
  { key: "wait", label: "Wait (time to first byte)" },
  { key: "receive", label: "Receive" },
];

export interface Segment {
  phase: Phase;
  /** Microseconds since the epoch, like the timers. */
  start: number;
  end: number;
}

/** Consecutive, non-overlapping segments; missing or inconsistent timers are left out. */
export function phasesOf(t: Timers): Segment[] {
  const out: Segment[] = [];
  const add = (phase: Phase, start?: number | null, end?: number | null) => {
    if (start == null || end == null || !(end > start)) return;
    const last = out[out.length - 1];
    if (last && start < last.end) start = last.end;
    if (end > start) out.push({ phase, start, end });
  };
  add("request", t.clientBeginRequest, t.clientDoneRequest);
  const cs = t.serverConnectStart;
  if (cs != null && t.serverConnected != null) {
    const dns = (t.dnsMs ?? 0) * 1000;
    const tcp = (t.tcpConnectMs ?? 0) * 1000;
    const tls = (t.tlsHandshakeMs ?? 0) * 1000;
    if (dns + tcp + tls > 0) {
      add("dns", cs, cs + dns);
      add("connect", cs + dns, cs + dns + tcp);
      add("tls", cs + dns + tcp, Math.min(t.serverConnected, cs + dns + tcp + tls) || cs + dns + tcp + tls);
    } else add("connect", cs, t.serverConnected);
  }
  add("send", t.serverBeginRequest, t.serverDoneRequest);
  add("wait", t.serverDoneRequest ?? t.serverBeginRequest, t.serverGotFirstByte);
  add("receive", t.serverGotFirstByte, t.serverDoneResponse ?? t.clientDoneResponse);
  return out;
}
