import { api } from "../api";
import { get, set } from "../store";
import { fmtDateTime } from "../lib/format";
import { t } from "../i18n";

export async function showProperties() {
  const id = get().focusId;
  if (id == null) return;
  const d = await api.detail(id);
  if (!d) return;
  const timers = d.timers;
  const lines = [
    `SESSION #${d.summary.id}`,
    `State: ${d.summary.state}   Kind: ${d.summary.kind}   Flags: 0x${d.summary.flags.toString(16)}`,
    `Process: ${d.process ? `${d.process.name}:${d.process.pid}` : "-"}`,
    `Client: ${d.connection.clientAddr ?? "-"}   Server: ${d.connection.serverAddr ?? "-"}   Reused: ${d.connection.serverConnReused}`,
    d.connection.gateway ? `Gateway: ${d.connection.gateway}` : "",
    d.connection.clientTls ? `Client TLS: ${d.connection.clientTls.version} ${d.connection.clientTls.cipher} SNI=${d.connection.clientTls.sni ?? ""} ALPN=${d.connection.clientTls.alpn ?? ""}` : "",
    d.connection.serverTls ? `Server TLS: ${d.connection.serverTls.version} ${d.connection.serverTls.cipher} ALPN=${d.connection.serverTls.alpn ?? ""}` : "",
    d.connection.streamId != null ? `HTTP/2 stream: ${d.connection.streamId}` : "",
    d.error ? `Error: ${d.error}` : "",
    "",
    "TIMERS",
    ...Object.entries(timers)
      .filter(([, v]) => v != null)
      .map(([k, v]) => `  ${k.padEnd(22)} ${k.endsWith("Ms") ? `${v} ms` : fmtDateTime(v as number)}`),
    "",
    "FLAGS",
    ...d.extraFlags.map(([k, v]) => `  ${k}: ${v}`),
  ].filter((l) => l !== "");
  set({ dialog: { kind: "text", title: t("Properties of #{id}", { id }), text: lines.join("\n") } });
}
