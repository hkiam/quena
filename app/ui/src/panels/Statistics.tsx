import { useEffect, useState } from "react";
import { api, type Statistics } from "../api";
import { fmtBytes, fmtDateTime, fmtInt, fmtMs, fmtUsd } from "../lib/format";
import { useStore } from "../store";
import { plural, t } from "../i18n";
import { openMenu, withSelection } from "../components/contextMenus";
import { copyItem } from "../inspectors/inspectMenus";

export function StatisticsPanel() {
  const selection = useStore((s) => s.selection);
  const version = useStore((s) => s.listVersion);
  const [st, setSt] = useState<Statistics | null>(null);
  useEffect(() => {
    // An answer that comes after a newer request was made is dropped.
    let alive = true;
    const t = setTimeout(() => api.statistics([...selection]).then((r) => alive && setSt(r)), 150);
    return () => {
      alive = false;
      clearTimeout(t);
    };
  }, [selection, Math.floor(version / 30)]);
  if (!st) return <div className="placeholder">{t("Computing…")}</div>;
  const maxCt = Math.max(1, ...st.contentTypes.map((c) => c[2]));
  const elapsed = st.firstRequest && st.lastResponse ? (st.lastResponse - st.firstRequest) / 1000 : null;
  return (
    <div className="scroll pad stats" onContextMenu={(e) => openMenu(e, withSelection([copyItem(t("Copy All"), e.currentTarget.innerText)], e.target as Element))}>
      <div className="muted">{selection.size ? plural(selection.size, "{n} selected session", "{n} selected sessions") : t("All sessions")}</div>
      <table className="kv">
        <tbody>
          <tr><td>{t("Request Count")}</td><td>{fmtInt(st.sessions)}</td></tr>
          <tr><td>{t("Bytes Sent (bodies)")}</td><td>{fmtInt(st.requestBytes)} ({fmtBytes(st.requestBytes)})</td></tr>
          <tr><td>{t("Bytes Received (bodies)")}</td><td>{fmtInt(st.responseBytes)} ({fmtBytes(st.responseBytes)})</td></tr>
          <tr><td>{t("Requests started at")}</td><td>{fmtDateTime(st.firstRequest)}</td></tr>
          <tr><td>{t("Responses completed at")}</td><td>{fmtDateTime(st.lastResponse)}</td></tr>
          <tr><td>{t("Sequence (clock) duration")}</td><td>{elapsed != null ? fmtMs(Math.round(elapsed)) : ""}</td></tr>
          <tr><td>{t("Aggregate Session time")}</td><td>{fmtMs(st.aggregateMs)}</td></tr>
          <tr><td>{t("In flight / aborted")}</td><td>{st.inFlight} / {st.aborted}</td></tr>
          {st.requestsPerS != null && <tr><td>{t("Throughput")}</td><td>{t("{r} requests/s · {b}/s", { r: st.requestsPerS.toFixed(st.requestsPerS < 10 ? 2 : 0), b: fmtBytes(Math.round(st.bytesPerS ?? 0)) })}</td></tr>}
          <tr><td>{t("Header bytes sent / received")}</td><td>{fmtBytes(st.requestHeaderBytes)} / {fmtBytes(st.responseHeaderBytes)}</td></tr>
        </tbody>
      </table>
      {st.timing && (
        <>
          <h4>{t("Durations")}</h4>
          <table className="kv">
            <tbody>
              <tr><td>{t("Median / mean")}</td><td>{fmtMs(st.timing.median)} / {fmtMs(Math.round(st.timing.mean))}</td></tr>
              <tr><td>p90 / p95 / p99</td><td>{fmtMs(st.timing.p90)} / {fmtMs(st.timing.p95)} / {fmtMs(st.timing.p99)}</td></tr>
              <tr><td>{t("Min / max")}</td><td>{fmtMs(st.timing.min)} / {fmtMs(st.timing.max)}</td></tr>
              <tr><td>{t("Standard deviation")}</td><td>{fmtMs(Math.round(st.timing.stddev))}</td></tr>
            </tbody>
          </table>
        </>
      )}
      {st.phases && (st.phases.dnsCount > 0 || st.phases.connectCount > 0 || st.phases.tlsCount > 0 || st.phases.waitCount > 0) && (
        <>
          <h4>{t("Connection phases (sum)")}</h4>
          <table className="kv">
            <tbody>
              {(
                [
                  [t("DNS lookup"), st.phases.dnsMs, st.phases.dnsCount],
                  [t("TCP connect"), st.phases.connectMs, st.phases.connectCount],
                  [t("TLS handshake"), st.phases.tlsMs, st.phases.tlsCount],
                  [t("Waiting for the first byte"), st.phases.waitMs, st.phases.waitCount],
                ] as const
              ).map(([label, ms, n]) => (
                <tr key={label}>
                  <td>{label}</td>
                  <td>{n > 0 ? t("{ms} in {n} sessions (⌀ {avg})", { ms: fmtMs(ms), n: fmtInt(n), avg: fmtMs(Math.round(ms / n)) }) : "–"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {st.phases.sampled > 0 && <p className="muted small">{t("Phases and header bytes of the first {n} sessions.", { n: fmtInt(st.phases.sampled) })}</p>}
        </>
      )}
      <h4>{t("Response Codes")}</h4>
      <table className="kv">
        <tbody>
          {Object.entries(st.statusCodes).map(([k, v]) => (
            <tr key={k}>
              <td>HTTP/{k}</td>
              <td>{fmtInt(v)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h4>{t("Response Bytes (by Content-Type)")}</h4>
      <div className="bars">
        {st.contentTypes.map(([ct, n, b]) => (
          <div key={ct} className="bar-row">
            <span className="bar-label" title={ct}>{ct}</span>
            <span className="bar"><span style={{ width: `${(b / maxCt) * 100}%` }} /></span>
            <span className="bar-val">{fmtBytes(b)} · {fmtInt(n)}</span>
          </div>
        ))}
      </div>
      <h4>{t("Hosts")}</h4>
      <table className="kv">
        <tbody>
          {st.hosts.slice(0, 20).map(([h, n, b]) => (
            <tr key={h}>
              <td>{h}</td>
              <td>{fmtInt(n)} · {fmtBytes(b)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {st.llmModels.length > 0 && (
        <>
          <h4>{t("LLM calls")}</h4>
          <table className="kv">
            <tbody>
              {st.llmModels.map(([m, n, tok, usd]) => (
                <tr key={m}>
                  <td>{m}</td>
                  <td>
                    {plural(n, "{n} call", "{n} calls")} · {t("{n} tokens", { n: fmtInt(tok) })}
                    {usd > 0 && ` · ${fmtUsd(usd)}`}
                  </td>
                </tr>
              ))}
              <tr>
                <td>
                  <b>{t("Total")}</b>
                </td>
                <td>
                  <b>
                    {t("{n} tokens", { n: fmtInt(st.llmTokens) })}
                    {st.llmCost > 0 && ` · ${fmtUsd(st.llmCost)}`}
                  </b>{" "}
                  <span className="muted small">{t("(cost estimated from list prices)")}</span>
                </td>
              </tr>
            </tbody>
          </table>
        </>
      )}
      {st.processes.length > 0 && (
        <>
          <h4>{t("Processes")}</h4>
          <table className="kv">
            <tbody>
              {st.processes.map(([p, n]) => (
                <tr key={p}>
                  <td>{p}</td>
                  <td>{fmtInt(n)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
