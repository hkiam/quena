// Capture → Connect Device: remote clients, QR code, certificate download and live status.
import { useEffect, useMemo, useState } from "react";
import qrcode from "qrcode-generator";
import { api, type DeviceInfo } from "../api";
import { useStore } from "../store";
import { patchSettings } from "../settingsActions";

function Qr({ text }: { text: string }) {
  const svg = useMemo(() => {
    const q = qrcode(0, "M");
    q.addData(text);
    q.make();
    return q.createSvgTag({ cellSize: 5, margin: 2, scalable: true });
  }, [text]);
  return <div className="qr" dangerouslySetInnerHTML={{ __html: svg }} />;
}

export function DeviceAssistant() {
  const [info, setInfo] = useState<DeviceInfo | null>(null);
  const [iface, setIface] = useState(0);
  const [os, setOs] = useState<"ios" | "android" | "other">("ios");
  const [seen, setSeen] = useState<{ ip: string; https: boolean } | null>(null);
  const version = useStore((s) => s.listVersion);
  const total = useStore((s) => s.listTotal);

  useEffect(() => {
    const load = () => api.deviceInfo().then(setInfo);
    load();
    const t = setInterval(load, 2000);
    return () => clearInterval(t);
  }, []);

  // Live status: look at the most recent sessions for remote clients.
  useEffect(() => {
    if (!total) return;
    api.rows(Math.max(0, total - 64), 64).then((w) => {
      const r = [...w.rows].reverse().find((x) => x.clientIp && x.clientIp !== "127.0.0.1" && x.clientIp !== "::1");
      if (r) setSeen({ ip: r.clientIp, https: w.rows.some((x) => x.clientIp === r.clientIp && x.protocol !== "HTTP" && x.kind === "http") });
    });
  }, [version, total]);

  if (!info) return <div>Loading…</div>;
  const addr = info.addresses[iface]?.[1];
  const url = addr ? `http://${addr}:${info.port}/` : "";
  return (
    <div className="device">
      {!info.allowRemote ? (
        <div className="banner warn" style={{ cursor: "default" }}>
          Remote connections are disabled.{" "}
          <button onClick={() => patchSettings((s) => (s.proxy.allowRemote = true))}>Allow remote computers to connect</button>
        </div>
      ) : (
        <div className="muted small">Remote connections are allowed (local networks unless an allowlist is configured).</div>
      )}
      <div className="device-grid">
        <div>
          <div className="f-row">
            <span>Interface</span>
            <select value={iface} onChange={(e) => setIface(Number(e.target.value))}>
              {info.addresses.map(([n, ip], i) => (
                <option key={ip} value={i}>
                  {n} – {ip}
                </option>
              ))}
            </select>
          </div>
          <div className="f-row">
            <span>Proxy server</span>
            <b className="mono">{addr ?? "no network"}</b>
          </div>
          <div className="f-row">
            <span>Port</span>
            <b className="mono">{info.port}</b>
          </div>
          <div className="tabs-row">
            {(["ios", "android", "other"] as const).map((o) => (
              <div key={o} className={`insp-tab ${os === o ? "active" : ""}`} onClick={() => setOs(o)}>
                {{ ios: "iPhone / iPad", android: "Android", other: "Other / VM" }[o]}
              </div>
            ))}
          </div>
          <ol className="steps">
            {os === "ios" && (
              <>
                <li>Settings → Wi-Fi → (i) of your network → Configure Proxy → Manual: server <b>{addr}</b>, port <b>{info.port}</b>.</li>
                <li>Scan the QR code (or open <span className="mono">{url}</span> in Safari) and download the <i>.mobileconfig</i> profile.</li>
                <li>Settings → General → VPN &amp; Device Management → install the Quena profile.</li>
                <li>Settings → General → About → Certificate Trust Settings → enable full trust for “Quena Root CA”.</li>
              </>
            )}
            {os === "android" && (
              <>
                <li>Settings → Network → Wi-Fi → your network → Advanced → Proxy: Manual, host <b>{addr}</b>, port <b>{info.port}</b>.</li>
                <li>Open <span className="mono">{url}</span> and download the certificate (.cer).</li>
                <li>Settings → Security → Encryption &amp; credentials → Install a certificate → CA certificate.</li>
                <li>Note: since Android 7 apps only trust user CAs if their network security config allows it – browsers do; many apps do not.</li>
              </>
            )}
            {os === "other" && (
              <>
                <li>Configure the HTTP and HTTPS proxy as <b>{addr}:{info.port}</b>.</li>
                <li>Download the root certificate from <span className="mono">{url}</span> and add it to the system trust store.</li>
              </>
            )}
          </ol>
        </div>
        <div className="qr-box">{url ? <Qr text={url} /> : null}<div className="mono small">{url}</div></div>
      </div>
      <div className="device-status">
        <div>{info.listening ? "✓ Quena is listening" : "✗ Quena is not capturing (F12)"}</div>
        <div>{seen ? `✓ First connection from ${seen.ip} detected` : "… waiting for a connection from the device"}</div>
        <div>{seen?.https ? "✓ HTTPS traffic decrypted" : seen ? "… no decrypted HTTPS yet (certificate trusted?)" : ""}</div>
      </div>
    </div>
  );
}
