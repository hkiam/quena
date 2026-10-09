// Capture → Connect Device: remote clients, QR code, certificate download and live status.
import { Fragment, useEffect, useMemo, useState, type ReactNode } from "react";
import qrcode from "qrcode-generator";
import { api, type DeviceInfo } from "../api";
import { useStore } from "../store";
import { patchSettings } from "../settingsActions";
import { t } from "../i18n";

/** Fill `{name}` placeholders of a translated text with React nodes (bold values, links…). */
function fill(s: string, parts: Record<string, ReactNode>): ReactNode[] {
  return s.split(/(\{\w+\})/).map((p, i) => {
    const m = /^\{(\w+)\}$/.exec(p);
    return <Fragment key={i}>{m && m[1] in parts ? parts[m[1]] : p}</Fragment>;
  });
}

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
  const [caName, setCaName] = useState("Quena Root CA");
  useEffect(() => {
    api.caInfo().then((c) => c.name && setCaName(c.name), () => {});
  }, []);
  const version = useStore((s) => s.listVersion);
  const total = useStore((s) => s.listTotal);

  useEffect(() => {
    const load = () => api.deviceInfo().then(setInfo);
    load();
    const timer = setInterval(load, 2000);
    return () => clearInterval(timer);
  }, []);

  // Live status: look at the most recent sessions for remote clients.
  useEffect(() => {
    if (!total) return;
    api.rows(Math.max(0, total - 64), 64).then((w) => {
      const r = [...w.rows].reverse().find((x) => x.clientIp && x.clientIp !== "127.0.0.1" && x.clientIp !== "::1");
      if (r) setSeen({ ip: r.clientIp, https: w.rows.some((x) => x.clientIp === r.clientIp && x.protocol !== "HTTP" && x.kind === "http") });
    });
  }, [version, total]);

  if (!info) return <div>{t("Loading…")}</div>;
  const addr = info.addresses[iface]?.[1];
  const url = addr ? `http://${addr}:${info.port}/` : "";
  return (
    <div className="device">
      {!info.allowRemote ? (
        <div className="banner warn" style={{ cursor: "default" }}>
          {t("Remote connections are disabled.")}{" "}
          <button onClick={() => patchSettings((s) => (s.proxy.allowRemote = true))}>{t("Allow remote computers to connect")}</button>
        </div>
      ) : (
        <div className="muted small">{t("Remote connections are allowed (local networks unless an allowlist is configured).")}</div>
      )}
      <div className="device-grid">
        <div>
          <div className="f-row">
            <span>{t("Interface")}</span>
            <select value={iface} onChange={(e) => setIface(Number(e.target.value))}>
              {info.addresses.map(([n, ip], i) => (
                <option key={ip} value={i}>
                  {n} – {ip}
                </option>
              ))}
            </select>
          </div>
          <div className="f-row">
            <span>{t("Proxy server")}</span>
            <b className="mono">{addr ?? t("no network")}</b>
          </div>
          <div className="f-row">
            <span>Port</span>
            <b className="mono">{info.port}</b>
          </div>
          <div className="tabs-row">
            {(["ios", "android", "other"] as const).map((o) => (
              <div key={o} className={`insp-tab ${os === o ? "active" : ""}`} onClick={() => setOs(o)}>
                {{ ios: "iPhone / iPad", android: "Android", other: t("Other / VM") }[o]}
              </div>
            ))}
          </div>
          <ol className="steps">
            {os === "ios" && (
              <>
                <li>{fill(t("Settings → Wi-Fi → (i) of your network → Configure Proxy → Manual: server {addr}, port {port}."), { addr: <b>{addr}</b>, port: <b>{info.port}</b> })}</li>
                <li>{fill(t("Scan the QR code (or open {url} in Safari) and download the {file} profile."), { url: <span className="mono">{url}</span>, file: <i>.mobileconfig</i> })}</li>
                <li>{t("Settings → General → VPN & Device Management → install the Quena profile.")}</li>
                <li>{t("Settings → General → About → Certificate Trust Settings → enable full trust for “{name}”.", { name: caName })}</li>
              </>
            )}
            {os === "android" && (
              <>
                <li>{fill(t("Settings → Network → Wi-Fi → your network → Advanced → Proxy: Manual, host {addr}, port {port}."), { addr: <b>{addr}</b>, port: <b>{info.port}</b> })}</li>
                <li>{fill(t("Open {url} and download the certificate (.cer)."), { url: <span className="mono">{url}</span> })}</li>
                <li>{t("Settings → Security → Encryption & credentials → Install a certificate → CA certificate.")}</li>
                <li>{t("Note: since Android 7 apps only trust user CAs if their network security config allows it – browsers do; many apps do not.")}</li>
              </>
            )}
            {os === "other" && (
              <>
                <li>{fill(t("Configure the HTTP and HTTPS proxy as {proxy}."), { proxy: <b>{addr}:{info.port}</b> })}</li>
                <li>{fill(t("Download the root certificate from {url} and add it to the system trust store."), { url: <span className="mono">{url}</span> })}</li>
              </>
            )}
          </ol>
        </div>
        <div className="qr-box">{url ? <Qr text={url} /> : null}<div className="mono small">{url}</div></div>
      </div>
      <div className="device-status">
        <div>{info.listening ? t("✓ Quena is listening") : t("✗ Quena is not capturing (F12)")}</div>
        <div>{seen ? t("✓ First connection from {ip} detected", { ip: seen.ip }) : t("… waiting for a connection from the device")}</div>
        <div>{seen?.https ? t("✓ HTTPS traffic decrypted") : seen ? t("… no decrypted HTTPS yet (certificate trusted?)") : ""}</div>
      </div>
    </div>
  );
}
