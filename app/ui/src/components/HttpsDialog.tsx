// Capture → HTTPS Settings: decryption options and root certificate management.
import { useEffect, useState } from "react";
import { save, open } from "@tauri-apps/plugin-dialog";
import { api, type CaInfo } from "../api";
import { say, set, useStore } from "../store";
import { patchSettings } from "../settingsActions";
import { osNames } from "../lib/format";
import { t } from "../i18n";
import { baseName, keyLogFilters } from "../lib/importFormats";

export function HttpsPanel() {
  const settings = useStore((s) => s.settings);
  const [ca, setCa] = useState<CaInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const load = () => api.caInfo().then(setCa);
  useEffect(() => {
    load();
  }, []);
  if (!settings) return null;
  const run = async (f: () => Promise<CaInfo>, ok: string) => {
    setBusy(true);
    try {
      setCa(await f());
      say(ok);
    } catch (e) {
      say(String(e), "error");
    } finally {
      setBusy(false);
    }
  };
  const h = settings.https;
  return (
    <div className="https">
      <label className="f-check strong">
        <input type="checkbox" checked={h.decrypt} onChange={(e) => patchSettings((s) => (s.https.decrypt = e.target.checked)).then(load)} /> {t("Decrypt HTTPS traffic")}
      </label>
      <div className="f-row">
        <span>{t("…from")}</span>
        <select value={h.scope} onChange={(e) => patchSettings((s) => (s.https.scope = e.target.value as typeof h.scope))}>
          <option value="all">{t("all processes")}</option>
          <option value="browsers">{t("browsers only")}</option>
          <option value="nonBrowsers">{t("non-browsers only")}</option>
          <option value="remote">{t("remote clients only")}</option>
        </select>
      </div>
      <div className="f-row">
        <span>{t("Skip decryption for")}</span>
        <input defaultValue={h.skipDecryption} placeholder="*.bank.example; login.live.com" onBlur={(e) => patchSettings((s) => (s.https.skipDecryption = e.target.value))} />
      </div>
      <label className="f-check">
        <input type="checkbox" checked={h.ignoreCertErrors} onChange={(e) => patchSettings((s) => (s.https.ignoreCertErrors = e.target.checked))} /> {t("Ignore server certificate errors (unsafe)")}
      </label>
      <label className="f-check">
        <input type="checkbox" checked={h.enableHttp2} onChange={(e) => patchSettings((s) => (s.https.enableHttp2 = e.target.checked))} /> {t("Enable HTTP/2")}
      </label>
      <fieldset className="f-section">
        <legend>{t("Client certificates (mTLS)")}</legend>
        <p className="muted small">{t("Presented to matching upstream hosts. Cert and key are PEM files (may be the same file).")}</p>
        {(h.clientCerts ?? []).map((c, i) => (
          <div className="cc-row" key={i}>
            <input
              className="cc-host"
              placeholder={t("host pattern e.g. *.corp.example")}
              defaultValue={c.host}
              onBlur={(e) => patchSettings((s) => (s.https.clientCerts[i].host = e.target.value))}
            />
            <button
              className="cc-file"
              title={c.certPath || t("choose certificate PEM")}
              onClick={async () => {
                const p = await open({ multiple: false, filters: [{ name: "PEM", extensions: ["pem", "crt", "cer", "key"] }] });
                if (typeof p === "string") patchSettings((s) => (s.https.clientCerts[i].certPath = p));
              }}
            >
              {c.certPath ? c.certPath.split("/").pop() : t("Cert…")}
            </button>
            <button
              className="cc-file"
              title={c.keyPath || t("choose key PEM (optional)")}
              onClick={async () => {
                const p = await open({ multiple: false, filters: [{ name: "PEM", extensions: ["pem", "key", "crt"] }] });
                if (typeof p === "string") patchSettings((s) => (s.https.clientCerts[i].keyPath = p));
              }}
            >
              {c.keyPath ? c.keyPath.split("/").pop() : t("Key…")}
            </button>
            <button className="cc-del" title={t("Remove")} onClick={() => patchSettings((s) => s.https.clientCerts.splice(i, 1))}>
              ✕
            </button>
          </div>
        ))}
        <button onClick={() => patchSettings((s) => (s.https.clientCerts = [...(s.https.clientCerts ?? []), { host: "", certPath: "", keyPath: "" }]))}>
          {t("Add client certificate")}
        </button>
      </fieldset>
      <fieldset className="f-section">
        <legend>{t("Packet captures")}</legend>
        <p className="muted small">{t("TLS key log (SSLKEYLOGFILE) used to decrypt HTTPS in imported pcap/pcapng files. Key logs next to a capture (name.keys, sslkeylog.log) and keys embedded in pcapng are used too.")}</p>
        <div className="cc-row">
          <button
            className="cc-file"
            title={h.tlsKeyLogFile || t("choose the TLS key log file")}
            onClick={async () => {
              const p = await open({ multiple: false, filters: keyLogFilters() });
              if (typeof p === "string") patchSettings((s) => (s.https.tlsKeyLogFile = p));
            }}
          >
            {h.tlsKeyLogFile ? baseName(h.tlsKeyLogFile) : t("Key log file…")}
          </button>
          {h.tlsKeyLogFile && (
            <button className="cc-del" title={t("Remove")} onClick={() => patchSettings((s) => (s.https.tlsKeyLogFile = ""))}>
              ✕
            </button>
          )}
        </div>
      </fieldset>
      <fieldset className="f-section">
        <legend>{t("Root certificate")}</legend>
        {!ca ? (
          t("Loading…")
        ) : !ca.exists ? (
          <p className="muted">{t("No root certificate yet. It is created when HTTPS decryption is enabled.")}</p>
        ) : (
          <>
            <div>
              {t("Status:")}{" "}
              {ca.trusted ? <b className="ok">{t("trusted by {os}", { os: osNames.os })}</b> : <b className="err">{t("not trusted – browsers will show certificate errors")}</b>}
            </div>
            <div className="mono small muted" style={{ wordBreak: "break-all" }}>
              SHA-256 {ca.sha256}
            </div>
            <div className="small muted">{ca.path}</div>
          </>
        )}
        <div className="btn-row">
          <button
            className="primary"
            disabled={busy}
            onClick={() => run(api.caTrust, t("Root certificate trusted"))}
            title={t("Adds the certificate to {store} as trusted root. {prompt}", { store: osNames.trustStore, prompt: osNames.prompt })}
          >
            {ca?.trusted ? t("Re-trust") : t("Trust root certificate…")}
          </button>
          <button disabled={busy || !ca?.exists} onClick={() => run(api.caRemove, t("Root certificate removed from the trust store"))}>
            {t("Remove from trust store")}
          </button>
          <button
            disabled={busy || !ca?.exists}
            onClick={async () => {
              const p = await save({ defaultPath: "quena-root-ca.crt", filters: [{ name: t("Certificate"), extensions: ["crt", "pem", "cer", "der"] }] });
              if (!p) return;
              await api.caExport(p, /\.(cer|der)$/i.test(p));
              say(t("Exported to {path}", { path: p }));
            }}
          >
            {t("Export…")}
          </button>
          <button
            disabled={busy || !ca?.exists}
            onClick={() => {
              if (ca?.trusted) {
                say(t("Remove the current certificate from the trust store first"), "error");
                return;
              }
              run(api.caRegenerate, t("New root certificate created"));
            }}
          >
            {t("Regenerate")}
          </button>
        </div>
        <p className="small muted">
          {t("The private key never leaves {machine} (stored with owner-only permissions). Only trust it on machines you use for debugging; remove it afterwards.", { machine: osNames.machine })}
        </p>
      </fieldset>
      <p>
        <button onClick={() => set({ dialog: { kind: "connect-device" } })}>{t("Connect a device (iOS/Android)…")}</button>
      </p>
    </div>
  );
}
