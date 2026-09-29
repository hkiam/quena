// Tools → HTTPS: decryption options and root certificate management.
import { useEffect, useState } from "react";
import { save, open } from "@tauri-apps/plugin-dialog";
import { api, type CaInfo } from "../api";
import { say, set, useStore } from "../store";
import { patchSettings } from "../settingsActions";

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
        <input type="checkbox" checked={h.decrypt} onChange={(e) => patchSettings((s) => (s.https.decrypt = e.target.checked)).then(load)} /> Decrypt HTTPS traffic
      </label>
      <div className="f-row">
        <span>…from</span>
        <select value={h.scope} onChange={(e) => patchSettings((s) => (s.https.scope = e.target.value as typeof h.scope))}>
          <option value="all">all processes</option>
          <option value="browsers">browsers only</option>
          <option value="nonBrowsers">non-browsers only</option>
          <option value="remote">remote clients only</option>
        </select>
      </div>
      <div className="f-row">
        <span>Skip decryption for</span>
        <input defaultValue={h.skipDecryption} placeholder="*.bank.example; login.live.com" onBlur={(e) => patchSettings((s) => (s.https.skipDecryption = e.target.value))} />
      </div>
      <label className="f-check">
        <input type="checkbox" checked={h.ignoreCertErrors} onChange={(e) => patchSettings((s) => (s.https.ignoreCertErrors = e.target.checked))} /> Ignore server certificate errors (unsafe)
      </label>
      <label className="f-check">
        <input type="checkbox" checked={h.enableHttp2} onChange={(e) => patchSettings((s) => (s.https.enableHttp2 = e.target.checked))} /> Enable HTTP/2
      </label>
      <fieldset className="f-section">
        <legend>Client certificates (mTLS)</legend>
        <p className="muted small">Presented to matching upstream hosts. Cert and key are PEM files (may be the same file).</p>
        {(h.clientCerts ?? []).map((c, i) => (
          <div className="cc-row" key={i}>
            <input
              className="cc-host"
              placeholder="host pattern e.g. *.corp.example"
              defaultValue={c.host}
              onBlur={(e) => patchSettings((s) => (s.https.clientCerts[i].host = e.target.value))}
            />
            <button
              className="cc-file"
              title={c.certPath || "choose certificate PEM"}
              onClick={async () => {
                const p = await open({ multiple: false, filters: [{ name: "PEM", extensions: ["pem", "crt", "cer", "key"] }] });
                if (typeof p === "string") patchSettings((s) => (s.https.clientCerts[i].certPath = p));
              }}
            >
              {c.certPath ? c.certPath.split("/").pop() : "Cert…"}
            </button>
            <button
              className="cc-file"
              title={c.keyPath || "choose key PEM (optional)"}
              onClick={async () => {
                const p = await open({ multiple: false, filters: [{ name: "PEM", extensions: ["pem", "key", "crt"] }] });
                if (typeof p === "string") patchSettings((s) => (s.https.clientCerts[i].keyPath = p));
              }}
            >
              {c.keyPath ? c.keyPath.split("/").pop() : "Key…"}
            </button>
            <button className="cc-del" title="Remove" onClick={() => patchSettings((s) => s.https.clientCerts.splice(i, 1))}>
              ✕
            </button>
          </div>
        ))}
        <button onClick={() => patchSettings((s) => (s.https.clientCerts = [...(s.https.clientCerts ?? []), { host: "", certPath: "", keyPath: "" }]))}>
          Add client certificate
        </button>
      </fieldset>
      <fieldset className="f-section">
        <legend>Root certificate</legend>
        {!ca ? (
          "Loading…"
        ) : !ca.exists ? (
          <p className="muted">No root certificate yet. It is created when HTTPS decryption is enabled.</p>
        ) : (
          <>
            <div>
              Status:{" "}
              {ca.trusted ? <b className="ok">trusted by macOS</b> : <b className="err">not trusted – browsers will show certificate errors</b>}
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
            onClick={() => run(api.caTrust, "Root certificate trusted")}
            title="Adds the certificate to your login keychain as trusted root. macOS asks for your password."
          >
            {ca?.trusted ? "Re-trust" : "Trust root certificate…"}
          </button>
          <button disabled={busy || !ca?.exists} onClick={() => run(api.caRemove, "Root certificate removed from the trust store")}>
            Remove from trust store
          </button>
          <button
            disabled={busy || !ca?.exists}
            onClick={async () => {
              const p = await save({ defaultPath: "piper-root-ca.crt", filters: [{ name: "Certificate", extensions: ["crt", "pem", "cer", "der"] }] });
              if (!p) return;
              await api.caExport(p, /\.(cer|der)$/i.test(p));
              say(`Exported to ${p}`);
            }}
          >
            Export…
          </button>
          <button
            disabled={busy || !ca?.exists}
            onClick={() => {
              if (ca?.trusted) {
                say("Remove the current certificate from the trust store first", "error");
                return;
              }
              run(api.caRegenerate, "New root certificate created");
            }}
          >
            Regenerate
          </button>
        </div>
        <p className="small muted">
          The private key never leaves this Mac (stored with owner-only permissions). Only trust it on machines you use for debugging; remove it afterwards.
        </p>
      </fieldset>
      <p>
        <button onClick={() => set({ dialog: { kind: "connect-device" } })}>Connect a device (iOS/Android)…</button>
      </p>
    </div>
  );
}
