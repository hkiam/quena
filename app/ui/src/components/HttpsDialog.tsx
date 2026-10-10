// Capture → HTTPS Settings: decryption options and root certificate management.
import { useEffect, useState } from "react";
import { save, open } from "@tauri-apps/plugin-dialog";
import { api, type CaImport, type CaInfo } from "../api";
import { say, set, useStore } from "../store";
import { patchSettings } from "../settingsActions";
import { fmtDate, isWindows, osNames } from "../lib/format";
import { t } from "../i18n";
import { baseName, keyLogFilters } from "../lib/importFormats";

const plain = { spellCheck: false, autoCorrect: "off", autoCapitalize: "off" } as const;
const name = (p?: string) => (p ? p.split(/[\\/]/).pop() : "");

/** Use an existing CA instead of Quena's: a PEM certificate with its key, or a .p12 file. */
function CaImportForm({ ca, onDone, onCancel }: { ca: CaInfo | null; onDone: (c: CaInfo) => void; onCancel: () => void }) {
  const [src, setSrc] = useState<CaImport>({});
  const [kind, setKind] = useState<"p12" | "pem">("p12");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pick = async (key: keyof CaImport, exts: string[], label: string) => {
    const p = await open({ multiple: false, filters: [{ name: label, extensions: exts }] });
    if (typeof p === "string") setSrc((x) => ({ ...x, [key]: p }));
  };
  const ready = kind === "p12" ? !!src.p12Path : !!src.certPath && !!src.keyPath;
  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      const out = await api.caImport(kind === "p12" ? { p12Path: src.p12Path, password: src.password ?? "" } : { certPath: src.certPath, keyPath: src.keyPath });
      onDone(out);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="ca-form">
      <p className="small muted">{t("Quena then issues its certificates with this CA, e.g. the company's interception CA that every machine already trusts. The current CA's files are kept in the data folder.")}</p>
      {ca?.trusted && <p className="small err">{t("The current certificate is trusted: remove it from the trust store first if it is no longer needed.")}</p>}
      <div className="f-inline">
        <label className="f-check">
          <input type="radio" checked={kind === "p12"} onChange={() => setKind("p12")} /> {t("PKCS#12 file (.p12, .pfx)")}
        </label>
        <label className="f-check">
          <input type="radio" checked={kind === "pem"} onChange={() => setKind("pem")} /> {t("Certificate and key (PEM)")}
        </label>
      </div>
      {kind === "p12" ? (
        <div className="cc-row">
          <button className="cc-file" onClick={() => void pick("p12Path", ["p12", "pfx"], "PKCS#12")}>
            {name(src.p12Path) || t("Choose .p12 file…")}
          </button>
          <input {...plain} type="password" placeholder={t("password")} value={src.password ?? ""} onChange={(e) => setSrc({ ...src, password: e.target.value })} />
        </div>
      ) : (
        <div className="cc-row">
          <button className="cc-file" title={src.certPath} onClick={() => void pick("certPath", ["pem", "crt", "cer"], "PEM")}>
            {name(src.certPath) || t("Certificate…")}
          </button>
          <button className="cc-file" title={src.keyPath} onClick={() => void pick("keyPath", ["pem", "key"], "PEM")}>
            {name(src.keyPath) || t("Private key…")}
          </button>
        </div>
      )}
      {error && <div className="mocks-error">{error}</div>}
      <div className="btn-row">
        <button className="primary" disabled={!ready || busy} onClick={() => void go()}>
          {t("Use this CA")}
        </button>
        <button onClick={onCancel}>{t("Cancel")}</button>
      </div>
    </div>
  );
}

/** Export the CA with its private key, password protected. */
function P12ExportForm({ onCancel }: { onCancel: () => void }) {
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const go = async () => {
    const p = await save({ defaultPath: "quena-root-ca.p12", filters: [{ name: "PKCS#12", extensions: ["p12", "pfx"] }] });
    if (!p) return;
    try {
      await api.caExport(p, "p12", pw);
      say(t("Exported to {path}", { path: p }));
      onCancel();
    } catch (e) {
      say(String(e), "error");
    }
  };
  return (
    <div className="ca-form">
      <p className="small err">{t("The file contains the private key: whoever has it and the password can read HTTPS traffic of every device that trusts this certificate. Share it only with people who should debug with it.")}</p>
      <div className="cc-row">
        <input {...plain} type="password" placeholder={t("password")} value={pw} onChange={(e) => setPw(e.target.value)} />
        <input {...plain} type="password" placeholder={t("repeat password")} value={pw2} onChange={(e) => setPw2(e.target.value)} />
      </div>
      <div className="btn-row">
        <button className="primary" disabled={pw.length < 4 || pw !== pw2} title={pw !== pw2 ? t("The passwords differ") : undefined} onClick={() => void go()}>
          {t("Export .p12…")}
        </button>
        <button onClick={onCancel}>{t("Cancel")}</button>
      </div>
    </div>
  );
}

export function HttpsPanel() {
  const settings = useStore((s) => s.settings);
  const [ca, setCa] = useState<CaInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState<"import" | "p12" | null>(null);
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
      <div className="f-row">
        <span>{t("Warn about server certificates expiring within (days)")}</span>
        <input type="number" min={0} max={3650} defaultValue={h.certWarnDays ?? 30} onBlur={(e) => patchSettings((s) => (s.https.certWarnDays = Math.max(0, Number(e.target.value) || 0)))} />
      </div>
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
            <div>
              <b>{ca.name}</b>
              {!ca.generated && <span className="muted small"> · {t("imported")}</span>}
              {ca.chain > 0 && <span className="muted small"> · {t("with {n} chain certificates", { n: ca.chain })}</span>}
            </div>
            <div className="small muted">{t("Valid until {date}", { date: fmtDate(ca.notAfter * 1_000_000) })}</div>
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
          {isWindows && (
            <button
              disabled={busy}
              title={t("Adds the certificate to the local machine's trusted roots, for every user of this computer (Windows asks for administrator rights). Right-click to remove it from there.")}
              onClick={() => run(() => api.caMachine(true), t("Root certificate trusted for all users"))}
              onContextMenu={(e) => {
                e.preventDefault();
                run(() => api.caMachine(false), t("Root certificate removed for all users"));
              }}
            >
              {t("Trust for all users…")}
            </button>
          )}
          <button
            disabled={busy || !ca?.exists}
            onClick={async () => {
              const p = await save({ defaultPath: "quena-root-ca.crt", filters: [{ name: t("Certificate"), extensions: ["crt", "pem", "cer", "der"] }] });
              if (!p) return;
              await api.caExport(p, /\.(cer|der)$/i.test(p) ? "der" : "pem");
              say(t("Exported to {path}", { path: p }));
            }}
          >
            {t("Export…")}
          </button>
          <button disabled={busy || !ca?.exists} title={t("Certificate and private key, password protected – for another machine or a colleague")} onClick={() => setForm(form === "p12" ? null : "p12")}>
            {t("Export with key (.p12)…")}
          </button>
          <button disabled={busy} title={t("Use an existing CA, e.g. the company's")} onClick={() => setForm(form === "import" ? null : "import")}>
            {t("Import CA…")}
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
        {form === "import" && (
          <CaImportForm
            ca={ca}
            onCancel={() => setForm(null)}
            onDone={(c) => {
              setCa(c);
              setForm(null);
              say(t("Quena now uses the CA {name}", { name: c.name }));
            }}
          />
        )}
        {form === "p12" && <P12ExportForm onCancel={() => setForm(null)} />}
        <p className="small muted">
          {t("The private key stays on {machine} (stored with owner-only permissions) unless you export it as .p12. Only trust the certificate on machines you use for debugging; remove it afterwards.", { machine: osNames.machine })}
        </p>
      </fieldset>
      <p>
        <button onClick={() => set({ dialog: { kind: "connect-device" } })}>{t("Connect a device (iOS/Android)…")}</button>
      </p>
    </div>
  );
}
