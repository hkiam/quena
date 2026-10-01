// Sanitized export (File → Export Sessions → Sanitized for Sharing): options with presets,
// the export job, and the redaction log afterwards. The replacement itself happens in
// crates/quena-app-core/src/sanitize.rs.
import { useEffect, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, on, type SanitizedExport, type SanitizeOptions, type SessionId } from "../api";
import { get, say, set, useStore } from "../store";
import { fmtNum, plural, t } from "../i18n";

type Flag = "authorization" | "cookies" | "secretHeaders" | "urlSecrets" | "bodySecrets" | "emails" | "payment" | "phones" | "ips" | "personalFields" | "nationalIds" | "process";

const CREDENTIALS: [Flag, () => string][] = [
  ["authorization", () => t("Authorization / Proxy-Authorization: only the scheme and the size stay")],
  ["cookies", () => t("Cookie / Set-Cookie: names and attributes stay, values are replaced")],
  ["secretHeaders", () => t("Headers with secrets (x-api-key, *token*, *secret*, x-csrf* …)")],
  ["urlSecrets", () => t("URLs: user info and secret parameters")],
  ["bodySecrets", () => t("Bodies: secret fields (password, client_secret, access_token …) and JWTs")],
];

const PERSONAL: [Flag, () => string][] = [
  ["emails", () => t("E-mail addresses")],
  ["payment", () => t("IBANs and card numbers (checksums)")],
  ["phones", () => t("Phone numbers")],
  ["ips", () => t("IP addresses (headers, bodies, client and server address)")],
  ["personalFields", () => t("Fields named like personal data (name, street, birthDate, telefon …)")],
  ["nationalIds", () => t("Tax ID and social security number")],
  ["process", () => t("Process name")],
];

/** Names of the redaction log categories. */
export const CATEGORY: Record<string, () => string> = {
  authorization: () => t("Authorization credentials"),
  cookie: () => t("Cookie values"),
  secretHeader: () => t("Secret header values"),
  urlSecret: () => t("Secret URL parameters"),
  userInfo: () => t("URL user info"),
  secretField: () => t("Secret fields (passwords, tokens …)"),
  jwt: () => t("JSON Web Tokens"),
  email: () => t("E-mail addresses"),
  iban: () => t("IBANs"),
  card: () => t("Card numbers"),
  phone: () => t("Phone numbers"),
  ip: () => t("IP addresses"),
  personalField: () => t("Personal fields (names, addresses …)"),
  taxId: () => t("Tax IDs"),
  socialSecurity: () => t("Social security numbers"),
  process: () => t("Process names"),
  custom: () => t("Own patterns and names"),
  bodyRemoved: () => t("Bodies removed"),
  bodyTruncated: () => t("Bodies truncated"),
  binaryRemoved: () => t("Binary bodies replaced"),
  fileRemoved: () => t("Uploaded files replaced"),
  undecodable: () => t("Undecodable bodies replaced"),
};

const LOCATIONS: [string, () => string][] = [
  ["header", () => t("Headers")],
  ["url", () => "URL"],
  ["body", () => t("Bodies")],
  ["ws", () => "WebSocket"],
  ["meta", () => t("Session data")],
];

function stamp() {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}`;
}

const list = (s: string) =>
  s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);
const lines = (s: string) =>
  s
    .split("\n")
    .map((x) => x.trim())
    .filter(Boolean);

/** Start the export; the redaction log opens when the job is done. */
export async function runSanitizedExport(ids: SessionId[], path: string, format: "saz" | "har", options: SanitizeOptions) {
  let job: number | null = null;
  let finished = false;
  const cleanups: (() => void)[] = [];
  const finish = () => {
    finished = true;
    cleanups.forEach((c) => c());
  };
  const unlisten = await on<SanitizedExport>("export-sanitized", (r) => {
    if (finished || r.path !== path) return;
    finish();
    set({ dialog: { kind: "sanitize-result", result: r } });
    // The export remembered its options in the settings.
    api
      .settingsGet()
      .then((s) => set({ settings: s }))
      .catch(() => {});
  });
  cleanups.push(unlisten);
  cleanups.push(
    useStore.subscribe((s) => {
      const j = job == null ? undefined : s.jobs.find((x) => x.id === job);
      if (!j || finished) return;
      if (j.status === "failed") {
        finish();
        say(t("Sanitized export failed: {error}", { error: j.error ?? "" }), "error");
      } else if (j.status === "cancelled") finish();
    }),
  );
  try {
    job = await api.exportSanitized(ids, path, format, options);
    say(t("Saving sanitized sessions to {path}", { path }));
  } catch (e) {
    finish();
    say(String(e), "error");
  }
}

export function SanitizeDialog({ selected, onClose }: { selected: SessionId[]; onClose: () => void }) {
  const saved = get().settings?.sanitize;
  const [presets, setPresets] = useState<SanitizeOptions[] | null>(null);
  const [o, setO] = useState<SanitizeOptions | null>(saved?.options ?? null);
  const [format, setFormat] = useState<"saz" | "har">(saved?.format === "har" ? "har" : "saz");
  const [rules, setRules] = useState(() => ({
    headers: (saved?.options.extraHeaders ?? []).join(", "),
    params: (saved?.options.extraParams ?? []).join(", "),
    fields: (saved?.options.extraFields ?? []).join(", "),
    patterns: (saved?.options.patterns ?? []).join("\n"),
  }));
  useEffect(() => {
    api
      .sanitizePresets()
      .then((p) => {
        setPresets(p);
        setO((cur) => cur ?? p[0]);
      })
      .catch((e) => say(String(e), "error"));
  }, []);
  if (!o) return <div className="muted">{t("Loading…")}</div>;
  const custom = (patch: Partial<SanitizeOptions>) => setO({ ...o, ...patch, preset: "custom" });
  const pick = (name: "support" | "gdpr" | "custom") => {
    const p = presets?.find((x) => x.preset === name);
    if (p)
      setO({
        ...p,
        extraHeaders: o.extraHeaders,
        extraParams: o.extraParams,
        extraFields: o.extraFields,
        patterns: o.patterns,
      });
    else setO({ ...o, preset: "custom" });
  };
  const check = ([k, label]: [Flag, () => string]) => (
    <label key={k} className="f-check">
      <input type="checkbox" checked={o[k]} onChange={(e) => custom({ [k]: e.target.checked } as Partial<SanitizeOptions>)} /> {label()}
    </label>
  );
  const start = async () => {
    const options: SanitizeOptions = {
      ...o,
      extraHeaders: list(rules.headers),
      extraParams: list(rules.params),
      extraFields: list(rules.fields),
      patterns: lines(rules.patterns),
    };
    // End-to-end tests have no native save dialog.
    const hook = (window as unknown as { __quenaSanitizePath?: string }).__quenaSanitizePath;
    const filters = format === "saz" ? [{ name: t("SAZ Session Archive"), extensions: ["saz"] }] : [{ name: t("HTTP Archive (HAR)"), extensions: ["har"] }];
    const path =
      hook ??
      (await save({
        defaultPath: `quena_${stamp()}_sanitized.${format}`,
        filters,
      }));
    if (!path) return;
    onClose();
    await runSanitizedExport(selected, path, format, options);
  };
  const scope = selected.length ? plural(selected.length, "{n} selected session", "{n} selected sessions") : t("All sessions in the list");
  return (
    <div className="sanitize-dialog">
      <div className="f-row">
        <span>{t("Sessions")}</span>
        <span>{scope}</span>
      </div>
      <div className="f-row">
        <span>{t("Preset")}</span>
        <span style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          {(
            [
              ["support", t("Support")],
              ["gdpr", t("GDPR strict")],
              ["custom", t("Custom")],
            ] as const
          ).map(([k, label]) => (
            <label key={k} className="f-check">
              <input type="radio" name="sanitize-preset" value={k} checked={o.preset === k || (k === "custom" && o.preset === "credentials")} onChange={() => pick(k)} /> {label}
            </label>
          ))}
        </span>
      </div>
      <div className="f-row">
        <span>{t("File format")}</span>
        <span style={{ display: "flex", gap: 12 }}>
          {(["saz", "har"] as const).map((f) => (
            <label key={f} className="f-check">
              <input type="radio" name="sanitize-format" value={f} checked={format === f} onChange={() => setFormat(f)} />{" "}
              {f === "saz" ? t("SAZ Session Archive") : t("HTTP Archive (HAR)")}
            </label>
          ))}
        </span>
      </div>
      <fieldset className="f-section">
        <legend>{t("Credentials")}</legend>
        {CREDENTIALS.map(check)}
      </fieldset>
      <fieldset className="f-section">
        <legend>{t("Personal data")}</legend>
        {PERSONAL.map(check)}
      </fieldset>
      <fieldset className="f-section">
        <legend>{t("Bodies")}</legend>
        <div className="f-row">
          <span>{t("Bodies")}</span>
          <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <select value={o.bodies} onChange={(e) => custom({ bodies: e.target.value as SanitizeOptions["bodies"] })}>
              <option value="keep">{t("keep (sanitized)")}</option>
              <option value="truncate">{t("first KiB only (sanitized)")}</option>
              <option value="placeholder">{t("replace by a placeholder")}</option>
              <option value="drop">{t("remove")}</option>
            </select>
            {o.bodies === "truncate" && (
              <>
                <input
                  type="number"
                  min={1}
                  style={{ width: 80 }}
                  value={o.truncateKib}
                  onChange={(e) =>
                    custom({
                      truncateKib: Math.max(1, Number(e.target.value) || 1),
                    })
                  }
                />{" "}
                KiB
              </>
            )}
          </span>
        </div>
        <label className="f-check">
          <input type="checkbox" checked={o.binary === "placeholder"} onChange={(e) => custom({ binary: e.target.checked ? "placeholder" : "keep" })} />{" "}
          {t("Replace binary bodies (images, fonts, PDF, archives) and uploaded files by a placeholder")}
        </label>
        <label className="f-check">
          <input type="checkbox" checked={o.pseudonyms} onChange={(e) => custom({ pseudonyms: e.target.checked })} />{" "}
          {t("Pseudonyms: the same value gets the same name (<email-3>) so that relations stay visible")}
        </label>
      </fieldset>
      <fieldset className="f-section">
        <legend>{t("Own rules")}</legend>
        <div className="f-row">
          <span>{t("Header names")}</span>
          <input value={rules.headers} placeholder="x-tenant, x-customer" onChange={(e) => setRules({ ...rules, headers: e.target.value })} />
        </div>
        <div className="f-row">
          <span>{t("Parameter names (URL, form)")}</span>
          <input value={rules.params} placeholder="customer, ref" onChange={(e) => setRules({ ...rules, params: e.target.value })} />
        </div>
        <div className="f-row">
          <span>{t("Field names (JSON, XML, multipart)")}</span>
          <input value={rules.fields} placeholder="customerNo, contractId" onChange={(e) => setRules({ ...rules, fields: e.target.value })} />
        </div>
        <div className="f-row">
          <span>{t("Regular expressions (one per line)")}</span>
          <textarea rows={2} className="mono" value={rules.patterns} placeholder={"ACME-\\d{6}"} onChange={(e) => setRules({ ...rules, patterns: e.target.value })} />
        </div>
      </fieldset>
      <div className="muted small">{t("Automatic detection can miss data. Check the file before sharing it.")}</div>
      <div
        className="modal-footer inline sticky"
        style={{
          display: "flex",
          gap: 8,
          justifyContent: "flex-end",
          marginTop: 8,
        }}
      >
        <button onClick={onClose}>{t("Cancel")}</button>
        <button className="primary" onClick={start}>
          {t("Export…")}
        </button>
      </div>
    </div>
  );
}

export function SanitizeResult({ result, onClose }: { result: SanitizedExport; onClose: () => void }) {
  const log = result.log;
  const cats = Object.entries(log.byCategory).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const cell = (c: string, l: string) => log.counts.find((x) => x.category === c && x.location === l)?.count ?? 0;
  const usedLocs = LOCATIONS.filter(([l]) => (log.byLocation[l] ?? 0) > 0);
  const open = async () => {
    try {
      await api.importArchive(result.path);
      say(t("Loading {path}", { path: result.path }));
      onClose();
    } catch (e) {
      say(String(e), "error");
    }
  };
  return (
    <div className="sanitize-result">
      <div className="mono small" style={{ wordBreak: "break-all" }}>
        {result.path}
      </div>
      <p>
        <b>{plural(log.total, "{n} value replaced", "{n} values replaced")}</b>{" "}
        {t("in {touched} of {sessions} sessions", {
          touched: fmtNum(log.touched.length),
          sessions: fmtNum(log.sessions),
        })}
        {log.distinctValues > 0 && <> · {plural(log.distinctValues, "{n} distinct value", "{n} distinct values")}</>}
      </p>
      {cats.length === 0 ? (
        <div className="muted">{t("Nothing was found to replace.")}</div>
      ) : (
        <table className="kv sanitize-log">
          <thead>
            <tr>
              <th style={{ textAlign: "left" }}>{t("Category")}</th>
              {usedLocs.map(([l, label]) => (
                <th key={l} style={{ textAlign: "right" }}>
                  {label()}
                </th>
              ))}
              <th style={{ textAlign: "right" }}>{t("Total")}</th>
            </tr>
          </thead>
          <tbody>
            {cats.map(([c, n]) => (
              <tr key={c} data-category={c}>
                <td>{CATEGORY[c]?.() ?? c}</td>
                {usedLocs.map(([l]) => (
                  <td key={l} style={{ textAlign: "right" }}>
                    {cell(c, l) ? fmtNum(cell(c, l)) : ""}
                  </td>
                ))}
                <td style={{ textAlign: "right" }}>{fmtNum(n)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {log.numbersAsStrings > 0 && (
        <p className="small">{plural(log.numbersAsStrings, "{n} JSON number was replaced by a text placeholder.", "{n} JSON numbers were replaced by text placeholders.")}</p>
      )}
      {log.wsMessages > 0 && <p className="small">{plural(log.wsMessages, "{n} WebSocket message checked.", "{n} WebSocket messages checked.")}</p>}
      {log.notes.map((n) => (
        <p key={n} className="small">
          {n}
        </p>
      ))}
      <p className="muted small">
        {result.format === "saz" ? t("The archive contains this log as QUENA-REDACTION.txt.") : t("The HAR file contains this log in log.comment and log._quenaRedaction.")}{" "}
        {t("Automatic detection can miss data. Check the file before sharing it.")}
      </p>
      <div
        className="modal-footer inline sticky"
        style={{
          display: "flex",
          gap: 8,
          justifyContent: "flex-end",
          alignItems: "center",
        }}
      >
        <span className="muted small" style={{ marginRight: "auto" }}>
          {t("Opening adds its sessions to the end of the list.")}
        </span>
        <button onClick={() => api.revealPath(result.path).catch((e) => say(String(e), "error"))}>{t("Show in Folder")}</button>
        <button onClick={open}>{t("Open Sanitized File")}</button>
        <button className="primary" onClick={onClose}>
          {t("Close")}
        </button>
      </div>
    </div>
  );
}
