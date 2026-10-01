// "Mocks from Sessions": Mock Rules right away, a Quena mock package, or a WireMock export,
// with the options of crates/quena-app-core/src/mockgen.rs and a live preview.
import { useEffect, useRef, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { api, type JobInfo, type MockOptions, type MockPreview, type MockSkipReason, type SessionId } from "../api";
import { get, say, set, useStore } from "../store";
import { plural, t } from "../i18n";

type Target = "apply" | "package" | "wiremock";
type Sanitize = "none" | "credentials" | "support" | "gdpr";

const DEFAULTS: MockOptions = {
  hosts: [],
  includeStatic: false,
  query: "ignore",
  ignoreParams: ["_", "t", "cacheBust", "utm_*"],
  repeats: "last",
  matchBody: true,
  latency: false,
  includePreflight: true,
  includeErrors: true,
  sanitize: "credentials",
  keepSetCookie: false,
};

const PREFS_KEY = "quena.mocks.options";

function loadPrefs(): MockOptions {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    return raw ? { ...DEFAULTS, ...(JSON.parse(raw) as Partial<MockOptions>) } : DEFAULTS;
  } catch {
    return DEFAULTS;
  }
}

function savePrefs(o: MockOptions) {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify({ ...o, hosts: [] }));
  } catch {
    /* private mode */
  }
}

export const skipReasonText = (r: MockSkipReason): string =>
  ({
    noResponse: t("no response"),
    incomplete: t("aborted"),
    truncated: t("body not recorded completely"),
    tunnel: t("tunnel (CONNECT)"),
    webSocket: "WebSocket",
    host: t("other host"),
    static: t("static resource"),
    preflight: t("CORS preflight"),
    errorStatus: t("error response"),
    notModified: t("304 Not Modified"),
    superseded: t("replaced by a later response"),
    duplicate: t("same response as before"),
  })[r];

const splitList = (s: string) =>
  s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);

/** Resolves when job `id` has finished: null when done, else the error. */
function waitJob(id: number): Promise<string | null> {
  return new Promise((resolve) => {
    const check = (jobs: JobInfo[]) => {
      const j = jobs.find((x) => x.id === id);
      if (!j || j.status === "queued" || j.status === "running") return false;
      resolve(j.status === "done" ? null : j.status === "cancelled" ? t("Cancelled") : (j.error ?? t("failed")));
      return true;
    };
    if (check(get().jobs)) return;
    const unsub = useStore.subscribe((s) => {
      if (check(s.jobs)) unsub();
    });
  });
}

export function MocksDialog({ selected, target: initialTarget, onDone }: { selected: SessionId[]; target?: Target; onDone: () => void }) {
  const [target, setTarget] = useState<Target>(initialTarget ?? "apply");
  const [scope, setScope] = useState<"selected" | "visible">(selected.length > 1 ? "selected" : "visible");
  const [opts, setOpts] = useState<MockOptions>(loadPrefs);
  const [hostsText, setHostsText] = useState("");
  const [ignoreText, setIgnoreText] = useState(opts.ignoreParams.join(", "));
  const [name, setName] = useState("");
  const [zip, setZip] = useState(true);
  const [preview, setPreview] = useState<MockPreview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const visible = useStore((s) => s.listTotal);
  const seq = useRef(0);

  const ids = scope === "selected" ? selected : [];
  const effective: MockOptions = { ...opts, hosts: splitList(hostsText), ignoreParams: splitList(ignoreText) };
  const key = JSON.stringify([ids, effective]);

  useEffect(() => {
    const n = ++seq.current;
    const timer = window.setTimeout(() => {
      api
        .mockPreview(ids, effective)
        .then((p) => {
          if (n !== seq.current) return;
          setPreview(p);
          setPreviewError(null);
        })
        .catch((e) => n === seq.current && setPreviewError(String(e)));
    }, 250);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  const up = (patch: Partial<MockOptions>) => setOpts((o) => ({ ...o, ...patch }));
  const sanitize: Sanitize = opts.sanitize ?? "none";

  const run = async () => {
    savePrefs(effective);
    try {
      let job: number;
      let where = "";
      if (target === "apply") {
        job = await api.mockApply(ids, effective, name.trim());
      } else if (target === "package") {
        const p = await save({ defaultPath: `${name.trim() || "mocks"}.quena-mocks`, filters: [{ name: t("Quena mock package"), extensions: ["quena-mocks"] }] });
        if (!p) return;
        where = p;
        job = await api.mockExportPackage(ids, p, effective);
      } else {
        const p = zip
          ? await save({ defaultPath: "wiremock-mocks.zip", filters: [{ name: "ZIP", extensions: ["zip"] }] })
          : await open({ directory: true, multiple: false, title: t("Folder for the WireMock files") });
        if (typeof p !== "string") return;
        where = p;
        job = await api.mockExportWiremock(ids, p, effective);
      }
      setBusy(true);
      const err = await waitJob(job);
      setBusy(false);
      if (err) return say(err, "error");
      const n = preview?.mappings ?? 0;
      if (target === "apply") {
        set({ activeTab: "autoresponder", arNonce: Date.now() });
        say(plural(n, "{n} mock rule created", "{n} mock rules created"));
      } else {
        say(plural(n, "{n} mock written to {path}", "{n} mocks written to {path}", { path: where }));
      }
      onDone();
    } catch (e) {
      setBusy(false);
      say(String(e), "error");
    }
  };

  const reasons = Object.entries(preview?.skippedByReason ?? {}) as [MockSkipReason, number][];

  return (
    <div className="mocks-dialog">
      <fieldset className="f-section">
        <legend>{t("Target")}</legend>
        <div className="f-radios">
          <label className="f-check">
            <input type="radio" name="mock-target" checked={target === "apply"} onChange={() => setTarget("apply")} /> {t("Create Mock Rules now")}
          </label>
          <label className="f-check">
            <input type="radio" name="mock-target" checked={target === "package"} onChange={() => setTarget("package")} /> {t("Save Quena mock package (.quena-mocks)")}
          </label>
          <label className="f-check">
            <input type="radio" name="mock-target" checked={target === "wiremock"} onChange={() => setTarget("wiremock")} /> {t("WireMock export (mappings and __files)")}
          </label>
        </div>
        {target !== "wiremock" && (
          <div className="f-row">
            <span>{t("Package name")}</span>
            <input value={name} placeholder={t("e.g. shop-api (empty: date and time)")} onChange={(e) => setName(e.target.value)} />
          </div>
        )}
        {target === "wiremock" && (
          <div className="f-row">
            <span>{t("Output")}</span>
            <select value={zip ? "zip" : "dir"} onChange={(e) => setZip(e.target.value === "zip")}>
              <option value="zip">{t("ZIP file")}</option>
              <option value="dir">{t("Folder")}</option>
            </select>
          </div>
        )}
      </fieldset>
      <fieldset className="f-section">
        <legend>{t("Sessions")}</legend>
        <div className="f-radios">
          <label className="f-check">
            <input type="radio" name="mock-scope" disabled={!selected.length} checked={scope === "selected"} onChange={() => setScope("selected")} />{" "}
            {plural(selected.length, "Selected session ({n})", "Selected sessions ({n})")}
          </label>
          <label className="f-check">
            <input type="radio" name="mock-scope" checked={scope === "visible"} onChange={() => setScope("visible")} /> {plural(visible, "Visible session ({n})", "Visible sessions ({n})")}
          </label>
        </div>
        <div className="f-row">
          <span>{t("Only hosts")}</span>
          <input className="mono" value={hostsText} placeholder={t("all (or e.g. api.example.com)")} onChange={(e) => setHostsText(e.target.value)} />
        </div>
        <label className="f-check">
          <input type="checkbox" checked={opts.includeStatic} onChange={(e) => up({ includeStatic: e.target.checked })} /> {t("Include static resources (JS, CSS, images, fonts)")}
        </label>
        <label className="f-check">
          <input type="checkbox" checked={opts.includeErrors} onChange={(e) => up({ includeErrors: e.target.checked })} /> {t("Include error responses (4xx/5xx)")}
        </label>
        <label className="f-check">
          <input type="checkbox" checked={opts.includePreflight} onChange={(e) => up({ includePreflight: e.target.checked })} /> {t("Include CORS preflights (OPTIONS)")}
        </label>
      </fieldset>
      <fieldset className="f-section">
        <legend>{t("Matching")}</legend>
        <div className="f-row">
          <span>{t("Query string")}</span>
          <select value={opts.query} onChange={(e) => up({ query: e.target.value as MockOptions["query"] })}>
            <option value="ignore">{t("Ignore parameters below")}</option>
            <option value="exact">{t("Exact URL")}</option>
          </select>
        </div>
        {opts.query === "ignore" && (
          <div className="f-row">
            <span>{t("Ignored parameters")}</span>
            <input className="mono" value={ignoreText} onChange={(e) => setIgnoreText(e.target.value)} />
          </div>
        )}
        <div className="f-row">
          <span>{t("Same request, several responses")}</span>
          <select value={opts.repeats} onChange={(e) => up({ repeats: e.target.value as MockOptions["repeats"] })}>
            <option value="last">{t("Last response wins")}</option>
            <option value="sequence">{t("In recorded order (sequence)")}</option>
          </select>
        </div>
        <label className="f-check" title={t("JSON is compared semantically, GraphQL by operation name and variables.")}>
          <input type="checkbox" checked={opts.matchBody} onChange={(e) => up({ matchBody: e.target.checked })} /> {t("Match request bodies (POST, PUT, PATCH)")}
        </label>
        <label className="f-check">
          <input type="checkbox" checked={opts.latency} onChange={(e) => up({ latency: e.target.checked })} /> {t("Recorded latency (time to first byte)")}
        </label>
      </fieldset>
      <fieldset className="f-section">
        <legend>{t("Responses")}</legend>
        <div className="f-row">
          <span>{t("Sanitize responses")}</span>
          <select value={sanitize} onChange={(e) => up({ sanitize: e.target.value === "none" ? null : (e.target.value as MockOptions["sanitize"]) })}>
            <option value="credentials">{t("Credentials and tokens")}</option>
            <option value="support">{t("Support (credentials and personal data)")}</option>
            <option value="gdpr">{t("GDPR strict")}</option>
            <option value="none">{t("As recorded")}</option>
          </select>
        </div>
        <label className="f-check">
          <input type="checkbox" checked={opts.keepSetCookie} onChange={(e) => up({ keepSetCookie: e.target.checked })} /> {t("Keep Set-Cookie headers")}
        </label>
        <span className="muted small">{t("Responses are served decoded: Content-Encoding and hop-by-hop headers are removed, Content-Length is recomputed.")}</span>
      </fieldset>
      <fieldset className="f-section mocks-preview">
        <legend>{t("Preview")}</legend>
        {previewError && <div className="mocks-error">{previewError}</div>}
        {!preview && !previewError && <span className="muted">{t("Loading…")}</span>}
        {preview && (
          <>
            <div className="mocks-counts">
              <b>{plural(preview.mappings, "{n} mapping", "{n} mappings")}</b>
              <span>{plural(preview.sequences, "{n} sequence", "{n} sequences")}</span>
              <span>{plural(preview.sessions, "from {n} session", "from {n} sessions")}</span>
              {preview.hosts.length > 0 && <span className="mono small">{preview.hosts.slice(0, 4).join(", ") + (preview.hosts.length > 4 ? " …" : "")}</span>}
            </div>
            {reasons.length > 0 && (
              <div className="muted small">
                {t("Left out:")} {reasons.map(([r, n]) => `${skipReasonText(r)} ${n}`).join(" · ")}
              </div>
            )}
            <div className="mocks-list">
              <table className="kv">
                <tbody>
                  {preview.entries.map((e, i) => (
                    <tr key={i}>
                      <td className="mono">{e.method}</td>
                      <td>{e.status}</td>
                      <td className="mono mocks-url" title={e.url}>
                        {e.url}
                      </td>
                      <td className="muted small">
                        {[e.bodyMatch ? t("body") : "", e.sequence ? `${e.sequence.index + 1}/${e.sequence.len}` : ""].filter(Boolean).join(" · ")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </fieldset>
      <div className="btn-row mocks-actions">
        <button onClick={onDone}>{t("Cancel")}</button>
        <button className="primary" disabled={busy || !preview?.mappings} onClick={run}>
          {busy ? t("Working…") : target === "apply" ? t("Create rules") : t("Save…")}
        </button>
      </div>
    </div>
  );
}
