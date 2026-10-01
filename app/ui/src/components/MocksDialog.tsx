// "Mocks from Sessions": Mock Rules right away, a Quena mock package, or a WireMock export,
// with the options of crates/quena-app-core/src/mockgen.rs and a live preview.
import { useEffect, useId, useRef, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { api, on, type MockJobResult, type MockOptions, type MockPreview, type MockSkipReason, type SessionId } from "../api";
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
    tooLarge: t("response too large"),
    undecodable: t("body could not be decoded"),
  })[r];

const splitList = (s: string) =>
  s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);

type JobEnd = { error: string | null; result: MockJobResult | null };

/**
 * Start a mock job with `start` (null: nothing started) and wait for its end: the `mocks`
 * event with the result, or the job's failure. A job that is gone from the list (pruned)
 * after it was seen, or that never shows up, ends as "done, result unknown".
 */
async function runMockJob(start: () => Promise<number | null>): Promise<JobEnd | null> {
  const results = new Map<number, MockJobResult>();
  let wake: (() => void) | null = null;
  const unlisten = await on<MockJobResult>("mocks", (r) => {
    results.set(r.job, r);
    wake?.();
  });
  try {
    const job = await start();
    if (job == null) return null;
    return await new Promise<JobEnd>((resolve) => {
      let seen = false;
      let grace: number | undefined;
      const done = (v: JobEnd) => {
        wake = null;
        unsub();
        window.clearTimeout(grace);
        window.clearTimeout(never);
        resolve(v);
      };
      // Finished (or gone) without the event yet: it follows right away, else give up on it.
      const soon = () => {
        grace ??= window.setTimeout(() => done({ error: null, result: results.get(job) ?? null }), 1500);
      };
      const check = () => {
        const r = results.get(job);
        if (r) return done({ error: null, result: r });
        const j = get().jobs.find((x) => x.id === job);
        if (j) seen = true;
        if (j?.status === "failed") return done({ error: j.error ?? t("failed"), result: null });
        if (j?.status === "cancelled") return done({ error: t("Cancelled"), result: null });
        if (j?.status === "done" || (!j && seen)) soon();
      };
      wake = check;
      const unsub = useStore.subscribe(check);
      const never = window.setTimeout(() => !seen && done({ error: null, result: results.get(job) ?? null }), 30000);
      check();
    });
  } finally {
    unlisten();
  }
}

export function MocksDialog({ selected, target: initialTarget, onDone }: { selected: SessionId[]; target?: Target; onDone: () => void }) {
  const id = useId();
  // This dialog in the store: closing after an await must not close another one.
  const mine = useRef(get().dialog);
  const close = () => {
    if (get().dialog === mine.current) onDone();
  };
  const [target, setTarget] = useState<Target>(initialTarget ?? "apply");
  const [scope, setScope] = useState<"selected" | "visible">(selected.length > 1 ? "selected" : "visible");
  const [opts, setOpts] = useState<MockOptions>(loadPrefs);
  const [hostsText, setHostsText] = useState("");
  const [ignoreText, setIgnoreText] = useState(opts.ignoreParams.join(", "));
  const [name, setName] = useState("");
  const [zip, setZip] = useState(true);
  const [preview, setPreview] = useState<{ key: string; p: MockPreview } | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const visible = useStore((s) => s.listTotal);
  const seq = useRef(0);

  const ids = scope === "selected" ? selected : [];
  const effective: MockOptions = { ...opts, hosts: splitList(hostsText), ignoreParams: splitList(ignoreText) };
  // The visible sessions change while the dialog is open (capture, filter): preview again.
  const key = JSON.stringify([ids, effective, scope === "visible" ? visible : 0]);

  useEffect(() => {
    const n = ++seq.current;
    const timer = window.setTimeout(() => {
      api
        .mockPreview(ids, effective)
        .then((p) => {
          // Only the answer to the latest request counts.
          if (n !== seq.current) return;
          setPreview({ key, p });
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
    if (busy) return;
    // Busy right away: a second click must not start a second job.
    setBusy(true);
    savePrefs(effective);
    let where = "";
    try {
      const end = await runMockJob(async () => {
        if (target === "apply") return api.mockApply(ids, effective, name.trim());
        if (target === "package") {
          const p = await save({ defaultPath: `${name.trim() || "mocks"}.quena-mocks`, filters: [{ name: t("Quena mock package"), extensions: ["quena-mocks"] }] });
          if (!p) return null;
          where = p;
          return api.mockExportPackage(ids, p, effective);
        }
        const p = zip
          ? await save({ defaultPath: "wiremock-mocks.zip", filters: [{ name: "ZIP", extensions: ["zip"] }] })
          : await open({ directory: true, multiple: false, title: t("Folder for the WireMock files") });
        if (typeof p !== "string") return null;
        where = p;
        return api.mockExportWiremock(ids, p, effective);
      });
      if (!end) return;
      if (end.error) return say(end.error, "error");
      // The counts of the job itself, not of the (possibly older) preview.
      const r = end.result;
      const left = r?.rejected ? `, ${plural(r.rejected, "{n} rule left out (unsafe or for any host)", "{n} rules left out (unsafe or for any host)")}` : "";
      if (target === "apply") {
        set({ activeTab: "autoresponder", arNonce: Date.now() });
        say((r ? plural(r.mappings - r.rejected, "{n} mock rule created", "{n} mock rules created") : t("Mock rules created")) + left);
      } else {
        say((r ? plural(r.mappings, "{n} mock written to {path}", "{n} mocks written to {path}", { path: r.path || where }) : t("Mocks written to {path}", { path: where })) + left);
      }
      close();
    } catch (e) {
      say(String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  const current = preview && preview.key === key ? preview.p : null;
  const shown = preview?.p ?? null;
  const reasons = Object.entries(shown?.skippedByReason ?? {}) as [MockSkipReason, number][];
  const fid = (k: string) => `${id}-${k}`;

  return (
    <div className="mocks-dialog">
      <fieldset className="f-section">
        <legend>{t("Target")}</legend>
        <div className="f-radios">
          <label className="f-check">
            <input type="radio" name="mock-target" value="apply" checked={target === "apply"} onChange={() => setTarget("apply")} /> {t("Create Mock Rules now")}
          </label>
          <label className="f-check">
            <input type="radio" name="mock-target" value="package" checked={target === "package"} onChange={() => setTarget("package")} /> {t("Save Quena mock package (.quena-mocks)")}
          </label>
          <label className="f-check">
            <input type="radio" name="mock-target" value="wiremock" checked={target === "wiremock"} onChange={() => setTarget("wiremock")} /> {t("WireMock export (mappings and __files)")}
          </label>
        </div>
        {target !== "wiremock" && (
          <div className="f-row">
            <label htmlFor={fid("name")}>{t("Package name")}</label>
            <input id={fid("name")} value={name} placeholder={t("e.g. shop-api (empty: date and time)")} onChange={(e) => setName(e.target.value)} />
          </div>
        )}
        {target === "wiremock" && (
          <div className="f-row">
            <label htmlFor={fid("output")}>{t("Output")}</label>
            <select id={fid("output")} value={zip ? "zip" : "dir"} onChange={(e) => setZip(e.target.value === "zip")}>
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
          <label htmlFor={fid("hosts")}>{t("Only hosts")}</label>
          <input id={fid("hosts")} className="mono" value={hostsText} placeholder={t("all (or e.g. api.example.com)")} onChange={(e) => setHostsText(e.target.value)} />
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
          <label htmlFor={fid("query")}>{t("Query string")}</label>
          <select id={fid("query")} value={opts.query} onChange={(e) => up({ query: e.target.value as MockOptions["query"] })}>
            <option value="ignore">{t("Ignore parameters below")}</option>
            <option value="exact">{t("Exact URL")}</option>
          </select>
        </div>
        {opts.query === "ignore" && (
          <div className="f-row">
            <label htmlFor={fid("ignore")}>{t("Ignored parameters")}</label>
            <input id={fid("ignore")} className="mono" value={ignoreText} onChange={(e) => setIgnoreText(e.target.value)} />
          </div>
        )}
        <div className="f-row">
          <label htmlFor={fid("repeats")}>{t("Same request, several responses")}</label>
          <select id={fid("repeats")} value={opts.repeats} onChange={(e) => up({ repeats: e.target.value as MockOptions["repeats"] })}>
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
          <label htmlFor={fid("sanitize")}>{t("Sanitize responses")}</label>
          <select id={fid("sanitize")} value={sanitize} onChange={(e) => up({ sanitize: e.target.value === "none" ? null : (e.target.value as MockOptions["sanitize"]) })}>
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
        {!shown && !previewError && <span className="muted">{t("Loading…")}</span>}
        {shown && (
          <>
            <div className="mocks-counts">
              <b>{plural(shown.mappings, "{n} mapping", "{n} mappings")}</b>
              <span>{plural(shown.sequences, "{n} sequence", "{n} sequences")}</span>
              <span>{plural(shown.sessions, "from {n} session", "from {n} sessions")}</span>
              {shown.hosts.length > 0 && <span className="mono small">{shown.hosts.slice(0, 4).join(", ") + (shown.hosts.length > 4 ? " …" : "")}</span>}
            </div>
            {reasons.length > 0 && (
              <div className="muted small">
                {t("Left out:")} {reasons.map(([r, n]) => `${skipReasonText(r)} ${n}`).join(" · ")}
              </div>
            )}
            <div className="mocks-list">
              <table className="kv">
                <tbody>
                  {shown.entries.map((e, i) => (
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
        {/* Disabled only when the preview of exactly these options found nothing. */}
        <button className="primary" disabled={busy || current?.mappings === 0} onClick={run}>
          {busy ? t("Working…") : target === "apply" ? t("Create rules") : t("Save…")}
        </button>
      </div>
    </div>
  );
}
