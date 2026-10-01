import { lazy, Suspense, useEffect, useRef, useState } from "react";
import { api, type Recoverable, type Settings } from "../api";
import { actions } from "../actions";
import { fmtBytes, fmtDateTime, modKey, osNames } from "../lib/format";
import { get, say, set, useStore, type Dialog } from "../store";
import { FindDialog } from "./FindDialog";
import { HttpsPanel } from "./HttpsDialog";

// Rarely used, heavy dialogs (diff editor, script editor, QR code…) load on first open.
const TextWizard = lazy(() => import("./TextWizard").then((m) => ({ default: m.TextWizard })));
const CompareView = lazy(() => import("./CompareView").then((m) => ({ default: m.CompareView })));
const DeviceAssistant = lazy(() => import("./DeviceDialog").then((m) => ({ default: m.DeviceAssistant })));
const PluginsPanel = lazy(() => import("./PluginsDialog").then((m) => ({ default: m.PluginsPanel })));
const RulesEditor = lazy(() => import("./RulesEditor").then((m) => ({ default: m.RulesEditor })));
const SanitizeDialog = lazy(() => import("./SanitizeDialog").then((m) => ({ default: m.SanitizeDialog })));
const SanitizeResult = lazy(() => import("./SanitizeDialog").then((m) => ({ default: m.SanitizeResult })));
const MocksDialog = lazy(() => import("./MocksDialog").then((m) => ({ default: m.MocksDialog })));
import { CommandPalette } from "./CommandPalette";
import { ErrorBoundary } from "./ErrorBoundary";
import { currentLang, plural, t } from "../i18n";

function Modal({ title, children, onClose, wide, footer }: { title: string; children: React.ReactNode; onClose: () => void; wide?: boolean; footer?: React.ReactNode }) {
  return (
    <div className="modal-back" onMouseDown={onClose}>
      <div className={`modal ${wide ? "wide" : ""}`} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-title">
          {title}
          <span className="modal-x" onClick={onClose}>
            ✕
          </span>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  );
}

const close = () => set({ dialog: null });

function PromptDialog({ title, label, initial, resolve }: { title: string; label: string; initial: string; resolve: (v: string | null) => void }) {
  const [v, setV] = useState(initial);
  const done = (x: string | null) => {
    close();
    resolve(x);
  };
  return (
    <Modal
      title={title}
      onClose={() => done(null)}
      footer={
        <>
          <button onClick={() => done(null)}>{t("Cancel")}</button>
          <button className="primary" onClick={() => done(v)}>
            OK
          </button>
        </>
      }
    >
      <div className="f-row">
        <span>{label}</span>
        <input autoFocus value={v} onChange={(e) => setV(e.target.value)} onKeyDown={(e) => e.key === "Enter" && done(v)} />
      </div>
    </Modal>
  );
}

/** Yes/no question; Enter confirms, Esc or closing cancels. */
function ConfirmDialog({ title, message, confirm, resolve }: { title: string; message: string; confirm: string; resolve: (ok: boolean) => void }) {
  const answered = useRef(false);
  const done = (ok: boolean) => {
    if (answered.current) return;
    answered.current = true;
    close();
    resolve(ok);
  };
  // Closed another way (Esc is handled globally): that is a "no".
  useEffect(
    () => () => {
      if (!answered.current) {
        answered.current = true;
        resolve(false);
      }
    },
    [resolve],
  );
  return (
    <Modal
      title={title}
      onClose={() => done(false)}
      footer={
        <>
          <button onClick={() => done(false)}>{t("Cancel")}</button>
          <button className="primary danger" autoFocus onClick={() => done(true)}>
            {confirm}
          </button>
        </>
      }
    >
      <p className="confirm-text">{message}</p>
    </Modal>
  );
}

function CommentDialog({ ids, initial }: { ids: number[]; initial: string }) {
  const [v, setV] = useState(initial);
  const ok = async () => {
    close();
    await actions.setComment(ids, v);
  };
  return (
    <Modal
      title={plural(ids.length, "Comment ({n} session)", "Comment ({n} sessions)")}
      onClose={close}
      footer={
        <>
          <button onClick={close}>{t("Cancel")}</button>
          <button className="primary" onClick={ok}>
            OK
          </button>
        </>
      }
    >
      <input autoFocus className="full" value={v} onChange={(e) => setV(e.target.value)} onKeyDown={(e) => e.key === "Enter" && ok()} />
    </Modal>
  );
}

// Command-field syntax: the commands stay as typed, only the descriptions are translated.
const QUICKEXEC_HELP = (
  [
    ["?text", t("select sessions whose URL contains text")],
    [">10k  <5k", t("select by response size")],
    ["=404  =POST", t("select by status or method")],
    ["@host", t("select by host")],
    ["select type", t("select by content type (e.g. select image)")],
    ["find expr", t("select by expression (e.g. find status == 5xx)")],
    ["filter expr", t("hide sessions not matching expr (empty: remove)")],
    ["keeponly type", t("remove sessions whose content type does not match")],
    ["cls | clear", t("remove all sessions")],
    ["tail 100", t("keep the most recent 100 sessions")],
    ["bpu [text]", t("break before request (URL contains text); without text: off")],
    ["bpafter [t]", t("break after response (URL contains t)")],
    ["bps 500", t("break on response status")],
    ["bpv POST", t("break on request method")],
    ["g | go", t("resume all paused sessions")],
    ["dump", t("save all sessions as .saz")],
    ["start | stop", t("start/stop capturing")],
    ["help", t("this help")],
  ] as const
)
  .map(([c, d]) => c.padEnd(14) + d)
  .join("\n");

const SHORTCUTS: [string, string][] = [
  ["F12", t("Capture on/off (incl. system proxy)")],
  ["Ctrl+X / ⌘X", t("Remove all sessions")],
  ["Del / Shift+Del", t("Remove selected / all except selected")],
  ["R / Shift+R / U", t("Replay / replay n times / unconditional replay")],
  [`${modKey}1…6 / ${modKey}0`, t("Mark in colour / unmark")],
  ["M", t("Comment")],
  [`${modKey}C`, t("Copy session summary")],
  [`${modKey}A`, t("Select all")],
  ["Enter", t("Show inspectors")],
  [`${modKey}F`, t("Find sessions")],
  [`${modKey}S`, t("Save all sessions")],
  [`${modKey}R`, t("Customize rules")],
  [`${modKey}E`, t("Text Tools")],
  ["F7 / F8 / F9", t("Statistics / Inspectors / Composer")],
  ["F11 / Alt+F11 / Shift+F11", t("Break before requests / after responses / off")],
  [t("Alt+Q or /"), t("Focus the command field")],
  [`${modKey}K`, t("Command palette")],
  [`${modKey}⇧P`, t("Performance overlay")],
];

function HelpDialog({ topic }: { topic: "quickexec" | "shortcuts" }) {
  return (
    <Modal title={topic === "quickexec" ? t("Filter and command syntax") : t("Keyboard shortcuts")} onClose={close} wide>
      {topic === "quickexec" ? (
        <pre className="help-pre">{QUICKEXEC_HELP}</pre>
      ) : (
        <table className="kv">
          <tbody>
            {SHORTCUTS.map(([k, v]) => (
              <tr key={k}>
                <td className="mono">{k}</td>
                <td>{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Modal>
  );
}

function RecoverDialog() {
  const [list, setList] = useState<Recoverable[] | null>(null);
  const load = () => api.recoverable().then(setList);
  useEffect(() => {
    load();
  }, []);
  return (
    <Modal
      title={t("Recover previous capture")}
      onClose={close}
      wide
      footer={
        <>
          <label className="f-check" style={{ marginRight: "auto" }}>
            <input
              type="checkbox"
              onChange={async (e) => {
                const s = get().settings;
                if (!s) return;
                const next = { ...s, offerRecovery: !e.target.checked };
                set({ settings: next });
                await api.settingsSet(next);
              }}
            />{" "}
            {t("Don't ask again (Options → General)")}
          </label>
          <button
            onClick={async () => {
              const n = await api.discardAll();
              say(plural(n, "{n} old capture discarded", "{n} old captures discarded"));
              close();
            }}
          >
            {t("Discard all")}
          </button>
          <button onClick={close}>{t("Later")}</button>
        </>
      }
    >
      {!list ? (
        t("Loading…")
      ) : list.length === 0 ? (
        <div className="muted">{t("No unfinished captures found.")}</div>
      ) : (
        <>
          <p>{t("Quena was not closed cleanly. The following captures can be restored:")}</p>
          <table className="kv">
            <tbody>
              {list.map((c) => (
                <tr key={c.dir}>
                  <td>
                    {plural(c.sessions, "{n} session", "{n} sessions")}
                    <div className="muted small">{c.modified ? fmtDateTime(c.modified * 1_000_000) : ""} · {c.dir}</div>
                  </td>
                  <td className="right">
                    <button
                      className="primary"
                      onClick={async () => {
                        close();
                        await api.recover(c.dir);
                        say(plural(c.sessions, "Restored {n} session", "Restored {n} sessions"));
                      }}
                    >
                      {t("Restore")}
                    </button>{" "}
                    <button
                      onClick={async () => {
                        await api.discard(c.dir);
                        load();
                      }}
                    >
                      {t("Discard")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </Modal>
  );
}

const JOB_STATUS: Record<string, () => string> = {
  queued: () => t("queued"),
  running: () => t("running"),
  done: () => t("done"),
  failed: () => t("failed"),
  cancelled: () => t("cancelled"),
};

function JobsDialog() {
  const jobs = useStore((s) => s.jobs);
  return (
    <Modal title={t("Background jobs")} onClose={close} wide>
      {jobs.length === 0 && <div className="muted">{t("No jobs.")}</div>}
      <table className="kv jobs">
        <tbody>
          {jobs.map((j) => (
            <tr key={j.id}>
              <td>
                {j.title}
                {j.error && <div className="err small">{j.error}</div>}
              </td>
              <td style={{ width: 160 }}>
                {j.status === "running" && j.total > 0 ? (
                  <div className="progress">
                    <span style={{ width: `${(j.done / j.total) * 100}%` }} />
                  </div>
                ) : (
                  <span className="muted">{JOB_STATUS[j.status]?.() ?? j.status}</span>
                )}
                <div className="muted small">
                  {j.total > 0 ? `${fmtBytes(j.done)} / ${fmtBytes(j.total)}` : ""} {j.elapsedMs != null ? `· ${(j.elapsedMs / 1000).toFixed(1)} s` : ""}
                </div>
              </td>
              <td style={{ width: 70 }}>{(j.status === "running" || j.status === "queued") && <button onClick={() => api.cancelJob(j.id)}>{t("Cancel")}</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Modal>
  );
}

function AuthOptions({ s, up }: { s: Settings; up: (f: (x: Settings) => void) => void }) {
  const [cred, setCred] = useState({ host: "", user: "", domain: "", password: "" });
  const [saved, setSaved] = useState<string | null>(null);
  return (
    <>
      <label className="f-check strong">
        <input type="checkbox" checked={s.auth.enabled} onChange={(e) => up((x) => (x.auth.enabled = e.target.checked))} /> {t("Enable Automatic Authentication")}
      </label>
      <p className="muted small">
        {t(
          "Quena answers 401/407 challenges (Negotiate/Kerberos, NTLM, Basic) with your credentials so you don't log in on every request. An authenticated connection is pinned to one client and never shared. Default off.",
        )}
      </p>
      <div className="f-row">
        <span>{t("Only for hosts")}</span>
        <input placeholder={t("empty = all; e.g. *.corp.example.com; sharepoint.corp")} value={s.auth.hosts} onChange={(e) => up((x) => (x.auth.hosts = e.target.value))} />
      </div>
      <label className="f-check">
        <input type="checkbox" checked={s.auth.upstream} onChange={(e) => up((x) => (x.auth.upstream = e.target.checked))} /> {t("Also authenticate to the upstream proxy (407)")}
      </label>
      <label className="f-check">
        <input type="checkbox" checked={s.auth.useCurrentIdentity} onChange={(e) => up((x) => (x.auth.useCurrentIdentity = e.target.checked))} /> {t("Use current OS identity for SSO (Kerberos) when available")}
      </label>
      <div className="f-row">
        <span>{t("Scheme order")}</span>
        <input value={s.auth.prefer} onChange={(e) => up((x) => (x.auth.prefer = e.target.value))} />
      </div>
      <fieldset className="f-section">
        <legend>{t("Credentials (passwords stored in {store})", { store: osNames.secrets })}</legend>
        {s.auth.credentials.length === 0 && <div className="muted small">{t("No credentials configured. Kerberos SSO needs none.")}</div>}
        <table className="kv">
          <tbody>
            {s.auth.credentials.map((c) => (
              <tr key={c.host}>
                <td className="mono">{c.host}</td>
                <td className="mono">{c.domain ? `${c.domain}\\${c.user}` : c.user}</td>
                <td>{c.hasPassword ? t("password stored") : t("SSO / no password")}</td>
                <td style={{ width: 60 }}>
                  <button
                    onClick={async () => {
                      await api.authRemoveCredential(c.host);
                      up((x) => (x.auth.credentials = x.auth.credentials.filter((y) => y.host !== c.host)));
                    }}
                  >
                    {t("Remove")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="f-grid2">
          <input placeholder={t("Host or realm (* = default)")} value={cred.host} onChange={(e) => setCred({ ...cred, host: e.target.value })} />
          <input placeholder={t("Domain (optional)")} value={cred.domain} onChange={(e) => setCred({ ...cred, domain: e.target.value })} />
          <input placeholder={t("User")} value={cred.user} onChange={(e) => setCred({ ...cred, user: e.target.value })} />
          <input type="password" placeholder={t("Password (blank = SSO)")} value={cred.password} onChange={(e) => setCred({ ...cred, password: e.target.value })} />
        </div>
        <div className="btn-row">
          <button
            className="primary"
            disabled={!cred.host || !cred.user}
            onClick={async () => {
              await api.authSetCredential(cred.host, cred.user, cred.domain, cred.password || null);
              up((x) => {
                const cref = { host: cred.host, user: cred.user, domain: cred.domain, hasPassword: !!cred.password };
                const i = x.auth.credentials.findIndex((y) => y.host.toLowerCase() === cred.host.toLowerCase());
                if (i >= 0) x.auth.credentials[i] = cref;
                else x.auth.credentials.push(cref);
              });
              setSaved(cred.host);
              setCred({ host: "", user: "", domain: "", password: "" });
            }}
          >
            {t("Add / update")}
          </button>
          {saved && <span className="muted small">{t("Saved for {host}", { host: saved })}</span>}
        </div>
      </fieldset>
    </>
  );
}

function OptionsDialog() {
  const [s, setS] = useState<Settings | null>(get().settings);
  const [tab, setTab] = useState<"general" | "connections" | "https" | "auth" | "bodies">("general");
  if (!s) return null;
  const up = (f: (x: Settings) => void) => {
    const n = structuredClone(s);
    f(n);
    setS(n);
  };
  const save = async () => {
    try {
      await api.settingsSet(s);
      set({ settings: s, dialog: null });
      say(t("Settings saved"));
    } catch (e) {
      say(String(e), "error");
    }
  };
  return (
    <Modal
      title={t("Options")}
      onClose={close}
      wide
      footer={
        <>
          <button onClick={close}>{t("Cancel")}</button>
          <button className="primary" onClick={save}>
            OK
          </button>
        </>
      }
    >
      <div className="tabs-row">
        {(["general", "connections", "https", "auth", "bodies"] as const).map((k) => (
          <div key={k} className={`insp-tab ${tab === k ? "active" : ""}`} onClick={() => setTab(k)}>
            {{ general: t("General"), connections: t("Connections"), https: "HTTPS", auth: t("Authentication"), bodies: t("Bodies & Storage") }[k]}
          </div>
        ))}
      </div>
      <div className="opt-body">
        {tab === "general" && (
          <>
            <LayoutChoice />
            <ThemeChoice />
            <LanguageChoice />
            <RememberViewsOption />
            <label className="f-check">
              <input type="checkbox" checked={s.proxy.captureOnStartup} onChange={(e) => up((x) => (x.proxy.captureOnStartup = e.target.checked))} /> {t("Capture traffic on startup")}
            </label>
            <label className="f-check">
              <input type="checkbox" checked={s.stream} onChange={(e) => up((x) => (x.stream = e.target.checked))} /> {t("Stream responses (instead of buffering)")}
            </label>
            <label className="f-check">
              <input type="checkbox" checked={s.decode} onChange={(e) => up((x) => (x.decode = e.target.checked))} /> {t("Decode compressed bodies in inspectors")}
            </label>
            <label className="f-check">
              <input type="checkbox" checked={s.keepCaptures} onChange={(e) => up((x) => (x.keepCaptures = e.target.checked))} /> {t("Keep capture data after exit")}
            </label>
            <label className="f-check">
              <input type="checkbox" checked={s.offerRecovery !== false} onChange={(e) => up((x) => (x.offerRecovery = e.target.checked))} /> {t("Offer to recover sessions after a crash")}
            </label>
          </>
        )}
        {tab === "connections" && (
          <>
            <div className="f-row">
              <span>{t("Listen port")}</span>
              <input type="number" value={s.proxy.port} onChange={(e) => up((x) => (x.proxy.port = Number(e.target.value)))} />
            </div>
            <label className="f-check">
              <input type="checkbox" checked={s.proxy.actAsSystemProxy} onChange={(e) => up((x) => (x.proxy.actAsSystemProxy = e.target.checked))} /> {t("Act as system proxy while capturing")}
            </label>
            <label className="f-check">
              <input type="checkbox" checked={s.proxy.allowRemote} onChange={(e) => up((x) => (x.proxy.allowRemote = e.target.checked))} /> {t("Allow remote computers to connect")}
            </label>
            <div className="f-row">
              <span>{t("Allowed remote networks")}</span>
              <input placeholder={t("empty = local subnets; e.g. 192.168.1.0/24; 10.0.0.5")} value={s.proxy.remoteAllowlist} onChange={(e) => up((x) => (x.proxy.remoteAllowlist = e.target.value))} />
            </div>
            <label className="f-check">
              <input type="checkbox" checked={s.proxy.useSystemUpstream} onChange={(e) => up((x) => (x.proxy.useSystemUpstream = e.target.checked))} /> {t("Chain to the previous system proxy (upstream gateway)")}
            </label>
            <div className="f-row">
              <span>{t("Manual upstream proxy")}</span>
              <input placeholder="host:port" value={s.proxy.manualUpstream} onChange={(e) => up((x) => (x.proxy.manualUpstream = e.target.value))} />
            </div>
            <div className="f-row">
              <span>{t("Bypass upstream for")}</span>
              <input value={s.proxy.upstreamBypass} onChange={(e) => up((x) => (x.proxy.upstreamBypass = e.target.value))} />
            </div>
            <label className="f-check">
              <input type="checkbox" checked={s.proxy.useSystemPac} onChange={(e) => up((x) => (x.proxy.useSystemPac = e.target.checked))} /> {t("Use the system proxy auto-config (PAC) script")}
            </label>
            <div className="f-row">
              <span>{t("PAC URL or file")}</span>
              <input placeholder={t("empty = use system PAC; or http://…/proxy.pac, file path")} value={s.proxy.pacUrl} onChange={(e) => up((x) => (x.proxy.pacUrl = e.target.value))} />
            </div>
            <div className="f-sep">{t("Bandwidth simulation")}</div>
            <div className="f-row">
              <span>{t("Throttle (kbit/s)")}</span>
              <input type="number" min={0} placeholder={t("0 = unlimited")} value={s.throttleKbps} onChange={(e) => up((x) => (x.throttleKbps = Math.max(0, Number(e.target.value))))} />
            </div>
            <div className="f-row">
              <span>{t("Added latency (ms)")}</span>
              <input type="number" min={0} value={s.throttleLatencyMs} onChange={(e) => up((x) => (x.throttleLatencyMs = Math.max(0, Number(e.target.value))))} />
            </div>
          </>
        )}
        {tab === "https" && (
          <>
            <label className="f-check">
              <input type="checkbox" checked={s.https.decrypt} onChange={(e) => up((x) => (x.https.decrypt = e.target.checked))} /> {t("Decrypt HTTPS traffic")}
            </label>
            <div className="f-row">
              <span>{t("Decrypt traffic from")}</span>
              <select value={s.https.scope} onChange={(e) => up((x) => (x.https.scope = e.target.value as Settings["https"]["scope"]))}>
                <option value="all">{t("…all processes")}</option>
                <option value="browsers">{t("…browsers only")}</option>
                <option value="nonBrowsers">{t("…non-browsers only")}</option>
                <option value="remote">{t("…remote clients only")}</option>
              </select>
            </div>
            <div className="f-row">
              <span>{t("Skip decryption for")}</span>
              <input placeholder="*.bank.example; login.live.com" value={s.https.skipDecryption} onChange={(e) => up((x) => (x.https.skipDecryption = e.target.value))} />
            </div>
            <label className="f-check">
              <input type="checkbox" checked={s.https.ignoreCertErrors} onChange={(e) => up((x) => (x.https.ignoreCertErrors = e.target.checked))} /> {t("Ignore server certificate errors (unsafe)")}
            </label>
            <div className="f-row">
              <span>{t("Ignore certificate errors for")}</span>
              <input value={s.https.ignoreCertErrorsHosts} onChange={(e) => up((x) => (x.https.ignoreCertErrorsHosts = e.target.value))} />
            </div>
            <label className="f-check">
              <input type="checkbox" checked={s.https.enableHttp2} onChange={(e) => up((x) => (x.https.enableHttp2 = e.target.checked))} /> {t("Enable HTTP/2")}
            </label>
            <div className="f-row">
              <span>{t("Downgrade to HTTP/1.1 for")}</span>
              <input value={s.https.http2DowngradeHosts} onChange={(e) => up((x) => (x.https.http2DowngradeHosts = e.target.value))} />
            </div>
            <p>
              <button onClick={() => set({ dialog: { kind: "https" } })}>{t("Certificate management…")}</button>
            </p>
          </>
        )}
        {tab === "auth" && <AuthOptions s={s} up={up} />}
        {tab === "bodies" && (
          <>
            <div className="f-row">
              <span>{t("Keep bodies in memory up to (KB)")}</span>
              <input type="number" value={s.bodies.inlineLimitKb} onChange={(e) => up((x) => (x.bodies.inlineLimitKb = Number(e.target.value)))} />
            </div>
            <div className="f-row">
              <span>{t("Record at most per body (MB)")}</span>
              <input type="number" value={s.bodies.maxRecordedBodyMb} onChange={(e) => up((x) => (x.bodies.maxRecordedBodyMb = Number(e.target.value)))} />
            </div>
            <div className="f-row">
              <span>{t("Storage quota (GB)")}</span>
              <input type="number" value={s.bodies.quotaGb} onChange={(e) => up((x) => (x.bodies.quotaGb = Number(e.target.value)))} />
            </div>
            <div className="f-row">
              <span>{t("Stop recording below free space (GB)")}</span>
              <input type="number" value={s.bodies.minFreeSpaceGb} onChange={(e) => up((x) => (x.bodies.minFreeSpaceGb = Number(e.target.value)))} />
            </div>
            <div className="f-row">
              <span>{t("Max decoded size (GB)")}</span>
              <input type="number" value={s.bodies.maxDerivedGb} onChange={(e) => up((x) => (x.bodies.maxDerivedGb = Number(e.target.value)))} />
            </div>
            <div className="f-row">
              <span>{t("Max decompression ratio")}</span>
              <input type="number" value={s.bodies.maxRatio} onChange={(e) => up((x) => (x.bodies.maxRatio = Number(e.target.value)))} />
            </div>
            <div className="f-row">
              <span>{t("Headers only for hosts")}</span>
              <input value={s.headersOnlyHosts} onChange={(e) => up((x) => (x.headersOnlyHosts = e.target.value))} />
            </div>
            <div className="f-row">
              <span>{t("Headers only for content types")}</span>
              <input placeholder="video/; audio/" value={s.headersOnlyTypes} onChange={(e) => up((x) => (x.headersOnlyTypes = e.target.value))} />
            </div>
            <label className="f-check">
              <input type="checkbox" checked={s.losslessRecording} onChange={(e) => up((x) => (x.losslessRecording = e.target.checked))} /> {t("Lossless recording (forwarding waits for the disk)")}
            </label>
          </>
        )}
      </div>
    </Modal>
  );
}

function AboutDialog() {
  const [info, setInfo] = useState<{ version: string; dataDir: string; captureDir: string } | null>(null);
  useEffect(() => {
    api.appInfo().then(setInfo);
  }, []);
  return (
    <Modal title={t("About Quena")} onClose={close}>
      <p>
        <b>Quena</b> {info?.version} – {t("easy-to-use, fast HTTP(S) debugging proxy.")}
      </p>
      <p className="muted small">{t("Data: {dir}", { dir: info?.dataDir ?? "" })}</p>
      <p className="muted small">{t("Capture: {dir}", { dir: info?.captureDir ?? "" })}</p>
    </Modal>
  );
}

function TextDialog({ title, text }: { title: string; text: string }) {
  return (
    <Modal title={title} onClose={close} wide footer={<button onClick={() => navigator.clipboard.writeText(text)}>{t("Copy")}</button>}>
      <pre className="help-pre">{text}</pre>
    </Modal>
  );
}

/** Layout preset picker (Settings → General and the first-run dialog). Applies immediately. */
function ThemeChoice() {
  const theme = useStore((st) => st.layout.theme ?? "system");
  const pick = (t: "system" | "light" | "dark") => {
    set((st) => ({ layout: { ...st.layout, theme: t } }));
    actions.saveLayout();
  };
  return (
    <div className="f-row layout-choice">
      <span>{t("Theme")}</span>
      <div className="f-inline">
        {(["system", "light", "dark"] as const).map((k) => (
          <label key={k} className="f-check">
            <input type="radio" name="theme" checked={theme === k} onChange={() => pick(k)} /> {k === "system" ? t("Like the system") : k === "light" ? t("Light") : t("Dark")}
          </label>
        ))}
      </div>
    </div>
  );
}

/** UI language (Settings → General). Switching saves the choice and reloads the UI. */
function LanguageChoice() {
  const pref = useStore((st) => st.layout.language ?? "system");
  const pick = async (l: "system" | "en" | "de") => {
    const before = get().layout.language;
    set((st) => ({ layout: { ...st.layout, language: l } }));
    try {
      await api.saveUiPrefs({ layout: get().layout });
    } catch (e) {
      // Not saved: keep the old language everywhere (UI and native menu).
      set((st) => ({ layout: { ...st.layout, language: before } }));
      say(String(e), "error");
      return;
    }
    const lang = await api.setLanguage(l).catch(() => currentLang());
    if (lang !== currentLang()) location.reload();
  };
  return (
    <div className="f-row layout-choice">
      <span>{t("Language")}</span>
      <div className="f-inline">
        {(["system", "en", "de"] as const).map((l) => (
          <label key={l} className="f-check">
            <input type="radio" name="language" checked={pref === l} onChange={() => void pick(l)} /> {l === "system" ? t("Like the system") : l === "en" ? "English" : "Deutsch"}
          </label>
        ))}
      </div>
    </div>
  );
}

/** Remember the inspector view per kind of content (Settings → General). */
function RememberViewsOption() {
  const on = useStore((st) => st.layout.rememberViews ?? true);
  const count = useStore((st) => Object.keys(st.layout.viewByType ?? {}).length);
  const update = (patch: { rememberViews?: boolean; viewByType?: Record<string, string> }) => {
    set((st) => ({ layout: { ...st.layout, ...patch } }));
    actions.saveLayout();
  };
  return (
    <div className="f-row layout-choice">
      <span>{t("Inspector views")}</span>
      <div className="layout-options">
        <label className="f-check">
          <input type="checkbox" checked={on} onChange={(e) => update({ rememberViews: e.target.checked })} />{" "}
          {t("Remember the chosen view for each kind of content, separately for request and response (e.g. SOAP → XML, JSON → Body)")}
        </label>
        {on && (
          <div className="muted small">
            {count ? `${t("{n} remembered", { n: count })} · ` : `${t("Until you pick one, Quena opens the view that fits the content.")} `}
            {count > 0 && (
              <button className="linklike" onClick={() => update({ viewByType: {} })}>
                {t("Forget remembered views")}
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function LayoutChoice() {
  const preset = useStore((st) => st.layout.preset);
  return (
    <div className="f-row layout-choice">
      <span>{t("Layout")}</span>
      <div className="layout-options">
        <label className="f-check">
          <input type="radio" name="layout-preset" checked={preset === "quena"} onChange={() => actions.applyLayoutPreset("quena")} /> {t("Quena — list left, request and response side by side")}
        </label>
        <label className="f-check">
          <input type="radio" name="layout-preset" checked={preset === "classic"} onChange={() => actions.applyLayoutPreset("classic")} /> {t("Classic — dense list, request above response, more columns")}
        </label>
      </div>
    </div>
  );
}

function ChooseLayoutDialog() {
  const pick = (p: "quena" | "classic") => {
    actions.applyLayoutPreset(p);
    close();
  };
  return (
    <Modal title={t("Choose a layout")} onClose={() => pick(get().layout.preset)}>
      <p className="muted">{t("You can change this any time in Settings → General or with View → Request Above / Beside Response.")}</p>
      <div className="layout-cards">
        <button className="layout-card" onClick={() => pick("quena")}>
          <b>Quena</b>
          <span>{t("Session list on the left, request and response side by side. Rows coloured by outcome.")}</span>
        </button>
        <button className="layout-card" onClick={() => pick("classic")}>
          <b>{t("Classic")}</b>
          <span>{t("Dense session list with more columns, request above response. For long-time proxy users.")}</span>
        </button>
      </div>
    </Modal>
  );
}

export function Dialogs() {
  const d = useStore((s) => s.dialog);
  const prevFocus = useRef<Element | null>(null);
  useEffect(() => {
    if (d) prevFocus.current = document.activeElement;
    else (prevFocus.current as HTMLElement | null)?.focus?.();
  }, [d]);
  if (!d) return null;
  // A dialog that throws while rendering must not take the window down.
  return (
    <ErrorBoundary
      name={`dialog ${d.kind}`}
      resetKey={d}
      fallback={(e, reset) => (
        <Modal title={t("Dialog failed")} onClose={close}>
          <div className="view-error">
            <div>{t("This view failed: {error}", { error: e.message || e.name })}</div>
            <button onClick={reset}>{t("Retry")}</button>
          </div>
        </Modal>
      )}
    >
      <Suspense fallback={null}>
        <DialogBody d={d} />
      </Suspense>
    </ErrorBoundary>
  );
}

function DialogBody({ d }: { d: Dialog }) {
  switch (d.kind) {
    case "confirm":
      return <ConfirmDialog key="confirm" title={d.title} message={d.message} confirm={d.confirm} resolve={d.resolve} />;
    case "prompt":
      return <PromptDialog title={d.title} label={d.label} initial={d.initial} resolve={d.resolve} />;
    case "comment":
      return <CommentDialog ids={d.ids} initial={d.initial} />;
    case "help":
      return <HelpDialog topic={d.topic} />;
    case "recover":
      return <RecoverDialog />;
    case "jobs":
      return <JobsDialog />;
    case "options":
      return <OptionsDialog />;
    case "about":
      return <AboutDialog />;
    case "text":
      return <TextDialog title={d.title} text={d.text} />;
    case "find":
      return (
        <Modal title={t("Find Sessions")} onClose={close}>
          <FindDialog onDone={close} />
        </Modal>
      );
    case "textwizard":
      return (
        <Modal title={t("Text Tools")} onClose={close} wide>
          <TextWizard initial={d.text} />
        </Modal>
      );
    case "compare":
      return (
        <Modal title={t("Compare {a} ↔ {b}", { a: d.titleA, b: d.titleB })} onClose={close} wide>
          <CompareView a={d.a} b={d.b} />
        </Modal>
      );
    case "connect-device":
      return (
        <Modal title={t("Connect Device")} onClose={close} wide>
          <DeviceAssistant />
        </Modal>
      );
    case "https":
      return (
        <Modal title="HTTPS" onClose={close} wide>
          <HttpsPanel />
        </Modal>
      );
    case "plugins":
      return (
        <Modal title={t("Plugins")} onClose={close} wide>
          <PluginsPanel />
        </Modal>
      );
    case "choose-layout":
      return <ChooseLayoutDialog />;
    case "palette":
      return <CommandPalette />;
    case "rules":
      return (
        <Modal title={t("Rules Script")} onClose={close} wide>
          <RulesEditor />
        </Modal>
      );
    case "mocks":
      return (
        <Modal title={t("Mocks from Sessions")} onClose={close} wide>
          <MocksDialog selected={d.selected} target={d.target} onDone={close} />
        </Modal>
      );
    case "sanitize":
      return (
        <Modal title={t("Sanitized Export")} onClose={close} wide>
          <SanitizeDialog selected={d.selected} scope={d.scope} onClose={close} />
        </Modal>
      );
    case "sanitize-result":
      return (
        <Modal title={t("Sanitized Export: Redaction Log")} onClose={close} wide>
          <SanitizeResult result={d.result} onClose={close} />
        </Modal>
      );
  }
}
