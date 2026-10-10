import { LibraryPanel } from "./LibraryPanel";
import { lazy, Suspense, useEffect, useRef, useState } from "react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { api, type CacheAdvice, type CacheStatus, type LlmPricesInfo, type McpStatus, type Recoverable, type SchemaStatus, type Settings } from "../api";
import { actions } from "../actions";
import { fmtBytes, fmtDateTime, isMac, modKey, osNames } from "../lib/format";
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
const ReverseProxyPanel = lazy(() => import("./ReverseProxyDialog").then((m) => ({ default: m.ReverseProxyPanel })));
const LaunchPanel = lazy(() => import("./LaunchDialog").then((m) => ({ default: m.LaunchPanel })));
const HostRemapPanel = lazy(() => import("./HostRemapDialog").then((m) => ({ default: m.HostRemapPanel })));
const CaptureDiffPanel = lazy(() => import("./CaptureDiffDialog").then((m) => ({ default: m.CaptureDiffPanel })));
const RewriteEditor = lazy(() => import("../panels/RewriteEditor").then((m) => ({ default: m.RewriteEditor })));
const RewriteApply = lazy(() => import("../panels/RewriteEditor").then((m) => ({ default: m.RewriteApply })));
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

function PromptDialog({ title, label, initial, secret, resolve }: { title: string; label: string; initial: string; secret?: boolean; resolve: (v: string | null) => void }) {
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
        <input
          autoFocus
          type={secret ? "password" : "text"}
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
          value={v}
          onChange={(e) => setV(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && done(v)}
        />
      </div>
    </Modal>
  );
}

/** Advanced replay: how often, one after the other or N at a time. */
function ReplayDialog({ ids }: { ids: number[] }) {
  const [count, setCount] = useState("10");
  const [mode, setMode] = useState<"sequential" | "parallel">("sequential");
  const [parallel, setParallel] = useState("5");
  const [unconditional, setUnconditional] = useState(false);
  const n = Math.max(1, Math.min(100000, Math.floor(Number(count)) || 1));
  const p = Math.max(1, Math.min(100, Math.floor(Number(parallel)) || 1));
  const go = () => {
    close();
    void import("../replay").then((m) => m.startReplay(ids, { count: n, unconditional, sequential: mode === "sequential", parallel: mode === "parallel" ? p : 0 }));
  };
  return (
    <Modal
      title={t("Advanced Replay")}
      onClose={close}
      footer={
        <>
          <button onClick={close}>{t("Cancel")}</button>
          <button className="primary" onClick={go}>
            {t("Replay")}
          </button>
        </>
      }
    >
      <p className="muted small">{plural(ids.length, "{n} selected request", "{n} selected requests")}</p>
      <div className="f-row">
        <span>{t("Times each (up to 100,000)")}</span>
        <input autoFocus type="number" min={1} max={100000} value={count} onChange={(e) => setCount(e.target.value)} onKeyDown={(e) => e.key === "Enter" && go()} />
      </div>
      <label className="f-check">
        <input type="radio" checked={mode === "sequential"} onChange={() => setMode("sequential")} /> {t("One after the other")}
      </label>
      <label className="f-check">
        <input type="radio" checked={mode === "parallel"} onChange={() => setMode("parallel")} /> {t("In parallel, at most")}{" "}
        <input type="number" className="num-small" min={1} max={100} value={parallel} onChange={(e) => setParallel(e.target.value)} disabled={mode !== "parallel"} /> {t("at a time")}
      </label>
      <label className="f-check">
        <input type="checkbox" checked={unconditional} onChange={(e) => setUnconditional(e.target.checked)} /> {t("Unconditionally (without If-None-Match / If-Modified-Since)")}
      </label>
      <p className="muted small">{t("{n} requests in all; Stop in the message or Replay → Stop Replay ends it.", { n: (n * ids.length).toLocaleString() })}</p>
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

/** Before an import into a non-empty list: remove or keep its sessions (Esc cancels). */
function ImportExistingDialog({ total, what, resolve }: { total: number; what: string; resolve: (a: { choice: "remove" | "keep"; remember: boolean } | null) => void }) {
  const answered = useRef(false);
  const [remember, setRemember] = useState(false);
  const done = (choice: "remove" | "keep" | null) => {
    if (answered.current) return;
    answered.current = true;
    close();
    resolve(choice && { choice, remember });
  };
  // Closed another way (Esc is handled globally): cancelled.
  useEffect(
    () => () => {
      if (!answered.current) {
        answered.current = true;
        resolve(null);
      }
    },
    [resolve],
  );
  return (
    <Modal
      title={t("Load {what}", { what })}
      onClose={() => done(null)}
      footer={
        <>
          <button onClick={() => done(null)}>{t("Cancel")}</button>
          <button onClick={() => done("keep")}>{t("Keep and load")}</button>
          <button className="primary" autoFocus onClick={() => done("remove")}>
            {t("Remove and load")}
          </button>
        </>
      }
    >
      <p className="confirm-text">
        {plural(total, "The list holds {n} session. Remove it, so that only the import is in the list?", "The list holds {n} sessions. Remove them, so that only the import is in the list?")}
      </p>
      <p className="muted small">{t("Capturing stops for the import.")}</p>
      <label className="f-check">
        <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} /> {t("Don't ask again (Settings → General)")}
      </label>
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
    ["bpllm [cond]", t("break before LLM requests: * any; model=claude tool=mcp__jira__* tokens=50k; without: off")],
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
  [`${modKey}${isMac ? "⌥" : "Alt+"}N`, t("Navigator: groups or structure")],
  ["Alt+1…5", t("Inspector: Headers, Body, Cookies, Auth, Raw (grouped views)")],
  ["Alt+← / Alt+→", t("Inspector: previous / next view")],
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

/** MCP server: lets AI agents (Claude Code …) read and, if allowed, control Quena. */
/** Settings → General → AutoSave. */
function AutoSaveOptions({ s, up }: { s: Settings; up: (f: (x: Settings) => void) => void }) {
  const a = s.autosave ?? { enabled: false, intervalMin: 10, folder: "", keep: 10, onlyVisible: false };
  const set = (p: Partial<typeof a>) => up((x) => (x.autosave = { ...a, ...p }));
  return (
    <div className="autosave">
      <label className="f-check">
        <input type="checkbox" checked={a.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> {t("AutoSave the sessions every")}{" "}
        <input type="number" className="num-small" min={1} max={1440} value={a.intervalMin} onChange={(e) => set({ intervalMin: Math.max(1, Number(e.target.value) || 10) })} /> {t("minutes (when something changed), keep the last")}{" "}
        <input type="number" className="num-small" min={1} max={1000} value={a.keep} onChange={(e) => set({ keep: Math.max(1, Number(e.target.value) || 10) })} /> {t("archives")}
      </label>
      <label className="f-check">
        <input type="checkbox" checked={!!a.onlyVisible} disabled={!a.enabled} onChange={(e) => set({ onlyVisible: e.target.checked })} /> {t("Only the sessions the filters show")}
      </label>
      <div className="f-inline small">
        <span className="muted mono pb-path" title={a.folder}>
          {a.folder || t("autosave folder in the data folder")}
        </span>
        <button
          onClick={async () => {
            const p = await openDialog({ directory: true, multiple: false });
            if (typeof p === "string") set({ folder: p });
          }}
        >
          {t("Choose folder…")}
        </button>
        {a.folder && (
          <button className="linklike" onClick={() => set({ folder: "" })}>
            {t("Default")}
          </button>
        )}
        <button className="linklike" onClick={() => void api.autosaveReveal().catch((e) => say(String(e), "error"))}>
          {t("Open folder")}
        </button>
        <button
          className="linklike"
          onClick={async () => {
            try {
              const p = await api.autosaveNow();
              say(p ? t("Saving to {path}", { path: p }) : t("There are no sessions to save"));
            } catch (e) {
              say(String(e), "error");
            }
          }}
        >
          {t("Save now")}
        </button>
      </div>
    </div>
  );
}

/** Settings → Bodies & Storage → Agent cache: LLM answers Quena serves again. */
function AgentCacheOptions() {
  const [st, setSt] = useState<CacheStatus | null>(null);
  const [advice, setAdvice] = useState<CacheAdvice[]>([]);
  const load = () => {
    api.llmCacheStatus().then(setSt, () => setSt(null));
    api.llmCacheAdvice().then(setAdvice, () => setAdvice([]));
  };
  useEffect(load, []);
  const run = (p: Promise<CacheStatus>) =>
    p.then(
      (s) => {
        setSt(s);
        api.llmCacheAdvice().then(setAdvice, () => setAdvice([]));
      },
      (e) => say(String(e), "error"),
    );
  if (!st) return null;
  const usd = (n: number) => `$${n.toFixed(n < 1 ? 4 : 2)}`;
  return (
    <fieldset className="f-section">
      <legend>{t("Agent cache")}</legend>
      <p className="muted small">{t("Answers of LLM API calls Quena serves again for the same request (URL and JSON body), so an agent or app under development does not pay or wait twice. Cache single calls in the LLM view.")}</p>
      <label className="f-check">
        <input type="checkbox" checked={st.auto} onChange={(e) => void run(api.llmCacheAuto(e.target.checked))} /> {t("Cache every LLM call")}
      </label>
      <div className="small">
        {t("{n} cached answer(s), {hits} hit(s): {tokens} tokens, ≈ {usd} and {s} s saved", { n: st.entries.length, hits: st.hits, tokens: st.savedTokens, usd: usd(st.savedUsd), s: Math.round(st.savedMs / 1000) })}
      </div>
      {st.entries.length > 0 && (
        <div className="cache-list">
          {st.entries.slice(0, 50).map((e) => (
            <div key={e.key} className="pb-path-row small">
              <span className="mono pb-path" title={e.url}>
                {e.model || "?"} · #{e.source} · {t("{n} hit(s)", { n: e.hits })}
              </span>
              <button className="linklike" onClick={() => actions.selectIds([e.source])}>
                {t("Show")}
              </button>
              <button className="cc-del" title={t("Remove")} onClick={() => void run(api.llmCacheRemove(e.key))}>
                ✕
              </button>
            </div>
          ))}
          <button className="linklike" onClick={() => void run(api.llmCacheRemove())}>
            {t("Remove all")}
          </button>
        </div>
      )}
      {advice.length > 0 && (
        <div className="small">
          <b>{t("Asked more than once (worth caching):")}</b>
          {advice.slice(0, 10).map((a) => (
            <div key={a.sessions.join(",")} className="pb-path-row">
              <span className="mono pb-path" title={a.url}>
                {a.model} · {t("{n}×", { n: a.sessions.length })} · {t("{tokens} tokens, ≈ {usd} for the repeats", { tokens: a.repeatTokens, usd: usd(a.repeatUsd) })}
              </span>
              <button className="linklike" onClick={() => void api.llmCacheSet(a.sessions[0], true).then(load, (e) => say(String(e), "error"))}>
                {t("Cache")}
              </button>
            </div>
          ))}
        </div>
      )}
    </fieldset>
  );
}

/** Settings → Bodies & Storage → LLM prices: own ones, a list fetched on request, built-in. */
function LlmPriceOptions() {
  const [info, setInfo] = useState<LlmPricesInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const load = () => api.llmPricesInfo().then(setInfo, () => setInfo(null));
  useEffect(() => {
    void load();
  }, []);
  const run = async (f: () => Promise<LlmPricesInfo>, done?: (i: LlmPricesInfo) => string) => {
    setBusy(true);
    try {
      const i = await f();
      setInfo(i);
      if (done) say(done(i));
    } catch (e) {
      say(String(e), "error");
    } finally {
      setBusy(false);
    }
  };
  if (!info) return null;
  const date = info.fetchedAt ? new Date(info.fetchedAt * 1000).toLocaleDateString() : null;
  return (
    <fieldset className="f-section">
      <legend>{t("LLM prices")}</legend>
      <p className="muted small">{t("Costs of LLM calls are estimated with your own prices first, then the fetched price list, then the built-in list prices.")}</p>
      <div className="f-inline small">
        <span>
          {t("Own prices")}: {info.exists ? t("{n} model(s)", { n: info.custom }) : t("none")}
        </span>
        <button className="linklike" onClick={() => void api.llmPricesOpen().then(load, (e) => say(String(e), "error"))}>
          {info.exists ? t("Edit llm-prices.json") : t("Create llm-prices.json")}
        </button>
        <button className="linklike" onClick={() => void load()}>
          {t("Check again")}
        </button>
      </div>
      {info.customError && <p className="err small">{t("llm-prices.json cannot be read, its prices are not used: {error}", { error: info.customError })}</p>}
      <div className="f-inline small">
        <span>{date ? t("Price list: {n} models, fetched {date}", { n: info.fetched, date }) : t("Price list: not fetched (built-in: {n} models)", { n: info.builtIn })}</span>
        <button
          disabled={busy}
          title={t("Downloads {url} (LiteLLM, MIT licence) through Quena's upstream settings. Nothing else is sent, and only when clicked.", { url: info.source })}
          onClick={() => void run(api.llmPricesUpdate, (i) => t("Fetched prices of {n} models", { n: i.fetched }))}
        >
          {busy ? t("Fetching…") : date ? t("Update prices") : t("Fetch prices")}
        </button>
        {date && (
          <button className="linklike" disabled={busy} onClick={() => void run(api.llmPricesForget)}>
            {t("Remove list")}
          </button>
        )}
      </div>
    </fieldset>
  );
}

/** Settings → Bodies & Storage → Protobuf schemas. */
function ProtobufOptions({ s, up }: { s: Settings; up: (f: (x: Settings) => void) => void }) {
  const [status, setStatus] = useState<SchemaStatus | null>(null);
  const saved = useStore((st) => st.settings?.protobuf);
  useEffect(() => {
    api.protobufStatus().then(setStatus, () => setStatus(null));
  }, [saved]);
  const pb = s.protobuf ?? { protoPaths: [], includePaths: [], reflection: false };
  const add = async (directory: boolean) => {
    const p = await openDialog(directory ? { directory: true, multiple: true } : { multiple: true, filters: [{ name: "Protocol Buffers", extensions: ["proto"] }] });
    const picked = Array.isArray(p) ? p : typeof p === "string" ? [p] : [];
    if (picked.length) up((x) => (x.protobuf = { ...pb, protoPaths: [...new Set([...pb.protoPaths, ...picked])] }));
  };
  const plain = { spellCheck: false, autoCorrect: "off", autoCapitalize: "off" } as const;
  return (
    <fieldset className="f-section">
      <legend>{t("Protobuf schemas")}</legend>
      <p className="muted small">{t("With .proto files the gRPC and protobuf view shows field names, types and enum values instead of field numbers. Folders are searched for .proto files; imports are resolved against them and the import paths.")}</p>
      {pb.protoPaths.map((p) => (
        <div key={p} className="pb-path-row">
          <span className="mono small pb-path" title={p}>
            {p}
          </span>
          <button className="cc-del" title={t("Remove")} onClick={() => up((x) => (x.protobuf = { ...pb, protoPaths: pb.protoPaths.filter((q) => q !== p) }))}>
            ✕
          </button>
        </div>
      ))}
      <div className="f-inline">
        <button onClick={() => void add(false)}>{t("Add .proto files…")}</button>
        <button onClick={() => void add(true)}>{t("Add folder…")}</button>
      </div>
      <div className="f-row">
        <span>{t("Import paths (one per line)")}</span>
        <textarea
          {...plain}
          className="mono"
          rows={2}
          value={pb.includePaths.join("\n")}
          onChange={(e) => up((x) => (x.protobuf = { ...pb, includePaths: e.target.value.split("\n") }))}
        />
      </div>
      <label className="f-check">
        <input type="checkbox" checked={pb.reflection} onChange={(e) => up((x) => (x.protobuf = { ...pb, reflection: e.target.checked }))} /> {t("Allow fetching schemas from gRPC servers (server reflection, on request in the gRPC view)")}
      </label>
      {status && (
        <p className={status.error ? "mocks-error" : "muted small"}>
          {status.error
            ? status.error
            : [
                plural(status.files, "{n} file", "{n} files"),
                plural(status.messages, "{n} message type", "{n} message types"),
                plural(status.services.length, "{n} service", "{n} services"),
                plural(status.reflected.length, "{n} schema fetched from servers", "{n} schemas fetched from servers"),
              ].join(" · ")}
        </p>
      )}
    </fieldset>
  );
}

function McpOptions({ s, up }: { s: Settings; up: (f: (x: Settings) => void) => void }) {
  const [status, setStatus] = useState<McpStatus | null>(null);
  useEffect(() => {
    api.mcpStatus().then(setStatus, () => setStatus(null));
  }, []);
  const m = s.mcp ?? { enabled: false, port: 8867, access: "readOnly", token: "", includeSecrets: false, filesDir: "" };
  const newToken = async () => {
    const token = await api.mcpNewToken();
    up((x) => (x.mcp = { ...m, ...x.mcp, token }));
  };
  const command = `claude mcp add --transport http quena http://127.0.0.1:${m.port}/mcp --header "Authorization: Bearer ${m.token}"`;
  // Clients are set up from the saved settings: not while the dialog holds other ones.
  const savedMcp = useStore((st) => st.settings?.mcp);
  const unsaved = !savedMcp || savedMcp.enabled !== m.enabled || savedMcp.port !== m.port || savedMcp.token !== m.token;
  return (
    <>
      <p className="muted small">{t("AI agents connect over the Model Context Protocol (MCP) to read sessions and, with full control, set rules and send requests. Only programs on this computer that know the token can connect.")}</p>
      <label className="f-check">
        <input
          type="checkbox"
          checked={m.enabled}
          onChange={async (e) => {
            const enabled = e.target.checked;
            const token = enabled && !m.token ? await api.mcpNewToken() : m.token;
            up((x) => (x.mcp = { ...m, enabled, token }));
          }}
        />{" "}
        {t("Enable MCP server")}
      </label>
      <div className="f-row">
        <span>{t("Port")}</span>
        <input type="number" min={1} max={65535} value={m.port} onChange={(e) => up((x) => (x.mcp = { ...m, port: Number(e.target.value) }))} />
      </div>
      <div className="f-row">
        <span>{t("Agents may")}</span>
        <select value={m.access} onChange={(e) => up((x) => (x.mcp = { ...m, access: e.target.value as "readOnly" | "full" }))}>
          <option value="readOnly">{t("…only read sessions, rules and statistics")}</option>
          <option value="full">{t("…also change rules and breakpoints, capture and send requests")}</option>
        </select>
      </div>
      <label className="f-check" title={t("Agents send what they read to their model provider. Off: Authorization, cookies, tokens and secret parameters and fields are replaced first.")}>
        <input type="checkbox" checked={m.includeSecrets} onChange={(e) => up((x) => (x.mcp = { ...m, includeSecrets: e.target.checked }))} /> {t("Show credentials and tokens to agents unredacted (unsafe)")}
      </label>
      <div className="f-row">
        <span>{t("Folder for agent files")}</span>
        <input
          className="mono"
          placeholder={t("empty = mcp-files in the data folder")}
          value={m.filesDir}
          onChange={(e) => up((x) => (x.mcp = { ...m, filesDir: e.target.value }))}
        />
        <button
          onClick={async () => {
            const p = await openDialog({ directory: true, multiple: false });
            if (typeof p === "string") up((x) => (x.mcp = { ...m, filesDir: p }));
          }}
        >
          {t("Choose folder…")}
        </button>
      </div>
      <p className="muted small">{t("Exports, .http collections and files served by mock rules: agents may only read and write files in this folder. Captured traffic is foreign content; an agent with full control could be misled by it, so grant full control only while you watch.")}</p>
      <div className="f-row">
        <span>{t("Token")}</span>
        <input readOnly className="mono" value={m.token} />
        <button onClick={() => navigator.clipboard.writeText(m.token)} disabled={!m.token}>
          {t("Copy")}
        </button>
        <button onClick={newToken}>{t("New token")}</button>
      </div>
      {m.token && (
        <div className="f-row">
          <span>{t("Claude Code")}</span>
          <input readOnly className="mono" value={command} />
          <button onClick={() => navigator.clipboard.writeText(command)}>{t("Copy")}</button>
        </div>
      )}
      {m.token && (
        <div className="f-row">
          <span>{t("Set up for")}</span>
          <div className="f-inline">
            {(
              [
                ["claudeCode", "Claude Code"],
                ["vsCode", "VS Code"],
                ["cursor", "Cursor"],
                ["codex", "Codex"],
              ] as const
            ).map(([c, name]) => (
              <button
                key={c}
                disabled={unsaved}
                title={unsaved ? t("Click OK first: the server's settings are not saved yet") : t("Writes the Quena server with its token into the user configuration of {name} (a copy of the file is kept as .bak). Click OK first so the server runs with these settings.", { name })}
                onClick={async () => {
                  try {
                    say(t("Added Quena: {where}", { where: await api.mcpSetupClient(c) }));
                  } catch (e) {
                    say(String(e), "error");
                  }
                }}
              >
                {name}
              </button>
            ))}
          </div>
        </div>
      )}
      <div className="f-row">
        <span>{t("Agent skill")}</span>
        <div className="f-inline">
          {(
            [
              ["claudeCode", "Claude Code"],
              ["codex", "Codex"],
            ] as const
          ).map(([c, name]) => (
            <button
              key={c}
              title={t("Installs a skill that tells the agent how to debug traffic with Quena's tools (failing and slow requests, diagnostics, LLM calls, mocks).")}
              onClick={async () => {
                try {
                  say(t("Skill installed: {path}", { path: await api.mcpInstallSkill(c) }));
                } catch (e) {
                  say(String(e), "error");
                }
              }}
            >
              {name}
            </button>
          ))}
        </div>
      </div>
      {status && (
        <p className="muted small">
          {status.running ? t("Running at {url}", { url: status.url ?? "" }) : status.error ? t("Not running: {error}", { error: status.error }) : t("Not running")}
        </p>
      )}
    </>
  );
}

function OptionsDialog() {
  const [s, setS] = useState<Settings | null>(get().settings);
  const [tab, setTab] = useState<"general" | "connections" | "https" | "auth" | "bodies" | "mcp">("general");
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
      if (s.mcp?.enabled) {
        const st = await api.mcpStatus().catch(() => null);
        if (st?.error) say(t("MCP server not running: {error}", { error: st.error }), "error");
      }
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
        {(["general", "connections", "https", "auth", "bodies", "mcp"] as const).map((k) => (
          <div key={k} className={`insp-tab ${tab === k ? "active" : ""}`} onClick={() => setTab(k)}>
            {{ general: t("General"), connections: t("Connections"), https: "HTTPS", auth: t("Authentication"), bodies: t("Bodies & Storage"), mcp: t("AI agents (MCP)") }[k]}
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
            <AutoSaveOptions s={s} up={up} />
            <label className="f-check">
              <input type="checkbox" checked={s.offerRecovery !== false} onChange={(e) => up((x) => (x.offerRecovery = e.target.checked))} /> {t("Offer to recover sessions after a crash")}
            </label>
            <div className="f-row">
              <span>{t("Importing into a non-empty list")}</span>
              <select value={s.importExisting ?? "ask"} onChange={(e) => up((x) => (x.importExisting = e.target.value as "ask" | "remove" | "keep"))}>
                <option value="ask">{t("Ask")}</option>
                <option value="remove">{t("Remove the sessions in the list")}</option>
                <option value="keep">{t("Keep them and add the import")}</option>
              </select>
            </div>
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
            <div className="f-row" title={t("These hosts become exceptions of the system proxy and of browsers and terminals Quena starts, so their traffic does not reach Quena; a client that sends them to Quena anyway gets them passed through without decryption.")}>
              <span>{t("Do not capture (bypass Quena)")}</span>
              <input placeholder="login.example.com; *.bank.example" value={s.proxy.bypassHosts ?? ""} onChange={(e) => up((x) => (x.proxy.bypassHosts = e.target.value))} />
            </div>
            <label className="f-check" title={t("Push, iMessage, iCloud and App Store hosts that pin their certificates and fail behind an intercepting proxy")}>
              <input type="checkbox" checked={s.proxy.bypassApple ?? isMac} onChange={(e) => up((x) => (x.proxy.bypassApple = e.target.checked))} /> {t("Also bypass Apple services that pin their certificates")}
            </label>
            <label className="f-check" title={t("The DNS domains of a VPN connected when capturing starts (e.g. the company's), so company traffic keeps its direct way")}>
              <input type="checkbox" checked={s.proxy.bypassVpn ?? false} onChange={(e) => up((x) => (x.proxy.bypassVpn = e.target.checked))} /> {t("Also bypass the domains of an active VPN")}
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
            <div className="f-row">
              <span>{t("Host remapping")}</span>
              <span>
                <button
                  onClick={async () => {
                    try {
                      await api.settingsSet(s);
                      set({ settings: s, dialog: { kind: "host-remap" } });
                    } catch (e) {
                      say(String(e), "error");
                    }
                  }}
                >
                  {t("Host Remapping…")}
                </button>{" "}
                <span className="muted small">{plural(s.hostRemap?.entries.length ?? 0, "{n} entry", "{n} entries")}</span>
              </span>
            </div>
            <div className="f-row">
              <span>{t("Reverse proxy ports")}</span>
              <span>
                <button
                  onClick={async () => {
                    // Keep what was changed here, then switch to the reverse proxy entries.
                    try {
                      await api.settingsSet(s);
                      set({ settings: s, dialog: { kind: "reverse-proxy" } });
                    } catch (e) {
                      say(String(e), "error");
                    }
                  }}
                >
                  {t("Reverse Proxy…")}
                </button>{" "}
                <span className="muted small">{plural(s.reverseProxy?.entries.length ?? 0, "{n} entry", "{n} entries")}</span>
              </span>
            </div>
            {(
              [
                ["socks", t("SOCKS5/4 port"), t("Clients that support SOCKS name their target; HTTPS is decrypted like proxied traffic.")],
                ["transparent", t("Transparent port"), t("For connections the firewall redirects here (iptables, pf): the target is the original destination, the TLS server name or the Host header.")],
              ] as const
            ).map(([key, label, hint]) => (
              <div className="f-row" key={key}>
                <span>{label}</span>
                <span className="opt-listener">
                  <label className="f-check">
                    <input type="checkbox" checked={s[key].enabled} onChange={(e) => up((x) => (x[key].enabled = e.target.checked))} /> {t("on")}
                  </label>
                  <input type="number" min={1} max={65535} value={s[key].port} onChange={(e) => up((x) => (x[key].port = Number(e.target.value)))} />
                  <label className="f-check">
                    <input type="checkbox" checked={s[key].allowRemote} onChange={(e) => up((x) => (x[key].allowRemote = e.target.checked))} /> {t("from other computers too")}
                  </label>
                  <span className="muted small" title={hint}>
                    ⓘ
                  </span>
                </span>
              </div>
            ))}
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
        {tab === "mcp" && <McpOptions s={s} up={up} />}
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
            <ProtobufOptions s={s} up={up} />
            <LlmPriceOptions />
            <AgentCacheOptions />
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
  const tabs = useStore((st) => st.layout.inspectorTabs ?? "grouped");
  const update = (patch: { rememberViews?: boolean; viewByType?: Record<string, string>; subViews?: Record<string, string>; inspectorTabs?: "grouped" | "flat" }) => {
    set((st) => ({ layout: { ...st.layout, ...patch } }));
    actions.saveLayout();
  };
  return (
    <div className="f-row layout-choice">
      <span>{t("Inspector views")}</span>
      <div className="layout-options">
        <label className="f-check">
          <input type="radio" name="insp-tabs" checked={tabs === "grouped"} onChange={() => update({ inspectorTabs: "grouped" })} />{" "}
          {t("Grouped: Headers, Body, Cookies, Auth, Raw; below them the views that fit the body")}
        </label>
        <label className="f-check">
          <input type="radio" name="insp-tabs" checked={tabs === "flat"} onChange={() => update({ inspectorTabs: "flat" })} /> {t("Flat: all views in one row")}
        </label>
        <label className="f-check">
          <input type="checkbox" checked={on} onChange={(e) => update({ rememberViews: e.target.checked })} />{" "}
          {t("Remember the chosen view for each kind of content, separately for request and response (e.g. SOAP → XML, JSON → Body)")}
        </label>
        {on && (
          <div className="muted small">
            {count ? `${t("{n} remembered", { n: count })} · ` : `${t("Until you pick one, Quena opens the view that fits the content.")} `}
            {count > 0 && (
              <button className="linklike" onClick={() => update({ viewByType: {}, subViews: {} })}>
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
          <input type="radio" name="layout-preset" checked={preset === "quena"} onChange={() => actions.applyLayoutPreset("quena")} /> {t("Quena — list left, request above response")}
        </label>
        <label className="f-check">
          <input type="radio" name="layout-preset" checked={preset === "classic"} onChange={() => actions.applyLayoutPreset("classic")} /> {t("Classic — dense list, request above response, more columns")}
        </label>
      </div>
    </div>
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
    case "import-existing":
      return <ImportExistingDialog key="import-existing" total={d.total} what={d.what} resolve={d.resolve} />;
    case "prompt":
      return <PromptDialog title={d.title} label={d.label} initial={d.initial} secret={d.secret} resolve={d.resolve} />;
    case "replay":
      return <ReplayDialog ids={d.ids} />;
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
    case "rewrite-rule":
      return (
        <Modal title={d.rule?.id ? t("Edit Rewrite Rule") : t("New Rewrite Rule")} onClose={close} wide>
          <RewriteEditor rule={d.rule} />
        </Modal>
      );
    case "rewrite-apply":
      return (
        <Modal title={t("Apply Rewrite Rules")} onClose={close} wide>
          <RewriteApply ids={d.ids} />
        </Modal>
      );
    case "capdiff":
      return (
        <Modal title={t("Compare Captures")} onClose={close} wide>
          <CaptureDiffPanel groupA={d.a} groupB={d.b} />
        </Modal>
      );
    case "library":
      return (
        <Modal title={t("Snapshot Library")} onClose={close} wide>
          <LibraryPanel />
        </Modal>
      );
    case "host-remap":
      return (
        <Modal title={t("Host Remapping")} onClose={close} wide>
          <HostRemapPanel />
        </Modal>
      );
    case "launch":
      return (
        <Modal title={t("Start Browser or Terminal")} onClose={close}>
          <LaunchPanel />
        </Modal>
      );
    case "reverse-proxy":
      return (
        <Modal title={t("Reverse Proxy")} onClose={close} wide>
          <ReverseProxyPanel target={d.target} />
        </Modal>
      );
    case "plugins":
      return (
        <Modal title={t("Plugins")} onClose={close} wide>
          <PluginsPanel />
        </Modal>
      );
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
