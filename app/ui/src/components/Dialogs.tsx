import { useEffect, useRef, useState } from "react";
import { api, type Recoverable, type Settings } from "../api";
import { actions } from "../actions";
import { fmtBytes, fmtDateTime, fmtInt, modKey } from "../lib/format";
import { get, say, set, useStore } from "../store";
import { TextWizard } from "./TextWizard";
import { CompareView } from "./CompareView";
import { FindDialog } from "./FindDialog";
import { HttpsPanel } from "./HttpsDialog";
import { DeviceAssistant } from "./DeviceDialog";
import { PluginsPanel } from "./PluginsDialog";
import { RulesEditor } from "./RulesEditor";

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
          <button onClick={() => done(null)}>Cancel</button>
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

function CommentDialog({ ids, initial }: { ids: number[]; initial: string }) {
  const [v, setV] = useState(initial);
  const ok = async () => {
    close();
    await actions.setComment(ids, v);
  };
  return (
    <Modal
      title={`Comment (${ids.length} session${ids.length > 1 ? "s" : ""})`}
      onClose={close}
      footer={
        <>
          <button onClick={close}>Cancel</button>
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

const QUICKEXEC_HELP = `?text         select sessions whose URL contains text
>10k  <5k     select by response size
=404  =POST   select by status or method
@host         select by host
select type   select by content type (e.g. select image)
find expr     select by expression (e.g. find status == 5xx)
filter expr   hide sessions not matching expr (empty: remove)
keeponly type remove sessions whose content type does not match
cls | clear   remove all sessions
tail 100      keep the most recent 100 sessions
bpu [text]    break before request (URL contains text); without text: off
bpafter [t]   break after response (URL contains t)
bps 500       break on response status
bpv POST      break on request method
g | go        resume all paused sessions
dump          save all sessions as .saz
start | stop  start/stop capturing
help          this help`;

const SHORTCUTS: [string, string][] = [
  ["F12", "Capture on/off (incl. system proxy)"],
  ["Ctrl+X / ⌘X", "Remove all sessions"],
  ["Del / Shift+Del", "Remove selected / all except selected"],
  ["R / Shift+R / U", "Replay / replay n times / unconditional replay"],
  [`${modKey}1…6 / ${modKey}0`, "Mark in colour / unmark"],
  ["M", "Comment"],
  [`${modKey}C`, "Copy session summary"],
  [`${modKey}A`, "Select all"],
  ["Enter", "Show inspectors"],
  [`${modKey}F`, "Find sessions"],
  [`${modKey}S`, "Save all sessions"],
  [`${modKey}R`, "Customize rules"],
  [`${modKey}E`, "Text Tools"],
  ["F7 / F8 / F9", "Statistics / Inspectors / Composer"],
  ["F11 / Alt+F11 / Shift+F11", "Break before requests / after responses / off"],
  ["Alt+Q or /", "Focus Command Bar"],
  [`${modKey}⇧P`, "Performance overlay"],
];

function HelpDialog({ topic }: { topic: "quickexec" | "shortcuts" }) {
  return (
    <Modal title={topic === "quickexec" ? "Command Bar commands" : "Keyboard shortcuts"} onClose={close} wide>
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
      title="Recover previous capture"
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
            Don't ask again (Options → General)
          </label>
          <button
            onClick={async () => {
              const n = await api.discardAll();
              say(`${n} old capture(s) discarded`);
              close();
            }}
          >
            Discard all
          </button>
          <button onClick={close}>Later</button>
        </>
      }
    >
      {!list ? (
        "Loading…"
      ) : list.length === 0 ? (
        <div className="muted">No unfinished captures found.</div>
      ) : (
        <>
          <p>Piper was not closed cleanly. The following captures can be restored:</p>
          <table className="kv">
            <tbody>
              {list.map((c) => (
                <tr key={c.dir}>
                  <td>
                    {fmtInt(c.sessions)} sessions
                    <div className="muted small">{c.modified ? fmtDateTime(c.modified * 1_000_000) : ""} · {c.dir}</div>
                  </td>
                  <td className="right">
                    <button
                      className="primary"
                      onClick={async () => {
                        close();
                        await api.recover(c.dir);
                        say(`Restored ${fmtInt(c.sessions)} sessions`);
                      }}
                    >
                      Restore
                    </button>{" "}
                    <button
                      onClick={async () => {
                        await api.discard(c.dir);
                        load();
                      }}
                    >
                      Discard
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

function JobsDialog() {
  const jobs = useStore((s) => s.jobs);
  return (
    <Modal title="Background jobs" onClose={close} wide>
      {jobs.length === 0 && <div className="muted">No jobs.</div>}
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
                  <span className="muted">{j.status}</span>
                )}
                <div className="muted small">
                  {j.total > 0 ? `${fmtBytes(j.done)} / ${fmtBytes(j.total)}` : ""} {j.elapsedMs != null ? `· ${(j.elapsedMs / 1000).toFixed(1)} s` : ""}
                </div>
              </td>
              <td style={{ width: 70 }}>{(j.status === "running" || j.status === "queued") && <button onClick={() => api.cancelJob(j.id)}>Cancel</button>}</td>
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
        <input type="checkbox" checked={s.auth.enabled} onChange={(e) => up((x) => (x.auth.enabled = e.target.checked))} /> Enable Automatic Authentication
      </label>
      <p className="muted small">
        Piper answers 401/407 challenges (Negotiate/Kerberos, NTLM, Basic) with your credentials so you don't log in on every request. An authenticated
        connection is pinned to one client and never shared. Default off.
      </p>
      <div className="f-row">
        <span>Only for hosts</span>
        <input placeholder="empty = all; e.g. *.corp.example.com; sharepoint.corp" value={s.auth.hosts} onChange={(e) => up((x) => (x.auth.hosts = e.target.value))} />
      </div>
      <label className="f-check">
        <input type="checkbox" checked={s.auth.upstream} onChange={(e) => up((x) => (x.auth.upstream = e.target.checked))} /> Also authenticate to the upstream proxy (407)
      </label>
      <label className="f-check">
        <input type="checkbox" checked={s.auth.useCurrentIdentity} onChange={(e) => up((x) => (x.auth.useCurrentIdentity = e.target.checked))} /> Use current OS identity for SSO (Kerberos) when available
      </label>
      <div className="f-row">
        <span>Scheme order</span>
        <input value={s.auth.prefer} onChange={(e) => up((x) => (x.auth.prefer = e.target.value))} />
      </div>
      <fieldset className="f-section">
        <legend>Credentials (passwords stored in the OS keychain)</legend>
        {s.auth.credentials.length === 0 && <div className="muted small">No credentials configured. Kerberos SSO needs none.</div>}
        <table className="kv">
          <tbody>
            {s.auth.credentials.map((c) => (
              <tr key={c.host}>
                <td className="mono">{c.host}</td>
                <td className="mono">{c.domain ? `${c.domain}\\${c.user}` : c.user}</td>
                <td>{c.hasPassword ? "password stored" : "SSO / no password"}</td>
                <td style={{ width: 60 }}>
                  <button
                    onClick={async () => {
                      await api.authRemoveCredential(c.host);
                      up((x) => (x.auth.credentials = x.auth.credentials.filter((y) => y.host !== c.host)));
                    }}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="f-grid2">
          <input placeholder="Host or realm (* = default)" value={cred.host} onChange={(e) => setCred({ ...cred, host: e.target.value })} />
          <input placeholder="Domain (optional)" value={cred.domain} onChange={(e) => setCred({ ...cred, domain: e.target.value })} />
          <input placeholder="User" value={cred.user} onChange={(e) => setCred({ ...cred, user: e.target.value })} />
          <input type="password" placeholder="Password (blank = SSO)" value={cred.password} onChange={(e) => setCred({ ...cred, password: e.target.value })} />
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
            Add / update
          </button>
          {saved && <span className="muted small">Saved for {saved}</span>}
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
      say("Settings saved");
    } catch (e) {
      say(String(e), "error");
    }
  };
  return (
    <Modal
      title="Options"
      onClose={close}
      wide
      footer={
        <>
          <button onClick={close}>Cancel</button>
          <button className="primary" onClick={save}>
            OK
          </button>
        </>
      }
    >
      <div className="tabs-row">
        {(["general", "connections", "https", "auth", "bodies"] as const).map((t) => (
          <div key={t} className={`insp-tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
            {{ general: "General", connections: "Connections", https: "HTTPS", auth: "Authentication", bodies: "Bodies & Storage" }[t]}
          </div>
        ))}
      </div>
      <div className="opt-body">
        {tab === "general" && (
          <>
            <label className="f-check">
              <input type="checkbox" checked={s.proxy.captureOnStartup} onChange={(e) => up((x) => (x.proxy.captureOnStartup = e.target.checked))} /> Capture traffic on startup
            </label>
            <label className="f-check">
              <input type="checkbox" checked={s.stream} onChange={(e) => up((x) => (x.stream = e.target.checked))} /> Stream responses (instead of buffering)
            </label>
            <label className="f-check">
              <input type="checkbox" checked={s.decode} onChange={(e) => up((x) => (x.decode = e.target.checked))} /> Decode compressed bodies in inspectors
            </label>
            <label className="f-check">
              <input type="checkbox" checked={s.keepCaptures} onChange={(e) => up((x) => (x.keepCaptures = e.target.checked))} /> Keep capture data after exit
            </label>
            <label className="f-check">
              <input type="checkbox" checked={s.offerRecovery !== false} onChange={(e) => up((x) => (x.offerRecovery = e.target.checked))} /> Offer to recover sessions after a crash
            </label>
          </>
        )}
        {tab === "connections" && (
          <>
            <div className="f-row">
              <span>Listen port</span>
              <input type="number" value={s.proxy.port} onChange={(e) => up((x) => (x.proxy.port = Number(e.target.value)))} />
            </div>
            <label className="f-check">
              <input type="checkbox" checked={s.proxy.actAsSystemProxy} onChange={(e) => up((x) => (x.proxy.actAsSystemProxy = e.target.checked))} /> Act as system proxy while capturing
            </label>
            <label className="f-check">
              <input type="checkbox" checked={s.proxy.allowRemote} onChange={(e) => up((x) => (x.proxy.allowRemote = e.target.checked))} /> Allow remote computers to connect
            </label>
            <div className="f-row">
              <span>Allowed remote networks</span>
              <input placeholder="empty = local subnets; e.g. 192.168.1.0/24; 10.0.0.5" value={s.proxy.remoteAllowlist} onChange={(e) => up((x) => (x.proxy.remoteAllowlist = e.target.value))} />
            </div>
            <label className="f-check">
              <input type="checkbox" checked={s.proxy.useSystemUpstream} onChange={(e) => up((x) => (x.proxy.useSystemUpstream = e.target.checked))} /> Chain to the previous system proxy (upstream gateway)
            </label>
            <div className="f-row">
              <span>Manual upstream proxy</span>
              <input placeholder="host:port" value={s.proxy.manualUpstream} onChange={(e) => up((x) => (x.proxy.manualUpstream = e.target.value))} />
            </div>
            <div className="f-row">
              <span>Bypass upstream for</span>
              <input value={s.proxy.upstreamBypass} onChange={(e) => up((x) => (x.proxy.upstreamBypass = e.target.value))} />
            </div>
            <label className="f-check">
              <input type="checkbox" checked={s.proxy.useSystemPac} onChange={(e) => up((x) => (x.proxy.useSystemPac = e.target.checked))} /> Use the system proxy auto-config (PAC) script
            </label>
            <div className="f-row">
              <span>PAC URL or file</span>
              <input placeholder="empty = use system PAC; or http://…/proxy.pac, file path" value={s.proxy.pacUrl} onChange={(e) => up((x) => (x.proxy.pacUrl = e.target.value))} />
            </div>
            <div className="f-sep">Bandwidth simulation</div>
            <div className="f-row">
              <span>Throttle (kbit/s)</span>
              <input type="number" min={0} placeholder="0 = unlimited" value={s.throttleKbps} onChange={(e) => up((x) => (x.throttleKbps = Math.max(0, Number(e.target.value))))} />
            </div>
            <div className="f-row">
              <span>Added latency (ms)</span>
              <input type="number" min={0} value={s.throttleLatencyMs} onChange={(e) => up((x) => (x.throttleLatencyMs = Math.max(0, Number(e.target.value))))} />
            </div>
          </>
        )}
        {tab === "https" && (
          <>
            <label className="f-check">
              <input type="checkbox" checked={s.https.decrypt} onChange={(e) => up((x) => (x.https.decrypt = e.target.checked))} /> Decrypt HTTPS traffic
            </label>
            <div className="f-row">
              <span>Decrypt traffic from</span>
              <select value={s.https.scope} onChange={(e) => up((x) => (x.https.scope = e.target.value as Settings["https"]["scope"]))}>
                <option value="all">…all processes</option>
                <option value="browsers">…browsers only</option>
                <option value="nonBrowsers">…non-browsers only</option>
                <option value="remote">…remote clients only</option>
              </select>
            </div>
            <div className="f-row">
              <span>Skip decryption for</span>
              <input placeholder="*.bank.example; login.live.com" value={s.https.skipDecryption} onChange={(e) => up((x) => (x.https.skipDecryption = e.target.value))} />
            </div>
            <label className="f-check">
              <input type="checkbox" checked={s.https.ignoreCertErrors} onChange={(e) => up((x) => (x.https.ignoreCertErrors = e.target.checked))} /> Ignore server certificate errors (unsafe)
            </label>
            <div className="f-row">
              <span>Ignore certificate errors for</span>
              <input value={s.https.ignoreCertErrorsHosts} onChange={(e) => up((x) => (x.https.ignoreCertErrorsHosts = e.target.value))} />
            </div>
            <label className="f-check">
              <input type="checkbox" checked={s.https.enableHttp2} onChange={(e) => up((x) => (x.https.enableHttp2 = e.target.checked))} /> Enable HTTP/2
            </label>
            <div className="f-row">
              <span>Downgrade to HTTP/1.1 for</span>
              <input value={s.https.http2DowngradeHosts} onChange={(e) => up((x) => (x.https.http2DowngradeHosts = e.target.value))} />
            </div>
            <p>
              <button onClick={() => set({ dialog: { kind: "https" } })}>Certificate management…</button>
            </p>
          </>
        )}
        {tab === "auth" && <AuthOptions s={s} up={up} />}
        {tab === "bodies" && (
          <>
            <div className="f-row">
              <span>Keep bodies in memory up to (KB)</span>
              <input type="number" value={s.bodies.inlineLimitKb} onChange={(e) => up((x) => (x.bodies.inlineLimitKb = Number(e.target.value)))} />
            </div>
            <div className="f-row">
              <span>Record at most per body (MB)</span>
              <input type="number" value={s.bodies.maxRecordedBodyMb} onChange={(e) => up((x) => (x.bodies.maxRecordedBodyMb = Number(e.target.value)))} />
            </div>
            <div className="f-row">
              <span>Storage quota (GB)</span>
              <input type="number" value={s.bodies.quotaGb} onChange={(e) => up((x) => (x.bodies.quotaGb = Number(e.target.value)))} />
            </div>
            <div className="f-row">
              <span>Stop recording below free space (GB)</span>
              <input type="number" value={s.bodies.minFreeSpaceGb} onChange={(e) => up((x) => (x.bodies.minFreeSpaceGb = Number(e.target.value)))} />
            </div>
            <div className="f-row">
              <span>Max decoded size (GB)</span>
              <input type="number" value={s.bodies.maxDerivedGb} onChange={(e) => up((x) => (x.bodies.maxDerivedGb = Number(e.target.value)))} />
            </div>
            <div className="f-row">
              <span>Max decompression ratio</span>
              <input type="number" value={s.bodies.maxRatio} onChange={(e) => up((x) => (x.bodies.maxRatio = Number(e.target.value)))} />
            </div>
            <div className="f-row">
              <span>Headers only for hosts</span>
              <input value={s.headersOnlyHosts} onChange={(e) => up((x) => (x.headersOnlyHosts = e.target.value))} />
            </div>
            <div className="f-row">
              <span>Headers only for content types</span>
              <input placeholder="video/; audio/" value={s.headersOnlyTypes} onChange={(e) => up((x) => (x.headersOnlyTypes = e.target.value))} />
            </div>
            <label className="f-check">
              <input type="checkbox" checked={s.losslessRecording} onChange={(e) => up((x) => (x.losslessRecording = e.target.checked))} /> Lossless recording (forwarding waits for the disk)
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
    <Modal title="About Piper" onClose={close}>
      <p>
        <b>Piper</b> {info?.version} – easy-to-use, fast HTTP(S) debugging proxy.
      </p>
      <p className="muted small">Data: {info?.dataDir}</p>
      <p className="muted small">Capture: {info?.captureDir}</p>
    </Modal>
  );
}

function TextDialog({ title, text }: { title: string; text: string }) {
  return (
    <Modal title={title} onClose={close} wide footer={<button onClick={() => navigator.clipboard.writeText(text)}>Copy</button>}>
      <pre className="help-pre">{text}</pre>
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
  switch (d.kind) {
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
        <Modal title="Find Sessions" onClose={close}>
          <FindDialog onDone={close} />
        </Modal>
      );
    case "textwizard":
      return (
        <Modal title="Text Tools" onClose={close} wide>
          <TextWizard initial={d.text} />
        </Modal>
      );
    case "compare":
      return (
        <Modal title={`Compare ${d.titleA} ↔ ${d.titleB}`} onClose={close} wide>
          <CompareView a={d.a} b={d.b} />
        </Modal>
      );
    case "connect-device":
      return (
        <Modal title="Connect Device" onClose={close} wide>
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
        <Modal title="Plugins" onClose={close} wide>
          <PluginsPanel />
        </Modal>
      );
    case "rules":
      return (
        <Modal title="Rules Script" onClose={close} wide>
          <RulesEditor />
        </Modal>
      );
  }
}
