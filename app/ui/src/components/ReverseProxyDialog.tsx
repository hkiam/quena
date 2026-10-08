// Capture → Reverse Proxy: local ports that forward every request to one target, for
// clients that cannot use a proxy (backends, containers, webhooks, gRPC).
import { useState } from "react";
import { api, type ListenerStatus, type ReverseProxyEntry, type SessionSummary, type Settings } from "../api";
import { actions } from "../actions";
import { get, say, set, useStore } from "../store";
import { rowCache } from "../grid/SessionGrid";
import { t } from "../i18n";

/** Save the settings; the backend checks the entries (ports, targets) and may refuse them. */
async function commit(next: Settings): Promise<boolean> {
  try {
    await api.settingsSet(next);
    set({ settings: next });
    return true;
  } catch (e) {
    say(String(e), "error");
    return false;
  }
}

function newId(): string {
  return typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `rp-${Date.now()}`;
}

/** The first port from 8080 on that neither the proxy nor another entry uses. */
function freePort(s: Settings): number {
  const used = new Set([s.proxy.port, ...s.reverseProxy.entries.map((e) => e.listenPort)]);
  let p = 8080;
  while (used.has(p)) p++;
  return p;
}

function blank(s: Settings, target = ""): ReverseProxyEntry {
  const host = target.replace(/^https?:\/\//, "").split(/[/:]/)[0];
  return {
    id: newId(),
    name: host,
    enabled: true,
    listenPort: freePort(s),
    allowRemote: false,
    clientProtocol: "auto",
    target,
    preserveHost: false,
    tlsHost: "",
    rewriteLocation: true,
    rewriteCookieDomain: false,
    forwardedHeaders: false,
    paths: [],
  };
}

/** How clients reach an entry. */
function clientUrl(e: ReverseProxyEntry): string {
  return `${e.clientProtocol === "https" ? "https" : "http"}://localhost:${e.listenPort}/`;
}

/** Session list: start a new entry for the focused session's origin. */
export function reverseProxyForSelection() {
  const i = get().focusIndex;
  const r: SessionSummary | undefined = i == null ? undefined : rowCache.get(i);
  if (!r) return;
  const host = r.host || r.url;
  const https = r.kind === "tunnel" || r.protocol !== "HTTP";
  const plain = host.replace(https ? /:443$/ : /:80$/, "");
  set({ dialog: { kind: "reverse-proxy", target: `${https ? "https" : "http"}://${plain}` } });
}

export function ReverseProxyPanel({ target }: { target?: string }) {
  const settings = useStore((s) => s.settings);
  const capturing = useStore((s) => s.status?.engine.capturing ?? false);
  const status = useStore((s) => s.status?.engine.listeners ?? []).filter((l) => l.kind === "reverse");
  const [editing, setEditing] = useState<ReverseProxyEntry | null>(() => {
    const s = get().settings;
    return s && target ? blank(s, target) : null;
  });
  if (!settings) return null;
  const rp = settings.reverseProxy;
  const isNew = editing != null && !rp.entries.some((e) => e.id === editing.id);

  const change = (f: (s: Settings) => void) => {
    const next = structuredClone(settings);
    f(next);
    return commit(next);
  };
  const saveEditing = async () => {
    if (!editing) return;
    const ok = await change((s) => {
      const i = s.reverseProxy.entries.findIndex((e) => e.id === editing.id);
      if (i >= 0) s.reverseProxy.entries[i] = editing;
      else {
        s.reverseProxy.entries.push(editing);
        // Adding an entry means using it.
        s.reverseProxy.enabled = true;
      }
    });
    if (ok) setEditing(null);
  };

  return (
    <div className="reverse-proxy">
      <label className="f-check strong">
        <input type="checkbox" checked={rp.enabled} onChange={(e) => change((s) => (s.reverseProxy.enabled = e.target.checked))} /> {t("Enable reverse proxy ports")}
      </label>
      <p className="muted small">
        {t("For clients that cannot use a proxy: they call a local port, Quena forwards every request to the target and records it like proxied traffic. The ports listen while capturing.")}
      </p>
      {rp.enabled && !capturing && (
        <p className="rp-note">
          {t("Capturing is off: the ports listen once capturing starts.")}{" "}
          <button className="linklike" onClick={() => actions.toggleCapture()}>
            {t("Start capturing")}
          </button>
        </p>
      )}
      {rp.entries.length > 0 && (
        <table className="rp-list">
          <tbody>
            {rp.entries.map((e) => (
              <EntryRow
                key={e.id}
                e={e}
                st={status.find((x) => x.id === e.id)}
                active={rp.enabled && capturing}
                onToggle={(on) => change((s) => (s.reverseProxy.entries.find((x) => x.id === e.id)!.enabled = on))}
                onEdit={() => setEditing(structuredClone(e))}
                onRemove={() => change((s) => (s.reverseProxy.entries = s.reverseProxy.entries.filter((x) => x.id !== e.id)))}
              />
            ))}
          </tbody>
        </table>
      )}
      {!editing && (
        <div>
          <button onClick={() => setEditing(blank(settings))}>{t("Add entry…")}</button>
        </div>
      )}
      {editing && <Editor e={editing} isNew={isNew} onChange={setEditing} onSave={saveEditing} onCancel={() => setEditing(null)} />}
    </div>
  );
}

function EntryRow({
  e,
  st,
  active,
  onToggle,
  onEdit,
  onRemove,
}: {
  e: ReverseProxyEntry;
  st?: ListenerStatus;
  active: boolean;
  onToggle: (on: boolean) => void;
  onEdit: () => void;
  onRemove: () => void;
}) {
  let state: [string, string];
  if (!e.enabled || !active) state = ["rp-off", t("off")];
  else if (st?.error) state = ["rp-err", t("error")];
  else if (st?.listen.length) state = ["rp-on", t("listening")];
  else state = ["rp-off", t("starting…")];
  return (
    <tr>
      <td>
        <input type="checkbox" checked={e.enabled} title={t("Use this entry")} onChange={(x) => onToggle(x.target.checked)} />
      </td>
      <td className="rp-name">{e.name || `:${e.listenPort}`}</td>
      <td className="rp-route" title={st?.error ?? st?.listen.join(", ") ?? ""}>
        <code>:{e.listenPort}</code> → <code>{e.target}</code>
        {e.paths.map((p) => (
          <div key={p.prefix} className="rp-path">
            <code>{p.prefix}</code> → <code>{p.target}</code>
            {p.stripPrefix && <span className="muted small"> {t("(prefix removed)")}</span>}
          </div>
        ))}
        {e.allowRemote && <span className="rp-tag rp-warn">{t("remote")}</span>}
        {st?.error && <div className="rp-error">{st.error}</div>}
      </td>
      <td>
        <span className={`rp-tag ${state[0]}`}>{state[1]}</span>
      </td>
      <td className="rp-actions">
        <button className="linklike" onClick={() => void navigator.clipboard.writeText(clientUrl(e)).then(() => say(t("Copied {url}", { url: clientUrl(e) })))}>
          {t("Copy address")}
        </button>
        <button className="linklike" onClick={onEdit}>
          {t("Edit")}
        </button>
        <button className="linklike" onClick={onRemove}>
          {t("Remove")}
        </button>
      </td>
    </tr>
  );
}

/** Names, URLs and paths: no spelling correction or capitalisation. */
const plain = { spellCheck: false, autoCorrect: "off", autoCapitalize: "off" } as const;

function Editor({ e, isNew, onChange, onSave, onCancel }: { e: ReverseProxyEntry; isNew: boolean; onChange: (e: ReverseProxyEntry) => void; onSave: () => void; onCancel: () => void }) {
  const up = (patch: Partial<ReverseProxyEntry>) => onChange({ ...e, ...patch });
  const isUrl = (u: string) => /^https?:\/\/[^/\s]+/i.test(u.trim());
  const validTarget = isUrl(e.target) && e.paths.every((p) => p.prefix.startsWith("/") && isUrl(p.target));
  const setPath = (i: number, patch: Partial<ReverseProxyEntry["paths"][number]>) => up({ paths: e.paths.map((p, j) => (j === i ? { ...p, ...patch } : p)) });
  return (
    <fieldset className="f-section rp-editor">
      <legend>{isNew ? t("New entry") : t("Edit entry")}</legend>
      <div className="f-row">
        <span>{t("Name")}</span>
        <input {...plain} value={e.name} placeholder="api" onChange={(x) => up({ name: x.target.value })} />
      </div>
      <div className="f-row">
        <span>{t("Local port")}</span>
        <input type="number" min={1} max={65535} value={e.listenPort} onChange={(x) => up({ listenPort: Number(x.target.value) })} />
      </div>
      <div className="f-row">
        <span>{t("Target")}</span>
        <input {...plain} value={e.target} placeholder="https://api.example.com/v1" autoFocus onChange={(x) => up({ target: x.target.value })} />
      </div>
      <div className="f-row rp-paths">
        <span>{t("Path routes")}</span>
        <div>
          {e.paths.map((p, i) => (
            <div className="cc-row" key={i}>
              <input {...plain} className="rp-prefix" value={p.prefix} placeholder="/auth" onChange={(x) => setPath(i, { prefix: x.target.value })} />
              <span>→</span>
              <input {...plain} className="cc-host" value={p.target} placeholder="https://sso.example.com" onChange={(x) => setPath(i, { target: x.target.value })} />
              <label className="f-check" title={t("Forward /auth/login as /login")}>
                <input type="checkbox" checked={p.stripPrefix} onChange={(x) => setPath(i, { stripPrefix: x.target.checked })} /> {t("remove prefix")}
              </label>
              <button className="cc-del" title={t("Remove")} onClick={() => up({ paths: e.paths.filter((_, j) => j !== i) })}>
                ✕
              </button>
            </div>
          ))}
          <button className="linklike" onClick={() => up({ paths: [...e.paths, { prefix: "/", target: "", stripPrefix: false }] })}>
            {t("Add path route")}
          </button>
          <p className="muted small">{t("Requests whose path starts with a prefix go to its target; the longest prefix wins, all others go to the target above.")}</p>
        </div>
      </div>
      <div className="f-row">
        <span>{t("Clients speak")}</span>
        <select value={e.clientProtocol} onChange={(x) => up({ clientProtocol: x.target.value as ReverseProxyEntry["clientProtocol"] })}>
          <option value="auto">{t("HTTP or HTTPS (detected)")}</option>
          <option value="http">{t("HTTP only")}</option>
          <option value="https">{t("HTTPS only")}</option>
        </select>
      </div>
      {e.clientProtocol !== "http" && (
        <div className="f-row">
          <span>{t("Certificate name")}</span>
          <input {...plain} value={e.tlsHost} placeholder="localhost" title={t("Used when the client sends no server name (SNI); clients must trust the Quena root certificate")} onChange={(x) => up({ tlsHost: x.target.value })} />
        </div>
      )}
      <label className="f-check">
        <input type="checkbox" checked={e.preserveHost} onChange={(x) => up({ preserveHost: x.target.checked })} /> {t("Keep the client's Host header (default: the target's)")}
      </label>
      <label className="f-check">
        <input type="checkbox" checked={e.rewriteLocation} onChange={(x) => up({ rewriteLocation: x.target.checked })} /> {t("Point redirects to the target back to this port (Location)")}
      </label>
      <label className="f-check">
        <input type="checkbox" checked={e.rewriteCookieDomain} onChange={(x) => up({ rewriteCookieDomain: x.target.checked })} /> {t("Remove the Domain of cookies the target sets")}
      </label>
      <label className="f-check">
        <input type="checkbox" checked={e.forwardedHeaders} onChange={(x) => up({ forwardedHeaders: x.target.checked })} /> {t("Add X-Forwarded-For, -Proto and -Host")}
      </label>
      <label className="f-check">
        <input type="checkbox" checked={e.allowRemote} onChange={(x) => up({ allowRemote: x.target.checked })} /> {t("Allow remote computers to connect")}
      </label>
      {e.allowRemote && <p className="rp-note">{t("Other machines in the allowed networks (Options → Connections) can then reach the target through this port.")}</p>}
      {e.listenPort > 0 && e.listenPort < 1024 && <p className="rp-note">{t("Ports below 1024 usually need administrator rights.")}</p>}
      <p className="muted small">
        {t("Clients call")} <code>{clientUrl(e)}</code>
        {e.clientProtocol !== "http" && <> · {t("HTTPS clients must trust the Quena root certificate (Capture → HTTPS Settings…).")}</>}
      </p>
      <div className="rp-buttons">
        <button className="primary" disabled={!validTarget || !(e.listenPort > 0 && e.listenPort < 65536)} onClick={onSave}>
          {isNew ? t("Add") : t("Save")}
        </button>
        <button onClick={onCancel}>{t("Cancel")}</button>
      </div>
    </fieldset>
  );
}
