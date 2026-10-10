// Capture → Host Remapping: connections to a host go to another host, IP or port, like a
// hosts-file entry for the traffic through Quena.
import { useState } from "react";
import { api, type HostRemapEntry, type Settings } from "../api";
import { get, say, set, useStore } from "../store";
import { t } from "../i18n";

/** Names and addresses: no spelling correction or capitalisation. */
const plain = { spellCheck: false, autoCorrect: "off", autoCapitalize: "off" } as const;

function newId(): string {
  return typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `rm-${Date.now()}`;
}

export function HostRemapPanel() {
  const settings = useStore((s) => s.settings);
  const [draft, setDraft] = useState<Settings["hostRemap"]>(() => structuredClone(get().settings?.hostRemap ?? { enabled: false, entries: [] }));
  const [dirty, setDirty] = useState(false);
  if (!settings) return null;
  const change = (f: (d: Settings["hostRemap"]) => void) => {
    const next = structuredClone(draft);
    f(next);
    setDraft(next);
    setDirty(true);
  };
  const up = (i: number, patch: Partial<HostRemapEntry>) => change((d) => Object.assign(d.entries[i], patch));
  const save = async () => {
    const next = { ...structuredClone(settings), hostRemap: draft };
    try {
      await api.settingsSet(next);
      set({ settings: next });
      setDirty(false);
      say(t("Host remapping saved"));
    } catch (e) {
      say(String(e), "error");
    }
  };
  const importHosts = async () => {
    try {
      const found = await api.hostsFileImport();
      const known = new Set(draft.entries.map((e) => e.host));
      const fresh = found.filter((e) => !known.has(e.host)).map((e) => ({ ...e, id: newId() }));
      change((d) => d.entries.push(...fresh));
      say(fresh.length ? t("{n} entries imported from the hosts file", { n: fresh.length }) : t("The hosts file has no new entries"));
    } catch (e) {
      say(String(e), "error");
    }
  };
  return (
    <div className="host-remap">
      <label className="f-check strong">
        <input type="checkbox" checked={draft.enabled} onChange={(e) => change((d) => (d.enabled = e.target.checked))} /> {t("Enable host remapping")}
      </label>
      <p className="muted small">
        {t("Connections to a host go to another host, IP address or port — like an entry in the hosts file, but only for traffic through Quena. With \"keep host\", the request keeps its Host header and TLS name (a staging server with the real certificate); without it, it is sent to the target as if addressed there.")}
      </p>
      <table className="rp-list hr-table">
        <thead>
          <tr>
            <th />
            <th>{t("Host, *.domain or host:port")}</th>
            <th />
            <th>{t("Target (host, IP, host:port)")}</th>
            <th>{t("Protocol")}</th>
            <th>{t("keep host")}</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {draft.entries.map((e, i) => (
            <tr key={e.id}>
              <td>
                <input type="checkbox" checked={e.enabled} title={t("Use this entry")} onChange={(x) => up(i, { enabled: x.target.checked })} />
              </td>
              <td>
                <input {...plain} value={e.host} placeholder="api.example.com" onChange={(x) => up(i, { host: x.target.value })} />
              </td>
              <td>→</td>
              <td>
                <input {...plain} value={e.target} placeholder="10.0.0.5:8443" onChange={(x) => up(i, { target: x.target.value })} />
              </td>
              <td>
                <select value={e.protocol ?? ""} title={t("Talk to the target over HTTP or HTTPS, whatever the client used (e.g. HTTPS to a local HTTP dev server)")} onChange={(x) => up(i, { protocol: x.target.value as "" | "http" | "https" })}>
                  <option value="">{t("as sent")}</option>
                  <option value="http">HTTP</option>
                  <option value="https">HTTPS</option>
                </select>
              </td>
              <td className="hr-center">
                <input type="checkbox" checked={e.keepHost} title={t("Keep Host header and TLS name of the original host")} onChange={(x) => up(i, { keepHost: x.target.checked })} />
              </td>
              <td>
                <button className="cc-del" title={t("Remove")} onClick={() => change((d) => d.entries.splice(i, 1))}>
                  ✕
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="rp-buttons">
        <button onClick={() => change((d) => d.entries.push({ id: newId(), enabled: true, host: "", target: "", keepHost: true, protocol: "", comment: "" }))}>{t("Add entry")}</button>
        <button onClick={() => void importHosts()}>{t("Import hosts file…")}</button>
        <span className="hr-spacer" />
        <button className="primary" disabled={!dirty} onClick={() => void save()}>
          {t("Save")}
        </button>
      </div>
      <p className="muted small">{t("Remapped hosts bypass the upstream proxy. Sessions show the remap in their flags (x-quena-remap) and the address used.")}</p>
    </div>
  );
}
