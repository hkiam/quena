import { useEffect, useState } from "react";
import { forgetInspectorHeaders } from "../inspectors/views";
import { api, type PluginInfo } from "../api";
import { say } from "../store";
import { t } from "../i18n";

/** Plugins were enabled, disabled or rescanned: header inspectors and the Diagnostics analyzer
 * list reload (the event name is PLUGINS_CHANGED in panels/Diagnostics, which is loaded lazily). */
function pluginsChanged() {
  forgetInspectorHeaders();
  window.dispatchEvent(new Event("quena:plugins-changed"));
}

/** What a plugin applies to, for the table. */
function appliesTo(p: PluginInfo): string {
  if (p.kind === "analyzer") return t("The whole capture (Diagnostics tab)");
  if (p.kind === "headerInspector") return t("Headers: {list}", { list: p.headers.join(", ") || t("all") });
  // A manifest without content types (e.g. a test plugin) applies to nothing by itself.
  return p.mimeTypes.length ? p.mimeTypes.join(", ") : "—";
}

/** Status from the plugin host ("Enabled", "Disabled", "Error"), in the UI language. */
function statusLabel(s: string): string {
  if (s === "Enabled") return t("Enabled");
  if (s === "Disabled") return t("Disabled");
  if (s === "Error") return t("Error");
  return s;
}

export function PluginsPanel() {
  const [list, setList] = useState<PluginInfo[] | null>(null);
  useEffect(() => {
    api.pluginsList().then(setList);
  }, []);
  if (!list) return <div>{t("Loading…")}</div>;
  return (
    <div className="plugins">
      <table className="kv plugins-table">
        <thead>
          <tr>
            <th className="pl-check">
              <span className="sr-only">{t("Enabled")}</span>
            </th>
            <th className="pl-name">{t("Name")}</th>
            <th className="pl-version">{t("Version")}</th>
            <th className="pl-status">{t("Status")}</th>
            <th className="pl-applies">{t("Applies to")}</th>
          </tr>
        </thead>
        <tbody>
          {list.map((p) => (
            <tr key={p.id}>
              <td className="pl-check">
                <input
                  type="checkbox"
                  aria-label={t("Enable {name}", { name: p.name })}
                  checked={p.enabled}
                  disabled={!!p.error}
                  onChange={async (e) => {
                    await api.pluginSetEnabled(p.id, e.target.checked);
                    pluginsChanged();
                    setList(await api.pluginsList());
                  }}
                />
              </td>
              <td className="pl-name">
                <b>{p.name}</b>
                <div className="muted small">{p.id}</div>
                {p.error && <div className="err small">{p.error}</div>}
              </td>
              <td className="pl-version">{p.version}</td>
              <td className={`pl-status ${p.error ? "err" : ""}`}>{statusLabel(p.status)}</td>
              <td className={`pl-applies small ${p.kind === "analyzer" ? "" : "mono"}`}>{appliesTo(p)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {list.length === 0 && <p className="muted">{t("No plugins installed.")}</p>}
      <div className="btn-row">
        <button
          onClick={async () => {
            setList(await api.pluginsRescan());
            pluginsChanged();
            say(t("Plugins rescanned"));
          }}
        >
          {t("Rescan")}
        </button>
        <button onClick={() => api.pluginsReveal()}>{t("Open plugin folder")}</button>
      </div>
      <p className="muted small">
        {t(
          "Plugins are sandboxed WebAssembly components (WIT API v1): no file system, network or environment access; memory and execution time are limited. Drop a folder with plugin.toml + .wasm into the plugin folder and press Rescan.",
        )}
      </p>
    </div>
  );
}
