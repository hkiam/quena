import { useEffect, useState } from "react";
import { forgetInspectorHeaders } from "../inspectors/views";
import { api, type PluginInfo } from "../api";
import { say } from "../store";
import { t } from "../i18n";

export function PluginsPanel() {
  const [list, setList] = useState<PluginInfo[] | null>(null);
  useEffect(() => {
    api.pluginsList().then(setList);
  }, []);
  if (!list) return <div>{t("Loading…")}</div>;
  return (
    <div className="plugins">
      <table className="kv">
        <thead>
          <tr>
            <th style={{ width: 30 }}></th>
            <th>Name</th>
            <th>Version</th>
            <th>Status</th>
            <th>{t("Applies to")}</th>
          </tr>
        </thead>
        <tbody>
          {list.map((p) => (
            <tr key={p.id}>
              <td>
                <input
                  type="checkbox"
                  checked={p.enabled}
                  disabled={!!p.error}
                  onChange={async (e) => {
                    await api.pluginSetEnabled(p.id, e.target.checked);
                    forgetInspectorHeaders();
                    setList(await api.pluginsList());
                  }}
                />
              </td>
              <td>
                <b>{p.name}</b>
                <div className="muted small">{p.id}</div>
                {p.error && <div className="err small">{p.error}</div>}
              </td>
              <td>{p.version}</td>
              <td>{p.status}</td>
              <td className="mono small">{p.kind === "headerInspector" ? t("Headers: {list}", { list: p.headers.join(", ") || t("all") }) : p.mimeTypes.join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {list.length === 0 && <p className="muted">{t("No plugins installed.")}</p>}
      <div className="btn-row">
        <button
          onClick={async () => {
            forgetInspectorHeaders();
            setList(await api.pluginsRescan());
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
