import { useEffect, useState } from "react";
import { api, type PluginInfo } from "../api";
import { say } from "../store";

export function PluginsPanel() {
  const [list, setList] = useState<PluginInfo[] | null>(null);
  useEffect(() => {
    api.pluginsList().then(setList);
  }, []);
  if (!list) return <div>Loading…</div>;
  return (
    <div className="plugins">
      <table className="kv">
        <thead>
          <tr>
            <th style={{ width: 30 }}></th>
            <th>Name</th>
            <th>Version</th>
            <th>Status</th>
            <th>Applies to</th>
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
              <td className="mono small">{p.kind === "headerInspector" ? `Headers: ${p.headers.join(", ") || "all"}` : p.mimeTypes.join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {list.length === 0 && <p className="muted">No plugins installed.</p>}
      <div className="btn-row">
        <button
          onClick={async () => {
            setList(await api.pluginsRescan());
            say("Plugins rescanned");
          }}
        >
          Rescan
        </button>
        <button onClick={() => api.pluginsReveal()}>Open plugin folder</button>
      </div>
      <p className="muted small">
        Plugins are sandboxed WebAssembly components (WIT API v1): no file system, network or environment access; memory and execution time are limited. Drop a folder with
        plugin.toml + .wasm into the plugin folder and press Rescan.
      </p>
    </div>
  );
}
