// Mock Rules tab: rules, rule editor, .farx import/export.
import { useEffect, useRef, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { api, type ArRule, type ArState } from "../api";
import { say, useStore } from "../store";
import { showContextMenu } from "../components/ContextMenu";

const MATCH_TEMPLATES = ["*", "EXACT:https://example.com/path", "regex:(?i)^https://.*\\.example\\.com/api/(.*)$", "NOT:tracking", "METHOD:POST /login", "HEADER:Accept=json", "URLWithBody:/soap regex:GetOrder"];
const ACTIONS = ["*200", "*204", "*404", "*500", "*502", "*drop", "*delay:2000", "*redir:https://example.com/", "*header:X-Quena=1", "*CORSPreflightAllow", "*bpu", "*bpafter"];

export default function AutoResponderPanel() {
  const [st, setSt] = useState<ArState | null>(null);
  const [sel, setSel] = useState<number | null>(null);
  const [edit, setEdit] = useState<{ match: string; action: string; latency: number }>({ match: "", action: "", latency: 0 });
  const [over, setOver] = useState(false);
  const nonce = useStore((s) => s.arNonce);
  const version = useStore((s) => s.listVersion);
  const saveTimer = useRef<number | undefined>(undefined);

  useEffect(() => {
    api.arGet().then(setSt);
  }, [nonce]);
  // Refresh hit counters now and then.
  useEffect(() => {
    const t = setTimeout(() => api.arGet().then((s) => setSt((cur) => (cur ? { ...cur, rules: cur.rules.map((r) => ({ ...r, hits: s.rules.find((x) => x.id === r.id)?.hits ?? r.hits })) } : s))), 400);
    return () => clearTimeout(t);
  }, [Math.floor(version / 10)]);

  if (!st) return <div className="placeholder">Loading…</div>;

  const commit = (next: ArState, immediate = false) => {
    setSt(next);
    window.clearTimeout(saveTimer.current);
    const run = () =>
      api
        .arSet(next)
        .then(() => api.arGet().then(setSt))
        .catch((e) => say(String(e), "error"));
    if (immediate) run();
    else saveTimer.current = window.setTimeout(run, 300);
  };

  const selected = st.rules.find((r) => r.id === sel) ?? null;
  const pick = (r: ArRule) => {
    setSel(r.id);
    setEdit({ match: r.match, action: r.action, latency: r.latencyMs });
  };
  const saveRule = () => {
    if (!edit.match.trim()) return;
    if (selected) {
      commit({ ...st, rules: st.rules.map((r) => (r.id === selected.id ? { ...r, match: edit.match, action: edit.action, latencyMs: edit.latency } : r)) }, true);
    } else {
      commit({ ...st, enabled: true, rules: [...st.rules, { id: 0, enabled: true, match: edit.match, action: edit.action, latencyMs: edit.latency, matchOnce: false, comment: "", hits: 0 }] }, true);
    }
  };
  const move = (d: number) => {
    if (!selected) return;
    const i = st.rules.findIndex((r) => r.id === selected.id);
    const j = i + d;
    if (j < 0 || j >= st.rules.length) return;
    const rules = [...st.rules];
    [rules[i], rules[j]] = [rules[j], rules[i]];
    commit({ ...st, rules }, true);
  };

  return (
    <div
      className={`ar ${over ? "drop" : ""}`}
      onDragOver={(e) => {
        if (e.dataTransfer.types.includes("quena/sessions")) {
          e.preventDefault();
          setOver(true);
        }
      }}
      onDragLeave={() => setOver(false)}
      onDrop={async (e) => {
        setOver(false);
        const ids = JSON.parse(e.dataTransfer.getData("quena/sessions") || "[]") as number[];
        if (!ids.length) return;
        const n = await api.arAddSessions(ids, true);
        say(`${n} rule(s) added`);
        setSt(await api.arGet());
      }}
    >
      <div className="ar-top">
        <label className="f-check strong">
          <input type="checkbox" checked={st.enabled} onChange={(e) => commit({ ...st, enabled: e.target.checked }, true)} /> Enable rules
        </label>
        <label className="f-check">
          <input type="checkbox" checked={st.unmatchedPassthrough} onChange={(e) => commit({ ...st, unmatchedPassthrough: e.target.checked }, true)} /> Unmatched requests passthrough
        </label>
        <label className="f-check">
          <input type="checkbox" checked={st.enableLatency} onChange={(e) => commit({ ...st, enableLatency: e.target.checked }, true)} /> Enable Latency
        </label>
        <span className="tp-spacer" />
        <button
          onClick={() => {
            setSel(null);
            setEdit({ match: "", action: "", latency: 0 });
          }}
        >
          Add Rule
        </button>
        <button
          onClick={async () => {
            const p = await open({ multiple: false, filters: [{ name: "Mock rules (.farx)", extensions: ["farx", "xml"] }] });
            if (typeof p !== "string") return;
            try {
              setSt(await api.arImportFarx(p));
              say("Rules imported");
            } catch (e) {
              say(String(e), "error");
            }
          }}
        >
          Import…
        </button>
        <button
          onClick={async () => {
            const p = await save({ defaultPath: "quena-rules.farx", filters: [{ name: "Mock rules (.farx)", extensions: ["farx"] }] });
            if (!p) return;
            await api.arExportFarx(p);
            say(`Rules exported to ${p}`);
          }}
        >
          Export…
        </button>
      </div>
      <div className="ar-list">
        <table className="kv ar-table">
          <thead>
            <tr>
              <th style={{ width: 24 }}></th>
              <th>If request matches…</th>
              <th>then respond with…</th>
              <th style={{ width: 72 }}>Latency</th>
              <th style={{ width: 52 }}>Hits</th>
            </tr>
          </thead>
          <tbody>
            {st.rules.map((r) => (
              <tr
                key={r.id}
                className={`${sel === r.id ? "sel" : ""} ${r.enabled ? "" : "disabled"}`}
                onClick={() => pick(r)}
                onContextMenu={(e) => {
                  e.preventDefault();
                  pick(r);
                  showContextMenu(e.clientX, e.clientY, [
                    { label: r.enabled ? "Disable" : "Enable", action: () => commit({ ...st, rules: st.rules.map((x) => (x.id === r.id ? { ...x, enabled: !x.enabled } : x)) }, true) },
                    { label: "Match only once", checked: r.matchOnce, action: () => commit({ ...st, rules: st.rules.map((x) => (x.id === r.id ? { ...x, matchOnce: !x.matchOnce } : x)) }, true) },
                    { label: "Clone", action: () => commit({ ...st, rules: [...st.rules, { ...r, id: 0, hits: 0 }] }, true) },
                    { separator: true },
                    { label: "Move up", action: () => move(-1) },
                    { label: "Move down", action: () => move(1) },
                    { separator: true },
                    { label: "Remove", action: () => commit({ ...st, rules: st.rules.filter((x) => x.id !== r.id) }, true) },
                  ]);
                }}
              >
                <td>
                  <input
                    type="checkbox"
                    checked={r.enabled}
                    onClick={(e) => e.stopPropagation()}
                    onChange={(e) => commit({ ...st, rules: st.rules.map((x) => (x.id === r.id ? { ...x, enabled: e.target.checked } : x)) }, true)}
                  />
                </td>
                <td className="mono">{r.match}</td>
                <td className="mono">{r.action}</td>
                <td>{r.latencyMs || ""}</td>
                <td>{r.hits || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {st.rules.length === 0 && <div className="placeholder">No rules. Add one below, or drag sessions from the list here to replay their responses.</div>}
      </div>
      <fieldset className="f-section ar-editor">
        <legend>{selected ? "Rule Editor" : "New Rule"}</legend>
        <div className="f-row">
          <span>If request matches</span>
          <div className="combo">
            <input className="mono" value={edit.match} placeholder="e.g. regex:(?i)^https://api\.example\.com/users" onChange={(e) => setEdit({ ...edit, match: e.target.value })} list="ar-match" />
            <datalist id="ar-match">
              {MATCH_TEMPLATES.map((m) => (
                <option key={m} value={m} />
              ))}
            </datalist>
          </div>
        </div>
        <div className="f-row">
          <span>then respond with</span>
          <div className="combo">
            <input className="mono" value={edit.action} placeholder="*404, file path, session:12, https://other/…" onChange={(e) => setEdit({ ...edit, action: e.target.value })} list="ar-action" />
            <datalist id="ar-action">
              {ACTIONS.map((a) => (
                <option key={a} value={a} />
              ))}
            </datalist>
            <button
              onClick={async () => {
                const p = await open({ multiple: false });
                if (typeof p === "string") setEdit({ ...edit, action: p });
              }}
            >
              Find a file…
            </button>
          </div>
        </div>
        <div className="f-row">
          <span>Latency (ms)</span>
          <input type="number" value={edit.latency} onChange={(e) => setEdit({ ...edit, latency: Number(e.target.value) })} style={{ width: 100 }} />
        </div>
        <div className="btn-row">
          <button className="primary" onClick={saveRule} disabled={!edit.match.trim() || !edit.action.trim()}>
            {selected ? "Save" : "Add"}
          </button>
          {selected && <button onClick={() => move(-1)}>↑</button>}
          {selected && <button onClick={() => move(1)}>↓</button>}
          {selected && (
            <button
              onClick={() => {
                commit({ ...st, rules: st.rules.filter((x) => x.id !== selected.id) }, true);
                setSel(null);
              }}
            >
              Remove
            </button>
          )}
          <span className="muted small">Rules are evaluated top to bottom; the first match wins. regex rules support $1 in the action.</span>
        </div>
      </fieldset>
    </div>
  );
}
