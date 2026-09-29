import { useState } from "react";
import { api, type FindOptions, type MarkColor } from "../api";
import { actions } from "../actions";
import { fmtInt } from "../lib/format";
import { get, say, set } from "../store";

const KEY = "quena.find.options";

export function FindDialog({ onDone }: { onDone: () => void }) {
  const saved = (() => {
    try {
      return JSON.parse(localStorage.getItem(KEY) ?? "{}") as Partial<FindOptions>;
    } catch {
      return {};
    }
  })();
  const [o, setO] = useState<FindOptions>({
    text: "",
    matchCase: false,
    regex: false,
    scope: "all",
    examine: "all",
    ids: [],
    decode: true,
    maxBodyMb: 64,
    mark: "gold",
    ...saved,
  });
  const [selectedOnly, setSelectedOnly] = useState(false);
  const [running, setRunning] = useState<string | null>(null);

  const run = async () => {
    if (!o.text) return;
    try {
      localStorage.setItem(KEY, JSON.stringify({ ...o, text: o.text, ids: [] }));
    } catch {
      /* ignore */
    }
    const opts = { ...o, ids: selectedOnly ? [...get().selection] : [] };
    const job = await api.findSessions(opts);
    const poll = async () => {
      const r = await api.findResult(job);
      if (!r) return;
      setRunning(`${fmtInt(r.examined)} / ${fmtInt(r.total)} examined · ${fmtInt(r.ids.length)} found`);
      if (!r.done) {
        setTimeout(poll, 150);
        return;
      }
      set((s) => ({ gridNonce: s.gridNonce + 1 }));
      await actions.selectIds(r.ids);
      say(`${fmtInt(r.ids.length)} session(s) found`);
      onDone();
    };
    poll();
  };

  const up = (p: Partial<FindOptions>) => setO({ ...o, ...p });
  return (
    <div className="find">
      <div className="f-row">
        <span>Find</span>
        <input autoFocus value={o.text} onChange={(e) => up({ text: e.target.value })} onKeyDown={(e) => e.key === "Enter" && run()} />
      </div>
      <div className="f-row">
        <span>Search</span>
        <select value={o.scope} onChange={(e) => up({ scope: e.target.value as FindOptions["scope"] })}>
          <option value="all">Requests and responses</option>
          <option value="requests">Requests only</option>
          <option value="responses">Responses only</option>
          <option value="urls">URLs only</option>
        </select>
      </div>
      <div className="f-row">
        <span>Examine</span>
        <select value={o.examine} onChange={(e) => up({ examine: e.target.value as FindOptions["examine"] })}>
          <option value="all">Headers and bodies</option>
          <option value="headers">Headers only</option>
          <option value="bodies">Bodies only</option>
        </select>
      </div>
      <div className="f-row">
        <span>Result highlight</span>
        <select value={o.mark ?? ""} onChange={(e) => up({ mark: (e.target.value || null) as MarkColor | null })}>
          <option value="">(select only)</option>
          {["gold", "red", "blue", "green", "orange", "purple"].map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </div>
      <div className="f-grid2">
        <label className="f-check">
          <input type="checkbox" checked={o.matchCase} onChange={(e) => up({ matchCase: e.target.checked })} /> Match case
        </label>
        <label className="f-check">
          <input type="checkbox" checked={o.regex} onChange={(e) => up({ regex: e.target.checked })} /> Regular expression
        </label>
        <label className="f-check">
          <input type="checkbox" checked={o.decode} onChange={(e) => up({ decode: e.target.checked })} /> Decode compressed bodies
        </label>
        <label className="f-check">
          <input type="checkbox" checked={selectedOnly} onChange={(e) => setSelectedOnly(e.target.checked)} /> Selected sessions only
        </label>
      </div>
      <div className="f-row">
        <span>Skip bodies larger than (MB)</span>
        <input type="number" value={o.maxBodyMb} onChange={(e) => up({ maxBodyMb: Number(e.target.value) })} />
      </div>
      <div className="modal-footer inline">
        <span className="muted">{running}</span>
        <button className="primary" onClick={run} disabled={!o.text}>
          Find Sessions
        </button>
      </div>
    </div>
  );
}
