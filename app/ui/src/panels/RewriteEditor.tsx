// Rewrite rule editor (dialog): filters, operations and a before/after preview on a
// captured session; and the dialog that applies rules to selected sessions.
import { useEffect, useState } from "react";
import { api, type RwOp, type RwPreview, type RwRule, type RwState, type SessionId } from "../api";
import { get, say, set } from "../store";
import { rowCache } from "../grid/SessionGrid";
import { emptyDraft, fromDraft, MARK_COLORS, OP_KINDS, toDraft, type OpDraft, type OpKind } from "./rewriteDraft";
import { t } from "../i18n";

const MATCH_TEMPLATES = ["*", "exact:https://example.com/path", "prefix:https://example.com/api/", "regex:(?i)^https://.*\\.example\\.com/api/", "NOT:tracking", "METHOD:POST /login", "HEADER:Accept=json"];
const plain = { spellCheck: false, autoCorrect: "off", autoCapitalize: "off" } as const;

export function newRule(): RwRule {
  return { id: 0, enabled: true, match: "*", phase: "response", direction: "both", status: "", contentType: "", ops: [], comment: "", group: "", hits: 0 };
}

/** The focused session in the list, for the preview. */
function focusedSession(): SessionId | null {
  const i = get().focusIndex;
  return i == null ? null : (rowCache.get(i)?.id ?? null);
}

function OpRow({ d, onChange, onRemove, onMove }: { d: OpDraft; onChange: (d: OpDraft) => void; onRemove: () => void; onMove: (dir: -1 | 1) => void }) {
  const up = (p: Partial<OpDraft>) => onChange({ ...d, ...p });
  return (
    <div className="rw-op">
      <select value={d.op} onChange={(e) => up({ op: e.target.value as OpKind })}>
        {OP_KINDS.map(([k, label]) => (
          <option key={k} value={k}>
            {label}
          </option>
        ))}
      </select>
      {(d.op === "jsonSet" || d.op === "jsonRemove" || d.op === "jsonAppend") && <input {...plain} className="mono rw-path" value={d.path} placeholder="$.items[0].name" title={t("JSONPath (RFC 9535)")} onChange={(e) => up({ path: e.target.value })} />}
      {(d.op === "jsonSet" || d.op === "jsonAppend" || d.op === "jsonAppendAll") && (
        <input
          {...plain}
          className="mono rw-value"
          value={d.valueText}
          placeholder={d.op === "jsonSet" ? '"text", 42, null, {"a":1}' : t("empty: a broken copy of the first element")}
          title={t("Value as JSON")}
          onChange={(e) => up({ valueText: e.target.value })}
        />
      )}
      {d.op === "regexReplace" && (
        <>
          <input {...plain} className="mono rw-value" value={d.pattern} placeholder={t("regex, e.g. \"price\":\\s*\\d+")} onChange={(e) => up({ pattern: e.target.value })} />
          <input {...plain} className="mono rw-value" value={d.replacement} placeholder={t("replacement ($1, ${name})")} onChange={(e) => up({ replacement: e.target.value })} />
        </>
      )}
      {(d.op === "setHeader" || d.op === "defaultHeader" || d.op === "removeHeader") && <input {...plain} className="mono rw-path" value={d.name} placeholder="X-Header" onChange={(e) => up({ name: e.target.value })} />}
      {(d.op === "setHeader" || d.op === "defaultHeader") && <input {...plain} className="mono rw-value" value={d.headerValue} placeholder={t("value")} onChange={(e) => up({ headerValue: e.target.value })} />}
      {d.op === "setStatus" && <input type="number" min={100} max={999} className="rw-code" value={d.code} onChange={(e) => up({ code: e.target.value })} />}
      {(d.op === "setQuery" || d.op === "removeQuery" || d.op === "setCookie" || d.op === "removeCookie") && (
        <input {...plain} className="mono rw-path" value={d.name} placeholder={d.op.endsWith("Cookie") ? "session_id" : "lang"} onChange={(e) => up({ name: e.target.value })} />
      )}
      {(d.op === "setQuery" || d.op === "setCookie") && <input {...plain} className="mono rw-value" value={d.headerValue} placeholder={t("value")} onChange={(e) => up({ headerValue: e.target.value })} />}
      {d.op === "mark" && (
        <select value={d.color} onChange={(e) => up({ color: e.target.value as OpDraft["color"] })}>
          {MARK_COLORS.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      )}
      {d.op === "comment" && <input {...plain} className="rw-value" value={d.text} placeholder={t("comment")} onChange={(e) => up({ text: e.target.value })} />}
      <span className="rw-op-buttons">
        <button title={t("Move up")} onClick={() => onMove(-1)}>
          ↑
        </button>
        <button title={t("Move down")} onClick={() => onMove(1)}>
          ↓
        </button>
        <button className="cc-del" title={t("Remove")} onClick={onRemove}>
          ✕
        </button>
      </span>
    </div>
  );
}

export function RewriteEditor({ rule: initial }: { rule?: RwRule }) {
  const [rule, setRule] = useState<RwRule>(() => structuredClone(initial ?? newRule()));
  const [ops, setOps] = useState<OpDraft[]>(() => (initial?.ops.length ? initial.ops.map(toDraft) : [emptyDraft()]));
  const [groups, setGroups] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<RwPreview | null>(null);
  const [previewOn] = useState<SessionId | null>(focusedSession);
  useEffect(() => {
    api.rwGet().then((s) => setGroups([...new Set(s.rules.map((r) => r.group).filter(Boolean))]), () => {});
  }, []);
  const up = (p: Partial<RwRule>) => setRule({ ...rule, ...p });
  /** The rule as the form describes it, or the form's first error. */
  const built = (): RwRule | null => {
    const out: RwOp[] = [];
    for (const d of ops) {
      const r = fromDraft(d);
      if ("error" in r) {
        setError(r.error);
        return null;
      }
      out.push(r.op);
    }
    if (!out.length) {
      setError(t("Add at least one change"));
      return null;
    }
    setError(null);
    return { ...rule, ops: out };
  };
  const save = async () => {
    const r = built();
    if (!r) return;
    try {
      await api.rwUpdate(r);
      set({ arNonce: Date.now(), dialog: null });
      say(t("Rewrite rule saved"));
    } catch (e) {
      setError(String(e));
    }
  };
  const runPreview = async () => {
    const r = built();
    if (!r || previewOn == null) return;
    try {
      setPreview(await api.rwPreview(r, previewOn));
    } catch (e) {
      setError(String(e));
    }
  };
  const move = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= ops.length) return;
    const next = [...ops];
    [next[i], next[j]] = [next[j], next[i]];
    setOps(next);
  };
  const headerDiff = (p: RwPreview) => {
    const before = new Map(p.headersBefore.map(([k, v]) => [k.toLowerCase(), v]));
    const after = new Map(p.headersAfter.map(([k, v]) => [k.toLowerCase(), v]));
    const lines: string[] = [];
    for (const [k, v] of after) if (before.get(k) !== v) lines.push(`+ ${k}: ${v}`);
    for (const [k, v] of before) if (!after.has(k)) lines.push(`− ${k}: ${v}`);
    return lines;
  };
  return (
    <div className="rw-editor">
      <div className="f-row">
        <span>{t("Name")}</span>
        <input {...plain} value={rule.comment} placeholder={t("e.g. Prices as strings")} onChange={(e) => up({ comment: e.target.value })} />
      </div>
      <div className="f-row">
        <span>{t("Group")}</span>
        <input {...plain} list="rw-groups" value={rule.group} placeholder={t("optional, e.g. chaos tests")} onChange={(e) => up({ group: e.target.value })} />
        <datalist id="rw-groups">
          {groups.map((g) => (
            <option key={g} value={g} />
          ))}
        </datalist>
      </div>
      <div className="f-row">
        <span>{t("If request matches…")}</span>
        <input {...plain} className="mono" list="rw-match" value={rule.match} onChange={(e) => up({ match: e.target.value })} />
        <datalist id="rw-match">
          {MATCH_TEMPLATES.map((m) => (
            <option key={m} value={m} />
          ))}
        </datalist>
      </div>
      <div className="f-row">
        <span>{t("Change")}</span>
        <select value={rule.phase} onChange={(e) => up({ phase: e.target.value as RwRule["phase"] })}>
          <option value="response">{t("the response")}</option>
          <option value="request">{t("the request")}</option>
          <option value="webSocket">{t("WebSocket messages")}</option>
        </select>
        {rule.phase === "webSocket" && (
          <select value={rule.direction ?? "both"} onChange={(e) => up({ direction: e.target.value as RwRule["direction"] })}>
            <option value="both">{t("both directions")}</option>
            <option value="up">↑ {t("client → server")}</option>
            <option value="down">↓ {t("server → client")}</option>
          </select>
        )}
      </div>
      {rule.phase === "webSocket" && <p className="muted small">{t("Text messages of WebSockets the pattern matches (by the upgrade request). JSON is also changed inside Socket.IO packets (42[\"event\",{…}]).")}</p>}
      {rule.phase === "response" && (
        <div className="f-row">
          <span>{t("Only status")}</span>
          <input {...plain} value={rule.status} placeholder={t("any; e.g. 200, 4xx, 500-599")} onChange={(e) => up({ status: e.target.value })} />
        </div>
      )}
      {rule.phase !== "webSocket" && (
        <div className="f-row">
          <span>{t("Only content types")}</span>
          <input {...plain} value={rule.contentType} placeholder={t("any text; e.g. json; xml")} onChange={(e) => up({ contentType: e.target.value })} />
        </div>
      )}
      <fieldset className="f-section">
        <legend>{t("Changes (in this order)")}</legend>
        {ops.map((d, i) => (
          <OpRow key={i} d={d} onChange={(n) => setOps(ops.map((x, j) => (j === i ? n : x)))} onRemove={() => setOps(ops.filter((_, j) => j !== i))} onMove={(dir) => move(i, dir)} />
        ))}
        <div>
          <button className="linklike" onClick={() => setOps([...ops, emptyDraft()])}>
            {t("Add change")}
          </button>
        </div>
      </fieldset>
      {error && <div className="mocks-error">{error}</div>}
      {preview && (
        <fieldset className="f-section rw-preview">
          <legend>{t("Preview on session #{id}", { id: previewOn ?? "" })}</legend>
          {!preview.matched && <p className="muted">{t("The rule's filters do not take this session.")}</p>}
          {preview.matched && !preview.changed && <p className="muted">{t("The rule changes nothing in this session.")}</p>}
          {preview.notes.map((n) => (
            <p key={n} className="muted small">
              {n}
            </p>
          ))}
          {preview.statusBefore !== preview.statusAfter && (
            <p className="mono">
              {t("Status")}: {preview.statusBefore} → {preview.statusAfter}
            </p>
          )}
          {headerDiff(preview).length > 0 && <pre className="rw-headers">{headerDiff(preview).join("\n")}</pre>}
          {preview.before !== preview.after && (
            <div className="rw-sides">
              <div>
                <div className="muted small">{t("Before")}</div>
                <pre>{preview.before}</pre>
              </div>
              <div>
                <div className="muted small">{t("After")}</div>
                <pre>{preview.after}</pre>
              </div>
            </div>
          )}
        </fieldset>
      )}
      <div className="rp-buttons">
        <button className="primary" onClick={() => void save()}>
          {rule.id ? t("Save") : t("Add")}
        </button>
        <button onClick={() => set({ dialog: null })}>{t("Cancel")}</button>
        <span className="hr-spacer" />
        <button disabled={previewOn == null} title={previewOn == null ? t("Select a session in the list first") : undefined} onClick={() => void runPreview()}>
          {previewOn == null ? t("Preview (select a session)") : t("Preview on #{id}", { id: previewOn })}
        </button>
      </div>
    </div>
  );
}

/** Apply rewrite rules to the selected sessions: changed copies are added to the list. */
export function RewriteApply({ ids }: { ids: SessionId[] }) {
  const [rw, setRw] = useState<RwState | null>(null);
  useEffect(() => {
    api.rwGet().then(setRw, (e) => say(String(e), "error"));
  }, []);
  const run = async (ruleIds?: number[], group?: string) => {
    try {
      const out = await api.rwApply(ids, ruleIds, group);
      set({ dialog: null });
      say(out.created.length ? t("{n} changed copies added to the list", { n: out.created.length }) : out.marked ? t("{n} sessions marked or commented", { n: out.marked }) : t("No rule changed the selected sessions"));
    } catch (e) {
      say(String(e), "error");
    }
  };
  if (!rw) return null;
  const groups = [...new Set(rw.rules.map((r) => r.group).filter(Boolean))];
  return (
    <div className="rw-apply">
      <p className="muted small">{t("Each selected session a rule changes gets a new copy with the changes, marked as tampered. The originals stay as they were; nothing is sent.")}</p>
      {rw.rules.length === 0 && <p className="muted">{t("There are no rewrite rules yet.")}</p>}
      {rw.rules.length > 0 && (
        <div className="launch-list">
          <button className="primary" onClick={() => void run()}>
            {t("All rules that are on")}
          </button>
          {groups.map((g) => (
            <button key={g} onClick={() => void run(undefined, g)}>
              {t("Group {name}", { name: g })}
            </button>
          ))}
        </div>
      )}
      {rw.rules.length > 0 && (
        <table className="kv ar-table">
          <tbody>
            {rw.rules.map((r) => (
              <tr key={r.id}>
                <td>{r.comment || `#${r.id}`}</td>
                <td className="mono">{r.match}</td>
                <td>
                  <button className="linklike" onClick={() => void run([r.id])}>
                    {t("Apply this rule")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
