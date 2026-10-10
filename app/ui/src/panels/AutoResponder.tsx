// Mock Rules tab: rules, rule editor, .farx import/export.
import { useEffect, useRef, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { api, type ArRule, type ArState, type MockPackage, type RwRule, type RwState } from "../api";
import { confirmAsk, get, say, set, useStore } from "../store";
import { describeOp } from "./rewriteDraft";
import { showContextMenu } from "../components/ContextMenu";
import { mapLocalRule, mapRemoteRule, mockPackageImported, mocksFromSelection, type MappingKind } from "./autoresponderActions";
import { plural, t } from "../i18n";
import { addTemplate, TEMPLATES } from "./ruleTemplates";

/** "From template" menu below the button. */
function templateMenu(e: React.MouseEvent) {
  const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
  showContextMenu(
    r.left,
    r.bottom,
    TEMPLATES.map((tpl) => ({ label: tpl.label, action: () => void addTemplate(tpl) })),
  );
}

const MATCH_TEMPLATES = ["*", "EXACT:https://example.com/path", "prefix:https://example.com/api/", "regex:(?i)^https://.*\\.example\\.com/api/(.*)$", "NOT:tracking", "METHOD:POST /login", "HEADER:Accept=json", "URLWithBody:/soap regex:GetOrder"];
const ACTIONS = ["dir:/path/to/folder", "https://staging.example.com/api/", "https://staging.example.com/api/ *nocreds", "*200", "*204", "*404", "*500", "*502", "*drop", "*delay:2000", "*redir:https://example.com/", "*header:X-Quena=1", "*CORSPreflightAllow", "*bpu", "*bpafter"];

/** Rewrite rules change real traffic: listed here (so it is visible why responses differ),
 * edited in the rewrite rule dialog, grouped, and applied to captured sessions. */
function RewriteRules({ version }: { version: number }) {
  const [rw, setRw] = useState<RwState | null>(null);
  const nonce = useStore((s) => s.arNonce);
  useEffect(() => {
    api.rwGet().then(setRw, () => setRw(null));
  }, [nonce, Math.floor(version / 10)]);
  if (!rw) return null;
  const commit = (next: RwState) =>
    api
      .rwSet(next)
      .then(setRw)
      .catch((e) => say(String(e), "error"));
  const edit = (r?: RwRule) => set({ dialog: { kind: "rewrite-rule", rule: r } });
  if (rw.rules.length === 0)
    return (
      <div className="ar-rewrite-empty muted small">
        {t("Rewrite rules change real requests and responses (JSON values, text, headers, status).")}{" "}
        <button className="linklike" onClick={() => edit()}>
          {t("New rewrite rule…")}
        </button>{" "}
        <button className="linklike" onClick={templateMenu}>
          {t("From template ▾")}
        </button>
      </div>
    );
  const groups = [...new Set(rw.rules.map((r) => r.group).filter(Boolean))];
  const groupOff = (g: string) => rw.disabledGroups.includes(g);
  const setGroup = (g: string, on: boolean) => commit({ ...rw, disabledGroups: on ? rw.disabledGroups.filter((x) => x !== g) : [...rw.disabledGroups, g] });
  const move = (i: number, d: -1 | 1) => {
    const j = i + d;
    if (j < 0 || j >= rw.rules.length) return;
    const rules = [...rw.rules];
    [rules[i], rules[j]] = [rules[j], rules[i]];
    commit({ ...rw, rules });
  };
  const menu = (e: React.MouseEvent, r: RwRule, i: number) => {
    e.preventDefault();
    const selected = [...get().selection];
    showContextMenu(e.clientX, e.clientY, [
      { label: t("Edit…"), action: () => edit(r) },
      { label: r.enabled ? t("Disable") : t("Enable"), action: () => commit({ ...rw, rules: rw.rules.map((x) => (x.id === r.id ? { ...x, enabled: !x.enabled } : x)) }) },
      { label: t("Clone"), action: () => edit({ ...structuredClone(r), id: 0, hits: 0, comment: r.comment ? t("{name} (copy)", { name: r.comment }) : "" }) },
      { separator: true },
      { label: t("Move Up"), disabled: i === 0, action: () => move(i, -1) },
      { label: t("Move Down"), disabled: i === rw.rules.length - 1, action: () => move(i, 1) },
      { separator: true },
      {
        label: plural(selected.length, "Apply to {n} selected session", "Apply to {n} selected sessions"),
        disabled: selected.length === 0,
        action: () =>
          void api.rwApply(selected, [r.id]).then(
            (out) => say(out.created.length ? t("{n} changed copies added to the list", { n: out.created.length }) : t("No rule changed the selected sessions")),
            (err) => say(String(err), "error"),
          ),
      },
      { separator: true },
      { label: t("Remove"), action: () => commit({ ...rw, rules: rw.rules.filter((x) => x.id !== r.id) }) },
    ]);
  };
  return (
    <fieldset className="f-section ar-rewrite">
      <legend>
        <label className="f-check strong">
          <input type="checkbox" checked={rw.enabled} onChange={(e) => commit({ ...rw, enabled: e.target.checked })} /> {t("Rewrite rules (change real traffic)")}
        </label>
      </legend>
      <div className="rw-bar">
        {groups.map((g) => (
          <label
            key={g}
            className={`ar-package ${groupOff(g) ? "off" : ""}`}
            title={t("Switch the rules of this group on or off")}
            onContextMenu={(e) => {
              e.preventDefault();
              showContextMenu(e.clientX, e.clientY, [
                {
                  label: t("Export group {name}…", { name: g }),
                  action: async () => {
                    const p = await save({ defaultPath: `${g.replace(/[^\w.-]+/g, "_")}.json`, filters: [{ name: t("Rewrite rules"), extensions: ["json"] }] });
                    if (!p) return;
                    try {
                      say(plural(await api.rwExport(p, g), "{n} rewrite rule saved", "{n} rewrite rules saved"));
                    } catch (err) {
                      say(String(err), "error");
                    }
                  },
                },
              ]);
            }}
          >
            <input type="checkbox" checked={!groupOff(g)} onChange={(e) => setGroup(g, e.target.checked)} /> {g}
          </label>
        ))}
        <span className="hr-spacer" />
        <label className="muted small" title={t("Largest body a rule changes; larger ones pass unchanged")}>
          {t("max. body (KiB)")}{" "}
          <input type="number" className="rw-max" min={1} max={16384} defaultValue={rw.maxBodyKb} onBlur={(e) => commit({ ...rw, maxBodyKb: Math.max(1, Math.min(16384, Number(e.target.value) || 4096)) })} />
        </label>
        <button onClick={() => edit()}>{t("New rewrite rule…")}</button>
        <button onClick={templateMenu}>{t("From template ▾")}</button>
        <button
          title={t("Add the rewrite rules of a file (exported from Quena)")}
          onClick={async () => {
            const p = await open({ multiple: false, filters: [{ name: t("Rewrite rules"), extensions: ["json"] }] });
            if (typeof p !== "string") return;
            try {
              setRw(await api.rwImport(p));
              say(t("Rewrite rules imported"));
            } catch (e) {
              say(String(e), "error");
            }
          }}
        >
          {t("Import…")}
        </button>
        <button
          title={t("Save the rewrite rules to a file to share (right-click a group chip for one group)")}
          onClick={async () => {
            const p = await save({ defaultPath: "quena-rewrite-rules.json", filters: [{ name: t("Rewrite rules"), extensions: ["json"] }] });
            if (!p) return;
            try {
              say(plural(await api.rwExport(p), "{n} rewrite rule saved", "{n} rewrite rules saved"));
            } catch (e) {
              say(String(e), "error");
            }
          }}
        >
          {t("Export…")}
        </button>
      </div>
      <table className="kv ar-table">
        <thead>
          <tr>
            <th style={{ width: 24 }}></th>
            <th>{t("Name")}</th>
            <th>{t("If request matches…")}</th>
            <th style={{ width: 80 }}>{t("Phase")}</th>
            <th>{t("Changes")}</th>
            <th style={{ width: 52 }}>{t("Hits")}</th>
          </tr>
        </thead>
        <tbody>
          {rw.rules.map((r, i) => {
            const off = !r.enabled || (r.group !== "" && groupOff(r.group));
            return (
              <tr key={r.id} className={off ? "disabled" : ""} onDoubleClick={() => edit(r)} onContextMenu={(e) => menu(e, r, i)} title={t("Double-click to edit, right-click for more")}>
                <td>
                  <input type="checkbox" checked={r.enabled} onChange={(e) => commit({ ...rw, rules: rw.rules.map((x) => (x.id === r.id ? { ...x, enabled: e.target.checked } : x)) })} />
                </td>
                <td>
                  {r.comment || `#${r.id}`}
                  {r.group && <span className="rw-group">{r.group}</span>}
                </td>
                <td className="mono">{r.match}</td>
                <td>{r.phase === "request" ? t("Request") : r.phase === "webSocket" ? "WebSocket" : t("Response")}</td>
                <td className="mono">{r.ops.map(describeOp).join(", ")}</td>
                <td>{r.hits || ""}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </fieldset>
  );
}

export default function AutoResponderPanel() {
  const [st, setSt] = useState<ArState | null>(null);
  const [packages, setPackages] = useState<MockPackage[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  const [edit, setEdit] = useState<{ match: string; action: string; latency: number }>({ match: "", action: "", latency: 0 });
  const [over, setOver] = useState(false);
  const [mapping, setMapping] = useState<{ kind: MappingKind; from: string; to: string; noCreds: boolean } | null>(null);
  const nonce = useStore((s) => s.arNonce);
  const version = useStore((s) => s.listVersion);
  const saveTimer = useRef<number | undefined>(undefined);

  useEffect(() => {
    api.arGet().then(setSt);
    api.mockPackages().then(setPackages, () => setPackages([]));
  }, [nonce]);
  // Refresh hit counters now and then.
  useEffect(() => {
    const t = setTimeout(() => api.arGet().then((s) => setSt((cur) => (cur ? { ...cur, rules: cur.rules.map((r) => ({ ...r, hits: s.rules.find((x) => x.id === r.id)?.hits ?? r.hits })) } : s))), 400);
    return () => clearTimeout(t);
  }, [Math.floor(version / 10)]);

  if (!st) return <div className="placeholder">{t("Loading…")}</div>;

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
  const addMapping = () => {
    if (!mapping) return;
    const r = mapping.kind === "remote" ? mapRemoteRule(mapping.from, mapping.to, mapping.noCreds) : mapLocalRule(mapping.from, mapping.to);
    if ("error" in r) return say(r.error, "error");
    // On top: a mapping is specific, and the first matching rule wins.
    commit({ ...st, enabled: true, rules: [{ id: 0, enabled: true, match: r.match, action: r.action, latencyMs: 0, matchOnce: false, comment: r.comment, hits: 0 }, ...st.rules] }, true);
    say(t("{name} rule added", { name: r.comment }));
    setMapping(null);
  };
  const importPackage = async (replace: boolean) => {
    const p = await open({ multiple: false, filters: [{ name: t("Quena mock package"), extensions: ["quena-mocks", "zip"] }] });
    if (typeof p !== "string") return;
    try {
      mockPackageImported(await api.mockImportPackage(p, replace));
      set({ arNonce: Date.now() });
    } catch (e) {
      say(String(e), "error");
    }
  };
  const removePackage = async (name: string) => {
    if (!(await confirmAsk(t("Remove package"), t("Remove the package {name} with its rules and response files?", { name }), t("Remove")))) return;
    try {
      const n = await api.mockRemovePackage(name);
      say(plural(n, "Package removed ({n} rule)", "Package removed ({n} rules)"));
      set({ arNonce: Date.now() });
    } catch (e) {
      say(String(e), "error");
    }
  };
  const resetSequences = async (name: string) => {
    try {
      const n = await api.mockResetSequences(name);
      say(plural(n, "Package {name}: sequences start again ({n} rule reset)", "Package {name}: sequences start again ({n} rules reset)", { name }));
      set({ arNonce: Date.now() });
    } catch (e) {
      say(String(e), "error");
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
        if (e.dataTransfer.types.includes("quena/sessions") || e.dataTransfer.types.includes("Files")) {
          e.preventDefault();
          setOver(true);
        }
      }}
      onDragLeave={() => setOver(false)}
      onDrop={async (e) => {
        // Files (mock packages, archives) go on to the window's drop handler, which imports
        // packages into Mock Rules and resets the drop highlight.
        setOver(false);
        const ids = JSON.parse(e.dataTransfer.getData("quena/sessions") || "[]") as number[];
        if (!ids.length) return;
        const n = await api.arAddSessions(ids, true);
        say(plural(n, "{n} rule added", "{n} rules added"));
        setSt(await api.arGet());
      }}
    >
      <div className="ar-top">
        <label className="f-check strong">
          <input type="checkbox" checked={st.enabled} onChange={(e) => commit({ ...st, enabled: e.target.checked }, true)} /> {t("Enable rules")}
        </label>
        <label className="f-check">
          <input type="checkbox" checked={st.unmatchedPassthrough} onChange={(e) => commit({ ...st, unmatchedPassthrough: e.target.checked }, true)} /> {t("Unmatched requests passthrough")}
        </label>
        <label className="f-check">
          <input type="checkbox" checked={st.enableLatency} onChange={(e) => commit({ ...st, enableLatency: e.target.checked }, true)} /> {t("Enable Latency")}
        </label>
        <span className="tp-spacer" />
        <button
          onClick={() => {
            setSel(null);
            setEdit({ match: "", action: "", latency: 0 });
          }}
        >
          {t("Add Rule")}
        </button>
        <button
          title={t("Map Remote (forward a URL prefix to another server) or Map Local (serve a folder)")}
          onClick={(e) => {
            const b = e.currentTarget.getBoundingClientRect();
            showContextMenu(b.left, b.bottom, [
              { label: t("Map Remote… (URL prefix → other server)"), action: () => setMapping({ kind: "remote", from: "", to: "", noCreds: true }) },
              { label: t("Map Local… (URL prefix → folder)"), action: () => setMapping({ kind: "local", from: "", to: "", noCreds: false }) },
            ]);
          }}
        >
          {t("Add mapping…")}
        </button>
        <button title={t("Mock rules from the selected or visible sessions; also as Quena mock package or WireMock export")} onClick={() => mocksFromSelection("apply")}>
          {t("Create from sessions…")}
        </button>
        <button
          onClick={(e) => {
            const b = e.currentTarget.getBoundingClientRect();
            showContextMenu(b.left, b.bottom, [
              { label: t("Add to the rules…"), action: () => void importPackage(false) },
              { label: t("Replace all rules…"), action: () => void importPackage(true) },
            ]);
          }}
        >
          {t("Import package…")}
        </button>
        <button
          onClick={async () => {
            const p = await open({ multiple: false, filters: [{ name: t("Mock rules (.farx)"), extensions: ["farx", "xml"] }] });
            if (typeof p !== "string") return;
            try {
              setSt(await api.arImportFarx(p));
              say(t("Rules imported"));
            } catch (e) {
              say(String(e), "error");
            }
          }}
        >
          {t("Import…")}
        </button>
        <button
          onClick={async () => {
            const p = await save({ defaultPath: "quena-rules.farx", filters: [{ name: t("Mock rules (.farx)"), extensions: ["farx"] }] });
            if (!p) return;
            await api.arExportFarx(p);
            say(t("Rules exported to {path}", { path: p }));
          }}
        >
          {t("Export…")}
        </button>
        {packages.length > 0 && (
          <div className="ar-packages">
            <span className="muted">{t("Packages:")}</span>
            {packages.map((p) => (
              <span key={p.name} className="ar-package" title={[p.dir, ...(p.hosts.length ? [t("Hosts: {hosts}", { hosts: p.hosts.join(", ") })] : [])].join("\n")}>
                <span className="mono">{p.name}</span> <span className="muted small">{plural(p.rules, "{n} rule", "{n} rules")}</span>
                {!!p.hosts.length && <span className="muted small mono ar-package-hosts">{p.hosts.slice(0, 2).join(", ") + (p.hosts.length > 2 ? " …" : "")}</span>}
                <button className="ar-package-x" title={t("Reset sequences (start again with the first recorded response)")} aria-label={t("Reset sequences of {name}", { name: p.name })} onClick={() => void resetSequences(p.name)}>
                  ↺
                </button>
                <button className="ar-package-x" title={t("Remove package")} aria-label={t("Remove package {name}", { name: p.name })} onClick={() => void removePackage(p.name)}>
                  ✕
                </button>
              </span>
            ))}
          </div>
        )}
      </div>
      <div className="ar-list">
        <RewriteRules version={version} />
        <table className="kv ar-table">
          <thead>
            <tr>
              <th style={{ width: 24 }}></th>
              <th>{t("If request matches…")}</th>
              <th>{t("then respond with…")}</th>
              <th style={{ width: 72 }}>{t("Latency")}</th>
              <th style={{ width: 52 }}>{t("Hits")}</th>
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
                    { label: r.enabled ? t("Disable") : t("Enable"), action: () => commit({ ...st, rules: st.rules.map((x) => (x.id === r.id ? { ...x, enabled: !x.enabled } : x)) }, true) },
                    { label: t("Match only once"), checked: r.matchOnce, action: () => commit({ ...st, rules: st.rules.map((x) => (x.id === r.id ? { ...x, matchOnce: !x.matchOnce } : x)) }, true) },
                    { label: t("Clone"), action: () => commit({ ...st, rules: [...st.rules, { ...r, id: 0, hits: 0 }] }, true) },
                    { separator: true },
                    { label: t("Move up"), action: () => move(-1) },
                    { label: t("Move down"), action: () => move(1) },
                    { separator: true },
                    { label: t("Remove"), action: () => commit({ ...st, rules: st.rules.filter((x) => x.id !== r.id) }, true) },
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
        {st.rules.length === 0 && <div className="placeholder">{t("No rules. Add one below, or drag sessions from the list here to replay their responses.")}</div>}
      </div>
      {mapping && (
        <fieldset className="f-section ar-editor">
          <legend>{mapping.kind === "remote" ? "Map Remote" : "Map Local"}</legend>
          <div className="f-row">
            <span>{t("From URL prefix")}</span>
            <div className="combo">
              <input
                className="mono"
                autoFocus
                value={mapping.from}
                placeholder={mapping.kind === "remote" ? "https://prod.example.com/api/" : "https://example.com/static/"}
                onChange={(e) => setMapping({ ...mapping, from: e.target.value })}
                onKeyDown={(e) => e.key === "Enter" && addMapping()}
              />
            </div>
          </div>
          <div className="f-row">
            <span>{mapping.kind === "remote" ? t("To URL prefix") : t("Folder")}</span>
            <div className="combo">
              <input
                className="mono"
                value={mapping.to}
                placeholder={mapping.kind === "remote" ? "https://staging.example.com/api/" : "/path/to/folder"}
                onChange={(e) => setMapping({ ...mapping, to: e.target.value })}
                onKeyDown={(e) => e.key === "Enter" && addMapping()}
              />
              {mapping.kind === "local" && (
                <button
                  onClick={async () => {
                    const p = await open({ directory: true, multiple: false });
                    if (typeof p === "string") setMapping({ ...mapping, to: p });
                  }}
                >
                  {t("Choose folder…")}
                </button>
              )}
            </div>
          </div>
          {mapping.kind === "remote" && (
            <label className="f-check" title={t("Adds *nocreds to the rule: Cookie and Authorization meant for the original host are not sent to another host (or from https to http).")}>
              <input type="checkbox" checked={mapping.noCreds} onChange={(e) => setMapping({ ...mapping, noCreds: e.target.checked })} /> {t("Remove credentials (Cookie, Authorization) when the host changes")}
            </label>
          )}
          <div className="btn-row">
            <button className="primary" onClick={addMapping} disabled={!mapping.from.trim() || !mapping.to.trim()}>
              {t("Add")}
            </button>
            <button onClick={() => setMapping(null)}>{t("Cancel")}</button>
            <span className="muted small">
              {mapping.kind === "remote"
                ? t("The rest of the path and the query are kept: …/api/users?id=1 → …/api/users?id=1 on the other server.")
                : t("Serves the file at the rest of the path (index.html for folders), never anything outside the folder.")}
            </span>
          </div>
        </fieldset>
      )}
      <fieldset className="f-section ar-editor">
        <legend>{selected ? t("Rule Editor") : t("New Rule")}</legend>
        <div className="f-row">
          <span>{t("If request matches")}</span>
          <div className="combo">
            <input className="mono" value={edit.match} placeholder={t("e.g. {example}", { example: "regex:(?i)^https://api\\.example\\.com/users" })} onChange={(e) => setEdit({ ...edit, match: e.target.value })} list="ar-match" />
            <datalist id="ar-match">
              {MATCH_TEMPLATES.map((m) => (
                <option key={m} value={m} />
              ))}
            </datalist>
          </div>
        </div>
        <div className="f-row">
          <span>{t("then respond with")}</span>
          <div className="combo">
            <input className="mono" value={edit.action} placeholder={t("*404, file path, dir:/folder, session:12, https://other/…")} onChange={(e) => setEdit({ ...edit, action: e.target.value })} list="ar-action" />
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
              {t("Find a file…")}
            </button>
          </div>
        </div>
        <div className="f-row">
          <span>{t("Latency (ms)")}</span>
          <input type="number" value={edit.latency} onChange={(e) => setEdit({ ...edit, latency: Number(e.target.value) })} style={{ width: 100 }} />
        </div>
        <div className="btn-row">
          <button className="primary" onClick={saveRule} disabled={!edit.match.trim() || !edit.action.trim()}>
            {selected ? t("Save") : t("Add")}
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
              {t("Remove")}
            </button>
          )}
          <span className="muted small">{t("Rules are evaluated top to bottom; the first match wins. regex rules support $1 in the action; after prefix: an https://… target or dir:folder gets the rest of the URL. An https://… target ending in *nocreds drops Cookie and Authorization when the host changes.")}</span>
        </div>
      </fieldset>
    </div>
  );
}
