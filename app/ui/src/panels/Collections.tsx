// Composer → Collections: saved requests as `.http` files in the data folder, with
// variables and environments; run one or all, results link to their sessions.
import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, type Collection, type CollectionInfo, type HttpRunResult } from "../api";
import { confirmAsk, promptText, say } from "../store";
import { actions } from "../actions";
import { fromCollectionRequest, moved, type Draft } from "./composerDraft";
import { plural, t } from "../i18n";

const plain = { spellCheck: false, autoCorrect: "off", autoCapitalize: "off" } as const;

/** `@name = value` lines ↔ pairs. */
const varsText = (v: [string, string][]) => v.map(([n, x]) => `${n} = ${x}`).join("\n");
function parseVars(text: string): [string, string][] {
  return text
    .split("\n")
    .map((l) => l.trim().replace(/^@/, ""))
    .filter(Boolean)
    .map((l) => {
      const i = l.indexOf("=");
      return (i < 0 ? [l, ""] : [l.slice(0, i).trim(), l.slice(i + 1).trim()]) as [string, string];
    });
}

function Results({ results, onClose }: { results: { coll: string; items: HttpRunResult[] }; onClose: () => void }) {
  const ok = results.items.filter((r) => r.status != null && r.status < 400 && !r.error).length;
  return (
    <div className="coll-results">
      <div className="coll-results-head">
        <b>{results.coll}</b>
        <span className="muted small">
          {" "}
          · {t("{ok} of {n} succeeded", { ok, n: results.items.length })}
        </span>
        <span className="tp-spacer" />
        <button className="linklike" onClick={onClose}>
          {t("Close")}
        </button>
      </div>
      <table className="kv coll-table">
        <tbody>
          {results.items.map((r, i) => (
            <tr key={i} className={r.session != null ? "clickable" : ""} onClick={() => r.session != null && actions.selectIds([r.session])}>
              <td className={r.error || (r.status ?? 0) >= 400 ? "err" : "ok"}>{r.error ? "✕" : r.pending ? "…" : (r.status ?? "")}</td>
              <td>{r.name ?? r.method}</td>
              <td className="mono small">{r.error ?? r.url}</td>
              <td className="small muted">{r.durationMs != null ? `${r.durationMs} ms` : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function CollectionsView({ env, setEnv, onLoad, nonce }: { env: string; setEnv: (e: string) => void; onLoad: (d: Draft) => void; nonce: number }) {
  const [list, setList] = useState<CollectionInfo[]>([]);
  const [opened, setOpened] = useState<Record<string, Collection>>({});
  const [envs, setEnvs] = useState<string[]>([]);
  const [results, setResults] = useState<{ coll: string; items: HttpRunResult[] } | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [varsEdit, setVarsEdit] = useState<Record<string, string>>({});

  const reload = async () => {
    try {
      const l = await api.collectionsList();
      setList(l);
      const fresh: Record<string, Collection> = {};
      for (const name of Object.keys(opened)) if (l.some((c) => c.name === name)) fresh[name] = await api.collectionRead(name);
      setOpened(fresh);
      if (l[0]) setEnvs((await api.collectionRead(l[0].name)).environments ?? []);
    } catch (e) {
      say(String(e), "error");
    }
  };
  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce]);

  const toggle = async (name: string) => {
    if (opened[name]) {
      const { [name]: _, ...rest } = opened;
      setOpened(rest);
      return;
    }
    try {
      const c = await api.collectionRead(name);
      setOpened({ ...opened, [name]: c });
      setVarsEdit({ ...varsEdit, [name]: varsText(c.variables) });
      setEnvs(c.environments ?? envs);
      (c.warnings ?? []).forEach((w) => say(`${name}: ${w}`, "error"));
    } catch (e) {
      say(String(e), "error");
    }
  };
  const save = async (c: Collection) => {
    try {
      await api.collectionSave(c);
      setOpened({ ...opened, [c.name]: c });
      setList(await api.collectionsList());
    } catch (e) {
      say(String(e), "error");
    }
  };
  const run = async (name: string, names: string[] = []) => {
    setRunning(name);
    try {
      setResults({ coll: name, items: await api.collectionRun(name, names, env) });
    } catch (e) {
      say(String(e), "error");
    } finally {
      setRunning(null);
    }
  };
  const runOne = async (name: string, r: Collection["requests"][number]) => {
    try {
      const res = await api.collectionSend(name, r, env);
      setResults({ coll: name, items: [res] });
      if (res.session != null) actions.selectIds([res.session]);
    } catch (e) {
      say(String(e), "error");
    }
  };
  const create = async () => {
    const name = await promptText(t("New collection"), t("Name"));
    if (!name?.trim()) return;
    if (list.some((c) => c.name === name.trim())) return say(t("A collection named {name} exists already", { name }), "error");
    await save({ name: name.trim(), variables: [], requests: [] });
  };
  const importFile = async () => {
    const p = await open({ multiple: false, filters: [{ name: "HTTP", extensions: ["http", "rest"] }] });
    if (typeof p !== "string") return;
    try {
      const name = await api.collectionImport(p);
      say(t("Imported as collection {name}", { name }));
      await reload();
    } catch (e) {
      say(String(e), "error");
    }
  };
  const rename = async (name: string) => {
    const to = await promptText(t("Rename collection"), t("Name"), name);
    if (!to?.trim() || to.trim() === name) return;
    try {
      await api.collectionRename(name, to.trim());
      const { [name]: c, ...rest } = opened;
      setOpened(c ? { ...rest, [to.trim()]: { ...c, name: to.trim() } } : rest);
      setList(await api.collectionsList());
    } catch (e) {
      say(String(e), "error");
    }
  };
  const remove = async (name: string) => {
    if (!(await confirmAsk(t("Delete collection"), t("Delete the collection {name} and its requests?", { name }), t("Delete")))) return;
    try {
      await api.collectionDelete(name);
      await reload();
    } catch (e) {
      say(String(e), "error");
    }
  };

  return (
    <div className="scroll pad coll">
      <div className="coll-bar">
        <button onClick={() => void create()}>{t("New collection…")}</button>
        <button onClick={() => void importFile()} title={t("Copy a .http file (JetBrains HTTP Client, VS Code REST Client) into the collections")}>
          {t("Import .http…")}
        </button>
        <button onClick={() => void api.collectionsReveal()}>{t("Open folder")}</button>
        <span className="tp-spacer" />
        <label className="small">
          {t("Environment")}{" "}
          <select value={env} onChange={(e) => setEnv(e.target.value)}>
            <option value="">{t("none")}</option>
            {envs.map((e) => (
              <option key={e} value={e}>
                {e}
              </option>
            ))}
            {env && !envs.includes(env) && <option value={env}>{env}</option>}
          </select>
        </label>
      </div>
      {list.length === 0 && <p className="muted">{t("No collections yet. Save a request with “Save to collection…”, or import a .http file.")}</p>}
      {list.map((info) => {
        const c = opened[info.name];
        return (
          <div key={info.name} className="coll-item">
            <div className="coll-head">
              <span className="j-toggle" onClick={() => void toggle(info.name)}>
                {c ? "▾" : "▸"}
              </span>
              <b className="clickable" onClick={() => void toggle(info.name)}>
                {info.name}
              </b>
              <span className="muted small">{plural(info.requests, "{n} request", "{n} requests")}</span>
              <span className="tp-spacer" />
              <button disabled={running != null || info.requests === 0} onClick={() => void run(info.name)}>
                {running === info.name ? t("Running…") : `▶ ${t("Run all")}`}
              </button>
              <button className="linklike" onClick={() => void rename(info.name)}>
                {t("Rename")}
              </button>
              <button className="cc-del" title={t("Delete")} onClick={() => void remove(info.name)}>
                ✕
              </button>
            </div>
            {c && (
              <div className="coll-body">
                {c.requests.map((r, i) => (
                  <div key={i} className="coll-req">
                    <span className="coll-method">{r.method}</span>
                    <span className="coll-name clickable" title={r.url} onClick={() => onLoad(fromCollectionRequest(r, c.name, i))}>
                      {r.name || r.url}
                    </span>
                    {r.version && <span className="muted small">{r.version}</span>}
                    <span className="tp-spacer" />
                    <button title={t("Run")} disabled={running != null} onClick={() => void runOne(c.name, r)}>
                      ▶
                    </button>
                    <button title={t("Move up")} onClick={() => void save({ ...c, requests: moved(c.requests, i, -1) })}>
                      ↑
                    </button>
                    <button title={t("Move down")} onClick={() => void save({ ...c, requests: moved(c.requests, i, 1) })}>
                      ↓
                    </button>
                    <button title={t("Duplicate")} onClick={() => void save({ ...c, requests: [...c.requests.slice(0, i + 1), { ...r, name: r.name ? `${r.name} (2)` : "" }, ...c.requests.slice(i + 1)] })}>
                      ⧉
                    </button>
                    <button className="cc-del" title={t("Remove")} onClick={() => void save({ ...c, requests: c.requests.filter((_, j) => j !== i) })}>
                      ✕
                    </button>
                  </div>
                ))}
                <div className="coll-vars">
                  <span className="small muted">{t("Variables (name = value, one per line; use as {{name}})")}</span>
                  <textarea
                    {...plain}
                    className="mono"
                    rows={Math.min(6, Math.max(2, (varsEdit[c.name] ?? "").split("\n").length))}
                    value={varsEdit[c.name] ?? ""}
                    onChange={(e) => setVarsEdit({ ...varsEdit, [c.name]: e.target.value })}
                    onBlur={() => {
                      const v = parseVars(varsEdit[c.name] ?? "");
                      if (JSON.stringify(v) !== JSON.stringify(c.variables)) void save({ ...c, variables: v });
                    }}
                  />
                </div>
              </div>
            )}
          </div>
        );
      })}
      {results && <Results results={results} onClose={() => setResults(null)} />}
    </div>
  );
}
