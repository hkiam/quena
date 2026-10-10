// Tools → Compare Captures: two captures in the list (live, or archives loaded into it)
// side by side — new, gone and changed requests.
import { useEffect, useMemo, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, type CaptureDiff, type DiffEntry, type DiffSource, type DiffSourceInfo } from "../api";
import { say } from "../store";
import { actions } from "../actions";
import { compareSessions } from "../panels/compare";
import { importWithPassword } from "../fileActions";
import { MARK, statusText, toMarkdown } from "../lib/capdiff";
import { ARCHIVE_EXTENSIONS, CAPTURE_EXTENSIONS } from "../lib/importFormats";
import { t } from "../i18n";

const key = (s: DiffSource) => JSON.stringify(s);
const KINDS: DiffEntry["kind"][] = ["changed", "added", "removed", "same"];

/** Sides made of chosen sessions (Compare Groups in the session menu). */
function groupSides(groupA?: number[], groupB?: number[]): DiffSourceInfo[] {
  const out: DiffSourceInfo[] = [];
  if (groupA?.length) out.push({ source: { kind: "ids", name: groupA }, label: t("Before: {n} chosen sessions", { n: groupA.length }), sessions: groupA.length });
  if (groupB?.length) out.push({ source: { kind: "ids", name: groupB }, label: t("After: {n} chosen sessions", { n: groupB.length }), sessions: groupB.length });
  return out;
}

export function CaptureDiffPanel({ groupA, groupB }: { groupA?: number[]; groupB?: number[] }) {
  const groups = useMemo(() => groupSides(groupA, groupB), [groupA, groupB]);
  const [sources, setSources] = useState<DiffSourceInfo[]>(groups);
  const [a, setA] = useState<string>(groupA?.length ? key(groups[0].source) : "");
  const [b, setB] = useState<string>(groupB?.length ? key(groups[groups.length - 1].source) : "");
  const [pairBy, setPairBy] = useState<"path" | "url" | "order">("path");
  const [ignoreHeaders, setIgnoreHeaders] = useState("");
  const [diff, setDiff] = useState<CaptureDiff | null>(null);
  const [show, setShow] = useState<Record<string, boolean>>({ changed: true, added: true, removed: true, same: false });
  const [busy, setBusy] = useState(false);
  const [ignoreHost, setIgnoreHost] = useState(false);
  const reload = async () => {
    const s = [...groups, ...(await api.compareSources())];
    setSources(s);
    // The two newest sides by default: the last but one as "before".
    if (s.length >= 2) {
      setA((x) => x || key(s[s.length - 2].source));
      setB((x) => x || key(s[s.length - 1].source));
    }
    return s;
  };
  useEffect(() => {
    void reload();
  }, []);
  const load = async (side: "a" | "b") => {
    const p = await open({ multiple: false, filters: [{ name: t("Session Archive or Packet Capture"), extensions: [...ARCHIVE_EXTENSIONS, ...CAPTURE_EXTENSIONS] }] });
    if (typeof p !== "string") return;
    const before = sources.length;
    try {
      await importWithPassword(p, (pw) => api.importArchive(p, pw));
      // Wait until the import is in the list.
      for (let i = 0; i < 120; i++) {
        await new Promise((r) => setTimeout(r, 250));
        const s = [...groups, ...(await api.compareSources())];
        if (s.length > before) {
          setSources(s);
          (side === "a" ? setA : setB)(key(s[s.length - 1].source));
          return;
        }
      }
    } catch (e) {
      say(String(e), "error");
    }
  };
  const run = async () => {
    if (!a || !b) return;
    setBusy(true);
    try {
      setDiff(await api.compareCaptures(JSON.parse(a), JSON.parse(b), { ignoreHost, pairBy, ignoreHeaders: ignoreHeaders.split(/[;,\s]+/).filter(Boolean) }));
    } catch (e) {
      say(String(e), "error");
    } finally {
      setBusy(false);
    }
  };
  const label = (k: string) => {
    const s = sources.find((x) => key(x.source) === k);
    return s ? (s.source.kind === "live" ? t("Live capture") : s.label) : "?";
  };
  const shown = useMemo(() => diff?.entries.filter((e) => show[e.kind]) ?? [], [diff, show]);
  const side = (value: string, set: (v: string) => void, which: "a" | "b") => (
    <div className="f-row">
      <span>{which === "a" ? t("Before") : t("After")}</span>
      <div className="f-inline">
        <select value={value} onChange={(e) => set(e.target.value)}>
          <option value="">–</option>
          {sources.map((s) => (
            <option key={key(s.source)} value={key(s.source)}>
              {s.source.kind === "live" ? t("Live capture") : s.label} ({s.sessions})
            </option>
          ))}
        </select>
        <button onClick={() => void load(which)}>{t("Load archive…")}</button>
      </div>
    </div>
  );
  return (
    <div className="capdiff">
      <p className="muted small">{t("Compares two captures in the list: what was recorded live, and archives loaded into it. Requests are paired by method, host and path (numbers and ids in the path do not count).")}</p>
      {side(a, setA, "a")}
      {side(b, setB, "b")}
      <label className="f-check" title={t("For two hosts, such as staging and production: requests are paired by method and path only.")}>
        <input type="checkbox" checked={ignoreHost} onChange={(e) => setIgnoreHost(e.target.checked)} /> {t("Ignore host")}
      </label>
      <div className="f-row">
        <span>{t("Pair requests by")}</span>
        <div className="f-inline">
          <select value={pairBy} onChange={(e) => setPairBy(e.target.value as typeof pairBy)}>
            <option value="path">{t("method and path (numbers and ids do not count)")}</option>
            <option value="url">{t("method and exact URL")}</option>
            <option value="order">{t("order (the n-th with the n-th)")}</option>
          </select>
        </div>
      </div>
      <div className="f-row">
        <span>{t("Also ignore headers")}</span>
        <input spellCheck={false} placeholder="X-Request-Id; X-Build" value={ignoreHeaders} onChange={(e) => setIgnoreHeaders(e.target.value)} />
      </div>
      <div className="btn-row">
        <button className="primary" disabled={!a || !b || a === b || busy} onClick={() => void run()}>
          {busy ? t("Comparing…") : t("Compare")}
        </button>
        {diff && (
          <button
            onClick={() => {
              void navigator.clipboard.writeText(toMarkdown(diff, label(a), label(b)));
              say(t("Copied as Markdown"));
            }}
          >
            {t("Copy as Markdown")}
          </button>
        )}
      </div>
      {diff && (
        <>
          <div className="capdiff-counts">
            {KINDS.map((k) => (
              <label key={k} className={`chip capdiff-${k}`}>
                <input type="checkbox" checked={show[k]} onChange={(e) => setShow({ ...show, [k]: e.target.checked })} /> {MARK[k]} {{ changed: t("changed"), added: t("new"), removed: t("gone"), same: t("same") }[k]} {diff.counts[k]}
              </label>
            ))}
            {diff.counts.newErrors > 0 && <b className="err">{t("{n} now fail", { n: diff.counts.newErrors })}</b>}
          </div>
          <div className="capdiff-table">
            <table className="kv">
              <tbody>
                {shown.slice(0, 2000).map((e, i) => (
                  <tr
                    key={i}
                    className={`capdiff-${e.kind} clickable`}
                    title={e.kind === "changed" ? t("Double-click: compare the two sessions") : undefined}
                    onClick={() => {
                      const id = e.idB ?? e.idA;
                      if (id != null) actions.selectIds([id]);
                    }}
                    onDoubleClick={() => e.idA != null && e.idB != null && void compareSessions(e.idA, e.idB)}
                  >
                    <td className="mono">{MARK[e.kind]}</td>
                    <td className="mono small">
                      {e.method} {e.key}
                    </td>
                    <td>{statusText(e)}</td>
                    <td className="small">{e.changes.join(" · ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {shown.length === 0 && <p className="muted">{t("Nothing to show with these filters.")}</p>}
          </div>
        </>
      )}
    </div>
  );
}
