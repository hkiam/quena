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

export function CaptureDiffPanel() {
  const [sources, setSources] = useState<DiffSourceInfo[]>([]);
  const [a, setA] = useState<string>("");
  const [b, setB] = useState<string>("");
  const [diff, setDiff] = useState<CaptureDiff | null>(null);
  const [show, setShow] = useState<Record<string, boolean>>({ changed: true, added: true, removed: true, same: false });
  const [busy, setBusy] = useState(false);
  const reload = async () => {
    const s = await api.compareSources();
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
        const s = await api.compareSources();
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
      setDiff(await api.compareCaptures(JSON.parse(a), JSON.parse(b)));
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
