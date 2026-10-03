// Navigator left of the session list: the structure (hosts and paths) or the groups (by
// connection, host, process, trace id, session cookie or Custom) of the filtered sessions.
// Clicking an entry narrows the list to it; "All sessions" (or the bar above the list) shows
// everything again. The group-by is the list's own: the list keeps showing its groups.
import { useEffect, useRef, useState } from "react";
import { X } from "lucide-react";
import { api, type GroupBy, type NavGroups } from "../api";
import { actions } from "../actions";
import { useStore } from "../store";
import { StructurePanel } from "./Structure";
import { openMenu } from "../components/contextMenus";
import { fmtBytes, fmtInt } from "../lib/format";
import { plural, t } from "../i18n";

const GROUPS: [Exclude<GroupBy, "none">, string][] = [
  ["connection", t("Connection")],
  ["host", t("Host")],
  ["process", t("Process")],
  ["trace", t("Trace ID")],
  ["session", t("Session cookie")],
  ["custom", t("Custom")],
];
// While traffic flows the groups are reloaded at most this often.
const REFRESH_MS = 1500;
/** Groups rendered before "more" (a busy capture has thousands of connections). */
const SHOW = 500;

export function Navigator() {
  // Until chosen: the groups when the list is grouped, else the structure (groups need a
  // group-by first).
  const mode = useStore((s) => s.layout.navMode ?? (s.layout.groupBy && s.layout.groupBy !== "none" ? "groups" : "structure"));
  const set = (m: "structure" | "groups") => {
    if (m === mode) return;
    void actions.setScope(null);
    actions.showNavigator(true, m);
  };
  return (
    <div className="navigator">
      <div className="nav-head">
        <div className="segmented">
          <button className={`seg ${mode === "groups" ? "active" : ""}`} onClick={() => set("groups")}>
            {t("Groups")}
          </button>
          <button className={`seg ${mode === "structure" ? "active" : ""}`} onClick={() => set("structure")}>
            {t("Structure")}
          </button>
        </div>
        <span className="tp-spacer" />
        <button className="icon-btn" title={t("Hide the navigator")} onClick={() => actions.showNavigator(false)}>
          <X size={13} />
        </button>
      </div>
      {mode === "structure" ? <StructurePanel /> : <GroupList />}
    </div>
  );
}

function GroupList() {
  const by = useStore((s) => s.layout.groupBy ?? "none");
  const version = useStore((s) => s.listVersion);
  const scope = useStore((s) => s.scope?.scope);
  const [data, setData] = useState<NavGroups | null>(null);
  const [filter, setFilter] = useState("");
  const [show, setShow] = useState(SHOW);
  const last = useRef(0);
  const loadedBy = useRef<GroupBy | null>(null);
  const timer = useRef<number | undefined>(undefined);

  // At once when the group-by changes, at most every REFRESH_MS while sessions come in.
  useEffect(() => {
    if (by === "none") {
      loadedBy.current = null;
      return setData(null);
    }
    const changed = loadedBy.current !== by;
    if (changed) setShow(SHOW);
    const load = () => {
      last.current = Date.now();
      // A late answer for the previous group-by is dropped.
      void api.navGroups(by).then(
        (d) => loadedBy.current === by && setData(d),
        () => loadedBy.current === by && setData(null),
      );
    };
    loadedBy.current = by;
    window.clearTimeout(timer.current);
    const wait = changed ? 0 : Math.max(0, last.current + REFRESH_MS - Date.now());
    timer.current = window.setTimeout(load, wait);
    return () => window.clearTimeout(timer.current);
  }, [by, version]);

  // Narrowed to a group of another group-by, setGroup widens the list again.
  const choose = (g: GroupBy) => void actions.setGroup(g);
  const active = (key: string) => scope?.kind === "group" && scope.by === by && scope.key === key;
  const f = filter.trim().toLowerCase();
  const groups = (data?.groups ?? []).filter((g) => !f || g.label.toLowerCase().includes(f));

  return (
    <div className="nav-groups">
      <div className="nav-bar">
        <select value={by} onChange={(e) => choose(e.target.value as GroupBy)} title={t("Group by (also the session list)")}>
          {by === "none" && <option value="none">{t("Group by…")}</option>}
          {GROUPS.map(([k, label]) => (
            <option key={k} value={k}>
              {label}
            </option>
          ))}
        </select>
        {by !== "none" && <input className="hv-filter nav-filter" placeholder={t("Filter groups")} value={filter} spellCheck={false} onChange={(e) => setFilter(e.target.value)} />}
      </div>
      {by === "none" ? (
        <div className="placeholder small">{t("Choose what to group the sessions by: their connection, host, process, trace id, session cookie or Custom column.")}</div>
      ) : (
        <div className="scroll nav-list">
          <div className={`nav-row nav-all ${scope ? "" : "picked"}`} onClick={() => void actions.setScope(null)}>
            <span className="nav-name">{t("All sessions")}</span>
            <span className="nav-count">{data ? fmtInt(data.total) : "…"}</span>
          </div>
          {groups.slice(0, show).map((g) => (
            <div
              key={g.key}
              className={`nav-row ${active(g.key) ? "picked" : ""}`}
              title={t("{sessions}, {errors}, {size} received", { sessions: plural(g.count, "{n} session", "{n} sessions"), errors: plural(g.errors, "{n} error", "{n} errors"), size: fmtBytes(g.bytes) })}
              onClick={() => void actions.setScope(active(g.key) ? null : { kind: "group", by, key: g.key }, g.label)}
              onContextMenu={(e) =>
                openMenu(e, [
                  { label: t("Show Only These Sessions"), checked: active(g.key), action: () => void actions.setScope({ kind: "group", by, key: g.key }, g.label) },
                  { label: t("Select These Sessions"), action: async () => actions.selectIds(await api.navIds({ kind: "group", by, key: g.key })) },
                ])
              }
            >
              <span className="nav-name">{g.label}</span>
              <span className="nav-count">
                {g.errors > 0 && <span className="st-err">{fmtInt(g.errors)} {t("err")} · </span>}
                {fmtInt(g.count)}
              </span>
            </div>
          ))}
          {groups.length > show && (
            <div className="j-more" onClick={() => setShow(show + SHOW)}>
              … {t("{n} more", { n: fmtInt(groups.length - show) })}
            </div>
          )}
          {data && data.ungrouped > 0 && <div className="nav-note muted small">{plural(data.ungrouped, "{n} session in no group", "{n} sessions in no group")}</div>}
          {data?.truncated && <div className="nav-note muted small">{t("… more groups not shown")}</div>}
        </div>
      )}
    </div>
  );
}

/** Above the session list while the navigator narrows it: what to, and a way back. */
export function ScopeBar() {
  const scope = useStore((s) => s.scope);
  const visible = useStore((s) => s.listTotal);
  // Always there (empty without a scope): the list keeps its grid row.
  if (!scope) return <div className="scope-bar" />;
  return (
    <div className="scope-bar">
      <span className="muted">{t("Only")}</span>
      <span className="scope-label" title={scope.label}>
        {scope.label}
      </span>
      <span className="muted">· {plural(visible, "{n} session", "{n} sessions")}</span>
      <span className="tp-spacer" />
      <button className="icon-btn" title={t("Show all sessions")} onClick={() => void actions.setScope(null)}>
        <X size={13} />
      </button>
    </div>
  );
}
