// Structure view: the visible sessions as a tree of hosts and paths. Levels are loaded
// lazily from the backend (all shown levels in one call); clicking a node selects its
// sessions in the list.
import { useCallback, useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Globe } from "lucide-react";
import { api, type TreeNode } from "../api";
import { fmtBytes, fmtInt } from "../lib/format";
import { actions } from "../actions";
import { useStore } from "../store";
import { plural, t } from "../i18n";
import { showContextMenu } from "../components/ContextMenu";
import { sessionMenu } from "../menus";
import { browserMenuWanted } from "../components/contextMenus";

interface Level {
  nodes: TreeNode[];
  truncated: boolean;
}

// A level is identified by host + path prefix ("" host for the list of hosts).
const keyOf = (host: string | null, prefix: string) => `${host ?? ""}\u0000${prefix}`;
// The "(this path)" entry of a folder: its own identity (the folder row has keyOf(host, path)),
// and it selects exactly that path, not everything below it.
const exactKeyOf = (host: string, path: string) => `${keyOf(host, path)}\u0000=`;
// While traffic flows, open levels are refreshed at most this often; expanding loads at once.
const REFRESH_MS = 1500;

export function StructurePanel() {
  const version = useStore((s) => s.listVersion);
  const [levels, setLevels] = useState<Map<string, Level>>(new Map());
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState("");
  const [picked, setPicked] = useState<string | null>(null);

  const load = useCallback(async (keys: string[]) => {
    const got = await api.structure(
      keys.map((k) => {
        const [h, p] = k.split("\u0000");
        return { host: h || null, prefix: p };
      }),
    );
    setLevels((old) => {
      const m = new Map(old);
      keys.forEach((k, i) => got[i] && m.set(k, got[i]));
      return m;
    });
  }, []);

  // The root and every open level, in one backend pass: at once when a node is expanded or
  // collapsed, and at most every REFRESH_MS while traffic comes in.
  const openRef = useRef(open);
  openRef.current = open;
  const lastLoad = useRef(0);
  const timer = useRef<number | undefined>(undefined);
  const refresh = useCallback(() => {
    lastLoad.current = Date.now();
    void load([keyOf(null, ""), ...openRef.current]).catch(() => {});
  }, [load]);
  useEffect(() => {
    window.clearTimeout(timer.current);
    timer.current = undefined;
    refresh();
  }, [open, refresh]);
  useEffect(() => {
    if (timer.current !== undefined) return;
    const wait = Math.max(0, lastLoad.current + REFRESH_MS - Date.now());
    timer.current = window.setTimeout(() => {
      timer.current = undefined;
      refresh();
    }, wait);
  }, [version, refresh]);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const toggle = (k: string) =>
    setOpen((o) => {
      const n = new Set(o);
      if (n.has(k)) n.delete(k);
      else n.add(k);
      return n;
    });

  const select = async (key: string, host: string, path: string, exact = false) => {
    setPicked(key);
    await actions.selectIds(await api.structureIds(host, path, exact));
  };

  const root = levels.get(keyOf(null, ""));
  if (!root) return <div className="placeholder">{t("Loading…")}</div>;
  if (!root.nodes.length) return <div className="placeholder">{t("No sessions to show.")}</div>;
  const f = filter.trim().toLowerCase();
  const hosts = f ? root.nodes.filter((n) => n.name.toLowerCase().includes(f)) : root.nodes;

  const rows: React.ReactNode[] = [];
  const walk = (host: string, prefix: string, depth: number) => {
    const lvl = levels.get(keyOf(host, prefix));
    if (!lvl) {
      rows.push(<div key={`${host}${prefix}…`} className="st-row muted" style={{ paddingLeft: 8 + depth * 14 }}>{t("Loading…")}</div>);
      return;
    }
    for (const n of lvl.nodes) {
      const path = prefix + n.name;
      const exact = n.name === "";
      const k = exact ? exactKeyOf(host, path) : keyOf(host, path);
      const dir = n.name.endsWith("/");
      rows.push(
        <Row key={k} node={n} label={n.name || t("(this path)")} depth={depth} open={open.has(k)} expandable={dir && n.hasChildren} picked={picked === k} onToggle={() => toggle(k)} onPick={() => select(k, host, path, exact)} />,
      );
      if (dir && open.has(k)) walk(host, path, depth + 1);
    }
    if (lvl.truncated) rows.push(<div key={`${host}${prefix}+`} className="st-row muted" style={{ paddingLeft: 8 + depth * 14 }}>{t("… more entries not shown")}</div>);
  };
  for (const h of hosts) {
    const k = keyOf(h.name, "/");
    const hk = keyOf(h.name, "");
    rows.push(<Row key={hk} node={h} label={h.name} host depth={0} open={open.has(k)} expandable={h.hasChildren} picked={picked === hk} onToggle={() => toggle(k)} onPick={() => select(hk, h.name, "")} />);
    if (open.has(k)) walk(h.name, "/", 1);
  }

  return (
    <div className="structure">
      <div className="st-bar">
        <input className="hv-filter st-filter" placeholder={t("Filter hosts")} value={filter} onChange={(e) => setFilter(e.target.value)} />
        <span className="muted">
          {plural(hosts.length, "{n} host", "{n} hosts")}
          {root.truncated ? t(" (more not shown)") : ""}
        </span>
        <button className="linklike" onClick={() => setOpen(new Set())}>
          {t("Collapse all")}
        </button>
      </div>
      <div className="scroll st-tree">{rows}</div>
    </div>
  );
}

function Row(p: { node: TreeNode; label: string; depth: number; open: boolean; expandable: boolean; picked: boolean; host?: boolean; onToggle: () => void; onPick: () => void | Promise<void> }) {
  const Chev = p.open ? ChevronDown : ChevronRight;
  return (
    <div
      className={`st-row ${p.picked ? "picked" : ""}`}
      style={{ paddingLeft: 4 + p.depth * 14 }}
      onClick={p.onPick}
      onContextMenu={(e) => {
        // Select the node's sessions, then offer what the session list offers for them.
        if (browserMenuWanted(e)) return;
        e.preventDefault();
        const { clientX: x, clientY: y } = e;
        void Promise.resolve(p.onPick()).then(() => showContextMenu(x, y, sessionMenu()));
      }}
      onDoubleClick={() => p.expandable && p.onToggle()}
      title={t("{sessions}, {errors}, {size} received", { sessions: plural(p.node.count, "{n} session", "{n} sessions"), errors: plural(p.node.errors, "{n} error", "{n} errors"), size: fmtBytes(p.node.bytes) })}
    >
      <span
        className="st-chev"
        onClick={(e) => {
          e.stopPropagation();
          if (p.expandable) p.onToggle();
        }}
      >
        {p.expandable && <Chev size={12} />}
      </span>
      {p.host && <Globe size={12} className="st-icon" />}
      <span className="st-name">{p.label}</span>
      <span className="st-count">
        {p.node.errors > 0 && <span className="st-err">{fmtInt(p.node.errors)} {t("err")} · </span>}
        {fmtInt(p.node.count)}
      </span>
    </div>
  );
}
