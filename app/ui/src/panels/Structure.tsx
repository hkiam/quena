// Structure view: the visible sessions as a tree of hosts and paths. Levels are loaded
// lazily from the backend; clicking a node selects its sessions in the list.
import { useCallback, useEffect, useState } from "react";
import { ChevronDown, ChevronRight, Globe } from "lucide-react";
import { api, type TreeNode } from "../api";
import { fmtBytes, fmtInt } from "../lib/format";
import { actions } from "../actions";
import { useStore } from "../store";

interface Level {
  nodes: TreeNode[];
  truncated: boolean;
}

// A level is identified by host + path prefix ("" host for the list of hosts).
const keyOf = (host: string | null, prefix: string) => `${host ?? ""}\u0000${prefix}`;

export function StructurePanel() {
  const version = useStore((s) => s.listVersion);
  const [levels, setLevels] = useState<Map<string, Level>>(new Map());
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState("");
  const [picked, setPicked] = useState<string | null>(null);

  const load = useCallback(async (keys: string[]) => {
    const got = await Promise.all(
      keys.map(async (k) => {
        const [h, p] = k.split("\u0000");
        return [k, await api.structure(h || null, p)] as const;
      }),
    );
    setLevels((old) => {
      const m = new Map(old);
      for (const [k, l] of got) m.set(k, l);
      return m;
    });
  }, []);

  // Reload the root and every open level as traffic comes in (throttled).
  const tick = Math.floor(version / 10);
  useEffect(() => {
    const t = setTimeout(() => void load([keyOf(null, ""), ...open]).catch(() => {}), 150);
    return () => clearTimeout(t);
  }, [tick, open, load]);

  const toggle = (k: string) =>
    setOpen((o) => {
      const n = new Set(o);
      if (n.has(k)) n.delete(k);
      else n.add(k);
      return n;
    });

  const select = async (host: string, path: string) => {
    setPicked(keyOf(host, path));
    await actions.selectIds(await api.structureIds(host, path));
  };

  const root = levels.get(keyOf(null, ""));
  if (!root) return <div className="placeholder">Loading…</div>;
  if (!root.nodes.length) return <div className="placeholder">No sessions to show.</div>;
  const f = filter.trim().toLowerCase();
  const hosts = f ? root.nodes.filter((n) => n.name.toLowerCase().includes(f)) : root.nodes;

  const rows: React.ReactNode[] = [];
  const walk = (host: string, prefix: string, depth: number) => {
    const lvl = levels.get(keyOf(host, prefix));
    if (!lvl) {
      rows.push(<div key={`${host}${prefix}…`} className="st-row muted" style={{ paddingLeft: 8 + depth * 14 }}>Loading…</div>);
      return;
    }
    for (const n of lvl.nodes) {
      const path = prefix + n.name;
      const k = keyOf(host, path);
      const dir = n.name.endsWith("/");
      rows.push(
        <Row key={k} node={n} label={n.name || "(this path)"} depth={depth} open={open.has(k)} expandable={dir && n.hasChildren} picked={picked === k} onToggle={() => toggle(k)} onPick={() => select(host, path)} />,
      );
      if (dir && open.has(k)) walk(host, path, depth + 1);
    }
    if (lvl.truncated) rows.push(<div key={`${host}${prefix}+`} className="st-row muted" style={{ paddingLeft: 8 + depth * 14 }}>… more entries not shown</div>);
  };
  for (const h of hosts) {
    const k = keyOf(h.name, "/");
    rows.push(<Row key={k} node={h} label={h.name} host depth={0} open={open.has(k)} expandable={h.hasChildren} picked={picked === keyOf(h.name, "")} onToggle={() => toggle(k)} onPick={() => select(h.name, "")} />);
    if (open.has(k)) walk(h.name, "/", 1);
  }

  return (
    <div className="structure">
      <div className="st-bar">
        <input className="hv-filter st-filter" placeholder="Filter hosts" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <span className="muted">
          {fmtInt(hosts.length)} host(s){root.truncated ? " (more not shown)" : ""}
        </span>
        <button className="linklike" onClick={() => setOpen(new Set())}>
          Collapse all
        </button>
      </div>
      <div className="scroll st-tree">{rows}</div>
    </div>
  );
}

function Row(p: { node: TreeNode; label: string; depth: number; open: boolean; expandable: boolean; picked: boolean; host?: boolean; onToggle: () => void; onPick: () => void }) {
  const Chev = p.open ? ChevronDown : ChevronRight;
  return (
    <div
      className={`st-row ${p.picked ? "picked" : ""}`}
      style={{ paddingLeft: 4 + p.depth * 14 }}
      onClick={p.onPick}
      onDoubleClick={() => p.expandable && p.onToggle()}
      title={`${fmtInt(p.node.count)} session(s), ${fmtInt(p.node.errors)} error(s), ${fmtBytes(p.node.bytes)} received`}
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
        {p.node.errors > 0 && <span className="st-err">{fmtInt(p.node.errors)} err · </span>}
        {fmtInt(p.node.count)}
      </span>
    </div>
  );
}
