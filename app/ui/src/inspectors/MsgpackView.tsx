// MessagePack inspector: the values of a MessagePack body as a tree, like the JSON tree,
// plus what JSON cannot show (binary, extension types, timestamps, non-string keys).
import { useEffect, useState } from "react";
import { api, type Detail, type MpNode, type Part } from "../api";
import { MoreRows } from "./views";
import { plural, t } from "../i18n";

const NODES = 500;

export function msgpackCandidate(detail: Detail, part: Part): boolean {
  const h = part === "request" ? detail.request.headers : (detail.response?.headers ?? []);
  const ct = (h.find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? "").toLowerCase();
  return ct.includes("msgpack") || ct.includes("messagepack");
}

const CLS: Record<string, string> = { string: "j-str", int: "j-num", float: "j-num", bool: "j-lit", nil: "j-lit" };

function Node({ n, depth }: { n: MpNode; depth: number }) {
  const [open, setOpen] = useState(depth < 2);
  const [limit, setLimit] = useState(NODES);
  const container = n.kind === "map" || n.kind === "array";
  return (
    <div className="j-row">
      {container ? (
        <span className="j-toggle" onClick={() => setOpen(!open)}>
          {open ? "▾" : "▸"}
        </span>
      ) : (
        <span className="j-toggle" />
      )}
      {n.key !== null && <span className="j-key">{n.key}: </span>}
      {container ? <span className="j-meta">{n.value}</span> : <span className={CLS[n.kind] ?? "pb-val"}>{n.kind === "string" ? JSON.stringify(n.value) : n.value}</span>}
      {!["string", "int", "float", "bool", "nil", "map", "array"].includes(n.kind) && <span className="mp-kind">{n.kind}</span>}
      {open && container && (
        <div className="j-children">
          {n.children.slice(0, limit).map((c, i) => (
            <Node key={i} n={c} depth={depth + 1} />
          ))}
          <MoreRows shown={limit} total={n.children.length} onMore={setLimit} step={NODES} />
        </div>
      )}
    </div>
  );
}

export function MsgpackView({ detail, part }: { detail: Detail; part: Part }) {
  const [m, setM] = useState<{ values: MpNode[]; error: string | null; truncated: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const id = detail.summary.id;
  useEffect(() => {
    let alive = true;
    setM(null);
    setError(null);
    api.msgpack(id, part).then(
      (r) => alive && (r ? setM(r) : setError(t("Not MessagePack."))),
      (e) => alive && setError(String(e)),
    );
    return () => {
      alive = false;
    };
  }, [id, part]);
  if (error) return <div className="placeholder">{t("Could not decode: {error}", { error })}</div>;
  if (!m) return <div className="placeholder">{t("Decoding…")}</div>;
  if (m.error && m.values.length === 0) return <div className="placeholder">{m.error}</div>;
  return (
    <div className="scroll pad">
      <div className="muted small">
        MessagePack · {plural(m.values.length, "{n} value", "{n} values")}
        {m.truncated && ` · ${t("not everything shown")}`}
        {m.error && <span className="err"> · {m.error}</span>}
      </div>
      <div className="mono">
        {m.values.map((v, i) => (
          <Node key={i} n={m.values.length > 1 ? { ...v, key: v.key ?? String(i) } : v} depth={0} />
        ))}
      </div>
    </div>
  );
}
