// gRPC / protobuf inspector (M16): message frames + schemaless field tree.
import { useEffect, useState } from "react";
import { api, type Detail, type Grpc, type PbField, type Part } from "../api";
import { fmtBytes } from "../lib/format";

export function grpcCandidate(detail: Detail, part: Part): boolean {
  const h = part === "request" ? detail.request.headers : detail.response?.headers ?? [];
  const ct = (h.find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? "").toLowerCase();
  return ct.startsWith("application/grpc") || ct.includes("protobuf");
}

function Field({ f, depth }: { f: PbField; depth: number }) {
  const [open, setOpen] = useState(depth < 3);
  const hasKids = f.children.length > 0;
  return (
    <div className="pb-row">
      {hasKids ? (
        <span className="j-toggle" onClick={() => setOpen(!open)}>
          {open ? "▾" : "▸"}
        </span>
      ) : (
        <span className="j-toggle" />
      )}
      <span className="pb-num">#{f.number}</span>
      <span className="pb-kind">{f.kind}</span>
      {!hasKids && <span className="pb-val">{f.value}</span>}
      {hasKids && <span className="pb-meta muted">{f.value}</span>}
      {open && hasKids && (
        <div className="j-children">
          {f.children.map((c, i) => (
            <Field key={i} f={c} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

export function GrpcView({ detail, part }: { detail: Detail; part: Part }) {
  const [g, setG] = useState<Grpc | null>(null);
  useEffect(() => {
    api.grpc(detail.summary.id, part).then(setG);
  }, [detail.summary.id, part]);
  if (!g) return <div className="placeholder">Decoding…</div>;
  if (g.error && g.messages.length === 0) return <div className="placeholder">{g.error}</div>;
  return (
    <div className="scroll pad grpc">
      <div className="muted small">
        {g.isGrpc ? "gRPC" : "Protobuf"} · {g.messages.length} message{g.messages.length === 1 ? "" : "s"}
        {g.status && ` · grpc-status ${g.status}`}
        {g.statusMessage && ` (${g.statusMessage})`}
      </div>
      {g.messages.map((m) => (
        <div key={m.index} className="grpc-msg">
          <div className="grpc-msg-head muted">
            Message {m.index} · {fmtBytes(m.len)}
            {m.compressed && " · compressed"}
            {m.error && <span className="err"> · {m.error}</span>}
          </div>
          <div className="mono">
            {m.fields.map((f, i) => (
              <Field key={i} f={f} depth={0} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
