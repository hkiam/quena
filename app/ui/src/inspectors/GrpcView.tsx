// gRPC / protobuf inspector (M16): message frames + schemaless field tree.
import { useEffect, useState } from "react";
import { api, type Detail, type Grpc, type PbField, type Part } from "../api";
import { fmtBytes } from "../lib/format";
import { MoreRows } from "./views";
import { plural, t } from "../i18n";

/** Messages / fields rendered before "more" (streams can carry thousands). */
const MSGS = 200;
const FIELDS = 500;

export function grpcCandidate(detail: Detail, part: Part): boolean {
  const h = part === "request" ? detail.request.headers : detail.response?.headers ?? [];
  const ct = (h.find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? "").toLowerCase();
  return ct.startsWith("application/grpc") || ct.includes("protobuf");
}

function Field({ f, depth }: { f: PbField; depth: number }) {
  const [open, setOpen] = useState(depth < 3);
  const [limit, setLimit] = useState(FIELDS);
  const hasKids = (f.children?.length ?? 0) > 0;
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
          {f.children.slice(0, limit).map((c, i) => (
            <Field key={i} f={c} depth={depth + 1} />
          ))}
          <MoreRows shown={limit} total={f.children.length} onMore={setLimit} step={FIELDS} />
        </div>
      )}
    </div>
  );
}

function Fields({ fields }: { fields: PbField[] }) {
  const [limit, setLimit] = useState(FIELDS);
  return (
    <div className="mono">
      {fields.slice(0, limit).map((f, i) => (
        <Field key={i} f={f} depth={0} />
      ))}
      <MoreRows shown={limit} total={fields.length} onMore={setLimit} step={FIELDS} />
    </div>
  );
}

export function GrpcView({ detail, part }: { detail: Detail; part: Part }) {
  const [g, setG] = useState<Grpc | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [limit, setLimit] = useState(MSGS);
  useEffect(() => {
    let alive = true;
    setG(null);
    setError(null);
    setLimit(MSGS);
    api.grpc(detail.summary.id, part).then(
      (r) => alive && setG(r),
      (e) => alive && setError(String(e)),
    );
    return () => {
      alive = false;
    };
  }, [detail.summary.id, part]);
  if (error) return <div className="placeholder">{t("Could not decode: {error}", { error })}</div>;
  if (!g) return <div className="placeholder">{t("Decoding…")}</div>;
  if (g.error && g.messages.length === 0) return <div className="placeholder">{g.error}</div>;
  return (
    <div className="scroll pad grpc">
      <div className="muted small">
        {g.isGrpc ? "gRPC" : "Protobuf"} · {plural(g.messages.length, "{n} message", "{n} messages")}
        {g.status && ` · grpc-status ${g.status}`}
        {g.statusMessage && ` (${g.statusMessage})`}
      </div>
      {g.messages.slice(0, limit).map((m) => (
        <div key={m.index} className="grpc-msg">
          <div className="grpc-msg-head muted">
            {t("Message {index}", { index: m.index })} · {fmtBytes(m.len)}
            {m.compressed && ` · ${t("compressed")}`}
            {m.error && <span className="err"> · {m.error}</span>}
          </div>
          <Fields fields={m.fields ?? []} />
        </div>
      ))}
      <MoreRows shown={limit} total={g.messages.length} onMore={setLimit} step={MSGS} />
    </div>
  );
}
