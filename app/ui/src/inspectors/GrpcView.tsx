// gRPC / protobuf inspector (M16): message frames and their field tree, with field names
// and types when a protobuf schema (.proto files, server reflection) knows the message.
import { useEffect, useState } from "react";
import { api, type Detail, type Grpc, type PbField, type Part, type SchemaStatus } from "../api";
import { say, useStore } from "../store";
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
      {f.name && <span className="pb-name">{f.name}</span>}
      <span className="pb-num">#{f.number}</span>
      <span className="pb-kind">{f.typeName ?? f.kind}</span>
      {!hasKids && <span className="pb-val">{f.value}</span>}
      {hasKids && <span className="pb-meta muted">{f.kind === "message" ? `{${plural(f.children.length, "{n} field", "{n} fields")}}` : f.value}</span>}
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

/** Message types of the schemas, loaded once per settings change. */
let schemaCache: { key: unknown; status: Promise<SchemaStatus> } | null = null;
function schemaStatus(key: unknown): Promise<SchemaStatus> {
  if (!schemaCache || schemaCache.key !== key) schemaCache = { key, status: api.protobufStatus() };
  return schemaCache.status;
}
/** Forget the loaded schema status (after reflection added files). */
export function forgetSchemaStatus() {
  schemaCache = null;
}

export function GrpcView({ detail, part }: { detail: Detail; part: Part }) {
  const [g, setG] = useState<Grpc | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [limit, setLimit] = useState(MSGS);
  const [typeName, setTypeName] = useState("");
  const [types, setTypes] = useState<string[]>([]);
  const [nonce, setNonce] = useState(0);
  const [fetching, setFetching] = useState(false);
  const protobuf = useStore((s) => s.settings?.protobuf);
  const id = detail.summary.id;
  useEffect(() => {
    let alive = true;
    schemaStatus(protobuf).then(
      (st) => alive && setTypes(st.messageTypes),
      () => {},
    );
    return () => {
      alive = false;
    };
  }, [protobuf, nonce]);
  useEffect(() => setTypeName(""), [id, part]);
  useEffect(() => {
    let alive = true;
    setG(null);
    setError(null);
    setLimit(MSGS);
    api.grpc(id, part, typeName || undefined).then(
      (r) => alive && setG(r),
      (e) => alive && setError(String(e)),
    );
    return () => {
      alive = false;
    };
  }, [id, part, typeName, protobuf, nonce]);
  const reflect = async () => {
    setFetching(true);
    try {
      const r = await api.grpcReflect(id);
      forgetSchemaStatus();
      setNonce((n) => n + 1);
      say(t("Schema of {service} fetched ({n} files)", { service: r.service, n: r.files.length }));
    } catch (e) {
      say(String(e), "error");
    } finally {
      setFetching(false);
    }
  };
  if (error) return <div className="placeholder">{t("Could not decode: {error}", { error })}</div>;
  if (!g) return <div className="placeholder">{t("Decoding…")}</div>;
  if (g.error && g.messages.length === 0) return <div className="placeholder">{g.error}</div>;
  return (
    <div className="scroll pad grpc">
      <div className="muted small">
        {g.isGrpc ? "gRPC" : "Protobuf"} · {plural(g.messages.length, "{n} message", "{n} messages")}
        {g.method && <span className="mono"> · {g.method}</span>}
        {g.status && ` · grpc-status ${g.status}`}
        {g.statusMessage && ` (${g.statusMessage})`}
        {g.truncated && ` · ${t("not everything shown")}`}
      </div>
      <div className="grpc-schema small">
        <span className="muted">{t("Schema")}: </span>
        {g.schema ?? <span className="muted">{t("none – field numbers only (.proto files under Options → Bodies & Storage)")}</span>}
        {types.length > 0 && (
          <>
            {" · "}
            <input
              className="mono grpc-type"
              list="grpc-types"
              spellCheck={false}
              autoCorrect="off"
              autoCapitalize="off"
              value={typeName}
              placeholder={t("message type (automatic)")}
              title={t("Decode with this message type instead of the one the method names")}
              onChange={(e) => setTypeName(e.target.value)}
            />
            <datalist id="grpc-types">
              {types.map((x) => (
                <option key={x} value={x} />
              ))}
            </datalist>
          </>
        )}
        {g.isGrpc && g.method && protobuf?.reflection && (
          <button className="linklike" disabled={fetching} title={t("Ask the server for its schema (gRPC server reflection); Quena sends this request itself")} onClick={() => void reflect()}>
            {fetching ? t("Fetching schema…") : t("Fetch schema from server")}
          </button>
        )}
      </div>
      {g.messages.slice(0, limit).map((m) => (
        <div key={m.index} className="grpc-msg">
          <div className="grpc-msg-head muted">
            {t("Message {index}", { index: m.index })} · {fmtBytes(m.len)}
            {m.messageType && <span className="mono"> · {m.messageType}</span>}
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
