// Multipart / MTOM inspector (M17): parts of multipart/related, form-data, mixed.
import { useEffect, useState } from "react";
import { api, bodyUrl, fetchBody, type Detail, type Multipart, type Part } from "../api";
import { fmtBytes } from "../lib/format";
import { decodeText } from "../lib/bodytext";
import { CodeView, langFor } from "./CodeView";
import { save } from "@tauri-apps/plugin-dialog";
import { say } from "../store";
import { MoreRows } from "./views";

/** Parts listed before "more". */
const PARTS = 500;

export function multipartCandidate(detail: Detail, part: Part): boolean {
  const h = part === "request" ? detail.request.headers : detail.response?.headers ?? [];
  const ct = h.find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? "";
  return ct.toLowerCase().startsWith("multipart/");
}

export function MultipartView({ detail, part }: { detail: Detail; part: Part }) {
  const [mp, setMp] = useState<Multipart | null>(null);
  const [sel, setSel] = useState(0);
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [partErr, setPartErr] = useState<string | null>(null);
  const [limit, setLimit] = useState(PARTS);

  useEffect(() => {
    let alive = true;
    setMp(null);
    setError(null);
    setSel(0);
    setLimit(PARTS);
    api.multipart(detail.summary.id, part).then(
      (r) => alive && setMp(r),
      (e) => alive && setError(String(e)),
    );
    return () => {
      alive = false;
    };
  }, [detail.summary.id, part]);

  const p = mp?.parts?.[sel];
  useEffect(() => {
    let alive = true;
    setText(null);
    setPartErr(null);
    if (!p || !p.isText) return;
    fetchBody(detail.summary.id, part, "raw", p.offset, Math.min(p.len, 8 << 20)).then(
      (r) => alive && setText(decodeText(r.data)),
      (e) => alive && setPartErr(String(e)),
    );
    return () => {
      alive = false;
    };
  }, [detail.summary.id, part, p?.offset, p?.len, p?.isText]);

  if (error) return <div className="placeholder">Could not parse the parts: {error}</div>;
  if (!mp) return <div className="placeholder">Parsing…</div>;
  if (mp.error) return <div className="placeholder">Not multipart: {mp.error}</div>;

  return (
    <div className="mpview">
      <div className="mp-info">
        multipart/{mp.subtype} · {mp.parts.length} parts
        {mp.rootType && ` · root ${mp.rootType}`}
      </div>
      <div className="mp-split">
        <div className="mp-list">
          {mp.parts.slice(0, limit).map((pt, i) => (
            <div key={i} className={`mp-part ${sel === i ? "sel" : ""}`} onClick={() => setSel(i)}>
              <div className="mp-part-ct">
                {mp.start && pt.contentId === mp.start ? "★ " : ""}
                {pt.contentType}
              </div>
              <div className="mp-part-meta muted">
                {pt.name && `name=${pt.name} `}
                {pt.filename && `file=${pt.filename} `}
                {pt.contentId && `cid:${pt.contentId} `}
                {fmtBytes(pt.len)}
                {pt.encoding && ` · ${pt.encoding}`}
              </div>
            </div>
          ))}
          <MoreRows shown={limit} total={mp.parts.length} onMore={setLimit} step={PARTS} />
        </div>
        {p && (
          <div className="mp-detail">
            <div className="mp-detail-bar">
              <span className="muted">
                {p.contentType} · {fmtBytes(p.len)}
              </span>
              <span className="tp-spacer" />
              <button
                onClick={async () => {
                  const name = p.filename || p.name || `part-${p.index}`;
                  try {
                    const path = await save({ defaultPath: name });
                    if (!path) return;
                    await api.saveBodyRange(detail.summary.id, part, p.offset, p.len, path);
                    say(`Saved ${name}`);
                  } catch (e) {
                    say(`Save failed: ${String(e)}`);
                  }
                }}
              >
                Save…
              </button>
            </div>
            {p.isText && partErr ? (
              <div className="placeholder">Could not load this part: {partErr}</div>
            ) : p.isText && text == null ? (
              <div className="placeholder">Loading…</div>
            ) : p.isText && text != null ? (
              <CodeView text={text} lang={langFor(p.contentType)} wrap />
            ) : (p.contentType ?? "").startsWith("image/") ? (
              <div className="img-wrap checker">
                <img src={`${bodyUrl(detail.summary.id, part, "raw")}#`} alt="" style={{ display: "none" }} />
                <PartImage id={detail.summary.id} part={part} offset={p.offset} len={p.len} type={p.contentType} />
              </div>
            ) : (
              <div className="placeholder">Binary part ({fmtBytes(p.len)}). Use Save to export it.</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function PartImage({ id, part, offset, len, type }: { id: number; part: Part; offset: number; len: number; type: string }) {
  const [url, setUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let u: string | null = null;
    let alive = true;
    setUrl(null);
    setError(null);
    fetchBody(id, part, "raw", offset, len).then(
      (r) => {
        if (!alive) return;
        const blob = new Blob([r.data.slice().buffer], { type });
        u = URL.createObjectURL(blob);
        setUrl(u);
      },
      (e) => alive && setError(String(e)),
    );
    return () => {
      alive = false;
      if (u) URL.revokeObjectURL(u);
    };
  }, [id, part, offset, len, type]);
  if (error) return <div className="muted">Could not load the image: {error}</div>;
  return url ? <img src={url} alt="attachment" onError={() => setError("not a displayable image")} /> : <div className="muted">Loading…</div>;
}
