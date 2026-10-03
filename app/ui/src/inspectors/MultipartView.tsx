// Multipart / MTOM inspector (M17): parts of multipart/related, form-data, mixed.
import { useEffect, useState } from "react";
import { api, bodyUrl, fetchBody, type Detail, type Multipart, type Part } from "../api";
import { fmtBytes } from "../lib/format";
import { decodeBytes } from "../lib/bodytext";
import { CharsetPicker, useCharsetOverride } from "./CharsetPicker";
import { CodeView, langFor } from "./CodeView";
import { save } from "@tauri-apps/plugin-dialog";
import { say } from "../store";
import { MoreRows } from "./views";
import { plural, t } from "../i18n";
import { openMenu } from "../components/contextMenus";
import { copyItem } from "./inspectMenus";

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
  // Each part has its own charset (its Content-Type, BOM, declaration) and its own override.
  const [override, setOverride] = useCharsetOverride(detail.summary.id, `${part}:part${p?.index ?? sel}`);
  const charset = override ?? p?.charset?.name ?? "UTF-8";
  useEffect(() => {
    let alive = true;
    setText(null);
    setPartErr(null);
    if (!p || !p.isText) return;
    fetchBody(detail.summary.id, part, "raw", p.offset, Math.min(p.len, 8 << 20)).then(
      (r) => alive && setText(decodeBytes(r.data, charset)),
      (e) => alive && setPartErr(String(e)),
    );
    return () => {
      alive = false;
    };
  }, [detail.summary.id, part, p?.offset, p?.len, p?.isText, charset]);

  const savePart = async (p: Multipart["parts"][number]) => {
    const name = p.filename || p.name || `part-${p.index}`;
    try {
      const path = await save({ defaultPath: name });
      if (!path) return;
      await api.saveBodyRange(detail.summary.id, part, p.offset, p.len, path);
      say(t("Saved {name}", { name }));
    } catch (e) {
      say(t("Save failed: {error}", { error: String(e) }));
    }
  };
  if (error) return <div className="placeholder">{t("Could not parse the parts: {error}", { error })}</div>;
  if (!mp) return <div className="placeholder">{t("Parsing…")}</div>;
  if (mp.error) return <div className="placeholder">{t("Not multipart: {error}", { error: mp.error })}</div>;

  return (
    <div className="mpview">
      <div className="mp-info">
        multipart/{mp.subtype} · {plural(mp.parts.length, "{n} part", "{n} parts")}
        {mp.rootType && ` · root ${mp.rootType}`}
      </div>
      <div className="mp-split">
        <div className="mp-list">
          {mp.parts.slice(0, limit).map((pt, i) => (
            <div
              key={i}
              className={`mp-part ${sel === i ? "sel" : ""}`}
              onClick={() => setSel(i)}
              onContextMenu={(e) => {
                setSel(i);
                openMenu(e, [{ label: t("Save Part…"), action: () => void savePart(pt) }, ...(pt.contentId ? [copyItem(t("Copy Content-ID"), pt.contentId)] : [])]);
              }}
            >
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
              {p.isText && p.charset && <CharsetPicker detected={p.charset} value={override} onChange={setOverride} />}
              <button onClick={() => void savePart(p)}>
                {t("Save…")}
              </button>
            </div>
            {p.isText && partErr ? (
              <div className="placeholder">{t("Could not load this part: {error}", { error: partErr })}</div>
            ) : p.isText && text == null ? (
              <div className="placeholder">{t("Loading…")}</div>
            ) : p.isText && text != null ? (
              <CodeView text={text} lang={langFor(p.contentType)} wrap />
            ) : (p.contentType ?? "").startsWith("image/") ? (
              <div className="img-wrap checker">
                <img src={`${bodyUrl(detail.summary.id, part, "raw")}#`} alt="" style={{ display: "none" }} />
                <PartImage id={detail.summary.id} part={part} offset={p.offset} len={p.len} type={p.contentType} />
              </div>
            ) : (
              <div className="placeholder">{t("Binary part ({size}). Use Save to export it.", { size: fmtBytes(p.len) })}</div>
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
  if (error) return <div className="muted">{t("Could not load the image: {error}", { error })}</div>;
  return url ? <img src={url} alt="attachment" onError={() => setError(t("not a displayable image"))} /> : <div className="muted">{t("Loading…")}</div>;
}
