// Tamper mode: shown while a session is paused at a breakpoint.
import { useEffect, useRef, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, type Detail, type Part, type Resume } from "../api";
import { CodeView, langFor } from "./CodeView";
import { loadBody } from "../lib/bodytext";
import { useCharsetOverride } from "./CharsetPicker";
import { fmtBytes, latin1ToUtf8 } from "../lib/format";
import { requestLine } from "../lib/http";
import { say } from "../store";
import { showContextMenu } from "../components/ContextMenu";
import { t } from "../i18n";

const EDIT_LIMIT = 1 << 20;

export function pausedPart(d: Detail | null): Part | null {
  if (!d) return null;
  if (d.summary.state === "breakpointRequest") return "request";
  if (d.summary.state === "breakpointResponse") return "response";
  return null;
}

function headText(d: Detail, part: Part): string {
  if (part === "request") {
    return [requestLine(d), ...d.request.headers.filter(([k]) => !k.startsWith(":")).map(([k, v]) => `${k}: ${latin1ToUtf8(v)}`)].join("\n");
  }
  const r = d.response!;
  return [`${r.version === "HTTP/2" ? "HTTP/1.1" : r.version} ${r.status} ${r.reason}`, ...r.headers.map(([k, v]) => `${k}: ${latin1ToUtf8(v)}`)].join("\n");
}

/** Edit state shared between the editor and the action bar. */
export interface TamperEdits {
  head: string | null;
  body: string | null;
  file: string | null;
  /** Charset the body text is shown in: an edited body is encoded in the declared charset,
   * else in this one (the core switches to UTF-8 and says so in the Content-Type if the text
   * does not fit). Unedited bodies are forwarded byte for byte. */
  charset?: string | null;
}

export function TamperEditor({ detail, part, edits, setEdits }: { detail: Detail; part: Part; edits: TamperEdits; setEdits: (e: TamperEdits) => void }) {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const [body, setBody] = useState<string | null>(null);
  const [charset, setCharset] = useState<string | null>(null);
  const [override] = useCharsetOverride(detail.summary.id, part);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const editable = info.len <= EDIT_LIMIT && (info.isText || info.len === 0) && !info.contentEncoding;
  const initialHead = useRef(headText(detail, part));
  useEffect(() => {
    initialHead.current = headText(detail, part);
    setLoadErr(null);
    if (editable && info.len)
      loadBody(detail.summary.id, part, info, EDIT_LIMIT, "raw", override).then(
        (b) => {
          setBody(b.text);
          // Transcoded text (UTF-16) is shown from UTF-8; it goes back in the body's own charset.
          setCharset(override ?? info.charset?.name ?? b.charset);
        },
        (e) => setLoadErr(String(e)),
      );
    else setBody("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail.summary.id, part, override]);
  return (
    <div className="tamper">
      <div className="tamper-label">{t("Headers (editable)")}</div>
      <div className="tamper-head">
        <CodeView text={edits.head ?? initialHead.current} editable wrap onChange={(s) => setEdits({ ...edits, head: s })} />
      </div>
      <div className="tamper-label">
        {t("Body {size}", { size: fmtBytes(info.len) })}
        <span className="tp-spacer" />
        {edits.file ? (
          <span className="muted">
            {t("Replaced by {file}", { file: edits.file })} <button onClick={() => setEdits({ ...edits, file: null })}>{t("Undo")}</button>
          </span>
        ) : (
          <button
            onClick={async () => {
              const p = await open({ multiple: false });
              if (typeof p === "string") setEdits({ ...edits, file: p, body: null });
            }}
          >
            {t("Replace with file…")}
          </button>
        )}
      </div>
      <div className="tamper-body">
        {edits.file ? (
          <div className="placeholder">{t("The body will be replaced by the selected file.")}</div>
        ) : editable ? (
          loadErr ? (
            <div className="placeholder">{t("Could not load the body ({error}). It is forwarded unchanged unless you replace it with a file.", { error: loadErr })}</div>
          ) : body == null ? (
            <div className="placeholder">{t("Loading…")}</div>
          ) : (
            <CodeView text={edits.body ?? body} editable lang={langFor(info.contentType)} onChange={(s) => setEdits({ ...edits, body: s, charset })} />
          )
        ) : (
          <div className="placeholder">
            {t("The body ({size}) is too large or binary to edit inline. It is forwarded unchanged unless you replace it with a file.", { size: `${fmtBytes(info.len)}${info.contentEncoding ? `, ${info.contentEncoding}` : ""}` })}
          </div>
        )}
      </div>
    </div>
  );
}

export function TamperBar({ detail, part, edits, onDone }: { detail: Detail; part: Part; edits: TamperEdits; onDone: () => void }) {
  const id = detail.summary.id;
  const resume = async (r: Resume) => {
    try {
      await api.bpResume(id, { ...r, headText: r.headText ?? edits.head, bodyText: r.bodyText ?? edits.body, bodyCharset: r.bodyText != null ? null : edits.charset ?? null, bodyFile: r.bodyFile ?? edits.file });
      onDone();
    } catch (e) {
      say(String(e), "error");
    }
  };
  return (
    <div className="tamper-bar">
      <span className="tamper-title">⏸ {part === "request" ? t("Breakpoint before request") : t("Breakpoint after response")}</span>
      {part === "request" && <button onClick={() => resume({ action: "breakOnResponse" })}>{t("Break on Response")}</button>}
      <button className="primary" onClick={() => resume({ action: "continue" })}>
        {t("Run to Completion")}
      </button>
      {part === "request" && (
        <button
          onClick={(e) =>
            showContextMenu(
              e.clientX,
              e.clientY + 6,
              [200, 204, 302, 401, 403, 404, 500, 502, 503].map((s) => ({
                label: t("Respond {status}", { status: s }),
                action: () => resume({ action: "respond", status: s, headText: null, bodyText: "" }),
              })),
            )
          }
        >
          {t("Choose Response")} ▾
        </button>
      )}
      <button onClick={() => resume({ action: "abort" })}>{t("Abort")}</button>
      <span className="muted small">{part === "request" ? t("Edits apply to the request. Content-Length is fixed automatically.") : t("Edits apply to the response. Content-Length is fixed automatically.")}</span>
    </div>
  );
}
