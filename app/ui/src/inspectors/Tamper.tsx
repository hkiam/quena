// Tamper mode: shown while a session is paused at a breakpoint.
import { useEffect, useRef, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, type Detail, type Part, type Resume } from "../api";
import { CodeView, langFor } from "./CodeView";
import { loadText } from "../lib/bodytext";
import { fmtBytes, latin1ToUtf8 } from "../lib/format";
import { requestLine } from "../lib/http";
import { say } from "../store";
import { showContextMenu } from "../components/ContextMenu";

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
}

export function TamperEditor({ detail, part, edits, setEdits }: { detail: Detail; part: Part; edits: TamperEdits; setEdits: (e: TamperEdits) => void }) {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const [body, setBody] = useState<string | null>(null);
  const editable = info.len <= EDIT_LIMIT && (info.isText || info.len === 0) && !info.contentEncoding;
  const initialHead = useRef(headText(detail, part));
  useEffect(() => {
    initialHead.current = headText(detail, part);
    if (editable && info.len) loadText(detail.summary.id, part, info, EDIT_LIMIT, "raw").then(setBody);
    else setBody("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail.summary.id, part]);
  return (
    <div className="tamper">
      <div className="tamper-label">Headers (editable)</div>
      <div className="tamper-head">
        <CodeView text={edits.head ?? initialHead.current} editable wrap onChange={(t) => setEdits({ ...edits, head: t })} />
      </div>
      <div className="tamper-label">
        Body {fmtBytes(info.len)}
        <span className="tp-spacer" />
        {edits.file ? (
          <span className="muted">
            Replaced by {edits.file} <button onClick={() => setEdits({ ...edits, file: null })}>Undo</button>
          </span>
        ) : (
          <button
            onClick={async () => {
              const p = await open({ multiple: false });
              if (typeof p === "string") setEdits({ ...edits, file: p, body: null });
            }}
          >
            Replace with file…
          </button>
        )}
      </div>
      <div className="tamper-body">
        {edits.file ? (
          <div className="placeholder">The body will be replaced by the selected file.</div>
        ) : editable ? (
          body == null ? (
            <div className="placeholder">Loading…</div>
          ) : (
            <CodeView text={edits.body ?? body} editable lang={langFor(info.contentType)} onChange={(t) => setEdits({ ...edits, body: t })} />
          )
        ) : (
          <div className="placeholder">
            The body ({fmtBytes(info.len)}{info.contentEncoding ? `, ${info.contentEncoding}` : ""}) is too large or binary to edit inline. It is forwarded unchanged unless you replace it with a file.
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
      await api.bpResume(id, { ...r, headText: r.headText ?? edits.head, bodyText: r.bodyText ?? edits.body, bodyFile: r.bodyFile ?? edits.file });
      onDone();
    } catch (e) {
      say(String(e), "error");
    }
  };
  return (
    <div className="tamper-bar">
      <span className="tamper-title">⏸ Breakpoint {part === "request" ? "before request" : "after response"}</span>
      {part === "request" && <button onClick={() => resume({ action: "breakOnResponse" })}>Break on Response</button>}
      <button className="primary" onClick={() => resume({ action: "continue" })}>
        Run to Completion
      </button>
      {part === "request" && (
        <button
          onClick={(e) =>
            showContextMenu(
              e.clientX,
              e.clientY + 6,
              [200, 204, 302, 401, 403, 404, 500, 502, 503].map((s) => ({
                label: `Respond ${s}`,
                action: () => resume({ action: "respond", status: s, headText: null, bodyText: "" }),
              })),
            )
          }
        >
          Choose Response ▾
        </button>
      )}
      <button onClick={() => resume({ action: "abort" })}>Abort</button>
      <span className="muted small">Edits apply to the {part}. Content-Length is fixed automatically.</span>
    </div>
  );
}
