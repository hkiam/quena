// Composer (F9): build a request from scratch or from a session.
import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, type ComposeRequest } from "../api";
import { CodeView } from "../inspectors/CodeView";
import { loadText } from "../lib/bodytext";
import { fmtBytes, latin1ToUtf8 } from "../lib/format";
import { say, useStore } from "../store";
import { actions } from "../actions";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"];
const HISTORY_KEY = "quena.composer.history";
const INLINE_BODY_LIMIT = 1 << 20;

interface Draft {
  method: string;
  url: string;
  headers: string;
  body: string;
  bodyFromSession: number | null;
  bodyFromSessionLen: number;
  bodyFile: string | null;
}

const EMPTY: Draft = {
  method: "GET",
  url: "https://",
  headers: "User-Agent: Quena\nAccept: */*",
  body: "",
  bodyFromSession: null,
  bodyFromSessionLen: 0,
  bodyFile: null,
};

function loadHistory(): (Draft & { at: number })[] {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
  } catch {
    return [];
  }
}

function toRaw(d: Draft): string {
  const u = (() => {
    try {
      return new URL(d.url);
    } catch {
      return null;
    }
  })();
  const path = u ? u.pathname + u.search : d.url;
  const hasHost = /^host\s*:/im.test(d.headers);
  return `${d.method} ${u ? d.url : path} HTTP/1.1\n${hasHost || !u ? "" : `Host: ${u.host}\n`}${d.headers.trim()}\n\n${d.body}`;
}

export default function ComposerPanel() {
  const [tab, setTab] = useState<"parsed" | "raw" | "history">("parsed");
  const [d, setD] = useState<Draft>(() => {
    try {
      return { ...EMPTY, ...JSON.parse(localStorage.getItem("quena.composer.draft") ?? "{}") };
    } catch {
      return EMPTY;
    }
  });
  const [raw, setRaw] = useState("");
  const [fixLen, setFixLen] = useState(true);
  const [inspect, setInspect] = useState(true);
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState(loadHistory);
  const [over, setOver] = useState(false);
  const load = useStore((s) => s.composerLoad);

  useEffect(() => {
    try {
      localStorage.setItem("quena.composer.draft", JSON.stringify({ ...d, body: d.body.length < 256 * 1024 ? d.body : "" }));
    } catch {
      /* ignore */
    }
  }, [d]);

  const fromSession = async (id: number) => {
    const det = await api.detail(id);
    if (!det) return;
    const headers = det.request.headers.filter(([k]) => !k.startsWith(":")).map(([k, v]) => `${k}: ${latin1ToUtf8(v)}`).join("\n");
    const big = det.requestBody.len > INLINE_BODY_LIMIT || !det.requestBody.isText;
    const body = big || det.requestBody.len === 0 ? "" : await loadText(id, "request", det.requestBody, INLINE_BODY_LIMIT, "raw");
    setD({
      method: det.request.method,
      url: det.request.url,
      headers,
      body,
      bodyFromSession: big && det.requestBody.len > 0 ? id : null,
      bodyFromSessionLen: det.requestBody.len,
      bodyFile: null,
    });
    setTab("parsed");
    say(`Loaded #${id} into the Composer`);
  };

  useEffect(() => {
    if (load) fromSession(load.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load?.nonce]);

  const execute = async (draft: Draft) => {
    setBusy(true);
    try {
      const req: ComposeRequest = {
        method: draft.method,
        url: draft.url,
        headers: draft.headers,
        body: draft.body,
        bodyFromSession: draft.bodyFromSession,
        bodyFile: draft.bodyFile,
        fixContentLength: fixLen,
      };
      const id = await api.compose(req);
      const h = [{ ...draft, body: draft.body.slice(0, 64 * 1024), at: Date.now() }, ...history.filter((x) => x.url !== draft.url || x.method !== draft.method)].slice(0, 50);
      setHistory(h);
      try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(h));
      } catch {
        /* ignore */
      }
      say(`Request issued as #${id}`);
      if (inspect) {
        setTimeout(() => {
          actions.selectIds([id]);
          actions.showTab("inspectors");
        }, 150);
      }
    } catch (e) {
      say(String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  const executeCurrent = async () => {
    if (tab === "raw") {
      try {
        const p = await api.parseRawRequest(raw);
        const nd = { ...d, method: p.method, url: p.url, headers: p.headers, body: p.body, bodyFromSession: null, bodyFile: null };
        setD(nd);
        await execute(nd);
      } catch (e) {
        say(String(e), "error");
      }
    } else await execute(d);
  };

  return (
    <div
      className={`composer ${over ? "drop" : ""}`}
      onDragOver={(e) => {
        if (e.dataTransfer.types.includes("quena/sessions")) {
          e.preventDefault();
          setOver(true);
        }
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        setOver(false);
        const ids = JSON.parse(e.dataTransfer.getData("quena/sessions") || "[]") as number[];
        if (ids[0]) fromSession(ids[0]);
      }}
    >
      <div className="lt-bar">
        <div className="tabs-inline">
          {(["parsed", "raw", "history"] as const).map((t) => (
            <span
              key={t}
              className={`insp-tab ${tab === t ? "active" : ""}`}
              onClick={() => {
                if (t === "raw" && tab !== "raw") setRaw(toRaw(d));
                setTab(t);
              }}
            >
              {{ parsed: "Parsed", raw: "Raw", history: "History" }[t]}
            </span>
          ))}
        </div>
        <span className="tp-spacer" />
        <label className="f-check">
          <input type="checkbox" checked={fixLen} onChange={(e) => setFixLen(e.target.checked)} /> Fix Content-Length
        </label>
        <label className="f-check">
          <input type="checkbox" checked={inspect} onChange={(e) => setInspect(e.target.checked)} /> Inspect session
        </label>
        <button className="primary" disabled={busy} onClick={executeCurrent}>
          ▶ Execute
        </button>
      </div>
      {tab === "parsed" && (
        <div className="cmp-parsed">
          <div className="cmp-line">
            <select value={d.method} onChange={(e) => setD({ ...d, method: e.target.value })}>
              {METHODS.map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
            <input className="mono" value={d.url} onChange={(e) => setD({ ...d, url: e.target.value })} onKeyDown={(e) => e.key === "Enter" && executeCurrent()} spellCheck={false} />
          </div>
          <div className="cmp-label">Request Headers</div>
          <textarea className="mono cmp-headers" value={d.headers} spellCheck={false} onChange={(e) => setD({ ...d, headers: e.target.value })} />
          <div className="cmp-label">
            Request Body
            <span className="tp-spacer" />
            {d.bodyFromSession != null ? (
              <span className="muted">
                Body of #{d.bodyFromSession} ({fmtBytes(d.bodyFromSessionLen)}) will be sent{" "}
                <button onClick={() => setD({ ...d, bodyFromSession: null })}>Use text instead</button>
              </span>
            ) : d.bodyFile ? (
              <span className="muted">
                File {d.bodyFile} <button onClick={() => setD({ ...d, bodyFile: null })}>Remove</button>
              </span>
            ) : (
              <button
                onClick={async () => {
                  const p = await open({ multiple: false });
                  if (typeof p === "string") setD({ ...d, bodyFile: p });
                }}
              >
                Upload file…
              </button>
            )}
          </div>
          <div className="cmp-body">{d.bodyFromSession == null && !d.bodyFile && <CodeView text={d.body} editable onChange={(t) => setD((x) => ({ ...x, body: t }))} />}</div>
          <div className="muted small">Tip: drag a session from the list onto the Composer to load it.</div>
        </div>
      )}
      {tab === "raw" && (
        <div className="cmp-raw">
          <div className="cmp-raw-bar">
            <span className="muted small">Paste a raw HTTP request, or a cURL command and import it.</span>
            <span className="tp-spacer" />
            <button
              onClick={async () => {
                try {
                  const p = await api.parseCurl(raw);
                  setD((x) => ({ ...x, method: p.method, url: p.url, headers: p.headers, body: p.body, bodyFromSession: null, bodyFile: null }));
                  setTab("parsed");
                  say("Imported cURL command");
                } catch (err) {
                  say(`Not a valid cURL command: ${err}`, "error");
                }
              }}
            >
              Import as cURL
            </button>
          </div>
          <CodeView text={raw} editable onChange={setRaw} />
        </div>
      )}
      {tab === "history" && (
        <div className="scroll pad">
          {history.length === 0 && <div className="muted">No requests issued yet.</div>}
          {history.map((h, i) => (
            <div key={i} className="cmp-hist" onClick={() => setD(h)} onDoubleClick={() => execute(h)} title="Click to load, double-click to execute">
              <b>{h.method}</b> {h.url} <span className="muted small">{new Date(h.at).toLocaleTimeString()}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
