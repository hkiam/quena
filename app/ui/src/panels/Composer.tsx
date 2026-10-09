// Composer (F9): build a request from scratch or from a session.
import { useEffect, useRef, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, type Collection, type ComposeRequest } from "../api";
import { CodeView } from "../inspectors/CodeView";
import { loadBody, sameCharset } from "../lib/bodytext";
import { fmtBytes, latin1ToUtf8 } from "../lib/format";
import { promptText, say, useStore } from "../store";
import { actions } from "../actions";
import { t } from "../i18n";
import { CollectionsView } from "./Collections";
import { defaultName, EMPTY, hasVariables, toCollectionRequest, toRaw, VERSIONS, type Draft } from "./composerDraft";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"];
const HISTORY_KEY = "quena.composer.history";
const INLINE_BODY_LIMIT = 1 << 20;

function loadHistory(): (Draft & { at: number })[] {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
  } catch {
    return [];
  }
}

export default function ComposerPanel() {
  const [tab, setTab] = useState<"parsed" | "raw" | "history" | "collections">("parsed");
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
  const [env, setEnvState] = useState(() => {
    try {
      return localStorage.getItem("quena.composer.env") ?? "";
    } catch {
      return "";
    }
  });
  const setEnv = (e: string) => {
    setEnvState(e);
    try {
      localStorage.setItem("quena.composer.env", e);
    } catch {
      /* ignore */
    }
  };
  const [collNonce, setCollNonce] = useState(0);
  const load = useStore((s) => s.composerLoad);
  // The session whose body the text shows: sent byte for byte as long as the text is unchanged.
  const loaded = useRef<{ id: number; text: string } | null>(null);

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
    const b = big || det.requestBody.len === 0 ? null : await loadBody(id, "request", det.requestBody, INLINE_BODY_LIMIT, "raw");
    const body = b?.text ?? "";
    loaded.current = b ? { id, text: body } : null;
    setD({
      version: "",
      coll: null,
      method: det.request.method,
      url: det.request.url,
      headers,
      body,
      bodyFromSession: big && det.requestBody.len > 0 ? id : null,
      bodyFromSessionLen: det.requestBody.len,
      bodyFile: null,
      // Transcoded text (UTF-16) came as UTF-8; edits go back in the body's own charset.
      bodyCharset: b ? (det.requestBody.charset?.name ?? b.charset) : null,
    });
    setTab("parsed");
    say(t("Loaded #{id} into the Composer", { id }));
  };

  useEffect(() => {
    if (load) fromSession(load.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load?.nonce]);

  const execute = async (draft: Draft) => {
    setBusy(true);
    try {
      // Unchanged text of a session body: send its original bytes (not the text re-encoded).
      const orig = loaded.current;
      const same = orig != null && draft.bodyFromSession == null && !draft.bodyFile && draft.body === orig.text;
      let id: number;
      // With a collection or {{variables}}: substituted like a collection request.
      if ((draft.coll || hasVariables(draft)) && draft.bodyFromSession == null && !same) {
        const res = await api.collectionSend(draft.coll?.name ?? null, toCollectionRequest(draft, draft.coll?.title ?? ""), env);
        if (res.session == null) throw new Error(res.error ?? "not sent");
        id = res.session;
      } else {
      const req: ComposeRequest = {
        method: draft.method,
        url: draft.url,
        headers: draft.headers,
        body: same ? "" : draft.body,
        bodyCharset: draft.bodyCharset ?? null,
        bodyFromSession: same ? orig.id : draft.bodyFromSession,
        bodyFile: draft.bodyFile,
        fixContentLength: fixLen,
        version: (draft.version || null) as ComposeRequest["version"],
      };
      id = await api.compose(req);
      }
      const h = [{ ...draft, body: draft.body.slice(0, 64 * 1024), at: Date.now() }, ...history.filter((x) => x.url !== draft.url || x.method !== draft.method)].slice(0, 50);
      setHistory(h);
      try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(h));
      } catch {
        /* ignore */
      }
      say(t("Request issued as #{id}", { id }));
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

  /** Save the draft into a collection: back where it came from, or (`as`) a chosen one. */
  const saveToCollection = async (as: boolean) => {
    if (d.bodyFromSession != null) return say(t("A session body cannot be saved in a collection; use text or a file."), "error");
    try {
      let name = d.coll?.name ?? "";
      let title = d.coll?.title ?? "";
      let index = d.coll?.index ?? -1;
      if (as || !d.coll) {
        const existing = await api.collectionsList();
        const n = await promptText(t("Save to collection"), t("Collection (existing or new): {names}", { names: existing.map((c) => c.name).join(", ") || "–" }), name || existing[0]?.name || t("My requests"));
        if (!n?.trim()) return;
        const r = await promptText(t("Save to collection"), t("Name of the request"), title || defaultName(d));
        if (r == null) return;
        name = n.trim();
        title = r.trim();
        index = -1;
      }
      // A collection that exists but cannot be read is not replaced by an empty one.
      // (Names compared as the file system may: `api` and `API` are one file on macOS.)
      const found = (await api.collectionsList()).find((x) => x.name.toLowerCase() === name.toLowerCase());
      if (found) name = found.name;
      const c: Collection = found ? await api.collectionRead(name) : { name, variables: [], requests: [] };
      const req = toCollectionRequest(d, title);
      // Back in its place only while that place still holds it (the collection may have been
      // sorted or shortened meanwhile); else appended.
      const same = index >= 0 && index < c.requests.length && c.requests[index].name === title;
      if (index >= 0 && !same) index = -1;
      const requests = same ? c.requests.map((x, i) => (i === index ? req : x)) : [...c.requests, req];
      await api.collectionSave({ ...c, requests });
      setD({ ...d, coll: { name, index: index >= 0 ? index : requests.length - 1, title } });
      setCollNonce((n) => n + 1);
      say(t("Saved to collection {name}", { name }));
    } catch (e) {
      say(String(e), "error");
    }
  };

  const executeCurrent = async () => {
    if (tab === "raw") {
      try {
        const p = await api.parseRawRequest(raw);
        const version = p.version.toUpperCase().startsWith("HTTP/2") ? "HTTP/2" : d.version === "HTTP/2" ? "" : d.version;
        const nd = { ...d, method: p.method, url: p.url, version, headers: p.headers, body: p.body, bodyFromSession: null, bodyFile: null };
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
          {(["parsed", "raw", "history", "collections"] as const).map((k) => (
            <span
              key={k}
              className={`insp-tab ${tab === k ? "active" : ""}`}
              onClick={() => {
                if (k === "raw" && tab !== "raw") setRaw(toRaw(d));
                setTab(k);
              }}
            >
              {{ parsed: t("Parsed"), raw: t("Raw"), history: t("History"), collections: t("Collections") }[k]}
            </span>
          ))}
        </div>
        <span className="tp-spacer" />
        <button title={d.coll ? t("Save back to {name}", { name: d.coll.name }) : t("Save the request in a collection")} onClick={() => void saveToCollection(false)}>
          {d.coll ? t("Save") : t("Save to collection…")}
        </button>
        {d.coll && (
          <button className="linklike" onClick={() => void saveToCollection(true)}>
            {t("Save as…")}
          </button>
        )}
        <label className="f-check">
          <input type="checkbox" checked={fixLen} onChange={(e) => setFixLen(e.target.checked)} /> {t("Fix Content-Length")}
        </label>
        <label className="f-check">
          <input type="checkbox" checked={inspect} onChange={(e) => setInspect(e.target.checked)} /> {t("Inspect session")}
        </label>
        <button className="primary" disabled={busy} onClick={executeCurrent}>
          ▶ {t("Execute")}
        </button>
      </div>
      {tab === "parsed" && (
        <div className={`cmp-parsed ${d.coll ? "with-coll" : ""}`}>
          <div className="cmp-line">
            <select value={d.method} onChange={(e) => setD({ ...d, method: e.target.value })}>
              {(METHODS.includes(d.method) ? METHODS : [d.method, ...METHODS]).map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
            <input className="mono" value={d.url} onChange={(e) => setD({ ...d, url: e.target.value })} onKeyDown={(e) => e.key === "Enter" && executeCurrent()} spellCheck={false} autoCorrect="off" autoCapitalize="off" />
            <select value={d.version ?? ""} title={t("HTTP version: automatic uses what the server offers")} onChange={(e) => setD({ ...d, version: e.target.value })}>
              {VERSIONS.map((v) => (
                <option key={v} value={v}>
                  {v || t("Automatic")}
                </option>
              ))}
            </select>
          </div>
          {d.coll && (
            <div className="muted small">
              {t("From collection {name}: {title}", { name: d.coll.name, title: d.coll.title || d.url })}{" "}
              <button className="linklike" onClick={() => setD({ ...d, coll: null })}>
                {t("Detach")}
              </button>
            </div>
          )}
          <div className="cmp-label">{t("Request Headers")}</div>
          <textarea className="mono cmp-headers" value={d.headers} spellCheck={false} onChange={(e) => setD({ ...d, headers: e.target.value })} />
          <div className="cmp-label">
            {t("Request Body")}
            {d.bodyCharset && !sameCharset(d.bodyCharset, "UTF-8") && d.bodyFromSession == null && !d.bodyFile && (
              <span className="muted small" title={t("Edited text is sent in the charset of the Content-Type, else in this one. Characters it cannot represent make it UTF-8 (the Content-Type is adjusted).")}>
                {" "}
                · {t("shown as {charset}", { charset: d.bodyCharset })}
              </span>
            )}
            <span className="tp-spacer" />
            {d.bodyFromSession != null ? (
              <span className="muted">
                {t("Body of #{id} ({size}) will be sent", { id: d.bodyFromSession, size: fmtBytes(d.bodyFromSessionLen) })}{" "}
                <button onClick={() => setD({ ...d, bodyFromSession: null })}>{t("Use text instead")}</button>
              </span>
            ) : d.bodyFile ? (
              <span className="muted">
                {t("File {name}", { name: d.bodyFile })} <button onClick={() => setD({ ...d, bodyFile: null })}>{t("Remove")}</button>
              </span>
            ) : (
              <button
                onClick={async () => {
                  const p = await open({ multiple: false });
                  if (typeof p === "string") setD({ ...d, bodyFile: p });
                }}
              >
                {t("Upload file…")}
              </button>
            )}
          </div>
          <div className="cmp-body">{d.bodyFromSession == null && !d.bodyFile && <CodeView text={d.body} editable onChange={(t) => setD((x) => ({ ...x, body: t }))} />}</div>
          <div className="muted small">{t("Tip: drag a session from the list onto the Composer to load it.")}</div>
        </div>
      )}
      {tab === "raw" && (
        <div className="cmp-raw">
          <div className="cmp-raw-bar">
            <span className="muted small">{t("Paste a raw HTTP request, or a cURL command and import it.")}</span>
            <span className="tp-spacer" />
            <button
              onClick={async () => {
                try {
                  const p = await api.parseCurl(raw);
                  loaded.current = null;
                  setD((x) => ({ ...x, method: p.method, url: p.url, headers: p.headers, body: p.body, bodyFromSession: null, bodyFile: null, bodyCharset: null }));
                  setTab("parsed");
                  say(t("Imported cURL command"));
                } catch (err) {
                  say(t("Not a valid cURL command: {error}", { error: String(err) }), "error");
                }
              }}
            >
              {t("Import as cURL")}
            </button>
          </div>
          <CodeView text={raw} editable onChange={setRaw} />
        </div>
      )}
      {tab === "collections" && (
        <CollectionsView
          env={env}
          setEnv={setEnv}
          nonce={collNonce}
          onLoad={(nd) => {
            loaded.current = null;
            setD(nd);
            setTab("parsed");
          }}
        />
      )}
      {tab === "history" && (
        <div className="scroll pad">
          {history.length === 0 && <div className="muted">{t("No requests issued yet.")}</div>}
          {history.map((h, i) => (
            <div key={i} className="cmp-hist" onClick={() => {
                loaded.current = null;
                setD(h);
              }}
              onDoubleClick={() => {
                loaded.current = null;
                execute(h);
              }} title={t("Click to load, double-click to execute")}>
              <b>{h.method}</b> {h.url} <span className="muted small">{new Date(h.at).toLocaleTimeString()}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
