// Inspectors tab: request on top, response below (Fiddler Classic).
import { useEffect, useRef, useState } from "react";
import { api, type Detail, type Part, type Variant } from "../api";
import { fmtBytes, fmtInt } from "../lib/format";
import { set, useStore } from "../store";
import { Splitter } from "../App";
import { HeadersView } from "./HeadersView";
import { BodyText } from "./BodyText";
import { HexView } from "./HexView";
import { AuthView, CachingView, CookiesView, ImageView, JsonView, RawView, TransformerView, WebFormsView, WebViewPane, XmlView } from "./views";
import { actions } from "../actions";
import { patchSettings } from "../settingsActions";

const REQUEST_TABS = ["headers", "textview", "syntaxview", "webforms", "hexview", "auth", "cookies", "raw", "json", "xml"] as const;
const RESPONSE_TABS = ["transformer", "headers", "textview", "syntaxview", "imageview", "hexview", "webview", "auth", "caching", "cookies", "raw", "json", "xml"] as const;
const TITLES: Record<string, string> = {
  headers: "Headers",
  textview: "TextView",
  syntaxview: "SyntaxView",
  webforms: "WebForms",
  hexview: "HexView",
  auth: "Auth",
  cookies: "Cookies",
  raw: "Raw",
  json: "JSON",
  xml: "XML",
  transformer: "Transformer",
  imageview: "ImageView",
  webview: "WebView",
  caching: "Caching",
};

/** Load the focused session's detail; refresh while it is in flight. */
function useDetail(): Detail | null {
  const focusId = useStore((s) => s.focusId);
  const listVersion = useStore((s) => s.listVersion);
  const gridNonce = useStore((s) => s.gridNonce);
  const [detail, setDetail] = useState<Detail | null>(null);
  const req = useRef(0);
  const last = useRef(0);
  const live = detail != null && detail.summary.state !== "done" && detail.summary.state !== "aborted";
  useEffect(() => {
    if (focusId == null) {
      setDetail(null);
      return;
    }
    const now = performance.now();
    // Throttle refreshes of in-flight sessions to 4 Hz.
    if (detail?.summary.id === focusId && live && now - last.current < 250) return;
    last.current = now;
    const my = ++req.current;
    api.detail(focusId).then((d) => {
      if (my === req.current) setDetail(d);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusId, gridNonce, live ? listVersion : 0]);
  return focusId == null ? null : detail;
}

function bodyVariant(detail: Detail, part: Part, decode: boolean, pretty: boolean): Variant {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  if (pretty && info.variants.includes("pretty")) return "pretty";
  if (decode && info.variants.includes("decoded")) return "decoded";
  return "raw";
}

function EncodedBanner({ detail, part }: { detail: Detail; part: Part }) {
  const decode = useStore((s) => s.settings?.decode ?? true);
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  if (decode || !info.variants.includes("decoded")) return null;
  return (
    <div className="banner warn" onClick={() => patchSettings((s) => (s.decode = true))}>
      Body is encoded ({info.contentEncoding}). Click to decode (toggles ‘Decode’).
    </div>
  );
}

function TextPane({ detail, part, syntax }: { detail: Detail; part: Part; syntax: boolean }) {
  const decode = useStore((s) => s.settings?.decode ?? true);
  const [wrap, setWrap] = useState(!syntax);
  const [pretty, setPretty] = useState(syntax);
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  if (part === "response" && !detail.response) return <div className="placeholder">No response yet</div>;
  if (!info.len) return <div className="placeholder">{info.complete ? "No body" : "Waiting for body…"}</div>;
  const v = bodyVariant(detail, part, decode, pretty);
  return (
    <div className="textpane">
      <EncodedBanner detail={detail} part={part} />
      <div className="tp-bar">
        <label>
          <input type="checkbox" checked={wrap} onChange={(e) => setWrap(e.target.checked)} /> Wrap
        </label>
        {info.variants.includes("pretty") && (
          <label>
            <input type="checkbox" checked={pretty} onChange={(e) => setPretty(e.target.checked)} /> Format
          </label>
        )}
        <span className="muted">
          {fmtBytes(info.len)}
          {info.truncated ? " (truncated)" : ""} · {v}
        </span>
        <span className="tp-spacer" />
        <button onClick={() => actions.menu(part === "request" ? "file.save-request-body" : "file.save-response-body")}>Save…</button>
      </div>
      <div className="tp-body">
        {info.isText || v !== "raw" ? (
          <BodyText id={detail.summary.id} part={part} info={info} variant={v} highlight={syntax} wrap={wrap} />
        ) : (
          <div className="placeholder">
            Binary content ({info.contentType ?? "unknown type"}, {fmtBytes(info.len)}). Use HexView{info.isImage ? " or ImageView" : ""}.
          </div>
        )}
      </div>
    </div>
  );
}

function Pane({ detail, part }: { detail: Detail | null; part: Part }) {
  const tab = useStore((s) => (part === "request" ? s.layout.requestTab : s.layout.responseTab));
  const decode = useStore((s) => s.settings?.decode ?? true);
  const tabs = part === "request" ? REQUEST_TABS : RESPONSE_TABS;
  const setTab = (t: string) => {
    set((s) => ({ layout: { ...s.layout, [part === "request" ? "requestTab" : "responseTab"]: t } }));
    actions.saveLayout();
  };
  let content: React.ReactNode = <div className="placeholder">Select a session to inspect it.</div>;
  if (detail) {
    const info = part === "request" ? detail.requestBody : detail.responseBody;
    switch (tab) {
      case "headers":
        content = <HeadersView detail={detail} part={part} />;
        break;
      case "textview":
        content = <TextPane detail={detail} part={part} syntax={false} />;
        break;
      case "syntaxview":
        content = <TextPane detail={detail} part={part} syntax />;
        break;
      case "webforms":
        content = <WebFormsView detail={detail} />;
        break;
      case "hexview":
        content = info.len ? <HexView id={detail.summary.id} part={part} variant={bodyVariant(detail, part, decode, false)} len={info.len} /> : <div className="placeholder">No body</div>;
        break;
      case "auth":
        content = <AuthView detail={detail} part={part} />;
        break;
      case "cookies":
        content = <CookiesView detail={detail} part={part} />;
        break;
      case "raw":
        content = <RawView detail={detail} part={part} wrap={false} />;
        break;
      case "json":
        content = <JsonView detail={detail} part={part} />;
        break;
      case "xml":
        content = <XmlView detail={detail} part={part} />;
        break;
      case "transformer":
        content = <TransformerView detail={detail} />;
        break;
      case "imageview":
        content = <ImageView detail={detail} />;
        break;
      case "webview":
        content = <WebViewPane detail={detail} />;
        break;
      case "caching":
        content = <CachingView detail={detail} />;
        break;
    }
  }
  return (
    <div className="insp-pane">
      <div className="insp-tabs">
        {tabs.map((t) => (
          <div key={t} className={`insp-tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
            {TITLES[t]}
          </div>
        ))}
      </div>
      <div className="insp-content">{content}</div>
    </div>
  );
}

function SessionHeader({ detail }: { detail: Detail }) {
  const s = detail.summary;
  return (
    <div className="insp-summary">
      <b>#{s.id}</b> {detail.request.method} <span className="muted">{s.host}</span>
      {s.status ? <span className={s.status >= 400 ? "err" : ""}> · {s.status}</span> : null}
      {s.durationMs != null && <span className="muted"> · {fmtInt(s.durationMs)} ms</span>}
      {s.process && <span className="muted"> · {s.process}</span>}
      {detail.error && <span className="err"> · {detail.error}</span>}
    </div>
  );
}

export function Inspectors() {
  const detail = useDetail();
  const split = useStore((s) => s.layout.inspectorSplit);
  const stacked = useStore((s) => s.layout.stacked);
  return (
    <div className="inspectors">
      {detail ? <SessionHeader detail={detail} /> : <div className="insp-summary muted">No session selected</div>}
      <div
        className={`insp-split ${stacked ? "stacked" : "side"}`}
        style={stacked ? { gridTemplateRows: `${split * 100}% 5px 1fr` } : { gridTemplateColumns: `${split * 100}% 5px 1fr` }}
      >
        <Pane detail={detail} part="request" />
        <Splitter vertical={stacked} onDrag={(f) => set((s) => ({ layout: { ...s.layout, inspectorSplit: f } }))} />
        <Pane detail={detail} part="response" />
      </div>
    </div>
  );
}
