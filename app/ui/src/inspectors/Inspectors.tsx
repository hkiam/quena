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
import { TamperBar, TamperEditor, pausedPart, type TamperEdits } from "./Tamper";
import { SoapView, soapCandidate } from "./Soap";

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
  soap: "SOAP",
};

/** Load the focused session's detail; refresh while it is in flight. */
function useDetail(): Detail | null {
  const focusId = useStore((s) => s.focusId);
  const listVersion = useStore((s) => s.listVersion);
  const gridNonce = useStore((s) => s.gridNonce);
  const [detail, setDetail] = useState<Detail | null>(null);
  const req = useRef(0);
  const live = detail != null && detail.summary.id === focusId && detail.summary.state !== "done" && detail.summary.state !== "aborted";
  useEffect(() => {
    if (focusId == null) {
      setDetail(null);
      return;
    }
    // Immediate load on selection change; trailing-edge debounce (≤ 5 Hz) while in flight,
    // so the final state is never missed.
    const fresh = detail?.summary.id !== focusId;
    const t = window.setTimeout(
      () => {
        const my = ++req.current;
        api.detail(focusId).then((d) => {
          if (my === req.current) setDetail(d);
        });
      },
      fresh ? 0 : 200,
    );
    return () => window.clearTimeout(t);
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

function PluginView({ detail, part, variant, output }: { detail: Detail; part: Part; variant: Variant; output: "text" | "xml" | "json" }) {
  const [wrap, setWrap] = useState(false);
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const fake = { ...info, contentType: output === "xml" ? "application/xml" : output === "json" ? "application/json" : "text/plain", isText: true };
  return (
    <div className="textpane">
      <div />
      <div className="tp-bar">
        <label>
          <input type="checkbox" checked={wrap} onChange={(e) => setWrap(e.target.checked)} /> Wrap
        </label>
        <span className="muted">decoded by plugin · {output}</span>
      </div>
      <div className="tp-body">
        <BodyText id={detail.summary.id} part={part} info={fake} variant={variant} highlight wrap={wrap} />
      </div>
    </div>
  );
}

function Pane({ detail, part, tamper }: { detail: Detail | null; part: Part; tamper?: { edits: TamperEdits; setEdits: (e: TamperEdits) => void } }) {
  const tab = useStore((s) => (part === "request" ? s.layout.requestTab : s.layout.responseTab));
  const decode = useStore((s) => s.settings?.decode ?? true);
  const info0 = detail ? (part === "request" ? detail.requestBody : detail.responseBody) : null;
  const pluginTabs = (info0?.plugins ?? []).map((p) => ({ key: `plugin:${p.variant}`, title: p.tab, p }));
  const soap = detail ? soapCandidate(detail, part) : false;
  const tabs: string[] = [...(part === "request" ? REQUEST_TABS : RESPONSE_TABS), ...(soap ? ["soap"] : []), ...pluginTabs.map((t) => t.key)];
  const setTab = (t: string) => {
    set((s) => ({ layout: { ...s.layout, [part === "request" ? "requestTab" : "responseTab"]: t } }));
    actions.saveLayout();
  };
  let content: React.ReactNode = <div className="placeholder">Select a session to inspect it.</div>;
  if (detail && tamper) {
    content = <TamperEditor detail={detail} part={part} edits={tamper.edits} setEdits={tamper.setEdits} />;
  } else if (detail) {
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
      case "soap":
        content = soap ? <SoapView detail={detail} part={part} /> : <div className="placeholder">Not a SOAP message.</div>;
        break;
      default: {
        const pt = pluginTabs.find((t) => t.key === tab);
        content = pt ? (
          info.len ? (
            <PluginView detail={detail} part={part} variant={pt.p.variant} output={pt.p.output} />
          ) : (
            <div className="placeholder">No body</div>
          )
        ) : (
          <div className="placeholder">This decoder does not apply to this session.</div>
        );
      }
    }
  }
  return (
    <div className="insp-pane">
      <div className="insp-tabs">
        {tabs.map((t) => (
          <div key={t} className={`insp-tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
            {TITLES[t] ?? pluginTabs.find((p) => p.key === t)?.title ?? t}
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
  const paused = pausedPart(detail);
  const [edits, setEdits] = useState<TamperEdits>({ head: null, body: null, file: null });
  const pausedKey = detail && paused ? `${detail.summary.id}:${paused}` : "";
  useEffect(() => setEdits({ head: null, body: null, file: null }), [pausedKey]);
  const tamper = { edits, setEdits };
  return (
    <div className="inspectors">
      {detail && paused ? (
        <TamperBar detail={detail} part={paused} edits={edits} onDone={() => setEdits({ head: null, body: null, file: null })} />
      ) : detail ? (
        <SessionHeader detail={detail} />
      ) : (
        <div className="insp-summary muted">No session selected</div>
      )}
      <div
        className={`insp-split ${stacked ? "stacked" : "side"}`}
        style={stacked ? { gridTemplateRows: `${split * 100}% 5px 1fr` } : { gridTemplateColumns: `${split * 100}% 5px 1fr` }}
      >
        <Pane detail={detail} part="request" tamper={paused === "request" ? tamper : undefined} />
        <Splitter vertical={stacked} onDrag={(f) => set((s) => ({ layout: { ...s.layout, inspectorSplit: f } }))} />
        <Pane detail={detail} part="response" tamper={paused === "response" ? tamper : undefined} />
      </div>
    </div>
  );
}
