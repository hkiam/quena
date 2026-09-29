// Inspect tab: request and response inspectors (side by side or stacked).
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
import { AtomView, atomCandidate } from "./Atom";
import { WebSocketView } from "./WebSocketView";
import { SseView } from "./SseView";
import { MultipartView, multipartCandidate } from "./MultipartView";
import { GrpcView, grpcCandidate } from "./GrpcView";
import { ChevronDown } from "lucide-react";
import { showContextMenu } from "../components/ContextMenu";
import { methodPill, statusPill } from "../grid/style";
import { ErrorBoundary } from "../components/ErrorBoundary";

const REQUEST_TABS = ["headers", "textview", "syntaxview", "webforms", "hexview", "auth", "cookies", "raw", "json", "xml"] as const;
const RESPONSE_TABS = ["transformer", "headers", "textview", "syntaxview", "imageview", "hexview", "webview", "auth", "caching", "cookies", "raw", "json", "xml"] as const;
/** Always-visible segments; everything else sits in the "More" menu. */
const PRIMARY = new Set(["headers", "syntaxview", "imageview", "webview", "cookies", "raw", "websocket", "sse", "grpc", "multipart", "soap"]);
const TITLES: Record<string, string> = {
  headers: "Headers",
  textview: "Plain Text",
  syntaxview: "Body",
  webforms: "Form Data",
  hexview: "Hex",
  auth: "Auth",
  cookies: "Cookies",
  raw: "Raw",
  json: "JSON",
  xml: "XML",
  transformer: "Encoding",
  imageview: "Image",
  webview: "Preview",
  caching: "Caching",
  soap: "SOAP",
  atom: "Atom/OData",
  websocket: "WebSocket",
  sse: "SSE",
  multipart: "Parts",
  grpc: "gRPC",
};

/** Load the focused session's detail; refresh while it is in flight. */
function useDetail(): { detail: Detail | null; error: string | null } {
  const focusId = useStore((s) => s.focusId);
  const listVersion = useStore((s) => s.listVersion);
  const gridNonce = useStore((s) => s.gridNonce);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const req = useRef(0);
  const live = detail != null && detail.summary.id === focusId && detail.summary.state !== "done" && detail.summary.state !== "aborted";
  useEffect(() => {
    if (focusId == null) {
      setDetail(null);
      setError(null);
      return;
    }
    // Immediate load on selection change; trailing-edge debounce (≤ 5 Hz) while in flight,
    // so the final state is never missed.
    const fresh = detail?.summary.id !== focusId;
    const t = window.setTimeout(
      () => {
        const my = ++req.current;
        api.detail(focusId).then(
          (d) => {
            if (my !== req.current) return;
            setDetail(d);
            setError(null);
          },
          (e) => {
            if (my === req.current) setError(String(e));
          },
        );
      },
      fresh ? 0 : 200,
    );
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusId, gridNonce, live ? listVersion : 0]);
  // Never show another session's detail under a failed load.
  if (focusId == null || (error && detail?.summary.id !== focusId)) return { detail: null, error: focusId == null ? null : error };
  return { detail, error: null };
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
            Binary content ({info.contentType ?? "unknown type"}, {fmtBytes(info.len)}). Open {info.isImage ? "Image or " : ""}Hex from the view menu.
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
  let tab = useStore((s) => (part === "request" ? s.layout.requestTab : s.layout.responseTab));
  if (part === "response" && detail?.summary.kind === "webSocket" && !["websocket", "headers", "raw"].includes(tab)) tab = "websocket";
  const decode = useStore((s) => s.settings?.decode ?? true);
  const info0 = detail ? (part === "request" ? detail.requestBody : detail.responseBody) : null;
  const pluginTabs = (info0?.plugins ?? []).map((p) => ({ key: `plugin:${p.variant}`, title: p.tab, p }));
  const soap = detail ? soapCandidate(detail, part) : false;
  const atom = detail ? atomCandidate(detail, part) : false;
  const isWs = part === "response" && detail?.summary.kind === "webSocket";
  const isSse = part === "response" && (detail?.responseBody.contentType ?? "").toLowerCase().includes("text/event-stream");
  const mp = detail ? multipartCandidate(detail, part) : false;
  const grpc = detail ? grpcCandidate(detail, part) : false;
  const special = [isWs ? "websocket" : "", isSse ? "sse" : "", grpc ? "grpc" : "", mp ? "multipart" : "", soap ? "soap" : "", atom ? "atom" : ""].filter(Boolean);
  const tabs: string[] = [...(part === "request" ? REQUEST_TABS : RESPONSE_TABS), ...special, ...pluginTabs.map((t) => t.key)];
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
      case "atom":
        content = atom ? <AtomView detail={detail} part={part} /> : <div className="placeholder">Not an Atom/OData document.</div>;
        break;
      case "grpc":
        content = <GrpcView detail={detail} part={part} />;
        break;
      case "multipart":
        content = <MultipartView detail={detail} part={part} />;
        break;
      case "websocket":
        content = <WebSocketView detail={detail} />;
        break;
      case "sse":
        content = <SseView detail={detail} />;
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
  const isImage = !!detail?.responseBody.isImage;
  const isHtml = (detail?.responseBody.contentType ?? "").toLowerCase().includes("html");
  const primary = tabs.filter(
    (t) => (PRIMARY.has(t) && (t !== "imageview" || isImage) && (t !== "webview" || isHtml)) || t === tab,
  );
  // Content-specific views (SOAP, gRPC, WebSocket …) come right after Headers.
  const rank = (t: string) => (t === "headers" ? 0 : special.includes(t) ? 1 : 2);
  primary.sort((a, b) => rank(a) - rank(b));
  const more = tabs.filter((t) => !primary.includes(t));
  const title = (t: string) => TITLES[t] ?? pluginTabs.find((p) => p.key === t)?.title ?? t;
  const pill = part === "response" && detail ? statusPill(detail.summary) : null;
  const segRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    segRef.current?.querySelector(".seg.active")?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [tab, primary.length]);
  return (
    <div className="insp-pane">
      <div className="insp-head">
        <span className="insp-part">{part === "request" ? "Request" : "Response"}</span>
        {pill && <span className={`pill pill-${pill.tone}`}>{pill.text}</span>}
        <div className="segmented" ref={segRef}>
          {primary.map((t) => (
            <button key={t} className={`seg ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
              {title(t)}
            </button>
          ))}
        </div>
        {more.length > 0 && (
          <button
            className="seg seg-more"
            title="More views"
            onClick={(e) => {
              const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
              showContextMenu(
                r.left,
                r.bottom + 2,
                more.map((t) => ({ label: title(t), action: () => setTab(t) })),
              );
            }}
          >
            More <ChevronDown size={11} />
          </button>
        )}
    </div>
      <div className="insp-content">
        <ErrorBoundary name={`${part} ${tab}`} resetKey={`${detail?.summary.id ?? ""}:${tab}:${tamper ? "tamper" : ""}`}>
          {content}
        </ErrorBoundary>
      </div>
    </div>
  );
}

function SessionHeader({ detail }: { detail: Detail }) {
  const s = detail.summary;
  const method = methodPill(s);
  return (
    <div className="insp-summary">
      {method && <span className={`pill pill-${method.tone}`}>{method.text}</span>}
      <span className="insp-url" title={detail.request.url}>
        {detail.request.url}
      </span>
      <span className="insp-meta">
        #{s.id}
        {s.durationMs != null && ` · ${fmtInt(s.durationMs)} ms`}
        {s.process && ` · ${s.process}`}
      </span>
      {detail.error && <span className="err"> · {detail.error}</span>}
    </div>
  );
}

export function Inspectors() {
  const { detail, error } = useDetail();
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
      ) : error ? (
        <div className="insp-summary err">Could not load session: {error}</div>
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
