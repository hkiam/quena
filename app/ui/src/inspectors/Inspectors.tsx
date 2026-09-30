// Inspect tab: request and response inspectors (side by side or stacked).
import { useEffect, useRef, useState } from "react";
import { api, type Detail, type Part, type Variant } from "../api";
import { fmtBytes, fmtInt } from "../lib/format";
import { get, set, useStore } from "../store";
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
import { ViewTabs } from "./ViewTabs";
import { defaultView, orderViews, viewFamily } from "./viewChoice";
import { methodPill, statusPill } from "../grid/style";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { CharsetPicker, useCharsetOverride } from "./CharsetPicker";
import { effectiveCharset, textVariant } from "../lib/bodytext";
import { t } from "../i18n";

const REQUEST_TABS = ["headers", "textview", "syntaxview", "webforms", "hexview", "auth", "cookies", "raw", "json", "xml"] as const;
const RESPONSE_TABS = ["transformer", "headers", "textview", "syntaxview", "imageview", "hexview", "webview", "auth", "caching", "cookies", "raw", "json", "xml"] as const;
const TITLES: Record<string, string> = {
  headers: t("Headers"),
  textview: t("Plain Text"),
  syntaxview: t("Body"),
  webforms: t("Form Data"),
  hexview: "Hex",
  auth: t("Auth"),
  cookies: t("Cookies"),
  raw: t("Raw"),
  json: "JSON",
  xml: "XML",
  transformer: t("Encoding"),
  imageview: t("Image"),
  webview: t("Preview"),
  caching: t("Caching"),
  soap: "SOAP",
  atom: "Atom/OData",
  websocket: "WebSocket",
  sse: "SSE",
  multipart: t("Parts"),
  grpc: "gRPC",
};

/** Body variants as shown in the text view's status line. */
const VARIANT_LABELS: Record<string, string> = { raw: t("raw"), decoded: t("decoded"), pretty: t("formatted") };

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
      {t("Body is encoded ({encoding}). Click to decode (toggles ‘Decode’).", { encoding: info.contentEncoding ?? "" })}
    </div>
  );
}

function TextPane({ detail, part, syntax }: { detail: Detail; part: Part; syntax: boolean }) {
  const decode = useStore((s) => s.settings?.decode ?? true);
  const [wrap, setWrap] = useState(!syntax);
  const [pretty, setPretty] = useState(syntax);
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const [override, setOverride] = useCharsetOverride(detail.summary.id, part);
  if (part === "response" && !detail.response) return <div className="placeholder">{t("No response yet")}</div>;
  if (!info.len) return <div className="placeholder">{info.complete ? t("No body") : t("Waiting for body…")}</div>;
  const want = bodyVariant(detail, part, decode, pretty);
  const text = info.isText || want !== "raw";
  const v = text && info.charset ? textVariant(info, want, override) : want;
  return (
    <div className="textpane">
      <EncodedBanner detail={detail} part={part} />
      <div className="tp-bar">
        <label>
          <input type="checkbox" checked={wrap} onChange={(e) => setWrap(e.target.checked)} /> {t("Wrap")}
        </label>
        {info.variants.includes("pretty") && (
          <label>
            <input type="checkbox" checked={pretty} onChange={(e) => setPretty(e.target.checked)} /> {t("Format")}
          </label>
        )}
        <span className="muted">
          {fmtBytes(info.len)}
          {info.truncated ? ` ${t("(truncated)")}` : ""} · {VARIANT_LABELS[v.startsWith("text:") ? "decoded" : v] ?? v}
        </span>
        <span className="tp-spacer" />
        {text && info.charset && <CharsetPicker detected={info.charset} value={override} onChange={setOverride} />}
        <button onClick={() => actions.menu(part === "request" ? "file.save-request-body" : "file.save-response-body")}>{t("Save…")}</button>
      </div>
      <div className="tp-body">
        {text ? (
          <BodyText id={detail.summary.id} part={part} info={info} variant={v} highlight={syntax} wrap={wrap} charset={effectiveCharset(info, override)} />
        ) : (
          <div className="placeholder">
            {info.isImage
              ? t("Binary content ({type}, {size}). Open Image or Hex from the view menu.", { type: info.contentType ?? t("unknown type"), size: fmtBytes(info.len) })
              : t("Binary content ({type}, {size}). Open Hex from the view menu.", { type: info.contentType ?? t("unknown type"), size: fmtBytes(info.len) })}
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
          <input type="checkbox" checked={wrap} onChange={(e) => setWrap(e.target.checked)} /> {t("Wrap")}
        </label>
        <span className="muted">
          {t("decoded by plugin")} · {output}
        </span>
      </div>
      <div className="tp-body">
        <BodyText id={detail.summary.id} part={part} info={fake} variant={variant} highlight wrap={wrap} />
      </div>
    </div>
  );
}

function Pane({ detail, part, tamper }: { detail: Detail | null; part: Part; tamper?: { edits: TamperEdits; setEdits: (e: TamperEdits) => void } }) {
  const globalTab = useStore((s) => (part === "request" ? s.layout.requestTab : s.layout.responseTab));
  const remember = useStore((s) => s.layout.rememberViews ?? true);
  const viewByType = useStore((s) => s.layout.viewByType);
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
  const family = detail ? viewFamily(detail, part, special, pluginTabs.map((t) => t.key)) : null;
  const memoKey = family ? `${part}:${family}` : null;
  // The view for this message: remembered for its kind of content, else a sensible default;
  // with remembering off, the last view chosen anywhere (the classic behaviour).
  let tab: string;
  if (remember && memoKey && family) {
    const chosen = viewByType?.[memoKey];
    tab = chosen && tabs.includes(chosen) ? chosen : defaultView(family, part, tabs);
  } else {
    tab = globalTab;
    if (part === "response" && detail?.summary.kind === "webSocket" && !["websocket", "headers", "raw"].includes(tab)) tab = "websocket";
  }
  if (detail && !tabs.includes(tab)) tab = "headers";
  const setTab = (t: string) => {
    set((s) => ({
      layout: {
        ...s.layout,
        [part === "request" ? "requestTab" : "responseTab"]: t,
        ...(remember && memoKey ? { viewByType: { ...(s.layout.viewByType ?? {}), [memoKey]: t } } : {}),
      },
    }));
    actions.saveLayout();
  };
  let content: React.ReactNode = <div className="placeholder">{t("Select a session to inspect it.")}</div>;
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
        content = info.len ? <HexView id={detail.summary.id} part={part} variant={bodyVariant(detail, part, decode, false)} len={info.len} /> : <div className="placeholder">{t("No body")}</div>;
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
        content = atom ? <AtomView detail={detail} part={part} /> : <div className="placeholder">{t("Not an Atom/OData document.")}</div>;
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
        content = soap ? <SoapView detail={detail} part={part} /> : <div className="placeholder">{t("Not a SOAP message.")}</div>;
        break;
      default: {
        const pt = pluginTabs.find((t) => t.key === tab);
        content = pt ? (
          info.len ? (
            <PluginView detail={detail} part={part} variant={pt.p.variant} output={pt.p.output} />
          ) : (
            <div className="placeholder">{t("No body")}</div>
          )
        ) : (
          <div className="placeholder">{t("This decoder does not apply to this session.")}</div>
        );
      }
    }
  }
  const views = orderViews(tabs, special, family);
  const title = (t: string) => TITLES[t] ?? pluginTabs.find((p) => p.key === t)?.title ?? t;
  const pill = part === "response" && detail ? statusPill(detail.summary) : null;
  return (
    <div className="insp-pane">
      <div className="insp-head">
        <span className="insp-part">{part === "request" ? t("Request") : t("Response")}</span>
        {pill && <span className={`pill pill-${pill.tone}`}>{pill.text}</span>}
        <ViewTabs views={views} active={tab} title={title} onSelect={setTab} />
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

/** Below this width, request and response go above each other even in the side-by-side
 * layout: two columns of ~300 px would cut tabs, toolbars and header values. */
const SIDE_BY_SIDE_MIN = 760;

export function Inspectors() {
  const { detail, error } = useDetail();
  const split = useStore((s) => s.layout.inspectorSplit);
  const stackedPref = useStore((s) => s.layout.stacked);
  const root = useRef<HTMLDivElement>(null);
  const [narrow, setNarrow] = useState(false);
  useEffect(() => {
    const el = root.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setNarrow(e.contentRect.width < SIDE_BY_SIDE_MIN));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const stacked = stackedPref || narrow;
  // Charsets chosen for a session's bodies apply until another session is shown.
  const shownId = detail?.summary.id ?? null;
  useEffect(() => {
    if (get().charsetOverrides.id !== shownId) set({ charsetOverrides: { id: shownId, map: {} } });
  }, [shownId]);
  const paused = pausedPart(detail);
  const [edits, setEdits] = useState<TamperEdits>({ head: null, body: null, file: null });
  const pausedKey = detail && paused ? `${detail.summary.id}:${paused}` : "";
  useEffect(() => setEdits({ head: null, body: null, file: null }), [pausedKey]);
  const tamper = { edits, setEdits };
  return (
    <div className="inspectors" ref={root}>
      {detail && paused ? (
        <TamperBar detail={detail} part={paused} edits={edits} onDone={() => setEdits({ head: null, body: null, file: null })} />
      ) : detail ? (
        <SessionHeader detail={detail} />
      ) : error ? (
        <div className="insp-summary err">{t("Could not load session: {error}", { error })}</div>
      ) : (
        <div className="insp-summary muted">{t("No session selected")}</div>
      )}
      <div
        className={`insp-split ${stacked ? "stacked" : "side"}`}
        style={stacked ? { gridTemplateRows: `minmax(90px, ${split * 100}%) 5px minmax(90px, 1fr)` } : { gridTemplateColumns: `minmax(260px, ${split * 100}%) 5px minmax(260px, 1fr)` }}
      >
        <Pane detail={detail} part="request" tamper={paused === "request" ? tamper : undefined} />
        <Splitter vertical={stacked} min={stacked ? [110, 110] : [300, 300]} onDrag={(f) => set((s) => ({ layout: { ...s.layout, inspectorSplit: f } }))} />
        <Pane detail={detail} part="response" tamper={paused === "response" ? tamper : undefined} />
      </div>
    </div>
  );
}
