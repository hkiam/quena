// Inspect tab: request and response inspectors (side by side or stacked).
import { useEffect, useRef, useState } from "react";
import { api, type Detail, type Part, type Variant } from "../api";
import { fmtBytes, fmtInt } from "../lib/format";
import { get, set, useStore } from "../store";
import { Splitter } from "../App";
import { HeadersView } from "./HeadersView";
import { BodyText } from "./BodyText";
import { HexView } from "./HexView";
import { AuthView, CachingView, CookiesView, ImageView, JsonView, ParamsView, RawView, TransformerView, WebFormsView, WebViewPane, XmlView } from "./views";
import { actions } from "../actions";
import { patchSettings } from "../settingsActions";
import { TamperBar, TamperEditor, pausedPart, type TamperEdits } from "./Tamper";
import { SoapView, soapCandidate } from "./Soap";
import { AtomView, atomCandidate } from "./Atom";
import { WebSocketView } from "./WebSocketView";
import { SseView } from "./SseView";
import { MultipartView, multipartCandidate } from "./MultipartView";
import { GrpcView, grpcCandidate } from "./GrpcView";
import { MsgpackView, msgpackCandidate } from "./MsgpackView";
import { LlmView, llmCandidate } from "./LlmView";
import { SocketIoView, socketioCandidate } from "./SocketIoView";
import { ViewTabs } from "./ViewTabs";
import { bodyItems } from "./inspectMenus";
import { openMenu, withSelection } from "../components/contextMenus";
import { SECTIONS, bodyViews, defaultView, orderViews, sectionOf, sectionViews, viewFamily, type Section } from "./viewChoice";
import { methodPill, statusPill } from "../grid/style";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { CharsetPicker, useCharsetOverride } from "./CharsetPicker";
import { effectiveCharset, textVariant } from "../lib/bodytext";
import { t } from "../i18n";

const REQUEST_TABS = ["headers", "params", "textview", "syntaxview", "webforms", "hexview", "auth", "cookies", "raw", "json", "xml"] as const;
const RESPONSE_TABS = ["transformer", "headers", "textview", "syntaxview", "imageview", "hexview", "webview", "auth", "caching", "cookies", "raw", "json", "xml"] as const;
const TITLES: Record<string, string> = {
  headers: t("Headers"),
  textview: t("Plain Text"),
  syntaxview: t("Body"),
  webforms: t("Form Data"),
  params: t("Params"),
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
  msgpack: "MessagePack",
  llm: "LLM",
  socketio: "Socket.IO",
};

/** Grouped tabs: titles of the sections, and of views where the section names the context. */
const SECTION_TITLES: Record<Section, string> = { headers: t("Headers"), body: t("Body"), cookies: t("Cookies"), auth: t("Auth"), raw: t("Raw") };
const SUB_TITLES: Record<string, string> = { headers: t("List"), syntaxview: t("Formatted"), json: t("Tree"), xml: t("Tree") };

const headerNames = (h: [string, string][] | undefined) => (h ?? []).map(([n]) => n.toLowerCase());

/** Section badges: number of headers and cookies, a mark when there is authentication. */
function sectionFacts(detail: Detail, part: Part) {
  const heads = part === "request" ? detail.request.headers : detail.response?.headers;
  const names = headerNames(heads);
  const cookies =
    part === "request" ? (heads ?? []).filter(([n]) => n.toLowerCase() === "cookie").reduce((n, [, v]) => n + v.split(";").filter((c) => c.trim()).length, 0) : names.filter((n) => n === "set-cookie").length;
  const auth = part === "request" ? names.some((n) => n === "authorization" || n === "proxy-authorization") : names.some((n) => n === "www-authenticate" || n === "proxy-authenticate" || n === "authentication-info");
  return { headers: names.length, cookies, auth };
}

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
  const onMenu = (e: React.MouseEvent) =>
    openMenu(
      e,
      withSelection(
        [
          ...bodyItems(detail, part),
          { separator: true },
          { label: t("Wrap"), checked: wrap, action: () => setWrap(!wrap) },
          ...(info.variants.includes("pretty") ? [{ label: t("Format"), checked: pretty, action: () => setPretty(!pretty) }] : []),
        ],
        e.target as Element,
      ),
    );
  return (
    <div className="textpane" onContextMenu={onMenu}>
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
  const grouped = useStore((s) => (s.layout.inspectorTabs ?? "grouped") === "grouped");
  const subViews = useStore((s) => s.layout.subViews);
  const decode = useStore((s) => s.settings?.decode ?? true);
  const info0 = detail ? (part === "request" ? detail.requestBody : detail.responseBody) : null;
  const pluginTabs = (info0?.plugins ?? []).map((p) => ({ key: `plugin:${p.variant}`, title: p.tab, p }));
  const soap = detail ? soapCandidate(detail, part) : false;
  const atom = detail ? atomCandidate(detail, part) : false;
  const isWs = part === "response" && detail?.summary.kind === "webSocket";
  const isSse = part === "response" && (detail?.responseBody.contentType ?? "").toLowerCase().includes("text/event-stream");
  const mp = detail ? multipartCandidate(detail, part) : false;
  const grpc = detail ? grpcCandidate(detail, part) : false;
  const msgpack = detail ? msgpackCandidate(detail, part) : false;
  const llm = detail ? llmCandidate(detail) : false;
  const sio = detail ? socketioCandidate(detail, part) : false;
  const special = [llm ? "llm" : "", sio ? "socketio" : "", isWs ? "websocket" : "", isSse ? "sse" : "", grpc ? "grpc" : "", msgpack ? "msgpack" : "", mp ? "multipart" : "", soap ? "soap" : "", atom ? "atom" : ""].filter(Boolean);
  const tabs: string[] = [...(part === "request" ? REQUEST_TABS : RESPONSE_TABS), ...special, ...pluginTabs.map((t) => t.key)];
  const family = detail ? viewFamily(detail, part, special, pluginTabs.map((t) => t.key)) : null;
  const memoKey = family ? `${part}:${family}` : null;
  const body = grouped && detail ? bodyViews(detail, part, tabs, special) : [];
  const bodyKey = `${part}:body:${family ?? ""}`;
  /** Grouped: the view a section opens with — the last one chosen there, else the best. */
  const sectionStart = (sec: Section): string => {
    if (sec === "body") {
      const last = subViews?.[bodyKey];
      return last && body.some((b) => b.view === last) ? last : (body[0]?.view ?? "syntaxview");
    }
    const views = sectionViews(sec, tabs, body);
    const last = subViews?.[`${part}:${sec}`];
    return last && views.includes(last) ? last : (views[0] ?? sec);
  };
  // The view for this message: remembered for its kind of content, else a sensible default;
  // with remembering off, the last view chosen anywhere (the classic behaviour).
  let tab: string;
  if (remember && memoKey && family) {
    const chosen = viewByType?.[memoKey];
    tab = chosen && tabs.includes(chosen) ? chosen : grouped && family !== "empty" && family !== "unknown" && body[0] ? body[0].view : defaultView(family, part, tabs);
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
        ...(grouped ? { subViews: { ...(s.layout.subViews ?? {}), [sectionOf(t) === "body" ? bodyKey : `${part}:${sectionOf(t)}`]: t } } : {}),
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
      case "params":
        content = <ParamsView detail={detail} />;
        break;
      case "atom":
        content = atom ? <AtomView detail={detail} part={part} /> : <div className="placeholder">{t("Not an Atom/OData document.")}</div>;
        break;
      case "grpc":
        content = <GrpcView detail={detail} part={part} />;
        break;
      case "msgpack":
        content = <MsgpackView detail={detail} part={part} />;
        break;
      case "llm":
        content = <LlmView detail={detail} />;
        break;
      case "socketio":
        content = <SocketIoView detail={detail} part={part} />;
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
  const title = (t: string) => TITLES[t] ?? pluginTabs.find((p) => p.key === t)?.title ?? t;
  const pill = part === "response" && detail ? statusPill(detail.summary) : null;
  let tabsRow: React.ReactNode;
  let subRow: React.ReactNode = null;
  /** Views Alt+←/→ steps through: those of the section (grouped) or of the row (flat). */
  let cycle: string[] = [];
  if (grouped) {
    const section = sectionOf(tab);
    const facts = detail ? sectionFacts(detail, part) : null;
    const emptyBody = !!detail && !info0?.len && !special.length && !pluginTabs.length;
    if (section === "body" && emptyBody && !tamper) content = <div className="placeholder">{t("No body")}</div>;
    const messages = special.includes("websocket") || special.includes("sse");
    tabsRow = (
      <ViewTabs
        className="view-sections"
        views={[...SECTIONS]}
        active={section}
        title={(v) => (v === "body" && messages ? t("Messages") : SECTION_TITLES[v as Section])}
        badge={(v) => (!facts ? null : v === "headers" && facts.headers ? String(facts.headers) : v === "cookies" && facts.cookies ? String(facts.cookies) : v === "auth" && facts.auth ? "•" : null)}
        dim={(v) => !!facts && ((v === "cookies" && !facts.cookies) || (v === "auth" && !facts.auth) || (v === "body" && emptyBody))}
        hint={(v) => (v === "body" && emptyBody ? t("No body") : undefined)}
        onSelect={(v) => setTab(sectionStart(v as Section))}
      />
    );
    if (section === "body" && !emptyBody) {
      const good = body.filter((b) => b.fit >= 2 || b.view === tab).map((b) => b.view);
      const others = body.filter((b) => !good.includes(b.view));
      cycle = good;
      if (good.length > 1 || others.length) subRow = <ViewTabs className="view-sub" views={good} active={tab} title={(v) => SUB_TITLES[v] ?? title(v)} onSelect={setTab} others={others} />;
    } else if (detail && section === "headers" && (tabs.includes("caching") || tabs.includes("params"))) {
      cycle = sectionViews("headers", tabs, body);
      subRow = <ViewTabs className="view-sub" views={sectionViews("headers", tabs, body)} active={tab} title={(v) => SUB_TITLES[v] ?? title(v)} onSelect={setTab} />;
    }
  } else {
    cycle = orderViews(tabs, special, family);
    tabsRow = <ViewTabs views={cycle} active={tab} title={title} onSelect={setTab} />;
  }
  // Alt+1…5: section (grouped); Alt+←/→: previous/next view. Not while typing.
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!detail || !e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
    const el = e.target as HTMLElement;
    if (el.closest("input, textarea, select, [contenteditable=true], .cm-editor")) return;
    const n = Number(e.code.startsWith("Digit") ? e.code.slice(5) : NaN);
    if (grouped && n >= 1 && n <= SECTIONS.length) setTab(sectionStart(SECTIONS[n - 1]));
    else if ((e.key === "ArrowLeft" || e.key === "ArrowRight") && cycle.length > 1) {
      const i = cycle.indexOf(tab);
      setTab(cycle[(i + (e.key === "ArrowRight" ? 1 : cycle.length - 1)) % cycle.length]);
    } else return;
    e.preventDefault();
    e.stopPropagation();
  };
  return (
    <div className={`insp-pane ${grouped ? "grouped" : ""}`} onKeyDown={onKeyDown}>
      <div className="insp-head">
        <span className="insp-part">{part === "request" ? t("Request") : t("Response")}</span>
        {pill && <span className={`pill pill-${pill.tone}`}>{pill.text}</span>}
        {tabsRow}
      </div>
      {grouped && <div className="insp-sub">{subRow}</div>}
      <div
        className="insp-content"
        onContextMenu={(e) => {
          // Views without a menu of their own (Hex, Image, Raw …): the body's, if it has one.
          // (Not for views of a part of the body: parts, frames, events, messages.)
          if (e.nativeEvent.defaultPrevented || !detail || tamper || !["body", "raw"].includes(sectionOf(tab)) || ["multipart", "websocket", "sse", "grpc", "msgpack", "llm", "socketio"].includes(tab)) return;
          openMenu(e, withSelection(bodyItems(detail, part), e.target as Element));
        }}
      >
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
