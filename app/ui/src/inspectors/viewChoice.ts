// Which inspector view to show for a message, and in which order to offer the views.
//
// With "remember views" on (default), the view last chosen is kept per request/response
// and per kind of content ("family"): JSON, XML, SOAP, Fast Infoset, images, … Until
// something was chosen for a family, a sensible default for that content is used.
import type { Detail, Part } from "../api";

/** Views that only make sense for particular content, shown right after Headers. */
export const SPECIAL = ["websocket", "sse", "grpc", "multipart", "soap", "atom"];

/** Kind of content a message carries, as far as picking a view is concerned. */
export function viewFamily(detail: Detail, part: Part, special: string[], pluginKeys: string[]): string {
  if (special.includes("websocket")) return "websocket";
  if (special.includes("sse")) return "sse";
  if (special.includes("grpc")) return "grpc";
  if (special.includes("multipart")) return "multipart";
  if (special.includes("soap")) return "soap";
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  // A plugin decodes this content (e.g. Fast Infoset): its view is the family.
  if (pluginKeys.length) return pluginKeys[0];
  if (!info.len) return "empty";
  const ct = (info.contentType ?? "").toLowerCase().split(";")[0].trim();
  if (!ct && !info.shape) return "unknown";
  if (ct === "application/json" || ct.endsWith("+json") || ct === "text/json") return "json";
  if (ct.includes("html")) return "html";
  if (ct === "application/xml" || ct === "text/xml" || ct.endsWith("+xml")) return special.includes("atom") ? "atom" : "xml";
  if (ct.includes("javascript") || ct.includes("ecmascript")) return "js";
  if (ct === "text/css") return "css";
  if (ct.startsWith("image/")) return "image";
  if (ct === "application/x-www-form-urlencoded") return "form";
  // Mislabelled text (JSON as text/plain, XML as octet-stream): by what it is.
  if (info.shape === "json" || info.shape === "odata-json") return "json";
  if (info.shape === "xml" || info.shape === "atom" || info.shape === "edmx") return special.includes("atom") ? "atom" : "xml";
  if (info.shape === "html") return "html";
  if (ct.startsWith("text/")) return "text";
  return ct; // e.g. application/octet-stream, application/pdf
}

/** The view to use for a family nobody chose one for yet. */
export function defaultView(family: string, part: Part, tabs: string[]): string {
  const pick = (...cands: string[]) => cands.find((c) => tabs.includes(c)) ?? "headers";
  if (family.startsWith("plugin:")) return pick(family, "syntaxview");
  switch (family) {
    case "websocket":
    case "sse":
    case "grpc":
    case "multipart":
    case "soap":
    case "atom":
      return pick(family, "syntaxview");
    case "empty":
    case "unknown":
      return "headers";
    case "image":
      return pick("imageview", "hexview");
    case "form":
      return pick(part === "request" ? "webforms" : "syntaxview");
    case "json":
    case "xml":
    case "html":
    case "js":
    case "css":
    case "text":
      return pick("syntaxview");
    default:
      return pick("hexview", "headers"); // binary
  }
}

/** Views in the order they are offered: what fits the content first, the rest after. */
export function orderViews(tabs: string[], special: string[], family: string | null): string[] {
  const rank = (t: string): number => {
    if (t === "headers") return 0;
    if (special.includes(t) || t.startsWith("plugin:")) return 1;
    if (t === "syntaxview") return 2;
    if (t === "imageview") return family === "image" ? 1.5 : 9;
    if (t === "webview") return family === "html" ? 2.5 : 9;
    if (t === "webforms") return family === "form" ? 1.5 : 6;
    if (t === "json") return family === "json" ? 2.5 : 6;
    if (t === "xml") return family === "xml" || family === "soap" || family === "atom" ? 2.5 : 6;
    if (t === "cookies") return 3;
    if (t === "raw") return 4;
    if (t === "hexview") return 5;
    return 7;
  };
  return tabs.map((t, i) => ({ t, i })).sort((a, b) => rank(a.t) - rank(b.t) || a.i - b.i).map((x) => x.t);
}

// ---- Grouped tabs: sections, and the views of a section ----

/** First level of the grouped tabs, always in this order. */
export const SECTIONS = ["headers", "body", "cookies", "auth", "raw"] as const;
export type Section = (typeof SECTIONS)[number];

export function sectionOf(view: string): Section {
  if (view === "headers" || view === "caching") return "headers";
  if (view === "cookies" || view === "auth" || view === "raw") return view;
  return "body";
}

/** How well a view fits: 3 made for it, 2 fits, 1 possible (under "Other"), 0 makes no sense. */
export type Fit = 0 | 1 | 2 | 3;

/** Order of the body views at the same fit. */
const BODY_ORDER = ["websocket", "sse", "soap", "atom", "grpc", "multipart", "plugin:", "imageview", "webforms", "syntaxview", "json", "xml", "webview", "textview", "hexview", "transformer"];

const orderOf = (v: string) => {
  const i = BODY_ORDER.indexOf(v.startsWith("plugin:") ? "plugin:" : v);
  return i < 0 ? BODY_ORDER.length : i;
};

/** The views of the body section with their fit, best first. `tabs` are all views of the
 * pane, `special` the content-specific ones that apply. */
export function bodyViews(detail: Detail, part: Part, tabs: string[], special: string[]): { view: string; fit: Fit }[] {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const ct = (info.contentType ?? "").toLowerCase().split(";")[0].trim();
  const shape = info.shape ?? null;
  const text = info.isText;
  const empty = !info.len;
  const isJson = shape === "json" || shape === "odata-json" || ct === "application/json" || ct.endsWith("+json") || ct === "text/json";
  const isXml = shape === "xml" || shape === "soap" || shape === "atom" || shape === "edmx" || (!shape && (ct.endsWith("/xml") || ct.endsWith("+xml")));
  const isHtml = shape === "html" || ct.includes("html");
  const fit = (v: string): Fit => {
    if (special.includes(v)) return 3;
    if (v.startsWith("plugin:")) return (info.plugins.find((p) => `plugin:${p.variant}` === v)?.confidence ?? 0) >= 90 ? 3 : 2;
    if (empty) return 0;
    switch (v) {
      case "syntaxview":
        return text ? 3 : 1;
      case "textview":
        return text ? 2 : 1;
      case "json":
        return isJson ? 2 : 0;
      case "xml":
        return isXml ? 2 : 0;
      case "webforms":
        return ct === "application/x-www-form-urlencoded" ? 3 : text ? 1 : 0;
      case "imageview":
        return info.isImage ? 3 : 0;
      case "webview":
        return isHtml ? 2 : 0;
      case "hexview":
        return text ? 1 : info.isImage || info.plugins.length ? 2 : 3;
      case "transformer":
        return info.contentEncoding || info.transferEncoding ? 2 : 1;
      default:
        return 0; // soap, atom, … when they do not apply
    }
  };
  return tabs
    .filter((v) => sectionOf(v) === "body")
    .map((view) => ({ view, fit: fit(view) }))
    .sort((a, b) => b.fit - a.fit || orderOf(a.view) - orderOf(b.view));
}

/** The views offered for a section: the body's by fit; Headers with Caching on responses. */
export function sectionViews(section: Section, tabs: string[], body: { view: string; fit: Fit }[]): string[] {
  if (section === "body") return body.map((b) => b.view);
  return tabs.filter((v) => sectionOf(v) === section);
}
