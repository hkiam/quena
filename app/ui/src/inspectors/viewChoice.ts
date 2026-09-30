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
  if (!ct) return "unknown";
  if (ct === "application/json" || ct.endsWith("+json") || ct === "text/json") return "json";
  if (ct.includes("html")) return "html";
  if (ct === "application/xml" || ct === "text/xml" || ct.endsWith("+xml")) return special.includes("atom") ? "atom" : "xml";
  if (ct.includes("javascript") || ct.includes("ecmascript")) return "js";
  if (ct === "text/css") return "css";
  if (ct.startsWith("image/")) return "image";
  if (ct === "application/x-www-form-urlencoded") return "form";
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
