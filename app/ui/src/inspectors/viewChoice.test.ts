import { describe, expect, it } from "vitest";
import type { BodyInfo, Detail } from "../api";
import { bodyViews, defaultView, sectionOf, sectionViews, viewFamily } from "./viewChoice";
import { msgpackCandidate } from "./MsgpackView";
import { grpcCandidate } from "./GrpcView";

const REQUEST = ["headers", "textview", "syntaxview", "webforms", "hexview", "auth", "cookies", "raw", "json", "xml"];
const RESPONSE = ["transformer", "headers", "textview", "syntaxview", "imageview", "hexview", "webview", "auth", "caching", "cookies", "raw", "json", "xml"];

const body = (o: Partial<BodyInfo>): BodyInfo => ({
  bodyId: 1,
  len: 100,
  wireLen: 100,
  complete: true,
  truncated: false,
  contentType: null,
  contentEncoding: null,
  transferEncoding: null,
  isText: true,
  isImage: false,
  variants: ["raw"],
  plugins: [],
  charset: null,
  shape: null,
  ...o,
});
const detail = (response: Partial<BodyInfo>, request: Partial<BodyInfo> = { len: 0 }): Detail =>
  ({ request: { method: "GET", url: "http://x/", headers: [] }, requestBody: body(request), responseBody: body(response) }) as unknown as Detail;

/** The views shown in the row (fit ≥ 2), best first. */
const shown = (d: Detail, special: string[] = [], part: "request" | "response" = "response", tabs = part === "request" ? REQUEST : RESPONSE) =>
  bodyViews(d, part, [...tabs, ...special], special)
    .filter((v) => v.fit >= 2)
    .map((v) => v.view);

describe("grouped inspector views", () => {
  it("offers the views that fit JSON, formatted first", () => {
    expect(shown(detail({ contentType: "application/json", shape: "json" }))).toEqual(["syntaxview", "json", "textview"]);
    // JSON sent as text/plain is still JSON.
    expect(shown(detail({ contentType: "text/plain", shape: "json" }))).toContain("json");
  });
  it("does not offer SOAP, a tree of the wrong kind, an image or a form for plain JSON", () => {
    const all = bodyViews(detail({ contentType: "application/json", shape: "json" }), "response", RESPONSE, []);
    const fit = Object.fromEntries(all.map((v) => [v.view, v.fit]));
    expect(fit.xml).toBe(0);
    expect(fit.imageview).toBe(0);
    expect(fit.webview).toBe(0);
    expect(fit.hexview).toBe(1); // under "Other"
  });
  it("puts SOAP first for a SOAP envelope", () => {
    expect(shown(detail({ contentType: "text/xml", shape: "soap" }), ["soap"])).toEqual(["soap", "syntaxview", "xml", "textview"]);
  });
  it("plain XML gets the XML tree, no SOAP", () => {
    expect(shown(detail({ contentType: "text/xml", shape: "xml" }))).toEqual(["syntaxview", "xml", "textview"]);
  });
  it("images, forms, binary and HTML", () => {
    expect(shown(detail({ contentType: "image/png", isText: false, isImage: true }))).toEqual(["imageview", "hexview"]);
    expect(shown(detail({ len: 0 }, { contentType: "application/x-www-form-urlencoded" }), [], "request")).toEqual(["webforms", "syntaxview", "textview"]);
    expect(shown(detail({ contentType: "application/octet-stream", isText: false }))[0]).toBe("hexview");
    expect(shown(detail({ contentType: "text/html", shape: "html" }))).toEqual(["syntaxview", "webview", "textview"]);
  });
  it("a decoder plugin comes first when it is sure", () => {
    const d = detail({ contentType: "application/fastinfoset", isText: false, plugins: [{ variant: "plugin:0" as never, tab: "Fast Infoset", confidence: 95, output: "xml" }] });
    const withPlugin = [...RESPONSE, "plugin:plugin:0"];
    expect(shown(d, ["soap"], "response", withPlugin).slice(0, 2)).toEqual(["soap", "plugin:plugin:0"]);
    expect(shown(d, [], "response", withPlugin)[0]).toBe("plugin:plugin:0");
    // Less sure: still offered, after what is made for the content.
    const unsure = detail({ contentType: "application/octet-stream", isText: false, plugins: [{ variant: "plugin:0" as never, tab: "X", confidence: 60, output: "text" }] });
    expect(bodyViews(unsure, "response", withPlugin, []).find((v) => v.view === "plugin:plugin:0")?.fit).toBe(2);
  });
  it("offers the encoding view when the body is encoded", () => {
    expect(shown(detail({ contentType: "application/json", shape: "json", contentEncoding: "gzip" }))).toContain("transformer");
  });
  it("an empty body offers nothing", () => {
    expect(shown(detail({ len: 0 }))).toEqual([]);
  });
});

describe("sections", () => {
  it("maps views to sections", () => {
    expect(["headers", "caching", "syntaxview", "soap", "plugin:x", "cookies", "auth", "raw", "hexview"].map(sectionOf)).toEqual(["headers", "headers", "body", "body", "body", "cookies", "auth", "raw", "body"]);
    expect(sectionViews("headers", RESPONSE, [])).toEqual(["headers", "caching"]);
    expect(sectionViews("headers", REQUEST, [])).toEqual(["headers"]);
  });
});

describe("family", () => {
  it("follows the shape when the type does not tell", () => {
    expect(viewFamily(detail({ contentType: "text/plain", shape: "json" }), "response", [], [])).toBe("json");
    expect(viewFamily(detail({ contentType: "text/xml", shape: "xml" }), "response", [], [])).toBe("xml");
    expect(viewFamily(detail({ contentType: null, shape: "xml" }), "response", [], [])).toBe("xml");
    expect(viewFamily(detail({ contentType: null, shape: null }), "response", [], [])).toBe("unknown");
  });
});

describe("gRPC and MessagePack", () => {
  const withType = (ct: string) =>
    ({ ...detail({ contentType: ct, isText: false }), response: { status: 200, headers: [["Content-Type", ct]] } }) as unknown as Detail;
  it("recognises the content types", () => {
    expect(msgpackCandidate(withType("application/msgpack"), "response")).toBe(true);
    expect(msgpackCandidate(withType("application/vnd.msgpack"), "response")).toBe(true);
    expect(msgpackCandidate(withType("application/x-msgpack"), "response")).toBe(true);
    expect(msgpackCandidate(withType("application/json"), "response")).toBe(false);
    expect(grpcCandidate(withType("application/grpc+proto"), "response")).toBe(true);
    expect(grpcCandidate(withType("application/x-protobuf"), "response")).toBe(true);
    expect(grpcCandidate(withType("application/msgpack"), "response")).toBe(false);
  });
  it("the special view comes first and is the default", () => {
    const d = withType("application/msgpack");
    expect(viewFamily(d, "response", ["msgpack"], [])).toBe("msgpack");
    expect(shown(d, ["msgpack"])[0]).toBe("msgpack");
    expect(defaultView("msgpack", "response", [...RESPONSE, "msgpack"])).toBe("msgpack");
    expect(viewFamily(withType("application/grpc"), "response", ["grpc"], [])).toBe("grpc");
    expect(shown(withType("application/grpc"), ["grpc"])[0]).toBe("grpc");
  });
});

describe("LLM calls", () => {
  const call = (url: string, method = "POST", llm = "") => ({ summary: { llm }, request: { method, url, headers: [] }, requestBody: body({}), responseBody: body({}) }) as unknown as Detail;
  it("are recognised by URL or by their mark", async () => {
    const { llmCandidate } = await import("./LlmView");
    expect(llmCandidate(call("https://api.openai.com/v1/chat/completions"))).toBe(true);
    expect(llmCandidate(call("https://api.anthropic.com/v1/messages"))).toBe(true);
    expect(llmCandidate(call("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"))).toBe(true);
    expect(llmCandidate(call("http://localhost:11434/api/chat"))).toBe(true);
    expect(llmCandidate(call("https://api.openai.com/v1/chat/completions", "GET"))).toBe(false);
    expect(llmCandidate(call("https://example.com/api/users"))).toBe(false);
    expect(llmCandidate(call("https://proxy.example/x", "POST", "OpenAI/gpt-4o"))).toBe(true);
  });
  it("open in the LLM view", () => {
    const d = call("https://api.openai.com/v1/chat/completions");
    expect(viewFamily(d, "response", ["llm", "sse"], [])).toBe("llm");
    expect(defaultView("llm", "request", [...REQUEST, "llm"])).toBe("llm");
    expect(viewFamily(d, "request", ["mcp"], [])).toBe("mcp");
    expect(defaultView("mcp", "response", [...REQUEST, "mcp"])).toBe("mcp");
  });
});
