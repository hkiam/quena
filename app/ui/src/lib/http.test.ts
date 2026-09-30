import { describe, expect, it } from "vitest";
import type { Detail } from "../api";
import { buildCurl, buildFetch, buildPowerShell, buildPython } from "./http";

const detail = (body = 0) =>
  ({
    summary: { id: 7 },
    request: {
      method: "POST",
      url: "https://api.example.com/v1/items?x=1",
      version: "HTTP/1.1",
      headers: [
        ["Host", "api.example.com"],
        ["Content-Type", "application/json"],
        ["User-Agent", "quena-test"],
        ["X-It's", "o'clock"],
        ["Content-Length", "13"],
      ],
    },
    requestBody: { len: body, isText: true },
  }) as unknown as Detail;

describe("copy as …", () => {
  it("fetch: method, headers without hop-by-hop ones, body", () => {
    const s = buildFetch(detail(13), '{"a":"b\'c"}');
    expect(s).toContain('await fetch("https://api.example.com/v1/items?x=1"');
    expect(s).toContain('"Content-Type": "application/json"');
    expect(s).not.toContain("Content-Length");
    expect(s).not.toContain('"Host"');
    expect(s).toContain(`body: ${JSON.stringify('{"a":"b\'c"}')}`);
  });
  it("PowerShell: content type and user agent as parameters, quotes escaped", () => {
    const s = buildPowerShell(detail(13), "{}");
    expect(s).toContain("-Method POST");
    expect(s).toContain("-ContentType 'application/json'");
    expect(s).toContain("-UserAgent 'quena-test'");
    expect(s).toContain("'X-It''s' = 'o''clock'");
    expect(s).not.toMatch(/Content-Type' =/);
  });
  it("Python: requests call with headers and data", () => {
    const s = buildPython(detail(13), "{}");
    expect(s).toContain("requests.request(");
    expect(s).toContain('"POST",');
    expect(s).toContain('"User-Agent": "quena-test",');
    expect(s).toContain('data="{}".encode("utf-8"),');
  });
  it("binary or large bodies are referenced, not inlined", () => {
    expect(buildPython(detail(5_000_000), null)).toContain('open("body-7.bin", "rb")');
    expect(buildPowerShell(detail(5_000_000), null)).toContain("-InFile 'body-7.bin'");
    expect(buildFetch(detail(5_000_000), null)).toContain("5000000 bytes");
    expect(buildCurl(detail(5_000_000), null)).toContain("@body-7.bin");
  });
});
