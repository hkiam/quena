import { describe, expect, it } from "vitest";
import { activeHeaders, defaultName, EMPTY, fromCollectionRequest, hasVariables, headerRows, headerText, moved, queryRows, toCollectionRequest, toRaw, withQuery } from "./composerDraft";

describe("composer draft", () => {
  it("writes the chosen HTTP version into the raw request", () => {
    const d = { ...EMPTY, url: "https://api.example.com/a?b=1", headers: "Accept: */*" };
    expect(toRaw(d).split("\n")[0]).toBe("GET https://api.example.com/a?b=1 HTTP/1.1");
    expect(toRaw({ ...d, version: "HTTP/2" }).split("\n")[0]).toBe("GET https://api.example.com/a?b=1 HTTP/2");
    expect(toRaw(d)).toContain("Host: api.example.com");
  });
  it("round-trips through a collection request", () => {
    const d = { ...EMPTY, method: "POST", url: "{{host}}/users", headers: "Content-Type: application/json", body: '{"a":1}', version: "HTTP/2" };
    const r = toCollectionRequest(d, "Create");
    expect(r).toMatchObject({ name: "Create", method: "POST", version: "HTTP/2", body: '{"a":1}', bodyFile: "" });
    const back = fromCollectionRequest(r, "Users", 3);
    expect(back.coll).toEqual({ name: "Users", index: 3, title: "Create" });
    expect(toCollectionRequest(back, "Create")).toEqual(r);
    // A body file replaces the text.
    expect(toCollectionRequest({ ...d, bodyFile: "data.json", bodyTemplate: true }, "x")).toMatchObject({ body: "", bodyFile: "data.json", bodyTemplate: true });
  });
  it("knows when variables need substituting", () => {
    expect(hasVariables({ url: "{{host}}/a", headers: "", body: "" })).toBe(true);
    expect(hasVariables({ url: "https://x/", headers: "Authorization: Bearer {{token}}", body: "" })).toBe(true);
    expect(hasVariables({ url: "https://x/", headers: "", body: "{ }" })).toBe(false);
  });
  it("names and moves requests", () => {
    expect(defaultName({ method: "GET", url: "https://x.example/api/users?page=2" })).toBe("GET /api/users");
    expect(defaultName({ method: "GET", url: "https://x.example" })).toBe("GET /");
    expect(moved([1, 2, 3], 0, 1)).toEqual([2, 1, 3]);
    const l = [1, 2];
    expect(moved(l, 0, -1)).toBe(l);
  });
  it("edits headers as a table, rows switched off with #", () => {
    const rows = headerRows("Accept: */*\n# X-Debug: 1\nX-Empty:");
    expect(rows).toEqual([{ on: true, name: "Accept", value: "*/*" }, { on: false, name: "X-Debug", value: "1" }, { on: true, name: "X-Empty", value: "" }]);
    expect(headerText([...rows, { on: true, name: "", value: "" }])).toBe("Accept: */*\n# X-Debug: 1\nX-Empty: ");
    expect(activeHeaders("A: 1\n# B: 2")).toBe("A: 1");
    expect(toRaw({ ...EMPTY, url: "https://x/", headers: "A: 1\n# B: 2" })).not.toContain("B: 2");
    expect(toCollectionRequest({ ...EMPTY, headers: "A: 1\n# B: 2" }, "n").headers).toBe("A: 1");
  });
  it("edits query parameters as a table", () => {
    const rows = queryRows("https://x/s?q=a+b&lang=de&flag#top", ["debug=1"]);
    expect(rows).toEqual([
      { on: true, name: "q", value: "a b" },
      { on: true, name: "lang", value: "de" },
      { on: true, name: "flag", value: "" },
      { on: false, name: "debug", value: "1" },
    ]);
    const next = withQuery("https://x/s?q=a+b&lang=de&flag#top", rows.map((r) => (r.name === "lang" ? { ...r, on: false } : r.name === "debug" ? { ...r, on: true } : r)));
    expect(next).toEqual({ url: "https://x/s?q=a+b&flag&debug=1#top", offParams: ["lang=de"] });
    expect(withQuery("https://x/s?a=1", []).url).toBe("https://x/s");
    expect(withQuery("https://x/s", [{ on: true, name: "a&b", value: "ä" }]).url).toBe("https://x/s?a%26b=%C3%A4");
  });
});
