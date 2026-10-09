import { describe, expect, it } from "vitest";
import { defaultName, EMPTY, fromCollectionRequest, hasVariables, moved, toCollectionRequest, toRaw } from "./composerDraft";

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
});
