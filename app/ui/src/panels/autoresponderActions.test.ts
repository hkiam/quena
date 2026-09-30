import { describe, expect, it, vi } from "vitest";

vi.mock("../api", () => ({ api: {} }));
vi.mock("../store", () => ({ get: () => ({}), set: () => {}, say: () => {} }));

const { mapLocalRule, mapRemoteRule } = await import("./autoresponderActions");

describe("mapping forms", () => {
  it("Map Remote keeps credentials unless asked to drop them", () => {
    expect(mapRemoteRule("https://prod.example.com/api/", "https://staging.example.com/api")).toEqual({ match: "prefix:https://prod.example.com/api/", action: "https://staging.example.com/api/", comment: "Map Remote" });
    expect(mapRemoteRule("https://prod.example.com/api/*", "https://staging.example.com/api/", true)).toEqual({ match: "prefix:https://prod.example.com/api/", action: "https://staging.example.com/api/ *nocreds", comment: "Map Remote" });
    expect(mapRemoteRule("prod.example.com", "https://x.example.com")).toHaveProperty("error");
  });
  it("Map Local needs an absolute folder", () => {
    expect(mapLocalRule("https://example.com/static/", "/srv/site")).toEqual({ match: "prefix:https://example.com/static/", action: "dir:/srv/site", comment: "Map Local" });
    expect(mapLocalRule("https://example.com/static/", "site")).toHaveProperty("error");
  });
});
