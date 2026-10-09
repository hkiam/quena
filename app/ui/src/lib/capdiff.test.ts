import { describe, expect, it } from "vitest";
import type { CaptureDiff, DiffEntry } from "../api";
import { statusText, toMarkdown } from "./capdiff";

const e = (o: Partial<DiffEntry>): DiffEntry => ({ kind: "changed", method: "GET", key: "x/a", idA: 1, idB: 2, urlA: null, urlB: null, statusA: 200, statusB: 200, sizeA: 0, sizeB: 0, msA: 1, msB: 1, changes: [], ...o });

describe("compare captures", () => {
  it("shows a status change or the one status", () => {
    expect(statusText(e({ statusA: 200, statusB: 500 }))).toBe("200 → 500");
    expect(statusText(e({ statusA: null, statusB: 201 }))).toBe("201");
    expect(statusText(e({ statusA: 404, statusB: null }))).toBe("404");
  });
  it("writes Markdown without the unchanged requests", () => {
    const d: CaptureDiff = {
      sessionsA: 3,
      sessionsB: 3,
      counts: { changed: 1, added: 1, removed: 0, same: 1, newErrors: 1 },
      entries: [e({ statusB: 500, changes: ["status 200 → 500"], key: "api/a|b" }), e({ kind: "added", idA: null, statusA: null, key: "api/new" }), e({ kind: "same", key: "api/same" })],
    };
    const md = toMarkdown(d, "v1.har", "v2.har");
    expect(md).toContain("## v1.har → v2.har");
    expect(md).toContain("| ~ | `GET api/a\\|b` | 200 → 500 | status 200 → 500 |");
    expect(md).toContain("| + | `GET api/new`");
    expect(md).not.toContain("api/same");
    expect(toMarkdown(d, "a", "b", true)).toContain("api/same");
  });
});
