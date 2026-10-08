import { describe, expect, it } from "vitest";
import type { RwOp } from "../api";
import { describeOp, emptyDraft, fromDraft, toDraft } from "./rewriteDraft";

describe("rewrite operation drafts", () => {
  const ops: RwOp[] = [
    { op: "jsonSet", path: "$.a.b", value: { x: [1, "y"] } },
    { op: "jsonRemove", path: "$.items[0]" },
    { op: "jsonAppend", path: "$.items" },
    { op: "jsonAppend", path: "$.items", value: null },
    { op: "jsonAppendAll", value: 5 },
    { op: "regexReplace", pattern: "a(\\d+)", replacement: "b$1" },
    { op: "setHeader", name: "X-A", value: "1" },
    { op: "removeHeader", name: "ETag" },
    { op: "setStatus", code: 503 },
  ];
  it("round-trips every operation", () => {
    for (const o of ops) expect(fromDraft(toDraft(o))).toEqual({ op: o });
  });
  it("explains what is wrong", () => {
    expect(fromDraft({ ...emptyDraft("jsonSet"), path: "a.b", valueText: "1" })).toHaveProperty("error");
    expect(fromDraft({ ...emptyDraft("jsonSet"), path: "$.a", valueText: "plain text" })).toHaveProperty("error");
    expect(fromDraft({ ...emptyDraft("setStatus"), code: "101" })).toHaveProperty("error");
    expect(fromDraft({ ...emptyDraft("setHeader"), name: " " })).toHaveProperty("error");
  });
  it("describes operations briefly", () => {
    expect(describeOp({ op: "setStatus", code: 500 })).toBe("→ 500");
    expect(describeOp({ op: "jsonSet", path: "$.n", value: "x" })).toBe('$.n = "x"');
  });
});
