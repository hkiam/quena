import { describe, expect, it } from "vitest";
import type { ConvSummary, TurnDiff } from "../api";
import { breaksCache, cacheText, convTree, diffText } from "./agentText";

const conv = (key: string, started: number, parent?: string): ConvSummary => ({
  key,
  title: key,
  agent: "",
  provider: "",
  models: [],
  turns: 1,
  first: 1,
  last: 1,
  started,
  ended: started,
  input: 0,
  output: 0,
  cacheRead: 0,
  cacheWrite: 0,
  cost: null,
  errors: 0,
  cacheMisses: 0,
  lastInput: 0,
  parent,
});
const diff = (d: Partial<TurnDiff>): TurnDiff => ({ kind: "append", added: 0, dropped: 0, systemChanged: false, toolsReordered: false, modelChanged: false, ...d });

describe("agent texts", () => {
  it("puts subagents under their parent", () => {
    const t = convTree([conv("b", 30), conv("a", 10), conv("a2", 25, "a"), conv("a1", 20, "a"), conv("x", 5, "gone")]);
    expect(t.map((x) => `${x.depth}${x.c.key}`)).toEqual(["0b", "0a", "1a1", "1a2", "0x"]);
  });
  it("survives a loop of parents", () => {
    const t = convTree([conv("a", 1, "b"), conv("b", 2, "a")]);
    expect(t.map((x) => x.c.key).sort()).toEqual(["a", "b"]);
  });
  it("describes changes and cache notes", () => {
    expect(diffText(diff({ added: 2 }))).toBe("+2 messages");
    expect(diffText(diff({ kind: "changed", at: 4, systemChanged: true }))).toBe("message 5 changed · system prompt changed");
    expect(breaksCache(diff({ added: 3 }))).toBe(false);
    expect(breaksCache(diff({ toolsAdded: ["x"] }))).toBe(true);
    expect(cacheText({ code: "expired", args: { minutes: "7", ttl: "5" } })).toContain("7 min");
    expect(cacheText({ code: "novel" })).toBe("novel");
  });
});
