import { describe, expect, test } from "vitest";
import type { InspectNode } from "../api";
import { nodesToTree } from "./inspect";

const n = (depth: number, kind: InspectNode["kind"], name: string, value = ""): InspectNode => ({ depth, kind, name, value });

describe("nodesToTree", () => {
  test("rebuilds nested sections (auth-tokens plugin output shape)", () => {
    const tree = nodesToTree([
      n(0, "section", "SPNEGO NegTokenResp"),
      n(0, "field", "Negotiation state", "accept-completed (0)"),
      n(1, "section", "Kerberos AP-REP (mutual authentication)"),
      n(1, "field", "Encryption type", "aes256-cts-hmac-sha1-96 (18)"),
      n(0, "code", "Raw token (186 bytes)", "0000  a1 81"),
    ]);
    expect(tree).toHaveLength(1);
    const root = tree[0];
    expect(root.title).toBe("SPNEGO NegTokenResp");
    expect(root.fields).toEqual([["Negotiation state", "accept-completed (0)"]]);
    expect(root.code).toEqual([{ caption: "Raw token (186 bytes)", text: "0000  a1 81" }]);
    expect(root.children.map((c) => c.title)).toEqual(["Kerberos AP-REP (mutual authentication)"]);
    expect(root.children[0].fields).toEqual([["Encryption type", "aes256-cts-hmac-sha1-96 (18)"]]);
  });

  test("siblings and returning to an outer level", () => {
    const tree = nodesToTree([
      n(0, "section", "AP-REQ"),
      n(1, "section", "Ticket"),
      n(1, "note", "", "encrypted"),
      n(1, "section", "Authenticator"),
      n(0, "section", "Second"),
    ]);
    expect(tree.map((s) => s.title)).toEqual(["AP-REQ", "Second"]);
    expect(tree[0].children.map((s) => s.title)).toEqual(["Ticket", "Authenticator"]);
    expect(tree[0].children[0].notes).toEqual(["encrypted"]);
  });

  test("tolerates depth jumps and content before the first section", () => {
    const tree = nodesToTree([n(0, "field", "Loose", "1"), n(3, "section", "Deep"), n(5, "field", "Deeper", "2")]);
    expect(tree[0].title).toBe("");
    expect(tree[0].fields).toEqual([["Loose", "1"]]);
    // A section can only be one level below the open ones.
    expect(tree[0].children[0].title).toBe("Deep");
    expect(tree[0].children[0].fields).toEqual([["Deeper", "2"]]);
  });

  test("empty input", () => {
    expect(nodesToTree([])).toEqual([]);
  });
});
