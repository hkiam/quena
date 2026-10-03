import { describe, expect, it } from "vitest";
import { jsonPath } from "./inspectMenus";

describe("JSONPath of a tree node", () => {
  it("uses dots for plain keys, brackets for indexes and odd keys", () => {
    expect(jsonPath("$", "items", false)).toBe("$.items");
    expect(jsonPath("$.items", "0", true)).toBe("$.items[0]");
    expect(jsonPath("$", "odd key", false)).toBe("$['odd key']");
    expect(jsonPath("$", "it's", false)).toBe("$['it\\'s']");
    expect(jsonPath("$", "@odata.context", false)).toBe("$['@odata.context']");
    expect(jsonPath("$", "1abc", false)).toBe("$['1abc']");
    // Control characters must be escaped in RFC 9535 string literals.
    expect(jsonPath("$", "a\nb\tc", false)).toBe("$['a\\nb\\tc']");
    expect(jsonPath("$", "x\u0001", false)).toBe("$['x\\u0001']");
    expect(jsonPath("$", "back\\slash", false)).toBe("$['back\\\\slash']");
  });
});
