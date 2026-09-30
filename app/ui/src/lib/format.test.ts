import { afterEach, describe, expect, it } from "vitest";
import { setLang } from "../i18n";
import { fmtInt } from "./format";

(globalThis as { document?: unknown }).document ??= { documentElement: {} };

describe("fmtInt", () => {
  afterEach(() => setLang("en"));
  it("follows the UI language after the first use", () => {
    setLang("en");
    expect(fmtInt(12345)).toBe("12,345");
    setLang("de");
    expect(fmtInt(12345)).toBe("12.345");
    setLang("en");
    expect(fmtInt(12345)).toBe("12,345");
  });
});
