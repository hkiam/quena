import { afterEach, describe, expect, it } from "vitest";
import { setLang } from "../i18n";
import { quickexecText } from "./quickexecText";

// setLang sets <html lang>; the tests run without a DOM.
(globalThis as { document?: unknown }).document ??= { documentElement: {} };

describe("quickexecText", () => {
  afterEach(() => setLang("en"));
  it("translates the backend's answers", () => {
    setLang("de");
    expect(quickexecText("Filter removed")).toBe("Filter entfernt");
    expect(quickexecText("Filter: cookie.b == 2")).toBe("Filter: cookie.b == 2");
    expect(quickexecText("3 session(s) selected")).toBe("3 Sessions ausgewählt");
    expect(quickexecText("1 session(s) removed")).toBe("1 Session entfernt");
    expect(quickexecText("bpu: breakpoints cleared")).toBe("bpu: Haltepunkte entfernt");
    expect(quickexecText("unknown command – type help")).toContain("Unbekannter Befehl");
  });
  it("keeps English counts and passes unknown texts through", () => {
    expect(quickexecText("1 session(s) selected")).toBe("1 session selected");
    expect(quickexecText("expected value at 7")).toBe("expected value at 7");
  });
});
