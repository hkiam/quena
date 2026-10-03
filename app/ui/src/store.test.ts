import { describe, expect, it } from "vitest";
import { restoreLayout } from "./store";

describe("restoreLayout", () => {
  it("starts in the Quena layout", () => {
    expect(restoreLayout(undefined).preset).toBe("quena");
    // Only a theme or language saved (e.g. written by hand): still Quena, its columns.
    const l = restoreLayout({ theme: "light" });
    expect(l.preset).toBe("quena");
    expect(l.stacked).toBe(true);
    expect(l.columns.find((c) => c.key === "protocol")?.visible).toBe(false);
  });
  it("keeps the arrangement of layouts from before the presets", () => {
    const cols = restoreLayout(undefined).columns;
    expect(restoreLayout({ columns: cols, stacked: true }).preset).toBe("classic");
    expect(restoreLayout({ columns: cols, stacked: false }).preset).toBe("quena");
    expect(restoreLayout({ preset: "classic" }).preset).toBe("classic");
  });
});
