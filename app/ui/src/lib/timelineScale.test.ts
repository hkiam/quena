import { describe, expect, it } from "vitest";
import { buildAxis, clampZoom, columnOrder, columnWidth, fmtSpan, moveColumn, tickLabel, tickStep, ticks, toggleColumn, zoomScroll } from "./timelineScale";

describe("timeline scale", () => {
  it("chooses steps in clock units at least minPx apart", () => {
    expect(tickStep(1000 / 10_000_000)).toBe(1_000_000); // 10 s over 1000 px → 1 s
    expect(tickStep(1000 / 1_000_000)).toBe(100_000); // 1 s → 100 ms
    expect(tickStep(1000 / 3_000_000)).toBe(500_000);
    expect(tickStep(1000 / 2_000)).toBe(200); // 2 ms → 0.2 ms
    expect(tickStep(1000 / 86_400_000_000)).toBe(3 * 3600 * 1e6); // a day → 3 h, not "20000 s"
    expect(tickStep(1000 / 600_000_000)).toBe(60 * 1e6); // 10 min → 1 min
    expect(tickStep(0)).toBe(1_000_000);
    expect(ticks(2_500_000, 1_000_000)).toEqual([0, 1_000_000, 2_000_000]);
  });
  it("labels offsets in readable units", () => {
    expect(tickLabel(0, 100_000)).toBe("0");
    expect(tickLabel(1_500_000, 500_000)).toBe("+1.5 s");
    expect(tickLabel(400, 200)).toBe("+0.4 ms");
    expect(tickLabel(4, 2)).toBe("+0.004 ms");
    expect(tickLabel(250_000, 50_000)).toBe("+250 ms");
    expect(tickLabel(150 * 1e6, 30 * 1e6)).toBe("+2 min 30 s");
    expect(tickLabel(6 * 3600e6, 3 * 3600e6)).toBe("+6 h");
    expect(tickLabel(30 * 3600e6, 6 * 3600e6)).toBe("+1 d 6 h");
    expect(tickLabel(86_400e6, 12 * 3600e6)).toBe("+1 d");
    expect(fmtSpan(20_000e6, 5 * 60e6)).toBe("5 h 33 min");
  });
  it("keeps the point under the cursor when zooming", () => {
    // Graph starts at 300 px; cursor at 500 px (200 px into the graph), no scroll.
    const s = zoomScroll(0, 300, 500, 1, 2);
    // At zoom 2 the same time is 400 px into the graph: scrollLeft must be 200.
    expect(s).toBe(200);
    expect(zoomScroll(200, 300, 500, 2, 1)).toBe(0);
    expect(clampZoom(0)).toBe(1);
    expect(clampZoom(1e9)).toBe(500);
  });
  it("orders, moves and toggles columns", () => {
    expect(columnOrder(undefined)).toEqual(["id", "method", "url", "duration", "graph"]);
    expect(columnOrder({ order: ["graph", "bogus" as never, "id", "id"] })).toEqual(["graph", "id", "url"]);
    expect(moveColumn(["id", "url", "graph"], "graph", "id")).toEqual(["graph", "id", "url"]);
    expect(moveColumn(["id", "url", "graph"], "id", null)).toEqual(["url", "graph", "id"]);
    expect(toggleColumn(["id", "url", "graph"], "status")).toEqual(["id", "status", "url", "graph"]);
    expect(toggleColumn(["id", "status", "url", "graph"], "status")).toEqual(["id", "url", "graph"]);
    expect(toggleColumn(["id", "url", "graph"], "url")).toEqual(["id", "url", "graph"]);
    expect(columnWidth({ widths: { url: 5 } }, "url")).toBe(36);
    expect(columnWidth(undefined, "url")).toBe(260);
  });
  it("cuts long idle gaps and keeps short pauses to scale", () => {
    const S = 1e6;
    // Two sessions of 20 ms / 120 ms, a day apart.
    const a = buildAxis([[0, 0.12 * S], [86_400 * S, 86_400 * S + 0.02 * S]], true, 0.05 * S);
    expect(a.clusters.length).toBe(2);
    expect(a.breaks).toEqual([{ at: 0.12 * S, gap: 86_400 * S - 0.12 * S }]);
    expect(a.length).toBeCloseTo(0.12 * S + 0.05 * S + 0.02 * S);
    expect(a.toAxis(86_400 * S)).toBeCloseTo(0.17 * S);
    // Without compression the day stays.
    expect(buildAxis([[0, 0.12 * S], [86_400 * S, 86_400 * S + 0.02 * S]], false, 0.05 * S).breaks).toEqual([]);
    // Polling every 2 s over 30 s: no cuts (short pauses are part of the picture).
    const poll = Array.from({ length: 15 }, (_, i) => [i * 2 * S, i * 2 * S + 0.05 * S] as [number, number]);
    expect(buildAxis(poll, true, 0.05 * S).breaks).toEqual([]);
    // A 30 s pause after 20 s of busy traffic is not cut (not 4× the activity).
    expect(buildAxis([[0, 20 * S], [50 * S, 70 * S]], true, S).breaks).toEqual([]);
    // Overlapping sessions merge; empty input is safe.
    expect(buildAxis([[0, 10], [5, 20]], true, 1).clusters).toEqual([{ from: 0, to: 20, at: 0 }]);
    expect(buildAxis([], true, 1).length).toBe(1);
  });
});
