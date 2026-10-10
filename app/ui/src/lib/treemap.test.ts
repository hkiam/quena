import { describe, expect, it } from "vitest";
import { treemap } from "./treemap";

describe("treemap", () => {
  it("fills the area in proportion", () => {
    const r = treemap([6, 6, 4, 3, 2, 2, 1], 600, 400);
    const area = r.reduce((a, b) => a + b.w * b.h, 0);
    expect(Math.round(area)).toBe(240_000);
    expect(r[0].w * r[0].h).toBeCloseTo(240_000 * (6 / 24), 3);
    for (const x of r) {
      expect(x.x).toBeGreaterThanOrEqual(-1e-9);
      expect(x.y).toBeGreaterThanOrEqual(-1e-9);
      expect(x.x + x.w).toBeLessThanOrEqual(600 + 1e-6);
      expect(x.y + x.h).toBeLessThanOrEqual(400 + 1e-6);
    }
  });
  it("keeps rectangles near square", () => {
    const r = treemap([1, 1, 1, 1], 200, 200);
    for (const x of r) expect(Math.max(x.w / x.h, x.h / x.w)).toBeLessThan(1.01);
  });
  it("leaves zeros empty and copes with nothing", () => {
    const r = treemap([5, 0, 5], 100, 50);
    expect(r[1]).toEqual({ x: 0, y: 0, w: 0, h: 0 });
    expect(treemap([], 10, 10)).toEqual([]);
    expect(treemap([0], 10, 10)[0].w).toBe(0);
  });
});
