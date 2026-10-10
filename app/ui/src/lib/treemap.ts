// Squarified treemap: rectangles with areas in proportion to the values, as square as can be.
// (Bruls, Huizing, van Wijk 2000.)

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** Rectangles for `values` (in their order; largest first gives the best result) within
 * `w × h`. Zero and negative values get an empty rectangle. */
export function treemap(values: number[], w: number, h: number): Rect[] {
  const out: Rect[] = values.map(() => ({ x: 0, y: 0, w: 0, h: 0 }));
  const items = values.map((v, i) => ({ v: Math.max(0, v), i })).filter((x) => x.v > 0);
  const total = items.reduce((a, b) => a + b.v, 0);
  if (!total || w <= 0 || h <= 0) return out;
  const scale = (w * h) / total;
  let rect = { x: 0, y: 0, w, h };
  let row: { a: number; i: number }[] = [];
  const worst = (r: { a: number }[], side: number) => {
    const s = r.reduce((a, b) => a + b.a, 0);
    const max = Math.max(...r.map((x) => x.a));
    const min = Math.min(...r.map((x) => x.a));
    return Math.max((side * side * max) / (s * s), (s * s) / (side * side * min));
  };
  const layRow = () => {
    const s = row.reduce((a, b) => a + b.a, 0);
    if (rect.w >= rect.h) {
      // A column on the left.
      const cw = s / rect.h;
      let y = rect.y;
      for (const r of row) {
        const rh = r.a / cw;
        out[r.i] = { x: rect.x, y, w: cw, h: rh };
        y += rh;
      }
      rect = { x: rect.x + cw, y: rect.y, w: rect.w - cw, h: rect.h };
    } else {
      // A row on top.
      const rh = s / rect.w;
      let x = rect.x;
      for (const r of row) {
        const rw = r.a / rh;
        out[r.i] = { x, y: rect.y, w: rw, h: rh };
        x += rw;
      }
      rect = { x: rect.x, y: rect.y + rh, w: rect.w, h: rect.h - rh };
    }
    row = [];
  };
  for (const it of items) {
    const a = it.v * scale;
    const side = Math.min(rect.w, rect.h);
    if (row.length && worst([...row, { a }], side) > worst(row, side)) layRow();
    row.push({ a, i: it.i });
  }
  if (row.length) layRow();
  return out;
}
