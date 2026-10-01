// Arithmetic of the Timeline panel: time axis ticks, zoom around a point, column layout.
// Times are µs (like the session timers); widths are CSS pixels.

const MS = 1000;
const S = 1000 * MS;
const MIN = 60 * S;
const H = 60 * MIN;
const D = 24 * H;
/** Steps in real time units, so labels read like a clock (µs). */
const STEPS = [
  1, 2, 5, 10, 20, 50, 100, 200, 500,
  MS, 2 * MS, 5 * MS, 10 * MS, 20 * MS, 50 * MS, 100 * MS, 200 * MS, 500 * MS,
  S, 2 * S, 5 * S, 10 * S, 15 * S, 30 * S,
  MIN, 2 * MIN, 5 * MIN, 10 * MIN, 15 * MIN, 30 * MIN,
  H, 2 * H, 3 * H, 6 * H, 12 * H,
  D, 2 * D, 7 * D, 14 * D, 30 * D,
];

/** Tick step (µs) for a scale of `pxPerUs` so that labels are at least `minPx` apart. */
export function tickStep(pxPerUs: number, minPx = 90): number {
  if (!(pxPerUs > 0) || !Number.isFinite(pxPerUs)) return S;
  const raw = minPx / pxPerUs; // µs per minPx
  for (const s of STEPS) if (s >= raw) return s;
  // Beyond the table: whole multiples of 30 days.
  return Math.ceil(raw / (30 * D)) * 30 * D;
}

/** Ticks (offsets from the start, µs) within [0, spanUs]. */
export function ticks(spanUs: number, step: number): number[] {
  if (!(step > 0) || !(spanUs >= 0)) return [0];
  const n = Math.min(10_000, Math.floor(spanUs / step));
  return Array.from({ length: n + 1 }, (_, i) => i * step);
}

/** A duration for axis labels, as precise as the step needs: "250 ms", "1.5 s", "2 min 30 s",
 *  "6 h", "1 d 6 h". `num(n, decimals)` formats numbers in the UI language. */
export function fmtSpan(us: number, step: number, num: (n: number, decimals: number) => string = (n, d) => n.toFixed(d)): string {
  if (step < MS) return `${num(us / MS, step < 10 ? 3 : step < 100 ? 2 : 1)} ms`;
  if (step < S) return us < S ? `${num(us / MS, 0)} ms` : `${num(us / S, step < 10 * MS ? 3 : step < 100 * MS ? 2 : 1)} s`;
  const parts: string[] = [];
  let rest = Math.round(us / S) * S;
  const units: [number, string][] = [
    [D, "d"],
    [H, "h"],
    [MIN, "min"],
    [S, "s"],
  ];
  // The finest unit worth showing is the step's own unit (30 s steps → seconds).
  const finest = units.find(([u]) => u <= step)?.[0] ?? S;
  for (const [unit, name] of units) {
    if (unit < finest) break;
    const n = Math.floor(rest / unit);
    if (n) parts.push(`${n} ${name}`);
    rest -= n * unit;
  }
  return parts.length ? parts.join(" ") : "0 s";
}

/** "+250 ms", "+1.5 s", "+1 d 6 h" — axis labels (offset from the start). */
export function tickLabel(offsetUs: number, step: number, num?: (n: number, decimals: number) => string): string {
  return offsetUs === 0 ? "0" : `+${fmtSpan(offsetUs, step, num)}`;
}

/** New scroll position that keeps the point under `cursorX` (px from the graph's left edge,
 *  in the viewport) in place when zooming from `oldZoom` to `newZoom`. */
export function zoomScroll(scrollLeft: number, graphLeft: number, cursorX: number, oldZoom: number, newZoom: number): number {
  const inGraph = scrollLeft + cursorX - graphLeft; // px into the graph at the old zoom
  const next = inGraph * (newZoom / oldZoom) + graphLeft - cursorX;
  return Math.max(0, next);
}

export const MIN_ZOOM = 1;
export const MAX_ZOOM = 500;
export const clampZoom = (z: number) => Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Number.isFinite(z) ? z : 1));

/** Columns of the table; `graph` is the waterfall. */
export type TlColumn = "id" | "method" | "status" | "url" | "duration" | "size" | "graph";
export const TL_COLUMNS: TlColumn[] = ["id", "method", "status", "url", "duration", "size", "graph"];
export const TL_DEFAULT: TlColumn[] = ["id", "method", "url", "duration", "graph"];
export const TL_DEFAULT_WIDTH: Record<Exclude<TlColumn, "graph">, number> = { id: 52, method: 80, status: 60, url: 260, duration: 80, size: 74 };
export const TL_MIN_WIDTH = 36;
export const TL_MIN_GRAPH = 240;
/** Room at the right end of the graph, so bars that end last stay visible. */
export const TL_GRAPH_PAD = 12;

export interface TlLayout {
  /** Visible columns in display order (always contains `url` and `graph`). */
  order?: TlColumn[];
  widths?: Partial<Record<TlColumn, number>>;
}

/** Visible columns in order: unknown entries dropped, duplicates removed, `url` and `graph`
 *  always present. */
export function columnOrder(l: TlLayout | undefined): TlColumn[] {
  const seen = new Set<TlColumn>();
  const out: TlColumn[] = [];
  for (const c of l?.order ?? TL_DEFAULT) if (TL_COLUMNS.includes(c) && !seen.has(c)) (seen.add(c), out.push(c));
  for (const must of ["url", "graph"] as TlColumn[]) if (!seen.has(must)) out.push(must);
  return out;
}

export function columnWidth(l: TlLayout | undefined, c: Exclude<TlColumn, "graph">): number {
  const w = l?.widths?.[c];
  return typeof w === "number" && Number.isFinite(w) ? Math.max(TL_MIN_WIDTH, Math.min(1200, w)) : TL_DEFAULT_WIDTH[c];
}

/** Move column `c` before column `before` (or to the end). */
export function moveColumn(order: TlColumn[], c: TlColumn, before: TlColumn | null): TlColumn[] {
  if (c === before) return order;
  const rest = order.filter((x) => x !== c);
  const i = before ? rest.indexOf(before) : -1;
  return i < 0 ? [...rest, c] : [...rest.slice(0, i), c, ...rest.slice(i)];
}

/** Show or hide a column (url and graph always stay). */
export function toggleColumn(order: TlColumn[], c: TlColumn): TlColumn[] {
  if (c === "url" || c === "graph") return order;
  if (order.includes(c)) return order.filter((x) => x !== c);
  // Re-insert at its default position relative to the others.
  const at = TL_COLUMNS.indexOf(c);
  const i = order.findIndex((x) => TL_COLUMNS.indexOf(x) > at);
  return i < 0 ? [...order, c] : [...order.slice(0, i), c, ...order.slice(i)];
}
