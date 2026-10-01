// Arithmetic of the Timeline panel: time axis ticks, zoom around a point, column layout.
// Times are µs (like the session timers); widths are CSS pixels.

/** Tick step (µs) for a scale of `pxPerUs` so that labels are at least `minPx` apart:
 *  1, 2 or 5 × 10ⁿ µs. */
export function tickStep(pxPerUs: number, minPx = 90): number {
  if (!(pxPerUs > 0) || !Number.isFinite(pxPerUs)) return 1_000_000;
  const raw = minPx / pxPerUs; // µs per minPx
  const pow = 10 ** Math.floor(Math.log10(raw));
  for (const m of [1, 2, 5, 10]) if (m * pow >= raw) return m * pow;
  return 10 * pow;
}

/** Ticks (offsets from the start, µs) within [0, spanUs]. */
export function ticks(spanUs: number, step: number): number[] {
  if (!(step > 0) || !(spanUs >= 0)) return [0];
  const n = Math.min(10_000, Math.floor(spanUs / step));
  return Array.from({ length: n + 1 }, (_, i) => i * step);
}

/** "+250 ms", "+1.5 s", "+2 min 5 s" — offset labels; `fmtMs` formats milliseconds. */
export function tickLabel(offsetUs: number, step: number, fmtMs: (ms: number) => string): string {
  if (offsetUs === 0) return "0";
  const ms = offsetUs / 1000;
  // Keep the precision of the step (0.5 ms steps show 0.5 ms).
  if (step < 1000) return `+${(ms).toFixed(step < 100 ? 2 : 1)} ms`;
  return `+${fmtMs(ms)}`;
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
