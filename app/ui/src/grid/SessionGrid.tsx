// Canvas session list. Rendering happens
// outside React: the controller draws only the visible rows from a page
// cache; React only renders the header.
import { useEffect, useRef, useState } from "react";
import { api, type SessionSummary } from "../api";
import { fmtDate, fmtInt, fmtMs, fmtTime, fmtUsd } from "../lib/format";
import { columnTitle, get, promptText, say, set, useStore, type ColumnConf, type ColumnKey } from "../store";
import { addClause, clause, fieldOf, filtersOn } from "../lib/columnFilter";
import { isHeaderColumn, removeHeaderColumn } from "../headerColumns";
import { RowCache } from "./rowCache";
import { methodPill, readPalette, rowStyle, stateMark, statusPill, type Palette, type Pill } from "./style";
import { actions } from "../actions";
import { showContextMenu } from "../components/ContextMenu";
import { groupMenu, listMenu, sessionMenu } from "../menus";
import { t } from "../i18n";
import { browserMenuWanted } from "../components/contextMenus";

/** Row height: roomy in the Quena layout, dense in Classic. */
let ROW_H = 24;
const rowHeightFor = (preset: string) => (preset === "classic" ? 20 : 24);
const MAX_SCROLL_PX = 8_000_000;
const FONT = "12px -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif";
const FONT_BOLD = "600 12px -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif";
const FONT_ITALIC = "italic 12px -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif";
const FONT_PILL = "600 10.5px -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif";

export const rowCache = new RowCache();

/**
 * Visible columns as drawn: when they are narrower than the list, the Path column (or Host,
 * or the last one) takes the rest, so a wide window shows longer URLs instead of empty space.
 * Stored widths stay as the user set them; they act as minimums here.
 */
/** What the sessions of a group share, for its first row. */
function groupLabel(r: SessionSummary, first: number): string {
  switch (get().layout.groupBy) {
    case "connection":
      return r.clientIp ? t("Connection of #{id} · {client}", { id: first, client: r.clientIp }) : t("Connection of #{id}", { id: first });
    case "host":
      return r.host;
    case "process":
      return r.process;
    case "trace":
      return t("Trace {id}", { id: r.trace ?? "" });
    case "session":
      return r.session ?? "";
    case "custom":
      return r.custom;
    case "via":
      return r.via ?? "";
    default:
      return "";
  }
}

/** The Group column (first, while the list is grouped) and the visible columns, fitted. */
export function displayColumns(width: number): ColumnConf[] {
  const { layout } = get();
  // With the navigator open it lists the groups' names: the column needs less room.
  const groupWidth = layout.groupWidth ?? (layout.navOpen ? 150 : 240);
  const group: ColumnConf[] = layout.groupBy && layout.groupBy !== "none" ? [{ key: "group", title: t("Group"), width: groupWidth, visible: true }] : [];
  return fitColumns([...group, ...layout.columns], width);
}

export function fitColumns(cols: ColumnConf[], width: number): ColumnConf[] {
  const vis = cols.filter((c) => c.visible);
  const total = vis.reduce((a, c) => a + c.width, 0);
  if (!vis.length || width <= total) return vis;
  const flex = vis.find((c) => c.key === "url") ?? vis.find((c) => c.key === "host") ?? vis[vis.length - 1];
  return vis.map((c) => (c === flex ? { ...c, width: c.width + (width - total) } : c));
}

function cellText(r: SessionSummary, key: ColumnKey): string {
  switch (key) {
    case "id":
      return String(r.id);
    case "result":
      return r.status ? String(r.status) : r.state === "aborted" ? "-" : "";
    case "protocol":
      return r.protocol;
    case "host":
      return r.host;
    case "url":
      return r.url;
    case "body":
      return r.kind === "tunnel" && !r.responseBodyLen ? "0" : fmtInt(r.responseBodyLen);
    case "caching":
      return r.caching;
    case "contentType":
      return r.contentType;
    case "process":
      return r.process;
    case "comments":
      return r.comment;
    case "custom":
      return r.custom;
    case "via":
      return r.via ?? "";
    case "method":
      return r.method;
    case "duration":
      return fmtMs(r.durationMs);
    case "started":
      return fmtTime(r.startedAt);
    case "cert":
      return r.certExpires ? fmtDate(r.certExpires * 1_000_000) : "";
    case "llm":
      return r.llm ?? "";
    case "tokens":
      return r.llmTokens != null ? fmtInt(r.llmTokens) : "";
    case "cost":
      return r.llmCostMicros != null ? fmtUsd(r.llmCostMicros / 1_000_000) : "";
    case "tls":
      return r.tls ?? "";
    case "remoteIp":
      return r.remoteIp ?? "";
    case "http":
      return r.httpVersion ?? "";
    case "header1":
      return r.headerValues?.[0] ?? "";
    case "header2":
      return r.headerValues?.[1] ?? "";
    case "header3":
      return r.headerValues?.[2] ?? "";
    case "group":
      return "";
  }
}

/** Slow and large responses stand out in the Duration and Size columns. */
const SLOW_MS = 1000;
const VERY_SLOW_MS = 5000;
const LARGE_BYTES = 1 << 20;
const VERY_LARGE_BYTES = 10 << 20;
function outlier(r: SessionSummary, key: ColumnKey, p: Palette): string | null {
  if (key === "duration" && r.durationMs != null) {
    if (r.durationMs >= VERY_SLOW_MS) return p.tones.err.fg;
    if (r.durationMs >= SLOW_MS) return p.tones.warn.fg;
  }
  if (key === "body" && r.kind !== "tunnel") {
    if (r.responseBodyLen >= VERY_LARGE_BYTES) return p.tones.err.fg;
    if (r.responseBodyLen >= LARGE_BYTES) return p.tones.warn.fg;
  }
  return null;
}

class Ellipsis {
  private cache = new Map<string, string>();
  fit(ctx: CanvasRenderingContext2D, text: string, width: number, font: string): string {
    if (!text) return "";
    const key = `${font}|${width}|${text}`;
    const hit = this.cache.get(key);
    if (hit !== undefined) return hit;
    let out = text;
    if (text.length * 3 > width || ctx.measureText(text).width > width) {
      if (ctx.measureText(text).width > width) {
        let lo = 0;
        let hi = Math.min(text.length, 400);
        while (lo < hi) {
          const mid = (lo + hi + 1) >> 1;
          if (ctx.measureText(text.slice(0, mid) + "…").width <= width) lo = mid;
          else hi = mid - 1;
        }
        out = lo > 0 ? text.slice(0, lo) + "…" : "";
      }
    }
    if (this.cache.size > 20000) this.cache.clear();
    this.cache.set(key, out);
    return out;
  }
}

export class GridController {
  scroller!: HTMLDivElement;
  canvas!: HTMLCanvasElement;
  spacer!: HTMLDivElement;
  private ctx!: CanvasRenderingContext2D;
  private pal!: Palette;
  private raf = 0;
  private vw = 0;
  private vh = 0;
  private dpr = 1;
  private hasFocus = false;
  private stickBottom = true;
  private ell = new Ellipsis();
  private unsub: (() => void)[] = [];
  onScrollX: (x: number) => void = () => {};

  attach(scroller: HTMLDivElement, canvas: HTMLCanvasElement, spacer: HTMLDivElement) {
    this.scroller = scroller;
    this.canvas = canvas;
    this.spacer = spacer;
    this.ctx = canvas.getContext("2d", { alpha: false })!;
    this.pal = readPalette(scroller);
    rowCache.onUpdate = () => this.schedule();
    const ro = new ResizeObserver(() => this.resize());
    ro.observe(scroller);
    this.unsub.push(() => ro.disconnect());
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onTheme = () => {
      this.pal = readPalette(scroller);
      this.schedule();
    };
    mq.addEventListener("change", onTheme);
    this.unsub.push(() => mq.removeEventListener("change", onTheme));
    const onScroll = () => {
      this.stickBottom = scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - ROW_H;
      this.onScrollX(scroller.scrollLeft);
      this.schedule();
    };
    scroller.addEventListener("scroll", onScroll, { passive: true });
    this.unsub.push(() => scroller.removeEventListener("scroll", onScroll));
    this.unsub.push(
      useStore.subscribe((s, prev) => {
        if (s.listVersion !== prev.listVersion || s.listTotal !== prev.listTotal) {
          const grew = s.listTotal > prev.listTotal;
          rowCache.invalidate(s.listVersion, s.listTotal);
          this.updateSpacer();
          if (grew && this.stickBottom && s.sort.column === "id" && !s.sort.descending) {
            scroller.scrollTop = scroller.scrollHeight;
          }
          this.schedule();
        }
        if (s.gridNonce !== prev.gridNonce) {
          rowCache.clear();
          this.schedule();
        }
        if (s.layout.theme !== prev.layout.theme) {
          // The document's theme attribute is applied in an effect; read colours after it.
          requestAnimationFrame(() => {
            this.pal = readPalette(scroller);
            this.schedule();
          });
        }
        if (s.layout.preset !== prev.layout.preset) {
          ROW_H = rowHeightFor(s.layout.preset);
          this.updateSpacer();
        }
        if (
          s.selection !== prev.selection ||
          s.focusIndex !== prev.focusIndex ||
          s.layout.columns !== prev.layout.columns ||
          s.layout.preset !== prev.layout.preset ||
          s.layout.groupBy !== prev.layout.groupBy ||
          s.layout.groupWidth !== prev.layout.groupWidth ||
          s.layout.navOpen !== prev.layout.navOpen
        ) {
          this.updateSpacer();
          this.schedule();
        }
      }),
    );
    ROW_H = rowHeightFor(get().layout.preset);
    this.resize();
  }

  detach() {
    this.unsub.forEach((u) => u());
    cancelAnimationFrame(this.raf);
  }

  setFocus(f: boolean) {
    this.hasFocus = f;
    this.schedule();
  }

  columns(): ColumnConf[] {
    return displayColumns(this.vw);
  }

  /** The column at a client x position. */
  columnAt(clientX: number): ColumnConf | undefined {
    const rect = this.canvas.getBoundingClientRect();
    let x = clientX - rect.left + this.scroller.scrollLeft;
    for (const c of this.columns()) {
      if (x < c.width) return c;
      x -= c.width;
    }
    return undefined;
  }

  /** Colour of a group (stable per group). */
  private hue(h: number): string {
    const p = this.pal;
    const all = [p.marks.blue, p.marks.green, p.marks.orange, p.marks.purple, p.marks.red, p.marks.gold, p.tones.info.fg, p.tones.violet.fg];
    return all[h % all.length];
  }

  /** The Group cell: a colour bar, and on a group's first row ▾/▸, what it shares and its size. */
  private groupCell(r: SessionSummary, i: number, x: number, y: number, width: number, sel: boolean) {
    const g = rowCache.group(i);
    if (!g) return;
    const ctx = this.ctx;
    ctx.fillStyle = this.hue(g.hue);
    ctx.fillRect(x + 6, y + 2, 3, ROW_H - 4);
    if (!g.start) return;
    const p = this.pal;
    const head = `${g.collapsed ? "▸" : "▾"} ${groupLabel(r, g.first)}`;
    const count = ` ${fmtInt(g.size)}`;
    ctx.font = FONT_BOLD;
    ctx.fillStyle = sel ? p.selFg : p.fg;
    const cw = ctx.measureText(count).width;
    const text = this.ell.fit(ctx, head, width - 22 - cw, FONT_BOLD);
    ctx.fillText(text, x + 14, y + ROW_H / 2 + 0.5);
    const tw = ctx.measureText(text).width; // in the bold font it was drawn in
    ctx.font = FONT;
    ctx.fillStyle = sel ? p.selFg : p.muted;
    ctx.fillText(count, x + 14 + tw + 2, y + ROW_H / 2 + 0.5);
  }

  totalWidth(): number {
    return this.columns().reduce((a, c) => a + c.width, 0);
  }

  private resize() {
    this.dpr = window.devicePixelRatio || 1;
    this.vw = this.scroller.clientWidth;
    if (get().gridWidth !== this.vw) set({ gridWidth: this.vw });
    this.vh = this.scroller.clientHeight;
    this.canvas.width = Math.max(1, Math.floor(this.vw * this.dpr));
    this.canvas.height = Math.max(1, Math.floor(this.vh * this.dpr));
    this.canvas.style.width = `${this.vw}px`;
    this.canvas.style.height = `${this.vh}px`;
    this.updateSpacer();
    this.draw();
  }

  private contentH() {
    return get().listTotal * ROW_H;
  }

  private virtualH() {
    return Math.min(this.contentH(), MAX_SCROLL_PX);
  }

  /** Ratio between real content pixels and scroll pixels (>1 for huge lists). */
  private ratio() {
    const c = this.contentH();
    const v = this.virtualH();
    if (c <= v || v <= this.vh) return 1;
    return (c - this.vh) / (v - this.vh);
  }

  private updateSpacer() {
    const h = Math.max(0, this.virtualH() - this.vh);
    this.spacer.style.height = `${h}px`;
    this.spacer.style.width = `${Math.max(this.totalWidth(), this.vw)}px`;
  }

  topPx(): number {
    return this.scroller.scrollTop * this.ratio();
  }

  firstVisible(): number {
    return Math.floor(this.topPx() / ROW_H);
  }

  visibleCount(): number {
    return Math.ceil(this.vh / ROW_H);
  }

  indexAt(clientY: number): number {
    const rect = this.canvas.getBoundingClientRect();
    return Math.floor((this.topPx() + clientY - rect.top) / ROW_H);
  }

  scrollToIndex(i: number, align: "nearest" | "center" = "nearest") {
    const top = this.topPx();
    const y = i * ROW_H;
    const r = this.ratio();
    if (align === "center") {
      this.scroller.scrollTop = Math.max(0, (y - this.vh / 2) / r);
    } else if (y < top) {
      this.scroller.scrollTop = y / r;
    } else if (y + ROW_H > top + this.vh) {
      this.scroller.scrollTop = (y + ROW_H - this.vh) / r;
    }
    this.schedule();
  }

  /** A rounded badge, left-aligned in the cell and clipped to its width. */
  private pill(pill: Pill, x: number, y: number, maxW: number) {
    const ctx = this.ctx;
    const tone = this.pal.tones[pill.tone];
    ctx.font = FONT_PILL;
    const text = this.ell.fit(ctx, pill.text, maxW - 10, FONT_PILL);
    if (!text) return;
    const w = Math.min(maxW, ctx.measureText(text).width + 10);
    const h = Math.min(16, ROW_H - 6);
    const top = y + (ROW_H - h) / 2;
    ctx.fillStyle = tone.bg;
    ctx.beginPath();
    ctx.roundRect(x, top, w, h, 4);
    ctx.fill();
    ctx.fillStyle = tone.fg;
    ctx.fillText(text, x + 5, y + ROW_H / 2 + 0.5);
  }

  schedule() {
    if (this.raf) return;
    this.raf = requestAnimationFrame(() => {
      this.raf = 0;
      this.draw();
    });
  }

  private draw() {
    const ctx = this.ctx;
    if (!ctx) return;
    const { listTotal, selection, focusIndex } = get();
    const p = this.pal;
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.fillStyle = p.bg;
    ctx.fillRect(0, 0, this.vw, this.vh);
    const top = this.topPx();
    const first = Math.floor(top / ROW_H);
    const offY = -(top - first * ROW_H);
    const n = Math.ceil(this.vh / ROW_H) + 1;
    rowCache.ensure(first, first + n + 16);
    const cols = this.columns();
    const sx = this.scroller.scrollLeft;
    ctx.textBaseline = "middle";
    for (let k = 0; k < n; k++) {
      const i = first + k;
      if (i >= listTotal) break;
      const y = offY + k * ROW_H;
      const r = rowCache.get(i);
      if (!r) {
        ctx.fillStyle = p.muted;
        ctx.font = FONT;
        ctx.fillText("…", 6 - sx, y + ROW_H / 2);
        continue;
      }
      const st = rowStyle(r, p);
      const selected = selection.has(r.id);
      if (selected) {
        ctx.fillStyle = this.hasFocus ? p.selBg : p.selInactiveBg;
        ctx.fillRect(0, y, this.vw, ROW_H);
      } else if (st.bg) {
        ctx.fillStyle = st.bg;
        ctx.fillRect(0, y, this.vw, ROW_H);
      }
      const font = st.bold ? FONT_BOLD : st.italic ? FONT_ITALIC : FONT;
      ctx.font = font;
      let x = -sx;
      for (const c of cols) {
        if (x + c.width < 0) {
          x += c.width;
          continue;
        }
        if (x > this.vw) break;
        const fg = selected && this.hasFocus ? p.selFg : st.fg;
        const sel = selected && this.hasFocus;
        if (c.key === "group") {
          this.groupCell(r, i, x, y, c.width, sel);
          ctx.font = font;
        } else if (c.key === "id") {
          ctx.fillStyle = sel ? p.selFg : p.muted;
          ctx.fillText(this.ell.fit(ctx, String(r.id), c.width - 12, font), x + 8, y + ROW_H / 2 + 0.5);
        } else if (c.key === "method" || c.key === "result") {
          const pill = c.key === "method" ? methodPill(r) : statusPill(r);
          if (pill) this.pill(pill, x + 4, y, c.width - 8);
          else if (c.key === "result" && r.state !== "done") {
            ctx.fillStyle = sel ? p.selFg : p.muted;
            ctx.fillText("…", x + 6, y + ROW_H / 2 + 0.5);
          }
          ctx.font = font;
        } else if (c.key === "url" && r.kind === "tunnel" && !r.url) {
          this.pill({ text: "TUNNEL", tone: "muted" }, x + 4, y, c.width - 8);
          ctx.font = font;
        } else {
          const text = this.ell.fit(ctx, cellText(r, c.key), c.width - 8, font);
          ctx.fillStyle = sel ? fg : (outlier(r, c.key, p) ?? fg);
          if (c.align === "right") {
            ctx.textAlign = "right";
            ctx.fillText(text, x + c.width - 4, y + ROW_H / 2 + 0.5);
            ctx.textAlign = "left";
          } else {
            ctx.fillText(text, x + 4, y + ROW_H / 2 + 0.5);
          }
        }
        x += c.width;
      }
      const mark = stateMark(r, p);
      if (mark) {
        ctx.fillStyle = mark;
        ctx.fillRect(0, y + 3, 3, ROW_H - 6);
      }
      if (focusIndex === i && this.hasFocus) {
        ctx.strokeStyle = p.focus;
        ctx.strokeRect(0.5, y + 0.5, this.vw - 1, ROW_H - 1);
      }
      // A group starts: a line across, in the group's colour.
      const g = rowCache.group(i);
      if (g?.start && i > 0) {
        ctx.fillStyle = this.hue(g.hue);
        ctx.fillRect(0, y, this.vw, 1);
      }
    }
    // Soft row separators (the Classic layout keeps column lines instead).
    ctx.strokeStyle = p.grid;
    ctx.beginPath();
    if (get().layout.preset === "classic") {
      let x = -sx;
      for (const c of cols) {
        x += c.width;
        if (x > 0 && x < this.vw) {
          ctx.moveTo(Math.floor(x) + 0.5, 0);
          ctx.lineTo(Math.floor(x) + 0.5, this.vh);
        }
      }
    } else {
      for (let k = 1; k <= n; k++) {
        const ly = Math.floor(offY + k * ROW_H) - 0.5;
        if (first + k > listTotal) break;
        ctx.moveTo(0, ly);
        ctx.lineTo(this.vw, ly);
      }
    }
    ctx.stroke();
    if (listTotal === 0) {
      ctx.fillStyle = p.muted;
      ctx.font = FONT;
      ctx.textAlign = "center";
      ctx.fillText(get().status?.engine.capturing ? t("Waiting for traffic…") : t("No sessions. Press F12 to start capturing."), this.vw / 2, 40);
      ctx.textAlign = "left";
    }
  }
}

export const grid = new GridController();

function Header({ scrollX }: { scrollX: number }) {
  const columns = useStore((s) => s.layout.columns);
  const gridWidth = useStore((s) => s.gridWidth);
  // Re-render when the Group column comes or goes or is resized.
  useStore((s) => s.layout.groupBy);
  useStore((s) => s.layout.groupWidth);
  useStore((s) => s.layout.navOpen);
  const shown = displayColumns(gridWidth);
  const sort = useStore((s) => s.sort);
  const headerCols = useStore((s) => s.settings?.headerColumns);
  const filterExpr = useStore((s) => (s.filters?.enabled ? s.filters.expression : ""));
  const drag = useRef<{ key: ColumnKey; startX: number; startW: number } | null>(null);
  const [dragOver, setDragOver] = useState<ColumnKey | null>(null);

  const setColumns = (cols: ColumnConf[]) => {
    set((s) => ({ layout: { ...s.layout, columns: cols } }));
    actions.saveLayout();
  };

  const onResizeDown = (e: React.PointerEvent, c: ColumnConf) => {
    e.stopPropagation();
    e.preventDefault();
    drag.current = { key: c.key, startX: e.clientX, startW: c.width };
    const move = (ev: PointerEvent) => {
      const d = drag.current;
      if (!d) return;
      const w = Math.max(24, d.startW + ev.clientX - d.startX);
      if (d.key === "group") set((s) => ({ layout: { ...s.layout, groupWidth: w } }));
      else set((s) => ({ layout: { ...s.layout, columns: s.layout.columns.map((x) => (x.key === d.key ? { ...x, width: w } : x)) } }));
    };
    const up = () => {
      drag.current = null;
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      actions.saveLayout();
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const onHeaderClick = (c: ColumnConf) => {
    if (c.key === "group") return;
    const cur = get().sort;
    let next;
    if (cur.column !== c.key) next = { column: c.key, descending: false };
    else if (!cur.descending) next = { column: c.key, descending: true };
    else next = { column: "id" as const, descending: false };
    actions.setSort(next);
  };

  const filterBy = async (key: ColumnKey) => {
    const field = fieldOf(key, headerCols);
    if (!field) return;
    const input = await promptText(t("Filter by {column}", { column: columnTitle(key, headerCols) }), t("Value, optionally after an operator: example, *.example.com, >= 400, != 200, =~ ^/v2"));
    if (input == null) return;
    const c = clause(field, input);
    const f = get().filters;
    if (!c || !f) return;
    const next = { ...f, enabled: true, expression: addClause(f.enabled ? f.expression : "", c) };
    try {
      await api.setFilters(next);
      set({ filters: next });
      say(t("Filter: {expr}", { expr: next.expression }));
    } catch (err) {
      say(String(err), "error");
    }
  };

  const onContext = (e: React.MouseEvent) => {
    e.preventDefault();
    const key = (e.target as HTMLElement).closest<HTMLElement>("[data-key]")?.dataset.key as ColumnKey | undefined;
    const field = key ? fieldOf(key, headerCols) : null;
    showContextMenu(e.clientX, e.clientY, [
      ...(key && field ? [{ label: t("Filter by {column}…", { column: columnTitle(key, headerCols) }), action: () => void filterBy(key) }] : []),
      ...(key && isHeaderColumn(key) && field ? [{ label: t("Remove header column {column}", { column: columnTitle(key, headerCols) }), action: () => void removeHeaderColumn(key) }] : []),
      ...(field ? [{ separator: true }] : []),
      ...columns
        .filter((c) => !isHeaderColumn(c.key) || fieldOf(c.key, headerCols))
        .map((c) => ({
          label: columnTitle(c.key, headerCols),
          checked: c.visible,
          action: () => setColumns(columns.map((x) => (x.key === c.key ? { ...x, visible: !x.visible } : x))),
        })),
      { separator: true },
      { label: t("Group by"), submenu: groupMenu() },
      { separator: true },
      { label: t("Reset Columns"), action: () => actions.resetColumns() },
    ]);
  };

  return (
    <div className="grid-header" onContextMenu={onContext}>
      <div className="grid-header-inner" style={{ transform: `translateX(${-scrollX}px)` }}>
        {shown.map((c) => (
            <div
              key={c.key}
              className={`gh-cell ${dragOver === c.key ? "drag-over" : ""} ${c.align === "right" ? "gh-right" : ""}`}
              style={{ width: c.width }}
              draggable={c.key !== "group"}
              onDragStart={(e) => e.dataTransfer.setData("quena/column", c.key)}
              onDragOver={(e) => {
                if (e.dataTransfer.types.includes("quena/column")) {
                  e.preventDefault();
                  setDragOver(c.key);
                }
              }}
              onDragLeave={() => setDragOver(null)}
              onDrop={(e) => {
                setDragOver(null);
                const from = e.dataTransfer.getData("quena/column") as ColumnKey;
                if (!from || from === c.key) return;
                const cols = [...columns];
                const fi = cols.findIndex((x) => x.key === from);
                const [moved] = cols.splice(fi, 1);
                const ti = cols.findIndex((x) => x.key === c.key);
                cols.splice(ti, 0, moved);
                setColumns(cols);
              }}
              onClick={() => onHeaderClick(c)}
              title={columnTitle(c.key, headerCols)}
              data-key={c.key}
            >
              <span className="gh-title">{columnTitle(c.key, headerCols)}</span>
              {filtersOn(filterExpr ?? "", fieldOf(c.key, headerCols)) && (
                <span className="gh-funnel" title={t("The filter tests this column")}>
                  ⏷
                </span>
              )}
              {sort.column === c.key && c.key !== "id" && <span className="gh-sort">{sort.descending ? "▼" : "▲"}</span>}
              {sort.column === "id" && c.key === "id" && sort.descending && <span className="gh-sort">▼</span>}
              <div className="gh-resize" onPointerDown={(e) => onResizeDown(e, c)} onClick={(e) => e.stopPropagation()} />
            </div>
          ))}
      </div>
    </div>
  );
}

export function SessionGrid() {
  const scrollerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const spacerRef = useRef<HTMLDivElement>(null);
  const [scrollX, setScrollX] = useState(0);

  useEffect(() => {
    grid.attach(scrollerRef.current!, canvasRef.current!, spacerRef.current!);
    grid.onScrollX = setScrollX;
    return () => grid.detach();
  }, []);

  const rightDownAt = useRef(-Infinity);
  const onMouseDown = (e: React.MouseEvent) => {
    if (e.button === 2 || (e.button === 0 && e.ctrlKey)) rightDownAt.current = performance.now(); // Ctrl+click on macOS
    scrollerRef.current?.focus();
    const i = grid.indexAt(e.clientY);
    if (i < 0 || i >= get().listTotal) {
      if (e.button === 0) actions.clearSelection();
      return;
    }
    if (e.button === 2) {
      const r = rowCache.get(i);
      if (r && !get().selection.has(r.id)) actions.selectIndex(i, "single");
      return;
    }
    if (e.button !== 0) return;
    // The Group cell of a group's first row collapses or expands the group.
    if (grid.columnAt(e.clientX)?.key === "group" && rowCache.group(i)?.start && !e.shiftKey && !e.metaKey && !e.ctrlKey) {
      actions.selectIndex(i, "single");
      void actions.toggleGroupAt(i);
      return;
    }
    if (e.shiftKey) actions.selectIndex(i, "range");
    else if (e.metaKey || e.ctrlKey) actions.selectIndex(i, "toggle");
    else actions.selectIndex(i, "single");
  };

  const onContextMenu = (e: React.MouseEvent) => {
    if (browserMenuWanted(e)) return;
    e.preventDefault();
    // From the keyboard (Shift+F10, menu key) the selection's menu; with the mouse, below the
    // last row (or with nothing selected), what applies to the list as a whole. A mouse menu
    // follows a right button press (`detail` is 0 for synthetic clicks too, e.g. WebKitGTK's).
    const keyboard = performance.now() - rightDownAt.current > 1000;
    const i = grid.indexAt(e.clientY);
    const onRow = keyboard || (i >= 0 && i < get().listTotal);
    if (!onRow || get().selection.size === 0) showContextMenu(e.clientX, e.clientY, listMenu());
    else showContextMenu(e.clientX, e.clientY, sessionMenu());
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (actions.gridKey(e.nativeEvent)) {
      e.preventDefault();
      e.stopPropagation();
    }
  };

  const onDragStart = (e: React.DragEvent) => {
    const ids = [...get().selection];
    if (!ids.length) {
      e.preventDefault();
      return;
    }
    e.dataTransfer.setData("quena/sessions", JSON.stringify(ids));
    e.dataTransfer.effectAllowed = "copy";
  };

  return (
    <div className="grid">
      <Header scrollX={scrollX} />
      <div
        ref={scrollerRef}
        className="grid-scroller"
        tabIndex={0}
        onMouseDown={onMouseDown}
        onDoubleClick={() => actions.showTab("inspectors")}
        onContextMenu={onContextMenu}
        onKeyDown={onKeyDown}
        onFocus={() => grid.setFocus(true)}
        onBlur={() => grid.setFocus(false)}
        onCopy={(e) => {
          e.preventDefault();
          actions.copySessions("summary");
        }}
        onCut={(e) => {
          e.preventDefault();
          actions.removeAll();
        }}
        draggable
        onDragStart={onDragStart}
      >
        <canvas ref={canvasRef} className="grid-canvas" />
        <div ref={spacerRef} className="grid-spacer" />
      </div>
    </div>
  );
}

export async function idAtIndex(i: number): Promise<number | undefined> {
  const r = rowCache.get(i);
  if (r) return r.id;
  const ids = await api.viewIds(i, 1);
  return ids[0];
}
