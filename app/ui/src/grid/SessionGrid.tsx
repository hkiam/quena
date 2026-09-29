// Canvas session list. Rendering happens
// outside React: the controller draws only the visible rows from a page
// cache; React only renders the header.
import { useEffect, useRef, useState } from "react";
import { api, type SessionSummary } from "../api";
import { fmtInt, fmtMs, fmtTime } from "../lib/format";
import { get, set, useStore, type ColumnConf, type ColumnKey } from "../store";
import { RowCache } from "./rowCache";
import { readPalette, rowIcon, rowStyle, type Palette } from "./style";
import { actions } from "../actions";
import { showContextMenu } from "../components/ContextMenu";
import { sessionMenu } from "../menus";

export const ROW_H = 18;
const MAX_SCROLL_PX = 8_000_000;
const FONT = "12px -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif";
const FONT_BOLD = "600 12px -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif";
const FONT_ITALIC = "italic 12px -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif";

export const rowCache = new RowCache();

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
    case "method":
      return r.method;
    case "duration":
      return fmtMs(r.durationMs);
    case "started":
      return fmtTime(r.startedAt);
  }
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
        if (s.selection !== prev.selection || s.focusIndex !== prev.focusIndex || s.layout.columns !== prev.layout.columns) {
          this.updateSpacer();
          this.schedule();
        }
      }),
    );
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
    return get().layout.columns.filter((c) => c.visible);
  }

  totalWidth(): number {
    return this.columns().reduce((a, c) => a + c.width, 0);
  }

  private resize() {
    this.dpr = window.devicePixelRatio || 1;
    this.vw = this.scroller.clientWidth;
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
        if (c.key === "id") {
          const icon = rowIcon(r, p);
          ctx.fillStyle = selected && this.hasFocus ? p.selFg : icon.color;
          ctx.font = FONT_BOLD;
          ctx.textAlign = "center";
          ctx.fillText(icon.glyph, x + 9, y + ROW_H / 2);
          ctx.font = font;
          ctx.textAlign = "left";
          ctx.fillStyle = fg;
          ctx.fillText(this.ell.fit(ctx, String(r.id), c.width - 24, font), x + 20, y + ROW_H / 2 + 0.5);
        } else {
          const t = this.ell.fit(ctx, cellText(r, c.key), c.width - 8, font);
          ctx.fillStyle = fg;
          if (c.align === "right") {
            ctx.textAlign = "right";
            ctx.fillText(t, x + c.width - 4, y + ROW_H / 2 + 0.5);
            ctx.textAlign = "left";
          } else {
            ctx.fillText(t, x + 4, y + ROW_H / 2 + 0.5);
          }
        }
        x += c.width;
      }
      if (focusIndex === i && this.hasFocus) {
        ctx.strokeStyle = p.focus;
        ctx.setLineDash([2, 2]);
        ctx.strokeRect(0.5, y + 0.5, this.vw - 1, ROW_H - 1);
        ctx.setLineDash([]);
      }
    }
    // Column separators (subtle)
    ctx.strokeStyle = p.grid;
    ctx.beginPath();
    let x = -sx;
    for (const c of cols) {
      x += c.width;
      if (x > 0 && x < this.vw) {
        ctx.moveTo(Math.floor(x) + 0.5, 0);
        ctx.lineTo(Math.floor(x) + 0.5, this.vh);
      }
    }
    ctx.stroke();
    if (listTotal === 0) {
      ctx.fillStyle = p.muted;
      ctx.font = FONT;
      ctx.textAlign = "center";
      ctx.fillText(get().status?.engine.capturing ? "Waiting for traffic…" : "No sessions. Press F12 to start capturing.", this.vw / 2, 40);
      ctx.textAlign = "left";
    }
  }
}

export const grid = new GridController();

function Header({ scrollX }: { scrollX: number }) {
  const columns = useStore((s) => s.layout.columns);
  const sort = useStore((s) => s.sort);
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
      set((s) => ({ layout: { ...s.layout, columns: s.layout.columns.map((x) => (x.key === d.key ? { ...x, width: w } : x)) } }));
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
    const cur = get().sort;
    let next;
    if (cur.column !== c.key) next = { column: c.key, descending: false };
    else if (!cur.descending) next = { column: c.key, descending: true };
    else next = { column: "id" as const, descending: false };
    actions.setSort(next);
  };

  const onContext = (e: React.MouseEvent) => {
    e.preventDefault();
    showContextMenu(e.clientX, e.clientY, [
      ...columns.map((c) => ({
        label: c.title,
        checked: c.visible,
        action: () => setColumns(columns.map((x) => (x.key === c.key ? { ...x, visible: !x.visible } : x))),
      })),
      { separator: true },
      { label: "Reset Columns", action: () => actions.resetColumns() },
    ]);
  };

  return (
    <div className="grid-header" onContextMenu={onContext}>
      <div className="grid-header-inner" style={{ transform: `translateX(${-scrollX}px)` }}>
        {columns
          .filter((c) => c.visible)
          .map((c) => (
            <div
              key={c.key}
              className={`gh-cell ${dragOver === c.key ? "drag-over" : ""} ${c.align === "right" ? "gh-right" : ""}`}
              style={{ width: c.width }}
              draggable
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
              title={c.title}
            >
              <span className="gh-title">{c.title}</span>
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

  const onMouseDown = (e: React.MouseEvent) => {
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
    if (e.shiftKey) actions.selectIndex(i, "range");
    else if (e.metaKey || e.ctrlKey) actions.selectIndex(i, "toggle");
    else actions.selectIndex(i, "single");
  };

  const onContextMenu = (e: React.MouseEvent) => {
    e.preventDefault();
    if (get().selection.size === 0) return;
    showContextMenu(e.clientX, e.clientY, sessionMenu());
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
