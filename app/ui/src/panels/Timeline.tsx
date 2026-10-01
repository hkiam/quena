// Timeline: the selected sessions as a waterfall with a time axis. Zoom with Ctrl/⌘ + wheel
// (or pinch) around the pointer, or with the buttons; columns can be moved (drag the header),
// resized (drag the header edge) and shown or hidden (right-click the header). Columns left of
// the graph stay in place while the graph scrolls horizontally.
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Maximize2, ZoomIn, ZoomOut } from "lucide-react";
import { api, type SessionSummary, type Timers } from "../api";
import { fmtBytes, fmtDateTime, fmtMs, fmtTime } from "../lib/format";
import { PHASES, phasesOf, type Segment } from "../lib/waterfall";
import {
  buildAxis,
  clampZoom,
  columnOrder,
  columnWidth,
  moveColumn,
  fmtSpan,
  tickLabel,
  tickStep,
  ticks,
  TL_COLUMNS,
  TL_DEFAULT,
  TL_GRAPH_PAD,
  TL_MIN_GRAPH,
  TL_MIN_WIDTH,
  toggleColumn,
  zoomScroll,
  type TlColumn,
  type TlLayout,
} from "../lib/timelineScale";
import { set, useStore } from "../store";
import { actions } from "../actions";
import { grid } from "../grid/SessionGrid";
import { showContextMenu } from "../components/ContextMenu";
import { currentLang, fmtNum, plural, t } from "../i18n";

/** Numbers with fixed decimals in the UI language (axis labels). */
const num = (n: number, decimals: number) => n.toLocaleString(currentLang() === "de" ? "de-DE" : "en-US", { minimumFractionDigits: decimals, maximumFractionDigits: decimals });

const MAX = 500;
const ROW_H = 20;
const HEADER_H = 24;
/** Width of a cut idle gap at zoom 1. */
const GAP_PX = 96;
/** Rough label width for collision checks (11 px tabular text). */
const labelW = (text: string) => text.length * 6.6 + 10;
/** Unit for the label of a cut gap. */
const gapUnit = (gap: number) => (gap >= 86_400e6 ? 3600e6 : gap >= 3600e6 ? 60e6 : 1e6);
const DRAG_TYPE = "quena/tl-col";

const TITLES: Record<TlColumn, () => string> = {
  id: () => "#",
  method: () => t("Method"),
  status: () => t("Status"),
  url: () => t("URL"),
  duration: () => t("Duration"),
  size: () => t("Size"),
  graph: () => t("Timeline"),
};

function useLayoutPrefs(): [TlLayout, (patch: TlLayout) => void] {
  const l = useStore((s) => s.layout.timeline) ?? {};
  const update = (patch: TlLayout) => {
    set((s) => ({ layout: { ...s.layout, timeline: { ...s.layout.timeline, ...patch } } }));
    actions.saveLayout();
  };
  return [l, update];
}

/** Focus a session (the inspector shows it) without changing the selection. */
async function focusSession(id: number) {
  const pos = await api.positionOf(id);
  set({ focusId: id, focusIndex: pos });
  if (pos != null) grid.scrollToIndex(pos, "nearest");
}

export function TimelinePanel() {
  const selection = useStore((s) => s.selection);
  const version = useStore((s) => s.listVersion);
  const focusId = useStore((s) => s.focusId);
  const [prefs, updatePrefs] = useLayoutPrefs();
  const [rows, setRows] = useState<SessionSummary[]>([]);
  const [timers, setTimers] = useState<Map<number, Timers>>(new Map());
  const [zoom, setZoom] = useState(1);
  const [viewport, setViewport] = useState({ width: 0, left: 0 });
  const [drag, setDrag] = useState<{ col: TlColumn; width: number } | null>(null);
  const [dropBefore, setDropBefore] = useState<TlColumn | null | undefined>(undefined);
  const scroller = useRef<HTMLDivElement>(null);
  const pendingScroll = useRef<number | null>(null);

  useEffect(() => {
    const ids = [...selection].sort((a, b) => a - b).slice(0, MAX);
    if (!ids.length) {
      setRows([]);
      setTimers(new Map());
      return;
    }
    let live = true;
    const tm = setTimeout(() => {
      api.summaries(ids).then((r) => live && setRows(r));
      api
        .timers(ids)
        .then((ts) => live && setTimers(new Map(ts.map((x) => [x.id, x.timers]))))
        .catch(() => {});
    }, 100);
    return () => {
      live = false;
      clearTimeout(tm);
    };
  }, [selection, Math.floor(version / 15)]);

  // Viewport size and horizontal scroll position (ticks are drawn for the visible part only).
  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const measure = () => setViewport({ width: el.clientWidth, left: el.scrollLeft });
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    measure();
    let raf = 0;
    const onScroll = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(measure);
    };
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      ro.disconnect();
      el.removeEventListener("scroll", onScroll);
      cancelAnimationFrame(raf);
    };
  }, [rows.length > 0]);

  const order = columnOrder(prefs);
  const widthOf = (c: TlColumn) => (drag?.col === c ? drag.width : c === "graph" ? 0 : columnWidth(prefs, c));
  const fixedTotal = order.filter((c) => c !== "graph").reduce((n, c) => n + widthOf(c), 0);
  const graphFit = Math.max(TL_MIN_GRAPH, viewport.width - fixedTotal);
  const graphW = Math.round(graphFit * zoom);
  const graphLeft = order.slice(0, order.indexOf("graph")).reduce((n, c) => n + widthOf(c), 0);
  const tableW = fixedTotal + graphW;

  // Keep the anchor point in place after a zoom.
  useLayoutEffect(() => {
    if (pendingScroll.current != null && scroller.current) {
      scroller.current.scrollLeft = pendingScroll.current;
      pendingScroll.current = null;
    }
  }, [zoom]);

  const zoomTo = (next: number, cursorX?: number) => {
    const el = scroller.current;
    const z = clampZoom(next);
    if (!el || z === zoom) return;
    // Default anchor: the middle of the visible graph area.
    const visibleGraphStart = Math.min(graphLeft, el.clientWidth);
    const x = cursorX ?? visibleGraphStart + (el.clientWidth - visibleGraphStart) / 2;
    pendingScroll.current = z === 1 ? 0 : zoomScroll(el.scrollLeft, graphLeft, x, zoom, z);
    setZoom(z);
  };

  // Ctrl/⌘ + wheel (trackpad pinch arrives as Ctrl + wheel) zooms around the pointer.
  const zoomRef = useRef(zoomTo);
  zoomRef.current = zoomTo;
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      if (!(e.ctrlKey || e.metaKey)) return;
      e.preventDefault();
      const x = e.clientX - el.getBoundingClientRect().left;
      zoomRef.current(zoom * Math.exp(-e.deltaY * 0.002), x);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  });

  const data = useMemo(() => {
    const segs = new Map<number, Segment[]>(rows.map((r) => [r.id, timers.has(r.id) ? phasesOf(timers.get(r.id)!) : []]));
    const endOf = (r: SessionSummary) => Math.max(r.startedAt + (r.durationMs ?? 0) * 1000, ...(segs.get(r.id) ?? []).map((s) => s.end));
    const startOf = (r: SessionSummary) => Math.min(r.startedAt, ...(segs.get(r.id) ?? []).map((s) => s.start));
    const start = rows.length ? Math.min(...rows.map(startOf)) : 0;
    const end = rows.length ? Math.max(...rows.map(endOf)) : 0;
    const used = new Set([...segs.values()].flat().map((s) => s.phase));
    const intervals = rows.map((r) => [startOf(r), endOf(r)] as [number, number]);
    return { segs, endOf, start, span: Math.max(1, end - start), used, intervals };
  }, [rows, timers]);

  if (!rows.length) return <div className="placeholder">{t("Select sessions to see their timeline.")}</div>;

  const { segs, endOf, span, used, intervals } = data;
  // Long idle gaps (e.g. sessions of two captures a day apart) are cut to a break of
  // GAP_PX at zoom 1, so every block of traffic stays readable.
  const compress = prefs.compress ?? true;
  const probe = buildAxis(intervals, true, 0);
  const canCompress = probe.breaks.length > 0;
  const drawW = Math.max(1, graphFit - TL_GRAPH_PAD);
  const busyAxis = probe.clusters.reduce((n, c) => n + Math.max(1, c.to - c.from), 0);
  const gapAxis = drawW > GAP_PX * probe.breaks.length + 40 ? (GAP_PX * busyAxis) / (drawW - GAP_PX * probe.breaks.length) : busyAxis * 0.05;
  const axis = buildAxis(intervals, compress && canCompress, gapAxis);
  // The scale leaves room at the right end, so bars that end last stay visible.
  const pxPerUs = Math.max(1, graphW - TL_GRAPH_PAD) / Math.max(1, axis.length);
  const x = (us: number) => axis.toAxis(us) * pxPerUs;
  const step = tickStep(pxPerUs);
  // Labels only where the graph is visible: the columns left of it stay in place and cover
  // the graph from 0 to scrollLeft (in graph coordinates).
  const stuck = order.indexOf("graph") > 0;
  const visFrom = Math.max(0, stuck ? viewport.left : viewport.left - graphLeft);
  const visTo = (stuck ? viewport.left : viewport.left - graphLeft) + viewport.width - (stuck ? graphLeft : 0);
  // Ticks per block of traffic: its start carries the clock time, the rest offsets from it.
  const multiDay = new Date(axis.clusters[0].from / 1000).toDateString() !== new Date(axis.clusters[axis.clusters.length - 1].to / 1000).toDateString();
  const shownTicks = axis.clusters.flatMap((c, ci) =>
    ticks(c.to - c.from, step)
      .map((o) => ({ key: `${ci}:${o}`, px: (c.at + o) * pxPerUs, label: o === 0 ? (multiDay || span >= 86_400e6 ? fmtDateTime(c.from) : fmtTime(c.from)) : tickLabel(o, step, num), first: o === 0 }))
      .filter((tk) => tk.px >= visFrom - 1 && tk.px <= visTo),
  );
  const breaks = axis.breaks.map((b) => ({ px: b.at * pxPerUs, w: gapAxis * pxPerUs, gap: b.gap }));
  // Labels must not overlap: block starts (clock time) win, then the offsets in order; a label
  // that would collide is left out (its grid line stays). Labels near the right end are
  // aligned to their right edge so they are not cut off.
  const graphEnd = graphW;
  const kept: [number, number][] = [];
  const place = (tk: (typeof shownTicks)[number]) => {
    const w = labelW(tk.label);
    const right = tk.px + w > graphEnd - 2;
    const span: [number, number] = right ? [tk.px - w, tk.px] : [tk.px, tk.px + w];
    if (kept.some(([a, b]) => span[0] < b && span[1] > a)) return null;
    kept.push(span);
    return { ...tk, right };
  };
  const firstLabels = shownTicks.filter((tk) => tk.first).map(place);
  // A break shows its length only where no block start needs the room.
  const breakLabel = breaks.map((b) => {
    const text = `⫽ ${fmtSpan(b.gap, gapUnit(b.gap), num)}`;
    const span: [number, number] = [b.px, b.px + Math.min(b.w, labelW(text))];
    if (kept.some(([a, c]) => span[0] < c && span[1] > a)) return "";
    kept.push([b.px, b.px + b.w]);
    return text;
  });
  const labels = [...firstLabels, ...shownTicks.filter((tk) => !tk.first).map(place)].filter((x): x is NonNullable<typeof x> => x != null);

  // Sticky offsets for the columns left of the graph.
  const stickyLeft = new Map<TlColumn, number>();
  {
    let acc = 0;
    for (const c of order) {
      if (c === "graph") break;
      stickyLeft.set(c, acc);
      acc += widthOf(c);
    }
  }
  const cellStyle = (c: TlColumn): React.CSSProperties => {
    const w = c === "graph" ? graphW : widthOf(c);
    const s: React.CSSProperties = { width: w, minWidth: w, maxWidth: w };
    if (stickyLeft.has(c)) s.left = stickyLeft.get(c);
    return s;
  };
  const cellClass = (c: TlColumn) => `tl-cell tl-c-${c}${stickyLeft.has(c) ? " sticky" : ""}`;

  const startResize = (e: React.PointerEvent, c: TlColumn) => {
    e.preventDefault();
    e.stopPropagation();
    const x0 = e.clientX;
    const w0 = widthOf(c);
    let w = w0;
    const move = (ev: PointerEvent) => {
      w = Math.max(TL_MIN_WIDTH, Math.min(1200, w0 + ev.clientX - x0));
      setDrag({ col: c, width: w });
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      setDrag(null);
      updatePrefs({ widths: { ...prefs.widths, [c]: w } });
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const headerMenu = (e: React.MouseEvent) => {
    e.preventDefault();
    showContextMenu(e.clientX, e.clientY, [
      ...TL_COLUMNS.filter((c) => c !== "graph").map((c) => ({
        label: TITLES[c](),
        checked: order.includes(c),
        disabled: c === "url",
        action: () => updatePrefs({ order: toggleColumn(order, c) }),
      })),
      { separator: true },
      { label: t("Reset columns"), action: () => updatePrefs({ order: TL_DEFAULT, widths: {} }) },
    ]);
  };

  const cellText = (r: SessionSummary, c: TlColumn): string => {
    switch (c) {
      case "id":
        return String(r.id);
      case "method":
        return r.method;
      case "status":
        return r.status ? String(r.status) : "";
      case "url":
        return `${r.host}${r.url}`;
      case "duration":
        return fmtMs(r.durationMs);
      case "size":
        return fmtBytes(r.responseBodyLen ?? 0);
      default:
        return "";
    }
  };

  return (
    <div className="timeline">
      <div className="tl-head">
        <span className="muted">
          {plural(rows.length, "{n} session over {time}", "{n} sessions over {time}", { time: span >= 60e6 ? fmtSpan(span, 1e6, num) : fmtMs(Math.round(span / 1000)) })}
          {selection.size > MAX ? t(" (first {max} of {total})", { max: fmtNum(MAX), total: fmtNum(selection.size) }) : ""}
        </span>
        <span className="tl-legend">
          {PHASES.filter((p) => used.has(p.key)).map((p) => (
            <span key={p.key}>
              <i className={`tl-seg ph-${p.key}`} /> {p.label}
            </span>
          ))}
        </span>
        {canCompress && (
          <label className="f-check tl-compress" title={t("Long pauses without traffic are shown as a narrow break, so every block of traffic stays readable")}>
            <input type="checkbox" checked={compress} onChange={(e) => updatePrefs({ compress: e.target.checked })} /> {t("Collapse pauses")}
          </label>
        )}
        <span className="tl-zoom">
          <button onClick={() => zoomTo(zoom / 1.5)} disabled={zoom <= 1} title={t("Zoom out (Ctrl/⌘ + wheel)")} aria-label={t("Zoom out")}>
            <ZoomOut size={13} />
          </button>
          <span className="tl-zoom-v" title={t("Zoom")}>
            {zoom < 10 ? `${fmtNum(Math.round(zoom * 10) / 10)}×` : `${fmtNum(Math.round(zoom))}×`}
          </span>
          <button onClick={() => zoomTo(zoom * 1.5)} title={t("Zoom in (Ctrl/⌘ + wheel)")} aria-label={t("Zoom in")}>
            <ZoomIn size={13} />
          </button>
          <button onClick={() => zoomTo(1)} disabled={zoom === 1} title={t("Fit the whole time span into the view")}>
            <Maximize2 size={12} /> {t("Fit")}
          </button>
        </span>
      </div>
      <div className="tl-scroll" ref={scroller}>
        <div className="tl-table" style={{ width: tableW }}>
          <div className="tl-hrow" onContextMenu={headerMenu}>
            {order.map((c) => (
              <div
                key={c}
                className={`${cellClass(c)} tl-hcell ${dropBefore === c ? "drop-before" : ""}`}
                style={cellStyle(c)}
                draggable={!drag}
                title={c === "graph" ? t("Drag to move; right-click for columns") : t("Drag to move, drag the edge to resize; right-click for columns")}
                onDragStart={(e) => {
                  e.dataTransfer.setData(DRAG_TYPE, c);
                  e.dataTransfer.effectAllowed = "move";
                }}
                onDragOver={(e) => {
                  if (![...e.dataTransfer.types].includes(DRAG_TYPE)) return;
                  e.preventDefault();
                  const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
                  const after = e.clientX > r.left + r.width / 2;
                  const i = order.indexOf(c);
                  setDropBefore(after ? (order[i + 1] ?? null) : c);
                }}
                onDragLeave={() => setDropBefore(undefined)}
                onDrop={(e) => {
                  const col = e.dataTransfer.getData(DRAG_TYPE) as TlColumn;
                  e.preventDefault();
                  if (col && dropBefore !== undefined) updatePrefs({ order: moveColumn(order, col, dropBefore) });
                  setDropBefore(undefined);
                }}
                onDragEnd={() => setDropBefore(undefined)}
              >
                {c === "graph" ? (
                  <div className="tl-axis">
                    {labels.map((tk) => (
                      <span key={tk.key} className={`tl-tick ${tk.first ? "first" : ""} ${tk.right ? "right" : ""}`} style={tk.right ? { right: graphW - tk.px } : { left: tk.px }} title={tk.label}>
                        {tk.label}
                      </span>
                    ))}
                    {breaks.map((b, i) => (
                      <span key={`b${i}`} className="tl-break" style={{ left: b.px, width: b.w }} title={t("Pause without traffic: {time}", { time: fmtSpan(b.gap, gapUnit(b.gap), num) })}>
                        {breakLabel[i]}
                      </span>
                    ))}
                  </div>
                ) : (
                  <>
                    <span className="tl-htext">{TITLES[c]()}</span>
                    <span className="tl-resize" onPointerDown={(e) => startResize(e, c)} onDragStart={(e) => e.preventDefault()} />
                  </>
                )}
              </div>
            ))}
            {dropBefore === null && <div className="tl-drop-end" />}
          </div>
          {/* Grid lines and breaks behind all rows (aligned with every block's ticks). */}
          <div className="tl-grid" style={{ left: graphLeft, width: graphW, top: HEADER_H, height: rows.length * ROW_H }}>
            {shownTicks.map((tk) => (
              <i key={tk.key} className={tk.first ? "first" : ""} style={{ left: tk.px }} />
            ))}
            {breaks.map((b, i) => (
              <b key={`b${i}`} style={{ left: b.px, width: b.w }} />
            ))}
          </div>
          {rows.map((r) => {
            const s = segs.get(r.id) ?? [];
            const tip = [`#${r.id} ${r.method} ${r.host}${r.url} – ${fmtMs(r.durationMs)}`, ...s.map((p) => `${PHASES.find((q) => q.key === p.phase)!.label}: ${fmtMs(Math.round((p.end - p.start) / 1000))}`)].join("\n");
            return (
              <div
                key={r.id}
                className={`tl-row ${focusId === r.id ? "focused" : ""}`}
                style={{ height: ROW_H }}
                onClick={() => void focusSession(r.id)}
                onDoubleClick={() => {
                  void focusSession(r.id);
                  actions.showTab("inspectors");
                }}
                title={tip}
              >
                {order.map((c) =>
                  c === "graph" ? (
                    <div key={c} className={cellClass(c)} style={cellStyle(c)}>
                      <div className="tl-track">
                        {s.length ? (
                          s.map((p, i) => <span key={i} className={`tl-seg ph-${p.phase}`} style={{ left: x(p.start), width: Math.max(1, x(p.end) - x(p.start)) }} />)
                        ) : (
                          <span
                            className={`tl-bar ${r.status >= 400 ? "err" : ""} ${r.state !== "done" ? "live" : ""}`}
                            style={{ left: x(r.startedAt), width: Math.max(2, (r.durationMs ?? 0) * 1000 * pxPerUs) }}
                          />
                        )}
                        {r.status >= 400 && s.length > 0 && <span className="tl-err-dot" style={{ left: x(endOf(r)) }} />}
                      </div>
                    </div>
                  ) : (
                    <div key={c} className={`${cellClass(c)} ${c === "status" && r.status >= 400 ? "err" : ""}`} style={cellStyle(c)}>
                      {cellText(r, c)}
                    </div>
                  ),
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
