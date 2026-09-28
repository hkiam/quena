// Virtualised text viewer for bodies of any size (PLAN.md §2.12.4). Lines
// come from the core's sampled line index in windows; only visible lines
// exist in the DOM. Scroll position is scaled for > 500k lines.
import { useCallback, useEffect, useRef, useState } from "react";
import { api, type BodyView, type Part, type SessionId, type Variant } from "../api";
import { fmtBytes, fmtInt } from "../lib/format";

const LINE_H = 16;
const MAX_PX = 8_000_000;
const WINDOW = 300;

interface Chunk {
  start: number;
  lines: string[];
}

export function LargeTextView({ id, part, variant, wrap }: { id: SessionId; part: Part; variant: Variant; wrap: boolean }) {
  const scroller = useRef<HTMLDivElement>(null);
  const [view, setView] = useState<BodyView | null>(null);
  const [chunk, setChunk] = useState<Chunk>({ start: 0, lines: [] });
  const [top, setTop] = useState(0);
  const [vh, setVh] = useState(400);
  const [search, setSearch] = useState("");
  const [hits, setHits] = useState<{ line: number; offset: number }[]>([]);
  const [hitIdx, setHitIdx] = useState(-1);
  const [searching, setSearching] = useState(false);
  const [goto, setGoto] = useState("");
  const req = useRef(0);
  const totalLines = view?.lines ?? 0;

  const contentH = totalLines * LINE_H;
  const virtualH = Math.min(contentH, MAX_PX);
  const ratio = contentH > virtualH && virtualH > vh ? (contentH - vh) / (virtualH - vh) : 1;
  const firstLine = Math.floor((top * ratio) / LINE_H);
  const visible = Math.ceil(vh / LINE_H) + 1;

  // Open the body and follow indexing progress.
  useEffect(() => {
    let alive = true;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const v = await api.bodyOpen(id, part, variant);
        if (!alive) return;
        setView(v);
        if (!v.linesDone || !v.complete) timer = window.setTimeout(poll, 300);
      } catch (e) {
        console.warn(e);
      }
    };
    setChunk({ start: 0, lines: [] });
    setHits([]);
    setHitIdx(-1);
    poll();
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [id, part, variant]);

  // Load the window around the viewport.
  const load = useCallback(async () => {
    if (!view) return;
    const need = Math.max(0, firstLine - 50);
    if (chunk.lines.length && need >= chunk.start && firstLine + visible <= chunk.start + chunk.lines.length && (view.linesDone || chunk.start + chunk.lines.length < view.lines - 1)) return;
    const my = ++req.current;
    const r = await api.bodyLines(id, part, variant, need, WINDOW);
    if (my !== req.current) return;
    setChunk({ start: r.start, lines: r.lines });
  }, [view, firstLine, visible, chunk, id, part, variant]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setVh(el.clientHeight));
    ro.observe(el);
    setVh(el.clientHeight);
    return () => ro.disconnect();
  }, []);

  const scrollToLine = (line: number) => {
    const el = scroller.current;
    if (!el) return;
    el.scrollTop = Math.max(0, (line * LINE_H - vh / 3) / ratio);
  };

  const runSearch = async () => {
    if (!search) return;
    setSearching(true);
    setHits([]);
    const job = await api.bodySearch(id, part, variant, search, true);
    const poll = async () => {
      const r = await api.searchResult(job);
      if (r) {
        setHits(r.hits);
        if (r.hits.length && hitIdx < 0) {
          setHitIdx(0);
          scrollToLine(r.hits[0].line);
        }
        if (!r.done) setTimeout(poll, 150);
        else setSearching(false);
      } else setSearching(false);
    };
    poll();
  };

  const step = (d: number) => {
    if (!hits.length) return;
    const i = (hitIdx + d + hits.length) % hits.length;
    setHitIdx(i);
    scrollToLine(hits[i].line);
  };

  const rows: React.ReactNode[] = [];
  const offY = -((top * ratio) % LINE_H);
  const hitLines = new Set(hits.map((h) => h.line));
  for (let k = 0; k < visible && firstLine + k < totalLines; k++) {
    const ln = firstLine + k;
    const text = ln >= chunk.start && ln < chunk.start + chunk.lines.length ? chunk.lines[ln - chunk.start] : null;
    rows.push(
      <div key={ln} className={`lt-line ${hitLines.has(ln) ? "hit" : ""} ${hits[hitIdx]?.line === ln ? "cur" : ""}`} style={{ top: offY + k * LINE_H }}>
        <span className="lt-no">{ln + 1}</span>
        <span className={`lt-text ${wrap ? "wrap" : ""}`}>{text ?? "…"}</span>
      </div>,
    );
  }

  return (
    <div className="largetext">
      <div className="lt-bar">
        <span className="lt-info">
          {view ? (
            <>
              {fmtBytes(view.len)} · {fmtInt(totalLines)} lines
              {!view.linesDone && ` (indexing ${view.len ? Math.floor((view.scanned / Math.max(1, view.len)) * 100) : 0}%)`}
              {!view.complete && " · receiving/decoding…"}
              {view.error && <span className="err"> · {view.error}</span>}
            </>
          ) : (
            "Opening…"
          )}
        </span>
        <input className="lt-goto" placeholder="Line" value={goto} onChange={(e) => setGoto(e.target.value)} onKeyDown={(e) => e.key === "Enter" && scrollToLine(Math.max(0, Number(goto) - 1))} />
        <input
          className="lt-search"
          placeholder="Find in body"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              if (hits.length && !searching) step(e.shiftKey ? -1 : 1);
              else runSearch();
            }
          }}
        />
        <button onClick={runSearch} disabled={!search}>
          Find
        </button>
        <span className="lt-hits">
          {searching ? "searching… " : ""}
          {hits.length ? `${hitIdx + 1}/${fmtInt(hits.length)}` : search && !searching ? "" : ""}
        </span>
        <button onClick={() => step(-1)} disabled={!hits.length}>
          ↑
        </button>
        <button onClick={() => step(1)} disabled={!hits.length}>
          ↓
        </button>
      </div>
      <div className="lt-scroller" ref={scroller} onScroll={(e) => setTop((e.target as HTMLDivElement).scrollTop)} tabIndex={0}>
        <div className="lt-viewport" style={{ height: vh }}>
          {rows}
        </div>
        <div style={{ height: Math.max(0, virtualH - vh) }} />
      </div>
    </div>
  );
}
