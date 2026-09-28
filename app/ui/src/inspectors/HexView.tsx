// Offset-virtualised hex viewer; fetches 64 KB blocks through the body protocol.
import { useEffect, useRef, useState } from "react";
import { fetchBody, type Part, type SessionId, type Variant } from "../api";
import { fmtBytes } from "../lib/format";

const ROW = 16;
const LINE_H = 16;
const BLOCK = 64 * 1024;
const MAX_PX = 8_000_000;

const hex = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

export function HexView({ id, part, variant, len }: { id: SessionId; part: Part; variant: Variant; len: number }) {
  const scroller = useRef<HTMLDivElement>(null);
  const blocks = useRef(new Map<number, Uint8Array>());
  const inflight = useRef(new Set<number>());
  const [, force] = useState(0);
  const [top, setTop] = useState(0);
  const [vh, setVh] = useState(400);
  const [goto, setGoto] = useState("");
  const [total, setTotal] = useState(len);

  useEffect(() => {
    blocks.current.clear();
    inflight.current.clear();
    setTotal(len);
    force((x) => x + 1);
  }, [id, part, variant, len]);

  useEffect(() => {
    const el = scroller.current!;
    const ro = new ResizeObserver(() => setVh(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const rowsTotal = Math.ceil(total / ROW);
  const contentH = rowsTotal * LINE_H;
  const virtualH = Math.min(contentH, MAX_PX);
  const ratio = contentH > virtualH && virtualH > vh ? (contentH - vh) / (virtualH - vh) : 1;
  const first = Math.floor((top * ratio) / LINE_H);
  const visible = Math.ceil(vh / LINE_H) + 1;

  const need = new Set<number>();
  for (let r = first; r < first + visible && r < rowsTotal; r++) need.add(Math.floor((r * ROW) / BLOCK));
  for (const b of need) {
    if (blocks.current.has(b) || inflight.current.has(b)) continue;
    inflight.current.add(b);
    fetchBody(id, part, variant, b * BLOCK, BLOCK)
      .then((res) => {
        blocks.current.set(b, res.data);
        if (res.total > total) setTotal(res.total);
        if (blocks.current.size > 64) {
          const k = blocks.current.keys().next().value!;
          blocks.current.delete(k);
        }
        force((x) => x + 1);
      })
      .finally(() => inflight.current.delete(b));
  }

  const lines: React.ReactNode[] = [];
  const offY = -((top * ratio) % LINE_H);
  for (let k = 0; k < visible; k++) {
    const r = first + k;
    if (r >= rowsTotal) break;
    const off = r * ROW;
    const b = Math.floor(off / BLOCK);
    const data = blocks.current.get(b);
    let hx = "";
    let asc = "";
    if (data) {
      const base = off - b * BLOCK;
      for (let i = 0; i < ROW; i++) {
        const idx = base + i;
        if (off + i >= total || idx >= data.length) {
          hx += "   ";
          continue;
        }
        const c = data[idx];
        hx += hex[c] + (i === 7 ? "  " : " ");
        asc += c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
      }
    } else hx = "…";
    lines.push(
      <div key={r} className="hex-line" style={{ top: offY + k * LINE_H }}>
        <span className="hex-off">{off.toString(16).padStart(total > 0xffffffff ? 10 : 8, "0")}</span>
        <span className="hex-bytes">{hx}</span>
        <span className="hex-ascii">{asc}</span>
      </div>,
    );
  }

  return (
    <div className="hexview">
      <div className="lt-bar">
        <span className="lt-info">{fmtBytes(total)}</span>
        <input
          className="lt-goto"
          placeholder="Offset (hex or dec)"
          value={goto}
          onChange={(e) => setGoto(e.target.value)}
          onKeyDown={(e) => {
            if (e.key !== "Enter") return;
            const v = goto.trim().toLowerCase();
            const n = v.startsWith("0x") ? parseInt(v.slice(2), 16) : /[a-f]/.test(v) ? parseInt(v, 16) : Number(v);
            if (!Number.isFinite(n)) return;
            scroller.current!.scrollTop = Math.floor(n / ROW) * LINE_H / ratio;
          }}
        />
      </div>
      <div className="lt-scroller mono" ref={scroller} onScroll={(e) => setTop((e.target as HTMLDivElement).scrollTop)} tabIndex={0}>
        <div className="lt-viewport" style={{ height: vh }}>
          {lines}
        </div>
        <div style={{ height: Math.max(0, virtualH - vh) }} />
      </div>
    </div>
  );
}
