// What fills an LLM request's context, as a treemap of its slices (system prompt, each tool,
// instruction files, tool results by tool …) with the largest listed beside it.
import { useLayoutEffect, useRef, useState } from "react";
import type { ContextBreakdown } from "../api";
import { fmtInt } from "../lib/format";
import { sliceName } from "../lib/agentText";
import { treemap } from "../lib/treemap";
import { t } from "../i18n";

export function ContextMap({ b, height = 160, list = 8 }: { b: ContextBreakdown; height?: number; list?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setWidth(el.clientWidth));
    ro.observe(el);
    setWidth(el.clientWidth);
    return () => ro.disconnect();
  }, []);
  const total = b.slices.reduce((a, s) => a + s.tokens, 0);
  const rects = treemap(
    b.slices.map((s) => s.tokens),
    width,
    height,
  );
  const pct = (n: number) => (total ? `${Math.round((n * 100) / total)} %` : "");
  return (
    <div className="ctx-map">
      <div className="ctx-tm" ref={ref} style={{ height }}>
        {b.slices.map((s, i) => {
          const r = rects[i];
          if (!r || r.w < 1 || r.h < 1) return null;
          const name = sliceName(s.category, s.label);
          return (
            <div key={`${s.category}:${s.label}`} className={`ctx-cell ctx-${s.category}`} style={{ left: r.x, top: r.y, width: r.w, height: r.h }} title={`${name}\n${t("{n} tokens", { n: fmtInt(s.tokens) })} · ${pct(s.tokens)}${s.count > 1 ? ` · ${s.count}×` : ""}`}>
              {r.w > 60 && r.h > 18 && <span>{s.label || name}</span>}
            </div>
          );
        })}
      </div>
      <table className="kv ctx-list">
        <tbody>
          {b.slices.slice(0, list).map((s) => (
            <tr key={`${s.category}:${s.label}`}>
              <td>
                <span className={`ctx-swatch ctx-${s.category}`} /> {sliceName(s.category, s.label)}
                {s.count > 1 && <span className="muted small"> {s.count}×</span>}
              </td>
              <td className="num">{fmtInt(s.tokens)}</td>
              <td className="num muted">{pct(s.tokens)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="muted small">
        {b.actual != null
          ? t("{n} input tokens as reported; the slices are estimates scaled to that.", { n: fmtInt(b.actual) })
          : t("≈ {n} input tokens (estimated; the response reports no usage).", { n: fmtInt(b.estimated) })}
      </div>
    </div>
  );
}
