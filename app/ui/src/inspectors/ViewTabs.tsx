// Segmented view tabs that show as many views as fit the available width; only the views
// that do not fit go into "More". The active view is always visible.
import { useLayoutEffect, useRef, useState } from "react";
import { ChevronDown } from "lucide-react";
import { showContextMenu } from "../components/ContextMenu";
import { t } from "../i18n";

export function ViewTabs({ views, active, title, onSelect }: { views: string[]; active: string; title: (v: string) => string; onSelect: (v: string) => void }) {
  const wrap = useRef<HTMLDivElement>(null);
  const measure = useRef<HTMLDivElement>(null);
  const [avail, setAvail] = useState(0);
  const [widths, setWidths] = useState<{ tabs: number[]; more: number; chrome: number } | null>(null);

  // Natural width of every tab (and of the More button), measured off-screen with the same styles.
  const key = views.map(title).join("\u0000");
  useLayoutEffect(() => {
    const m = measure.current;
    if (!m) return;
    const kids = [...m.children] as HTMLElement[];
    const tabs = kids.slice(0, views.length).map((k) => k.getBoundingClientRect().width);
    const more = kids[views.length]?.getBoundingClientRect().width ?? 60;
    const cs = getComputedStyle(m);
    const chrome = (parseFloat(cs.paddingLeft) || 0) + (parseFloat(cs.paddingRight) || 0);
    setWidths({ tabs, more, chrome });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  useLayoutEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setAvail(Math.floor(e.contentRect.width)));
    ro.observe(el);
    setAvail(Math.floor(el.getBoundingClientRect().width));
    return () => ro.disconnect();
  }, []);

  let shown = views;
  let rest: string[] = [];
  if (widths && avail > 0) {
    const GAP = 1; // gap between segments
    const MORE_GAP = 6; // gap between the segments and More
    const fits = (n: number, withMore: boolean) => {
      let w = widths.chrome;
      for (let i = 0; i < n; i++) w += widths.tabs[i] + (i ? GAP : 0);
      if (withMore) w += MORE_GAP + widths.more;
      return w <= avail;
    };
    if (!fits(views.length, false)) {
      let n = views.length - 1;
      while (n > 0 && !fits(n, true)) n--;
      n = Math.max(n, 1);
      shown = views.slice(0, n);
      // Keep the active view visible: it takes the place of the last visible one.
      if (!shown.includes(active) && views.includes(active)) shown = [...views.slice(0, n - 1), active].filter((v, i, a) => a.indexOf(v) === i);
      rest = views.filter((v) => !shown.includes(v));
    }
  }

  return (
    <div className="view-tabs" ref={wrap}>
      <div className="segmented">
        {shown.map((v) => (
          <button key={v} className={`seg ${active === v ? "active" : ""}`} onClick={() => onSelect(v)}>
            {title(v)}
          </button>
        ))}
      </div>
      {rest.length > 0 && (
        <button
          className="seg seg-more"
          title={t("More views")}
          onClick={(e) => {
            const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
            showContextMenu(
              r.left,
              r.bottom + 2,
              rest.map((v) => ({ label: title(v), action: () => onSelect(v) })),
            );
          }}
        >
          {t("More")} <ChevronDown size={11} />
        </button>
      )}
      {/* Off-screen copy for measuring natural widths (never visible, not focusable). */}
      <div className="segmented view-tabs-measure" ref={measure} aria-hidden="true">
        {views.map((v) => (
          <span key={v} className="seg active">
            {title(v)}
          </span>
        ))}
        <span className="seg seg-more">
          {t("More")} <ChevronDown size={11} />
        </span>
      </div>
    </div>
  );
}
