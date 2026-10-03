// Segmented view tabs that show as many views as fit the available width; only the views
// that do not fit go into "More". The active view is always visible.
import { useLayoutEffect, useRef, useState } from "react";
import { ChevronDown } from "lucide-react";
import { showContextMenu } from "../components/ContextMenu";
import { t } from "../i18n";

export function ViewTabs({
  views,
  active,
  title,
  onSelect,
  badge,
  dim,
  hint,
  others,
  className,
}: {
  views: string[];
  active: string;
  title: (v: string) => string;
  onSelect: (v: string) => void;
  /** A count or mark shown after the title. */
  badge?: (v: string) => string | null;
  /** Shown faint (e.g. nothing in it), still selectable. */
  dim?: (v: string) => boolean;
  /** Tooltip of a tab. */
  hint?: (v: string) => string | undefined;
  /** Views offered only in the menu ("Other"): those that may fit first, then those that do not. */
  others?: { view: string; fit: number }[];
  className?: string;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const measure = useRef<HTMLDivElement>(null);
  const [avail, setAvail] = useState(0);
  const [widths, setWidths] = useState<{ tabs: number[]; more: number; chrome: number } | null>(null);

  // Natural width of every tab (and of the More button), measured off-screen with the same
  // styles. Measured again whenever the available width changes: while the Inspect tab is
  // hidden (another right-pane tab is open) everything measures 0, and those widths must not
  // be kept — otherwise all views "fit" and the strip overflows when Inspect shows again.
  const label = (v: string) => {
    const b = badge?.(v);
    return b ? `${title(v)} ${b}` : title(v);
  };
  const key = views.map(label).join("\u0000");
  const remeasure = () => {
    const m = measure.current;
    if (!m) return;
    const kids = [...m.children] as HTMLElement[];
    const tabs = kids.slice(0, views.length).map((k) => k.getBoundingClientRect().width);
    if (!tabs.length || tabs.some((w) => w <= 0)) {
      setWidths(null); // not laid out (hidden): measure again when visible
      return;
    }
    const more = kids[views.length]?.getBoundingClientRect().width ?? 60;
    const cs = getComputedStyle(m);
    const chrome = (parseFloat(cs.paddingLeft) || 0) + (parseFloat(cs.paddingRight) || 0);
    setWidths((old) => (old && old.more === more && old.chrome === chrome && old.tabs.length === tabs.length && old.tabs.every((w, i) => w === tabs[i]) ? old : { tabs, more, chrome }));
  };
  const remeasureRef = useRef(remeasure);
  remeasureRef.current = remeasure;
  useLayoutEffect(() => {
    remeasure();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  useLayoutEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => {
      setAvail(Math.floor(e.contentRect.width));
      remeasureRef.current();
    });
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
    const menu = !!others?.length;
    if (!fits(views.length, menu)) {
      let n = views.length - 1;
      while (n > 0 && !fits(n, true)) n--;
      n = Math.max(n, 1);
      shown = views.slice(0, n);
      // Keep the active view visible: it takes the place of the last visible one.
      if (!shown.includes(active) && views.includes(active)) shown = [...views.slice(0, n - 1), active].filter((v, i, a) => a.indexOf(v) === i);
      rest = views.filter((v) => !shown.includes(v));
    }
  }

  const may = (others ?? []).filter((o) => o.fit > 0);
  const unfit = (others ?? []).filter((o) => o.fit <= 0);
  const seg = (v: string) => (
    <>
      {title(v)}
      {badge?.(v) && <span className="seg-badge">{badge(v)}</span>}
    </>
  );
  return (
    <div className={`view-tabs ${className ?? ""}`} ref={wrap}>
      <div className="segmented">
        {shown.map((v) => (
          <button key={v} className={`seg ${active === v ? "active" : ""} ${dim?.(v) ? "dim" : ""}`} title={hint?.(v)} onClick={() => onSelect(v)}>
            {seg(v)}
          </button>
        ))}
      </div>
      {(rest.length > 0 || may.length > 0 || unfit.length > 0) && (
        <button
          className="seg seg-more"
          title={others?.length ? t("Other views") : t("More views")}
          onClick={(e) => {
            const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
            const item = (v: string) => ({ label: label(v), action: () => onSelect(v) });
            const notFitting = (v: string) => ({ ...item(v), label: t("{view} (does not fit this content)", { view: title(v) }) });
            const groups = [rest.map(item), may.map((o) => item(o.view)), unfit.map((o) => notFitting(o.view))].filter((g) => g.length);
            showContextMenu(
              r.left,
              r.bottom + 2,
              groups.flatMap((g, i) => (i ? [{ separator: true }, ...g] : g)),
            );
          }}
        >
          {others?.length ? t("Other") : t("More")} <ChevronDown size={11} />
        </button>
      )}
      {/* Off-screen copy for measuring natural widths (never visible, not focusable). */}
      <div className="segmented view-tabs-measure" ref={measure} aria-hidden="true">
        {views.map((v) => (
          <span key={v} className="seg active">
            {seg(v)}
          </span>
        ))}
        <span className="seg seg-more">
          {others?.length ? t("Other") : t("More")} <ChevronDown size={11} />
        </span>
      </div>
    </div>
  );
}
