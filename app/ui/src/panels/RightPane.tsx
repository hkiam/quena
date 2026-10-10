import { lazy, Suspense, useLayoutEffect, useRef, useState } from "react";
import type { LucideIcon } from "lucide-react";
import { Bot, ChartColumn, ChartGantt, Filter, ScanSearch, ScrollText, Send, Stethoscope, Zap } from "lucide-react";
import { set, useStore, type RightTab } from "../store";
import { Inspectors } from "../inspectors/Inspectors";
import { StatisticsPanel } from "./Statistics";
import { FiltersPanel } from "./Filters";
import { LogPanel } from "./Log";
import { TimelinePanel } from "./Timeline";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { t } from "../i18n";

const AutoResponderPanel = lazy(() => import("./AutoResponder"));
const ComposerPanel = lazy(() => import("./Composer"));
const DiagnosticsPanel = lazy(() => import("./Diagnostics"));
const AgentsPanel = lazy(() => import("./Agents"));

const TABS: [RightTab, string, LucideIcon][] = [
  ["inspectors", t("Inspect"), ScanSearch],
  ["composer", t("Composer"), Send],
  ["autoresponder", t("Mock Rules"), Zap],
  ["filters", t("Filters"), Filter],
  ["timeline", t("Timeline"), ChartGantt],
  ["diagnostics", t("Diagnostics"), Stethoscope],
  ["statistics", t("Statistics"), ChartColumn],
  ["agents", t("Agents"), Bot],
  ["log", t("Log"), ScrollText],
];

export function RightPane() {
  const tab = useStore((s) => s.activeTab);
  const filtersOn = useStore((s) => s.filters?.enabled);
  const arOn = useStore((s) => s.status?.engine.autoresponder);
  // Re-measure when a tab's content changes (the Filters / Mock Rules dots).
  const compact = useCompactTabs(`${!!filtersOn}${!!arOn}`);
  return (
    <div className="rpane">
      <div className={`rp-tabs ${compact.on ? "compact" : ""}`} ref={compact.ref} role="tablist">
        {TABS.map(([k, title, Icon]) => (
          <div
            key={k}
            className={`rp-tab ${tab === k ? "active" : ""}`}
            title={title}
            role="tab"
            aria-selected={tab === k}
            aria-label={title}
            tabIndex={tab === k ? 0 : -1}
            onClick={() => set({ activeTab: k })}
            onKeyDown={(e) => {
              const i = TABS.findIndex(([x]) => x === k);
              const go = (j: number) => {
                const next = TABS[(j + TABS.length) % TABS.length][0];
                set({ activeTab: next });
                (e.currentTarget.parentElement?.children[(j + TABS.length) % TABS.length] as HTMLElement | undefined)?.focus();
              };
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                set({ activeTab: k });
              } else if (e.key === "ArrowRight") {
                e.preventDefault();
                go(i + 1);
              } else if (e.key === "ArrowLeft") {
                e.preventDefault();
                go(i - 1);
              }
            }}
          >
            <Icon size={14} strokeWidth={1.8} className="rp-icon" />
            <span className="rp-label">{title}</span>
            {k === "filters" && filtersOn && <span className="rp-dot" />}
            {k === "autoresponder" && arOn && <span className="rp-dot" />}
          </div>
        ))}
      </div>
      <div className="rp-content">
        {/* Keep inspectors mounted to preserve scroll positions. */}
        <div style={{ display: tab === "inspectors" ? "contents" : "none" }}>
          <ErrorBoundary name="inspectors">
            <Inspectors />
          </ErrorBoundary>
        </div>
        {tab !== "inspectors" && (
          <ErrorBoundary name={tab} resetKey={tab}>
            {tab === "statistics" && <StatisticsPanel />}
            {tab === "filters" && <FiltersPanel />}
            {tab === "log" && <LogPanel />}
            {tab === "timeline" && <TimelinePanel />}
            <Suspense fallback={<div className="placeholder">{t("Loading…")}</div>}>
              {tab === "autoresponder" && <AutoResponderPanel />}
              {tab === "composer" && <ComposerPanel />}
              {tab === "diagnostics" && <DiagnosticsPanel />}
              {tab === "agents" && <AgentsPanel />}
            </Suspense>
          </ErrorBoundary>
        )}
      </div>
    </div>
  );
}

/** Icons only when the tab labels do not fit (German labels are longer than English ones).
 * `content` changes whenever a tab's content changes (e.g. a status dot appears). */
function useCompactTabs(content: string) {
  const ref = useRef<HTMLDivElement>(null);
  const [on, setOn] = useState(false);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const check = () => {
      // Measure the width the tabs need with labels, also while compact (the class is
      // restored before the browser paints).
      const compact = el.classList.contains("compact");
      if (compact) el.classList.remove("compact");
      const full = el.scrollWidth;
      if (compact) el.classList.add("compact");
      setOn(full > el.clientWidth + 1);
    };
    const ro = new ResizeObserver(check);
    ro.observe(el);
    for (const c of el.children) ro.observe(c);
    check();
    return () => ro.disconnect();
  }, [content]);
  return { ref, on };
}
