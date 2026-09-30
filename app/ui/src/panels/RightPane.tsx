import { lazy, Suspense, useLayoutEffect, useRef, useState } from "react";
import type { LucideIcon } from "lucide-react";
import { ChartColumn, ChartGantt, Filter, FolderTree, ScanSearch, ScrollText, Send, Stethoscope, Zap } from "lucide-react";
import { set, useStore, type RightTab } from "../store";
import { Inspectors } from "../inspectors/Inspectors";
import { StatisticsPanel } from "./Statistics";
import { FiltersPanel } from "./Filters";
import { LogPanel } from "./Log";
import { TimelinePanel } from "./Timeline";
import { StructurePanel } from "./Structure";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { t } from "../i18n";

const AutoResponderPanel = lazy(() => import("./AutoResponder"));
const ComposerPanel = lazy(() => import("./Composer"));
const DiagnosticsPanel = lazy(() => import("./Diagnostics"));

const TABS: [RightTab, string, LucideIcon][] = [
  ["inspectors", t("Inspect"), ScanSearch],
  ["composer", t("Composer"), Send],
  ["autoresponder", t("Mock Rules"), Zap],
  ["filters", t("Filters"), Filter],
  ["timeline", t("Timeline"), ChartGantt],
  ["structure", t("Structure"), FolderTree],
  ["diagnostics", t("Diagnostics"), Stethoscope],
  ["statistics", t("Statistics"), ChartColumn],
  ["log", t("Log"), ScrollText],
];

export function RightPane() {
  const tab = useStore((s) => s.activeTab);
  const filtersOn = useStore((s) => s.filters?.enabled);
  const arOn = useStore((s) => s.status?.engine.autoresponder);
  const compact = useCompactTabs();
  return (
    <div className="rpane">
      <div className={`rp-tabs ${compact.on ? "compact" : ""}`} ref={compact.ref}>
        {TABS.map(([k, title, Icon]) => (
          <div key={k} className={`rp-tab ${tab === k ? "active" : ""}`} title={title} onClick={() => set({ activeTab: k })}>
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
            {tab === "structure" && <StructurePanel />}
            <Suspense fallback={<div className="placeholder">{t("Loading…")}</div>}>
              {tab === "autoresponder" && <AutoResponderPanel />}
              {tab === "composer" && <ComposerPanel />}
              {tab === "diagnostics" && <DiagnosticsPanel />}
            </Suspense>
          </ErrorBoundary>
        )}
      </div>
    </div>
  );
}

/** Icons only when the tab labels do not fit (German labels are longer than English ones). */
function useCompactTabs() {
  const ref = useRef<HTMLDivElement>(null);
  const [on, setOn] = useState(false);
  const full = useRef(0); // width the tabs need with labels
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const check = () => {
      const compact = el.classList.contains("compact");
      if (!compact) full.current = el.scrollWidth;
      setOn(full.current > el.clientWidth + 1);
    };
    const ro = new ResizeObserver(check);
    ro.observe(el);
    check();
    return () => ro.disconnect();
  }, []);
  return { ref, on };
}
