import { lazy, Suspense } from "react";
import type { LucideIcon } from "lucide-react";
import { ChartColumn, ChartGantt, Filter, ScanSearch, ScrollText, Send, Zap } from "lucide-react";
import { set, useStore, type RightTab } from "../store";
import { Inspectors } from "../inspectors/Inspectors";
import { StatisticsPanel } from "./Statistics";
import { FiltersPanel } from "./Filters";
import { LogPanel } from "./Log";
import { TimelinePanel } from "./Timeline";
import { ErrorBoundary } from "../components/ErrorBoundary";

const AutoResponderPanel = lazy(() => import("./AutoResponder"));
const ComposerPanel = lazy(() => import("./Composer"));

const TABS: [RightTab, string, LucideIcon][] = [
  ["inspectors", "Inspect", ScanSearch],
  ["composer", "Composer", Send],
  ["autoresponder", "Mock Rules", Zap],
  ["filters", "Filters", Filter],
  ["timeline", "Timeline", ChartGantt],
  ["statistics", "Statistics", ChartColumn],
  ["log", "Log", ScrollText],
];

export function RightPane() {
  const tab = useStore((s) => s.activeTab);
  const filtersOn = useStore((s) => s.filters?.enabled);
  const arOn = useStore((s) => s.status?.engine.autoresponder);
  return (
    <div className="rpane">
      <div className="rp-tabs">
        {TABS.map(([k, title, Icon]) => (
          <div key={k} className={`rp-tab ${tab === k ? "active" : ""}`} onClick={() => set({ activeTab: k })}>
            <Icon size={14} strokeWidth={1.8} className="rp-icon" />
            {title}
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
            <Suspense fallback={<div className="placeholder">Loading…</div>}>
              {tab === "autoresponder" && <AutoResponderPanel />}
              {tab === "composer" && <ComposerPanel />}
            </Suspense>
          </ErrorBoundary>
        )}
      </div>
    </div>
  );
}
