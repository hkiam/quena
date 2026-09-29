import { lazy, Suspense } from "react";
import { set, useStore, type RightTab } from "../store";
import { Inspectors } from "../inspectors/Inspectors";
import { StatisticsPanel } from "./Statistics";
import { FiltersPanel } from "./Filters";
import { LogPanel } from "./Log";
import { TimelinePanel } from "./Timeline";

const AutoResponderPanel = lazy(() => import("./AutoResponder"));
const ComposerPanel = lazy(() => import("./Composer"));

const TABS: [RightTab, string, string][] = [
  ["inspectors", "Inspect", "🔎︎"],
  ["composer", "Composer", "✎"],
  ["autoresponder", "Mock Rules", "⚡"],
  ["filters", "Filters", "⛛"],
  ["timeline", "Timeline", "▤"],
  ["statistics", "Statistics", "📊︎"],
  ["log", "Log", "☰"],
];

export function RightPane() {
  const tab = useStore((s) => s.activeTab);
  const filtersOn = useStore((s) => s.filters?.enabled);
  const arOn = useStore((s) => s.status?.engine.autoresponder);
  return (
    <div className="rpane">
      <div className="rp-tabs">
        {TABS.map(([k, title, icon]) => (
          <div key={k} className={`rp-tab ${tab === k ? "active" : ""}`} onClick={() => set({ activeTab: k })}>
            <span className="rp-icon">{icon}</span>
            {title}
            {k === "filters" && filtersOn && <span className="rp-dot" />}
            {k === "autoresponder" && arOn && <span className="rp-dot" />}
          </div>
        ))}
      </div>
      <div className="rp-content">
        {/* Keep inspectors mounted to preserve scroll positions. */}
        <div style={{ display: tab === "inspectors" ? "contents" : "none" }}>
          <Inspectors />
        </div>
        {tab === "statistics" && <StatisticsPanel />}
        {tab === "filters" && <FiltersPanel />}
        {tab === "log" && <LogPanel />}
        {tab === "timeline" && <TimelinePanel />}
        <Suspense fallback={<div className="placeholder">Loading…</div>}>
          {tab === "autoresponder" && <AutoResponderPanel />}
          {tab === "composer" && <ComposerPanel />}
        </Suspense>
      </div>
    </div>
  );
}
