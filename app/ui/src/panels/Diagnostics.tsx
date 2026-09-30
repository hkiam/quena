// Diagnostics: run an analyzer plugin (e.g. webdiag) over the visible or selected sessions and
// show its report — findings with the affected sessions one click away, key metrics,
// operations, export (JSON/Markdown/AI prompt) and the comparison with a saved report.
// Report texts come localized from the plugin; the frame is translated here.
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { create } from "zustand";
import { open, save } from "@tauri-apps/plugin-dialog";
import { ChevronDown, ChevronRight, CircleAlert, FileDown, Play, Plus, RotateCcw, Search, Settings2, Square, X } from "lucide-react";
import { api, on } from "../api";
import { actions, copyText } from "../actions";
import { say, set as setApp, useStore, type DiagPrefs } from "../store";
import { showContextMenu } from "../components/ContextMenu";
import { currentLang, plural, t } from "../i18n";
import { fmtDateTime, fmtInt, fmtTime } from "../lib/format";
import {
  compare,
  confidenceLabel,
  fmtDelta,
  fmtValue,
  opDuration,
  parseDescribe,
  parseReport,
  scopeLabel,
  severityLabel,
  severityPlural,
  categoryLabel,
  SEVERITIES,
  toAiPrompt,
  toMarkdown,
  type DiagDescribe,
  type DiagFinding,
  type DiagMetric,
  type DiagReport,
  type MetricDelta,
  type NetworkProfile,
  type Severity,
} from "../lib/diagReport";

interface Analyzer {
  index: number;
  id: string;
  name: string;
  title: string;
  version: string;
}

/** Findings rendered per severity before "Show more" (huge reports stay responsive). */
const PAGE = 200;
const OP_PAGE = 100;
const TABLE_ROWS = 200;
/** Findings list and details side by side from this panel width on. */
const WIDE = 720;

// Panel state survives switching tabs (the panel unmounts).
interface DiagUi {
  analyzers: Analyzer[] | null;
  analyzersError: string | null;
  describe: Record<number, DiagDescribe>;
  raw: unknown;
  report: DiagReport | null;
  jobId: number | null;
  runError: string | null;
  base: { report: DiagReport; name: string } | null;
  picked: number | null;
  pickedOp: string | null;
  sev: Severity | null;
  cat: string;
  q: string;
  showOptions: boolean;
  limits: Record<Severity, number>;
  opLimit: number;
}

const useDiag = create<DiagUi>(() => ({
  analyzers: null,
  analyzersError: null,
  describe: {},
  raw: null,
  report: null,
  jobId: null,
  runError: null,
  base: null,
  picked: null,
  pickedOp: null,
  sev: null,
  cat: "",
  q: "",
  showOptions: false,
  limits: { critical: PAGE, warning: PAGE, info: PAGE },
  opLimit: OP_PAGE,
}));
const setDiag = useDiag.setState;

async function fetchReport() {
  let text: string | null;
  try {
    text = await api.diagReport();
  } catch {
    return;
  }
  if (!text) return;
  try {
    const { raw, report } = parseReport(text);
    setDiag({ raw, report, picked: null, pickedOp: null, jobId: null, runError: null, limits: { critical: PAGE, warning: PAGE, info: PAGE }, opLimit: OP_PAGE });
  } catch {
    setDiag({ jobId: null, runError: t("The analyzer returned an invalid report.") });
  }
}

/** Narrow the scope to processes or target hosts: a button with a checkable, searchable list. */
function ScopePick({ kind, value, onChange }: { kind: "processes" | "hosts"; value: string[]; onChange: (v: string[]) => void }) {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<[string, number][] | null>(null);
  const [q, setQ] = useState("");
  const ref = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    setItems(null);
    api
      .diagScopeOptions()
      .then((o) => setItems(o[kind]))
      .catch(() => setItems([]));
    const close = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open, kind]);
  const label = kind === "processes" ? t("Process") : t("Host");
  const summary = value.length === 0 ? t("all") : value.length === 1 ? value[0] : t("{first} (+{n})", { first: value[0], n: value.length - 1 });
  const toggle = (name: string) => onChange(value.includes(name) ? value.filter((v) => v !== name) : [...value, name]);
  const shown = (items ?? []).filter(([name]) => !q || name.toLowerCase().includes(q.toLowerCase())).slice(0, 200);
  // Host patterns: a typed "*.example.com" can be added as it is.
  const pattern = kind === "hosts" && q.startsWith("*.") && q.length > 3 && !value.includes(q) ? q : null;
  return (
    <span className="diag-pick" ref={ref}>
      <button className={value.length ? "on" : ""} onClick={() => setOpen(!open)} title={kind === "processes" ? t("Analyse only the traffic of these processes") : t("Analyse only the traffic to these hosts")}>
        {label}: <b>{summary}</b> <ChevronDown size={11} />
      </button>
      {open && (
        <div className="diag-pick-pop">
          <input autoFocus className="diag-search" placeholder={kind === "hosts" ? t("Filter, or *.example.com") : t("Filter")} value={q} onChange={(e) => setQ(e.target.value)} />
          <div className="diag-pick-list">
            {items == null && <div className="muted small">{t("Loading…")}</div>}
            {pattern && (
              <label className="f-check">
                <input type="checkbox" checked={false} onChange={() => toggle(pattern)} /> {t("Add {pattern} (with subdomains)", { pattern })}
              </label>
            )}
            {value
              .filter((v) => !(items ?? []).some(([n]) => n === v))
              .map((v) => (
                <label key={v} className="f-check">
                  <input type="checkbox" checked onChange={() => toggle(v)} /> {v}
                </label>
              ))}
            {shown.map(([name, n]) => (
              <label key={name} className="f-check">
                <input type="checkbox" checked={value.includes(name)} onChange={() => toggle(name)} /> <span className="diag-pick-name">{name || t("(unknown)")}</span>
                <span className="muted small">{fmtInt(n)}</span>
              </label>
            ))}
            {items != null && !items.length && <div className="muted small">{t("No sessions")}</div>}
          </div>
          <div className="diag-pick-foot">
            <button className="linklike" disabled={!value.length} onClick={() => onChange([])}>
              {t("All")}
            </button>
          </div>
        </div>
      )}
    </span>
  );
}

function usePrefs(): [DiagPrefs, (patch: Partial<DiagPrefs>) => void] {
  const prefs = useStore((s) => s.layout.diag) ?? {};
  const update = (patch: Partial<DiagPrefs>) => {
    setApp((s) => ({ layout: { ...s.layout, diag: { ...s.layout.diag, ...patch } } }));
    actions.saveLayout();
  };
  return [prefs, update];
}

function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [w, setW] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setW(el.clientWidth));
    ro.observe(el);
    setW(el.clientWidth);
    return () => ro.disconnect();
  }, []);
  return { ref, w };
}

const stamp = (us: number | null) => {
  const d = us ? new Date(us / 1000) : new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}`;
};

export default function DiagnosticsPanel() {
  const st = useDiag();
  const [prefs, updatePrefs] = usePrefs();
  const jobs = useStore((s) => s.jobs);
  const selection = useStore((s) => s.selection);

  // Analyzers, the last report, and new reports as they arrive.
  useEffect(() => {
    if (!useDiag.getState().analyzers)
      api
        .diagAnalyzers()
        .then((a) => setDiag({ analyzers: a, analyzersError: null }))
        .catch((e) => setDiag({ analyzers: [], analyzersError: String(e) }));
    void fetchReport();
    const un = on("diag-report", () => void fetchReport());
    return () => void un.then((f) => f());
  }, []);

  const analyzers = st.analyzers ?? [];
  const analyzer = analyzers.find((a) => a.id === prefs.analyzer) ?? analyzers[0];
  const desc = analyzer ? st.describe[analyzer.index] : undefined;
  useEffect(() => {
    if (!analyzer || useDiag.getState().describe[analyzer.index]) return;
    const idx = analyzer.index;
    api
      .diagDescribe(idx, currentLang())
      .then((text) => parseDescribe(text))
      .catch(() => parseDescribe(""))
      .then((d) => setDiag((s) => ({ describe: { ...s.describe, [idx]: d } })));
  }, [analyzer?.index]);

  // The running job: progress, and its end (failed/cancelled; "done" fetches the report).
  const job = st.jobId != null ? jobs.find((j) => j.id === st.jobId) : undefined;
  const running = st.jobId != null && (!job || job.status === "running" || job.status === "queued");
  useEffect(() => {
    if (!job) return;
    if (job.status === "done") void fetchReport().then(() => setDiag({ jobId: null }));
    else if (job.status === "failed") setDiag({ jobId: null, runError: job.error || t("The analysis failed.") });
    else if (job.status === "cancelled") {
      setDiag({ jobId: null });
      say(t("Diagnostics cancelled"));
    }
  }, [job?.status]);

  const profiles = desc?.profiles ?? [];
  const profile = profiles.find((p) => p.id === prefs.profile) ?? profiles.find((p) => p.default) ?? profiles[0];
  const scope = prefs.scope === "selection" && selection.size > 0 ? "selection" : "visible";

  const run = async () => {
    if (!analyzer || !desc) return;
    const o = desc.options;
    const options = { ...o, ...prefs.options, networks: prefs.options?.networks ?? o.networks, profile: profile?.id ?? o.profile, lang: currentLang() };
    setDiag({ runError: null });
    try {
      const filter = { processes: prefs.processes ?? [], hosts: prefs.hosts ?? [] };
      const id = await api.diagRun(analyzer.index, JSON.stringify(options), scope === "selection" ? [...selection] : null, filter);
      setDiag({ jobId: id });
    } catch (e) {
      setDiag({ runError: String(e) });
    }
  };

  if (!st.analyzers) return <div className="placeholder">{t("Loading…")}</div>;
  if (!analyzer)
    return (
      <div className="placeholder diag-empty">
        <p>{t("No diagnostics analyzer is installed.")}</p>
        <p>{t("Diagnostics come from analyzer plugins such as webdiag. Install one and enable it in the plugin manager.")}</p>
        {st.analyzersError && <p className="small">{st.analyzersError}</p>}
        <button onClick={() => setApp({ dialog: { kind: "plugins" } })}>{t("Manage plugins…")}</button>
      </div>
    );

  const pct = job && job.total > 0 ? Math.min(100, Math.round((job.done / job.total) * 100)) : null;

  return (
    <div className="diag">
      <div className="diag-bar">
        {analyzers.length > 1 && (
          <select className="diag-sel" value={analyzer.id} title={t("Analyzer")} onChange={(e) => updatePrefs({ analyzer: e.target.value, profile: undefined })}>
            {analyzers.map((a) => (
              <option key={a.id} value={a.id}>
                {a.title || a.name}
              </option>
            ))}
          </select>
        )}
        <select className="diag-sel" value={profile?.id ?? ""} disabled={!profiles.length} title={profile?.description || t("Profile")} onChange={(e) => updatePrefs({ profile: e.target.value })}>
          {profiles.map((p) => (
            <option key={p.id} value={p.id} title={p.description}>
              {p.name}
            </option>
          ))}
        </select>
        <div className="diag-scope" role="radiogroup">
          <label>
            <input type="radio" checked={scope === "visible"} onChange={() => updatePrefs({ scope: "visible" })} />
            {t("Visible sessions")}
          </label>
          <label className={selection.size ? "" : "muted"}>
            <input type="radio" checked={scope === "selection"} disabled={!selection.size} onChange={() => updatePrefs({ scope: "selection" })} />
            {t("Selected sessions ({n})", { n: fmtInt(selection.size) })}
          </label>
          <ScopePick kind="processes" value={prefs.processes ?? []} onChange={(v) => updatePrefs({ processes: v })} />
          <ScopePick kind="hosts" value={prefs.hosts ?? []} onChange={(v) => updatePrefs({ hosts: v })} />
        </div>
        <div className="diag-actions">
          {running ? (
            <>
              <span className="diag-progress" title={job?.title}>
                <span className="diag-progress-bar">
                  <span style={{ width: `${pct ?? 100}%` }} className={pct == null ? "busy" : ""} />
                </span>
                <span className="muted small">{pct != null ? `${pct} %` : t("Analyzing…")}</span>
              </span>
              <button onClick={() => st.jobId != null && void api.cancelJob(st.jobId)}>
                <Square size={11} /> {t("Cancel")}
              </button>
            </>
          ) : (
            <button className="primary" disabled={!desc} onClick={() => void run()} title={t("Analyze the sessions with the chosen profile")}>
              <Play size={11} /> {t("Run")}
            </button>
          )}
          <button className={st.showOptions ? "on" : ""} onClick={() => setDiag({ showOptions: !st.showOptions })} title={t("Thresholds and network profiles")}>
            <Settings2 size={12} /> {t("Options")}
          </button>
          <button disabled={!st.report} onClick={(e) => reportMenu(e.currentTarget)} title={t("Save, copy or compare the report")}>
            <FileDown size={12} /> {t("Report")} <ChevronDown size={11} />
          </button>
        </div>
      </div>
      {st.showOptions && desc && <OptionsSection desc={desc} prefs={prefs} update={updatePrefs} />}
      {st.runError && (
        <div className="diag-error">
          <CircleAlert size={13} /> <span>{st.runError}</span>
          <button className="linklike" onClick={() => setDiag({ runError: null })}>
            <X size={12} />
          </button>
        </div>
      )}
      {st.report && st.base ? (
        <CompareView base={st.base} report={st.report} />
      ) : st.report ? (
        <ReportView report={st.report} />
      ) : (
        <Intro running={running} />
      )}
    </div>
  );
}

function reportMenu(el: HTMLElement) {
  const r = el.getBoundingClientRect();
  const report = useDiag.getState().report;
  showContextMenu(r.left, r.bottom + 2, [
    { label: t("Save as JSON…"), disabled: !report, action: () => void saveReport("json") },
    { label: t("Save as Markdown…"), disabled: !report, action: () => void saveReport("md") },
    { label: t("Copy for AI"), disabled: !report, action: () => void copyForAi() },
    { separator: true },
    { label: t("Compare with saved report…"), disabled: !report, action: () => void loadBase() },
  ]);
}

async function saveReport(kind: "json" | "md") {
  const { report, raw } = useDiag.getState();
  if (!report) return;
  const path = await save({
    defaultPath: `quena-diagnostics_${stamp(report.generatedAt)}.${kind}`,
    filters: [kind === "json" ? { name: t("Diagnostics report (JSON)"), extensions: ["json"] } : { name: t("Markdown"), extensions: ["md"] }],
  });
  if (!path) return;
  try {
    await api.writeTextFile(path, kind === "json" ? JSON.stringify(raw ?? report, null, 2) + "\n" : toMarkdown(report, t));
    say(t("Report saved to {path}", { path }));
  } catch (e) {
    say(String(e), "error");
  }
}

async function copyForAi() {
  const report = useDiag.getState().report;
  if (!report) return;
  await copyText(toAiPrompt(report, t));
  say(t("Report copied as a prompt for an AI assistant"));
}

async function loadBase() {
  const path = await open({ multiple: false, filters: [{ name: t("Diagnostics report (JSON)"), extensions: ["json"] }] });
  if (typeof path !== "string") return;
  try {
    const { report } = parseReport(await api.readTextFile(path));
    setDiag({ base: { report, name: path.split(/[\\/]/).pop() || path } });
  } catch {
    say(t("{path} is not a diagnostics report", { path }), "error");
  }
}

// ------------------------------------------------------------------ before the first run

function Intro({ running }: { running: boolean }) {
  return (
    <div className="scroll pad diag-intro">
      <h4>{running ? t("Analyzing the sessions…") : t("Diagnose the recorded traffic")}</h4>
      <p>{t("The analyzer looks at the visible or selected sessions for slow and sequential requests, duplicates, caching, compression, errors, authentication round trips and connection problems. It explains each finding and selects the affected sessions with one click.")}</p>
      <p>{t("Everything runs locally in Quena; nothing is sent anywhere. Header values, cookies and tokens are redacted before the analyzer sees them.")}</p>
      <p>
        {t("Statements marked")} <span className="pill pill-violet">{t("Estimate")}</span> {t("are modelled from the measured timings (for example for slower networks), not measured.")}
      </p>
      {!running && <p className="muted">{t("Choose a profile and the sessions, then click Run.")}</p>}
    </div>
  );
}

// ------------------------------------------------------------------ options

function NumField(p: { value: number; onChange: (v: number) => void; scale?: number; step?: number; title?: string; className?: string }) {
  const scale = p.scale ?? 1;
  const shown = +(p.value / scale).toFixed(3);
  const [text, setText] = useState(String(shown));
  useEffect(() => {
    if (parseFloat(text) !== shown) setText(String(shown));
  }, [shown]);
  return (
    <input
      type="number"
      className={p.className ?? "diag-num"}
      min={0}
      step={p.step ?? 1}
      value={text}
      title={p.title}
      onChange={(e) => {
        setText(e.target.value);
        const n = parseFloat(e.target.value);
        if (Number.isFinite(n) && n >= 0) p.onChange(n * scale);
      }}
    />
  );
}

function OptionsSection({ desc, prefs, update }: { desc: DiagDescribe; prefs: DiagPrefs; update: (p: Partial<DiagPrefs>) => void }) {
  const o = { ...desc.options, ...prefs.options };
  const nets = prefs.options?.networks ?? desc.options.networks;
  const setOpt = (k: string, v: unknown) => update({ options: { ...prefs.options, [k]: v } });
  const setNets = (n: NetworkProfile[]) => setOpt("networks", n);
  const patchNet = (i: number, patch: Partial<NetworkProfile>) => setNets(nets.map((n, j) => (j === i ? { ...n, ...patch } : n)));
  const label = (k: string, en: string) => desc.optionLabels[k] || en;
  return (
    <div className="diag-options">
      <div className="diag-opt-grid">
        <label>
          <span>{label("slowMs", t("Slow request (ms)"))}</span>
          <NumField value={o.slowMs} step={100} onChange={(v) => setOpt("slowMs", Math.round(v))} />
        </label>
        <label>
          <span>{label("ttfbMs", t("Slow first byte (ms)"))}</span>
          <NumField value={o.ttfbMs} step={50} onChange={(v) => setOpt("ttfbMs", Math.round(v))} />
        </label>
        <label>
          <span>{t("Large response (MB)")}</span>
          <NumField value={o.largeResponseBytes} scale={1048576} step={0.5} onChange={(v) => setOpt("largeResponseBytes", Math.round(v))} />
        </label>
        <label>
          <span>{label("operationGapMs", t("Operation gap (ms)"))}</span>
          <NumField value={o.operationGapMs} step={100} onChange={(v) => setOpt("operationGapMs", Math.round(v))} />
        </label>
      </div>
      <div className="diag-opt-h">
        <span>{t("Network profiles for estimates")}</span>
        <button className="linklike" onClick={() => setNets([...nets, { id: `custom-${Date.now().toString(36)}`, name: t("Custom"), rttMs: 50, mbps: 50, lossPct: 0 }])}>
          <Plus size={11} /> {t("Add")}
        </button>
      </div>
      <div className="diag-nets">
        <table>
          <thead>
            <tr>
              <th>{t("Name")}</th>
              <th>{t("RTT ms")}</th>
              <th>{t("Mbit/s")}</th>
              <th>{t("Loss %")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {nets.map((n, i) => (
              <tr key={n.id + i}>
                <td>
                  <input className="diag-net-name" value={n.name} onChange={(e) => patchNet(i, { name: e.target.value })} />
                </td>
                <td>
                  <NumField className="diag-num sm" value={n.rttMs} onChange={(v) => patchNet(i, { rttMs: v })} />
                </td>
                <td>
                  <NumField className="diag-num sm" value={n.mbps} onChange={(v) => patchNet(i, { mbps: v })} />
                </td>
                <td>
                  <NumField className="diag-num sm" value={n.lossPct} step={0.1} onChange={(v) => patchNet(i, { lossPct: v })} />
                </td>
                <td>
                  <button className="linklike" title={t("Remove")} onClick={() => setNets(nets.filter((_, j) => j !== i))}>
                    <X size={12} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="diag-opt-foot">
        <button className="linklike" onClick={() => update({ options: undefined })} title={t("Thresholds and network profiles back to the analyzer's defaults")}>
          <RotateCcw size={11} /> {t("Reset to defaults")}
        </button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ report

function ReportView({ report }: { report: DiagReport }) {
  const st = useDiag();
  const { ref, w } = useWidth<HTMLDivElement>();
  const wide = w >= WIDE;

  const categories = useMemo(() => [...new Set(report.findings.flatMap((f) => f.categories))].sort(), [report]);
  const q = st.q.trim().toLowerCase();
  const shown = useMemo(() => {
    const out: Record<Severity, number[]> = { critical: [], warning: [], info: [] };
    report.findings.forEach((f, i) => {
      if (st.sev && f.severity !== st.sev) return;
      if (st.cat && !f.categories.includes(st.cat)) return;
      if (q && ![f.title, f.observation, f.id, f.key, ...f.categories, ...f.tags].some((s) => s.toLowerCase().includes(q))) return;
      out[f.severity].push(i);
    });
    return out;
  }, [report, st.sev, st.cat, q]);
  const nShown = shown.critical.length + shown.warning.length + shown.info.length;
  const picked = st.picked != null ? report.findings[st.picked] : undefined;

  const overview = (
    <>
      <ReportHead report={report} />
      <div className="diag-chips">
        {SEVERITIES.map((s) => (
          <button key={s} className={`diag-chip sev-${s} ${st.sev === s ? "on" : ""}`} onClick={() => setDiag({ sev: st.sev === s ? null : s })} title={t("Show only this severity")}>
            <span className="diag-chip-n">{fmtInt(report.summary[s])}</span> {severityPlural(s, report.summary[s], t)}
          </button>
        ))}
      </div>
      {report.summary.headline.length > 0 && (
        <ul className="diag-headline">
          {report.summary.headline.map((h, i) => (
            <li key={i}>{h}</li>
          ))}
        </ul>
      )}
      {report.metrics.length > 0 && <Metrics metrics={report.metrics} />}
    </>
  );

  const list = (
    <>
      <div className="diag-filter">
        {categories.length > 0 && (
          <select className="diag-sel" value={st.cat} onChange={(e) => setDiag({ cat: e.target.value })}>
            <option value="">{t("All categories")}</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {categoryLabel(c, t)}
              </option>
            ))}
          </select>
        )}
        <span className="diag-search">
          <Search size={12} />
          <input placeholder={t("Search findings")} value={st.q} onChange={(e) => setDiag({ q: e.target.value })} />
        </span>
        {nShown !== report.findings.length && <span className="muted small">{t("{n} of {total}", { n: fmtInt(nShown), total: fmtInt(report.findings.length) })}</span>}
      </div>
      {!report.findings.length && <div className="muted diag-none">{t("No findings. Nothing stood out in these sessions.")}</div>}
      {report.findings.length > 0 && !nShown && <div className="muted diag-none">{t("No findings match the filter.")}</div>}
      {SEVERITIES.map((s) =>
        shown[s].length ? (
          <div key={s} className="diag-group">
            <div className={`diag-group-h sev-${s}`}>
              {severityPlural(s, 2, t)} <span className="muted">({fmtInt(shown[s].length)})</span>
            </div>
            {shown[s].slice(0, st.limits[s]).map((i) => (
              <FindingRow key={i} f={report.findings[i]} picked={st.picked === i} onPick={() => setDiag({ picked: st.picked === i ? null : i })}>
                {!wide && st.picked === i && <FindingDetail f={report.findings[i]} report={report} />}
              </FindingRow>
            ))}
            {shown[s].length > st.limits[s] && (
              <button className="linklike diag-more" onClick={() => setDiag({ limits: { ...st.limits, [s]: st.limits[s] + PAGE } })}>
                {t("Show {n} more", { n: fmtInt(Math.min(PAGE, shown[s].length - st.limits[s])) })}
              </button>
            )}
          </div>
        ) : null,
      )}
      {report.operations.length > 0 && <Operations report={report} />}
    </>
  );

  return (
    <div className="diag-body" ref={ref}>
      {wide ? (
        <div className="diag-split">
          <div className="scroll diag-main">
            {overview}
            {list}
          </div>
          <div className="scroll diag-side" key={st.picked ?? -1}>
            {picked ? <FindingDetail f={picked} report={report} onClose={() => setDiag({ picked: null })} /> : <div className="muted diag-none">{t("Select a finding to see the details.")}</div>}
          </div>
        </div>
      ) : (
        <div className="scroll diag-main">
          {overview}
          {list}
        </div>
      )}
    </div>
  );
}

function ReportHead({ report }: { report: DiagReport }) {
  const parts: string[] = [];
  if (report.profile.name) parts.push(report.profile.name);
  const n = report.scope?.sessions || report.range.sessions;
  const scope = scopeLabel(report, t);
  parts.push(scope ? `${scope}: ${plural(n, "{n} session", "{n} sessions")}` : plural(n, "{n} session", "{n} sessions"));
  if (report.range.from != null) parts.push(`${fmtDateTime(report.range.from)} – ${fmtTime(report.range.to)}`);
  return (
    <div className="diag-head">
      <span>{parts.join(" · ")}</span>
      {report.generatedAt != null && <span className="muted"> · {t("created {time}", { time: fmtDateTime(report.generatedAt) })}</span>}
    </div>
  );
}

function Metrics({ metrics }: { metrics: DiagMetric[] }) {
  return (
    <div className="diag-metrics">
      {metrics.map((m, i) => (
        <div key={m.key || i} className="diag-metric" title={m.key}>
          <span className="diag-metric-v">{fmtValue(m.value, m.unit)}</span>
          <span className="diag-metric-l">{m.label}</span>
        </div>
      ))}
    </div>
  );
}

function FindingRow(p: { f: DiagFinding; picked: boolean; onPick: () => void; children?: React.ReactNode }) {
  const f = p.f;
  const Chev = p.picked ? ChevronDown : ChevronRight;
  return (
    <div className={`diag-f sev-${f.severity} ${p.picked ? "picked" : ""}`}>
      <div className="diag-f-row" onClick={p.onPick}>
        <Chev size={12} className="diag-f-chev" />
        <div className="diag-f-text">
          <div className="diag-f-title">{f.title}</div>
          <div className="diag-f-meta">
            <span className="pill pill-muted">{confidenceLabel(f.confidence, t)}</span>
            {f.estimate && <span className="pill pill-violet">{t("Estimate")}</span>}
            {f.categories.length > 0 && <span className="muted small">{f.categories.map((c) => categoryLabel(c, t)).join(", ")}</span>}
            {f.sessions.length > 0 && <span className="muted small">· {plural(f.sessions.length, "{n} session", "{n} sessions")}</span>}
          </div>
        </div>
      </div>
      {p.children}
    </div>
  );
}

function FindingDetail({ f, report, onClose }: { f: DiagFinding; report: DiagReport; onClose?: () => void }) {
  const op = f.operation ? report.operations.find((o) => o.id === f.operation) : undefined;
  const rows = f.table?.rows ?? [];
  const [, updatePrefs] = usePrefs();
  // Mixed traffic: offer to narrow the scope to one of the processes in the breakdown.
  const narrowTo = f.id === "SCOPE-MIXED" ? rows.map((r) => r[0]).filter((n) => n && !/^site /i.test(n) && n !== "?").slice(0, 3) : [];
  return (
    <div className="diag-detail">
      {onClose && (
        <div className="diag-detail-h">
          <span className={`pill ${f.severity === "critical" ? "pill-err" : f.severity === "warning" ? "pill-warn" : "pill-info"}`}>{severityLabel(f.severity, t)}</span>
          <span className="diag-detail-title">{f.title}</span>
          <button className="linklike" onClick={onClose} title={t("Close")}>
            <X size={13} />
          </button>
        </div>
      )}
      {onClose && (
        <div className="diag-f-meta">
          <span className="pill pill-muted">{confidenceLabel(f.confidence, t)}</span>
          {f.estimate && <span className="pill pill-violet">{t("Estimate")}</span>}
          {f.categories.length > 0 && <span className="muted small">{f.categories.map((c) => categoryLabel(c, t)).join(", ")}</span>}
        </div>
      )}
      {f.observation && <p className="diag-obs">{f.observation}</p>}
      {f.facts.length > 0 && (
        <table className="kv diag-facts">
          <tbody>
            {f.facts.map((x, i) => (
              <tr key={i}>
                <td>{x.label}</td>
                <td>{x.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {f.table && f.table.columns.length > 0 && (
        <div className="diag-table-wrap">
          <table className="diag-table">
            <thead>
              <tr>
                {f.table.columns.map((c, i) => (
                  <th key={i}>{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, TABLE_ROWS).map((r, i) => (
                <tr key={i}>
                  {f.table!.columns.map((_, j) => (
                    <td key={j}>{r[j] ?? ""}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length > TABLE_ROWS && <div className="muted small">{t("{n} more rows not shown", { n: fmtInt(rows.length - TABLE_ROWS) })}</div>}
        </div>
      )}
      {f.impact && <Section title={t("Impact")}>{<p>{f.impact}</p>}</Section>}
      {f.hypotheses.length > 0 && (
        <Section title={t("Hypotheses (not verified)")} className="diag-hyp">
          <ul>
            {f.hypotheses.map((h, i) => (
              <li key={i}>{h}</li>
            ))}
          </ul>
        </Section>
      )}
      {f.recommendations.length > 0 && (
        <Section title={t("Recommendations")}>
          <ul>
            {f.recommendations.map((h, i) => (
              <li key={i}>{h}</li>
            ))}
          </ul>
        </Section>
      )}
      {f.nextSteps.length > 0 && (
        <Section title={t("Next steps")}>
          <ul>
            {f.nextSteps.map((h, i) => (
              <li key={i}>{h}</li>
            ))}
          </ul>
        </Section>
      )}
      {f.threshold && (
        <div className="muted small diag-threshold">
          {t("Threshold")}: {f.threshold}
        </div>
      )}
      <div className="diag-detail-actions">
        {narrowTo.map((name) => (
          <button
            key={name}
            onClick={() => {
              updatePrefs({ processes: [name], hosts: [] });
              say(t("Scope: only {name} – run the analysis again", { name }));
            }}
            title={t("Narrow the scope to this process")}
          >
            {t("Only {name}", { name })}
          </button>
        ))}
        {f.sessions.length > 0 && (
          <>
            <button onClick={() => void actions.selectIds(f.sessions)} title={t("Select the affected sessions in the list")}>
              {plural(f.sessions.length, "Select {n} session", "Select {n} sessions")}
            </button>
            <button
              onClick={() => {
                void actions.selectIds([f.sessions[0]]);
                actions.showTab("inspectors");
              }}
              title={t("Select the first affected session and show it in Inspect")}
            >
              {t("Inspect first")}
            </button>
          </>
        )}
        {f.operation && (
          <button
            className="linklike"
            onClick={() => {
              setDiag({ pickedOp: f.operation });
              if (op) void actions.selectIds(op.sessions);
            }}
            title={t("Select the sessions of this operation")}
          >
            {t("Operation")}: {op?.label || f.operation}
          </button>
        )}
      </div>
      <div className="muted small diag-id">
        {f.id}
        {f.tags.length > 0 && ` · ${f.tags.join(", ")}`}
      </div>
    </div>
  );
}

function Section({ title, className, children }: { title: string; className?: string; children: React.ReactNode }) {
  return (
    <div className={`diag-sec ${className ?? ""}`}>
      <div className="diag-sec-h">{title}</div>
      {children}
    </div>
  );
}

function Operations({ report }: { report: DiagReport }) {
  const pickedOp = useDiag((s) => s.pickedOp);
  const limit = useDiag((s) => s.opLimit);
  return (
    <div className="diag-group diag-ops">
      <div className="diag-group-h">
        {t("Operations")} <span className="muted">({fmtInt(report.operations.length)})</span>
      </div>
      {report.operations.slice(0, limit).map((o) => {
        const req = o.metrics.find((m) => m.key === "requests");
        const rest = o.metrics.filter((m) => m !== req);
        return (
          <div
            key={o.id}
            className={`diag-op ${pickedOp === o.id ? "picked" : ""}`}
            onClick={() => {
              setDiag({ pickedOp: o.id });
              void actions.selectIds(o.sessions);
            }}
            title={t("Select the sessions of this operation")}
          >
            <div className="diag-op-row">
              <span className="diag-op-label">{o.label}</span>
              <span className="diag-op-num">{opDuration(o)}</span>
              <span className="diag-op-num">{req ? plural(Number(req.value) || 0, "{n} request", "{n} requests") : plural(o.sessions.length, "{n} session", "{n} sessions")}</span>
            </div>
            {rest.length > 0 && <div className="muted small">{rest.map((m) => `${m.label}: ${fmtValue(m.value, m.unit)}`).join(" · ")}</div>}
          </div>
        );
      })}
      {report.operations.length > limit && (
        <button className="linklike diag-more" onClick={() => setDiag({ opLimit: limit + OP_PAGE })}>
          {t("Show {n} more", { n: fmtInt(Math.min(OP_PAGE, report.operations.length - limit)) })}
        </button>
      )}
    </div>
  );
}

// ------------------------------------------------------------------ comparison

function CompareView({ base, report }: { base: { report: DiagReport; name: string }; report: DiagReport }) {
  const c = useMemo(() => compare(base.report, report), [base, report]);
  const pick = (f: DiagFinding) => {
    const i = report.findings.indexOf(f);
    setDiag({ base: null, picked: i >= 0 ? i : null, sev: null, cat: "", q: "" });
  };
  const sevRows = c.severity.map((d) => ({ ...d, label: severityLabel(d.key as Severity, t) }));
  return (
    <div className="scroll pad diag-compare">
      <div className="diag-cmp-h">
        <div>
          <div>
            <span className="muted">{t("Before")}:</span> {base.name}
            {base.report.generatedAt != null && <span className="muted"> · {fmtDateTime(base.report.generatedAt)}</span>}
          </div>
          <div>
            <span className="muted">{t("After")}:</span> {t("current report")}
            {report.generatedAt != null && <span className="muted"> · {fmtDateTime(report.generatedAt)}</span>}
          </div>
        </div>
        <button onClick={() => setDiag({ base: null })}>
          <X size={12} /> {t("Close comparison")}
        </button>
      </div>
      {base.report.profile.id !== report.profile.id && <div className="diag-note">{t("The reports use different profiles; not every difference is a change in the traffic.")}</div>}
      <div className="diag-table-wrap">
        <table className="diag-table diag-cmp">
          <thead>
            <tr>
              <th>{t("Metric")}</th>
              <th>{t("Before")}</th>
              <th>{t("After")}</th>
              <th>{t("Change")}</th>
            </tr>
          </thead>
          <tbody>
            {[...sevRows, ...c.metrics].map((d, i) => (
              <DeltaRow key={`${d.key}-${i}`} d={d} />
            ))}
          </tbody>
        </table>
      </div>
      <CmpList title={t("New findings")} items={c.added.map((f) => ({ f, onClick: () => pick(f) }))} />
      <CmpList title={t("Resolved findings")} items={c.resolved.map((f) => ({ f }))} />
      <CmpList
        title={t("Changed severity")}
        items={c.changed.map((x) => ({ f: x.after, from: x.before.severity, onClick: () => pick(x.after) }))}
      />
      <div className="muted small">{plural(c.unchanged, "{n} finding unchanged.", "{n} findings unchanged.")}</div>
    </div>
  );
}

function DeltaRow({ d }: { d: MetricDelta }) {
  return (
    <tr>
      <td>{d.label}</td>
      <td className="num">{fmtValue(d.before, d.unit)}</td>
      <td className="num">{fmtValue(d.after, d.unit)}</td>
      <td className={`num diag-trend-${d.trend}`}>{d.delta != null ? fmtDelta(d.delta, d.unit) : ""}</td>
    </tr>
  );
}

function CmpList({ title, items }: { title: string; items: { f: DiagFinding; from?: Severity; onClick?: () => void }[] }) {
  const [limit, setLimit] = useState(PAGE);
  return (
    <div className="diag-group">
      <div className="diag-group-h">
        {title} <span className="muted">({fmtInt(items.length)})</span>
      </div>
      {!items.length && <div className="muted small diag-none">{t("None")}</div>}
      {items.slice(0, limit).map(({ f, from, onClick }, i) => (
        <div key={`${f.key}-${i}`} className={`diag-f sev-${f.severity}`}>
          <div className="diag-f-row" onClick={onClick} style={onClick ? undefined : { cursor: "default" }}>
            <div className="diag-f-text">
              <div className="diag-f-title">{f.title}</div>
              <div className="diag-f-meta">
                {from && (
                  <>
                    <span className={`pill ${sevPill(from)}`}>{severityLabel(from, t)}</span>
                    <span className="muted small">→</span>
                  </>
                )}
                <span className={`pill ${sevPill(f.severity)}`}>{severityLabel(f.severity, t)}</span>
                {f.categories.length > 0 && <span className="muted small">{f.categories.map((c) => categoryLabel(c, t)).join(", ")}</span>}
              </div>
            </div>
          </div>
        </div>
      ))}
      {items.length > limit && (
        <button className="linklike diag-more" onClick={() => setLimit(limit + PAGE)}>
          {t("Show {n} more", { n: fmtInt(Math.min(PAGE, items.length - limit)) })}
        </button>
      )}
    </div>
  );
}

const sevPill = (s: Severity) => (s === "critical" ? "pill-err" : s === "warning" ? "pill-warn" : "pill-info");
