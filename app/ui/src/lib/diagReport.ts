// Diagnostics reports (analyzer API 1, see plugins/webdiag/REPORT.md): tolerant parsing,
// value formatting, Markdown export and the comparison of two reports. Pure functions, no UI.
import { currentLang } from "../i18n";
import { fmtBytes, fmtDateTime, fmtInt, fmtMs } from "./format";

export type Translate = (en: string, vars?: Record<string, string | number>) => string;
export type Severity = "critical" | "warning" | "info";
export const SEVERITIES: Severity[] = ["critical", "warning", "info"];

export interface NetworkProfile {
  id: string;
  name: string;
  rttMs: number;
  mbps: number;
  lossPct: number;
}

export interface DiagOptions {
  profile: string;
  lang: string;
  slowMs: number;
  ttfbMs: number;
  largeRequestBytes: number;
  largeResponseBytes: number;
  operationGapMs: number;
  networks: NetworkProfile[];
  [key: string]: unknown;
}

export interface DiagProfile {
  id: string;
  name: string;
  description: string;
  default: boolean;
}

export interface DiagDescribe {
  profiles: DiagProfile[];
  options: DiagOptions;
  optionLabels: Record<string, string>;
}

export interface DiagMetric {
  key: string;
  label: string;
  value: number | string | null;
  unit: string;
}

export interface DiagFinding {
  id: string;
  key: string;
  title: string;
  severity: Severity;
  confidence: string;
  categories: string[];
  score: number;
  observation: string;
  impact: string;
  hypotheses: string[];
  recommendations: string[];
  nextSteps: string[];
  estimate: boolean;
  threshold: string;
  facts: { label: string; value: string }[];
  table: { columns: string[]; rows: string[][] } | null;
  sessions: number[];
  operation: string | null;
  tags: string[];
}

export interface DiagOperation {
  id: string;
  label: string;
  start: number | null;
  end: number | null;
  sessions: number[];
  metrics: DiagMetric[];
}

export interface DiagReport {
  schema: 1;
  tool: { id: string; version: string };
  profile: { id: string; name: string };
  lang: string;
  range: { from: number | null; to: number | null; sessions: number };
  summary: { critical: number; warning: number; info: number; headline: string[] };
  metrics: DiagMetric[];
  operations: DiagOperation[];
  findings: DiagFinding[];
  scope: { kind: string; sessions: number; processes: string[]; hosts: string[] } | null;
  generatedAt: number | null;
}

// ------------------------------------------------------------------ tolerant readers

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown, d = ""): string => (typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : d);
const num = (v: unknown, d = 0): number => (typeof v === "number" && Number.isFinite(v) ? v : d);
const numOrNull = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const strs = (v: unknown): string[] => arr(v).map((x) => str(x)).filter((x) => x !== "");
const ids = (v: unknown): number[] => arr(v).filter((x): x is number => typeof x === "number" && Number.isFinite(x));

const SEV_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };
const severity = (v: unknown): Severity => (v === "critical" || v === "warning" || v === "info" ? v : "info");

function metric(v: unknown): DiagMetric | null {
  const m = obj(v);
  const key = str(m.key);
  if (!key && !str(m.label)) return null;
  const value = typeof m.value === "number" && Number.isFinite(m.value) ? m.value : typeof m.value === "string" ? m.value : null;
  return { key, label: str(m.label, key), value, unit: str(m.unit, typeof value === "string" ? "text" : "count") };
}
const metrics = (v: unknown) => arr(v).map(metric).filter((m): m is DiagMetric => m !== null);

function finding(v: unknown, i: number): DiagFinding {
  const f = obj(v);
  const id = str(f.id, `F${i + 1}`);
  const table = obj(f.table);
  const columns = strs(table.columns);
  const rows = arr(table.rows).map((r) => arr(r).map((c) => str(c)));
  return {
    id,
    key: str(f.key, id),
    title: str(f.title, id),
    severity: severity(f.severity),
    confidence: str(f.confidence, "medium"),
    categories: strs(f.categories),
    score: num(f.score),
    observation: str(f.observation),
    impact: str(f.impact),
    hypotheses: strs(f.hypotheses),
    recommendations: strs(f.recommendations),
    nextSteps: strs(f.nextSteps),
    estimate: f.estimate === true,
    threshold: str(f.threshold),
    facts: arr(f.facts).map((x) => ({ label: str(obj(x).label), value: str(obj(x).value) })).filter((x) => x.label || x.value),
    table: columns.length || rows.length ? { columns, rows } : null,
    sessions: ids(f.sessions),
    operation: str(f.operation) || null,
    tags: strs(f.tags),
  };
}

/** A report from its JSON value; null unless it is an object with `schema: 1`. Missing
 * fields get defaults, unknown keys are ignored. */
export function normalizeReport(raw: unknown): DiagReport | null {
  const r = obj(raw);
  if (r.schema !== 1) return null;
  const tool = obj(r.tool);
  const profile = obj(r.profile);
  const range = obj(r.range);
  const summary = obj(r.summary);
  const scope = r.scope == null ? null : obj(r.scope);
  const findings = arr(r.findings)
    .map(finding)
    .map((f, i) => [f, i] as const)
    .sort(([a, i], [b, j]) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || b.score - a.score || i - j)
    .map(([f]) => f);
  // Counts from a (possibly foreign) report: whole, non-negative numbers, else counted.
  const count = (s: Severity) => {
    const v = summary[s];
    return typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : findings.filter((f) => f.severity === s).length;
  };
  return {
    schema: 1,
    tool: { id: str(tool.id), version: str(tool.version) },
    profile: { id: str(profile.id), name: str(profile.name, str(profile.id)) },
    lang: str(r.lang),
    range: { from: numOrNull(range.from), to: numOrNull(range.to), sessions: num(range.sessions) },
    summary: { critical: count("critical"), warning: count("warning"), info: count("info"), headline: strs(summary.headline) },
    metrics: metrics(r.metrics),
    operations: arr(r.operations).map((v, i) => {
      const o = obj(v);
      return { id: str(o.id, `op-${i + 1}`), label: str(o.label, str(o.id)), start: numOrNull(o.start), end: numOrNull(o.end), sessions: ids(o.sessions), metrics: metrics(o.metrics) };
    }),
    findings,
    scope: scope
      ? {
          kind: str(scope.kind, "visible"),
          sessions: num(scope.sessions),
          processes: Array.isArray(scope.processes) ? scope.processes.map(String) : [],
          hosts: Array.isArray(scope.hosts) ? scope.hosts.map(String) : [],
        }
      : null,
    generatedAt: numOrNull(r.generatedAt),
  };
}

/** Parse report JSON text; throws when it is not JSON or not a schema 1 report. */
export function parseReport(text: string): { raw: unknown; report: DiagReport } {
  const raw: unknown = JSON.parse(text);
  const report = normalizeReport(raw);
  if (!report) throw new Error("not a schema 1 diagnostics report");
  return { raw, report };
}

export const DEFAULT_NETWORKS: NetworkProfile[] = [
  { id: "lan", name: "LAN", rttMs: 1, mbps: 1000, lossPct: 0 },
  { id: "good-wan", name: "Good WAN", rttMs: 20, mbps: 100, lossPct: 0 },
  { id: "vpn", name: "VPN/WAN", rttMs: 60, mbps: 20, lossPct: 0.1 },
  { id: "weak-wan", name: "Weak WAN", rttMs: 120, mbps: 5, lossPct: 0.5 },
  { id: "mobile", name: "Mobile", rttMs: 80, mbps: 10, lossPct: 1 },
];

export function normalizeNetworks(v: unknown, fallback: NetworkProfile[] = DEFAULT_NETWORKS): NetworkProfile[] {
  if (!Array.isArray(v)) return fallback.map((n) => ({ ...n }));
  return v.map((x, i) => {
    const n = obj(x);
    return { id: str(n.id, `net-${i + 1}`), name: str(n.name, str(n.id)), rttMs: num(n.rttMs), mbps: num(n.mbps), lossPct: num(n.lossPct) };
  });
}

/** describe() JSON of an analyzer; falls back to the documented defaults. */
export function parseDescribe(text: string): DiagDescribe {
  let d: Obj = {};
  try {
    d = obj(JSON.parse(text));
  } catch {
    /* defaults below */
  }
  const o = obj(d.options);
  const profiles = arr(d.profiles)
    .map((v) => {
      const p = obj(v);
      return { id: str(p.id), name: str(p.name, str(p.id)), description: str(p.description), default: p.default === true };
    })
    .filter((p) => p.id);
  const def = profiles.find((p) => p.default) ?? profiles[0];
  const labels: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj(d.optionLabels))) if (typeof v === "string") labels[k] = v;
  return {
    profiles,
    options: {
      ...o,
      profile: str(o.profile, def?.id ?? ""),
      lang: str(o.lang, "en"),
      slowMs: num(o.slowMs, 1000),
      ttfbMs: num(o.ttfbMs, 500),
      largeRequestBytes: num(o.largeRequestBytes, 1048576),
      largeResponseBytes: num(o.largeResponseBytes, 5242880),
      operationGapMs: num(o.operationGapMs, 1500),
      networks: normalizeNetworks(o.networks),
    },
    optionLabels: labels,
  };
}

// ------------------------------------------------------------------ formatting

function decimal(v: number, digits: number): string {
  return v.toLocaleString(currentLang() === "de" ? "de-DE" : "en-US", { minimumFractionDigits: 0, maximumFractionDigits: digits });
}

/** A metric value by its unit (count/bytes/ms/ratio/rate/text). */
export function fmtValue(value: number | string | null, unit: string): string {
  if (value == null) return "–";
  if (typeof value === "string") return value;
  switch (unit) {
    case "bytes":
      return fmtBytes(Math.round(value));
    case "ms":
      return fmtMs(Math.round(value));
    case "ratio":
      return `${decimal(value * 100, 1)} %`;
    case "rate":
      return `${decimal(value, 2)}/s`;
    case "count":
      return Number.isInteger(value) ? fmtInt(value) : decimal(value, 2);
    default:
      return decimal(value, 2);
  }
}

/** Signed difference between two values of a unit (`+1.2 MB`, `−3`, `+4.0 %` points). */
export function fmtDelta(delta: number, unit: string): string {
  const sign = delta > 0 ? "+" : delta < 0 ? "−" : "±";
  const abs = Math.abs(delta);
  if (unit === "ratio") return `${sign}${decimal(abs * 100, 1)} pp`;
  return `${sign}${fmtValue(abs, unit)}`;
}

export function severityLabel(s: Severity, t: Translate): string {
  return s === "critical" ? t("Critical") : s === "warning" ? t("Warning") : t("Info");
}

/** Severity with a count: "1 Warning", "8 Warnings", group headings (plural). */
export function severityPlural(s: Severity, n: number, t: Translate): string {
  if (s === "critical") return t("Critical");
  if (s === "warning") return n === 1 ? t("Warning") : t("Warnings");
  return n === 1 ? t("Note") : t("Notes");
}

/** Display name of a finding category (ids come from the analyzer). */
export function categoryLabel(c: string, t: Translate): string {
  switch (c) {
    case "auth": return t("Authentication");
    case "bandwidth": return t("Bandwidth");
    case "caching": return t("Caching");
    case "chattiness": return t("Chattiness");
    case "cookies": return t("Cookies");
    case "cors": return t("CORS");
    case "duplicates": return t("Duplicates");
    case "errors": return t("Errors");
    case "latency": return t("Latency");
    case "network": return t("Network");
    case "odata": return t("OData");
    case "payload": return t("Payload");
    case "performance": return t("Performance");
    case "polling": return t("Polling");
    case "redirects": return t("Redirects");
    case "resilience": return t("Resilience");
    case "scope": return t("Scope");
    case "security": return t("Security");
    case "server": return t("Server");
    case "timing": return t("Timing");
    case "tls": return t("TLS");
    case "troubleshooting": return t("Troubleshooting");
    default: return c;
  }
}

export function confidenceLabel(c: string, t: Translate): string {
  return c === "high" ? t("High confidence") : c === "low" ? t("Low confidence") : t("Medium confidence");
}

export function scopeLabel(r: DiagReport, t: Translate): string {
  if (!r.scope) return "";
  const parts = [r.scope.kind === "selection" ? t("Selected sessions") : t("Visible sessions")];
  if (r.scope.processes.length) parts.push(t("Process: {list}", { list: r.scope.processes.join(", ") }));
  if (r.scope.hosts.length) parts.push(t("Host: {list}", { list: r.scope.hosts.join(", ") }));
  return parts.join(" · ");
}

/** Duration of an operation in µs timestamps → display text. */
export function opDuration(o: DiagOperation): string {
  return o.start != null && o.end != null && o.end >= o.start ? fmtMs(Math.round((o.end - o.start) / 1000)) : "";
}

// ------------------------------------------------------------------ Markdown

/** Report texts (partly derived from the traffic) as inline Markdown: one line, and nothing that
 * Markdown or HTML would interpret — no headings, lists, emphasis, links, code or tags. */
export function mdText(s: string): string {
  const one = s.replace(/\s*[\r\n]+\s*/g, " ").trim();
  const esc = one.replace(/[\\`*_[\]<>|~]/g, "\\$&");
  // Block markers at the start of a line (list, heading, quote, ordered list).
  return esc.replace(/^([-+#>=])/, "\\$1").replace(/^(\d+)([.)])/, "$1\\$2");
}
const cell = (s: string) => mdText(s);
const mdTable = (head: string[], rows: string[][]) =>
  [`| ${head.map(cell).join(" | ")} |`, `|${head.map(() => " --- ").join("|")}|`, ...rows.map((r) => `| ${head.map((_, i) => cell(r[i] ?? "")).join(" | ")} |`)].join("\n");
/** A bullet list; `raw` items are frame texts that are already Markdown-safe. */
const list = (items: string[], raw = false) => items.map((s) => `- ${raw ? s : mdText(s)}`).join("\n");

export interface MarkdownOptions {
  /** At most this many findings per severity (the rest is counted). */
  limit?: number;
  /** At most this many session ids per finding. */
  sessionIds?: number;
}

/** The report as Markdown, in the UI language for the frame (report texts are already localized). */
export function toMarkdown(r: DiagReport, t: Translate, opts: MarkdownOptions = {}): string {
  const limit = opts.limit ?? Infinity;
  const maxIds = opts.sessionIds ?? 50;
  const out: string[] = [];
  out.push(`# ${t("Diagnostics report")}${r.profile.name ? `: ${mdText(r.profile.name)}` : ""}`);
  const meta: string[] = [];
  if (r.tool.id) meta.push(`${t("Analyzer")}: ${mdText(r.tool.id)}${r.tool.version ? ` ${mdText(r.tool.version)}` : ""}`);
  if (r.scope) meta.push(`${t("Scope")}: ${mdText(scopeLabel(r, t))}`);
  meta.push(`${t("Sessions")}: ${fmtInt(r.range.sessions || r.scope?.sessions || 0)}`);
  if (r.range.from != null) meta.push(`${t("Time range")}: ${fmtDateTime(r.range.from)} – ${fmtDateTime(r.range.to)}`);
  if (r.generatedAt != null) meta.push(`${t("Generated")}: ${fmtDateTime(r.generatedAt)}`);
  out.push(list(meta, true));

  out.push(`## ${t("Summary")}`);
  out.push(`${t("Critical")}: ${r.summary.critical} · ${t("Warning")}: ${r.summary.warning} · ${t("Info")}: ${r.summary.info}`);
  if (r.summary.headline.length) out.push(list(r.summary.headline));

  if (r.metrics.length) {
    out.push(`## ${t("Key metrics")}`);
    out.push(mdTable([t("Metric"), t("Value")], r.metrics.map((m) => [m.label, fmtValue(m.value, m.unit)])));
  }

  if (r.findings.length) {
    out.push(`## ${t("Findings")}`);
    for (const s of SEVERITIES) {
      const all = r.findings.filter((f) => f.severity === s);
      for (const f of all.slice(0, limit)) out.push(findingMarkdown(f, r, t, maxIds));
      if (all.length > limit) out.push(`_${t("{n} more findings of this severity not shown.", { n: all.length - limit })}_`);
    }
  }

  if (r.operations.length) {
    out.push(`## ${t("Operations")}`);
    const ops = r.operations.slice(0, Number.isFinite(limit) ? limit : undefined);
    out.push(
      mdTable(
        [t("Operation"), t("Duration"), t("Metrics")],
        ops.map((o) => [o.label, opDuration(o), o.metrics.map((m) => `${m.label}: ${fmtValue(m.value, m.unit)}`).join(", ")]),
      ),
    );
    if (r.operations.length > ops.length) out.push(`_${t("{n} more operations not shown.", { n: r.operations.length - ops.length })}_`);
  }
  return out.join("\n\n") + "\n";
}

function findingMarkdown(f: DiagFinding, r: DiagReport, t: Translate, maxIds: number): string {
  const out: string[] = [];
  out.push(`### [${severityLabel(f.severity, t)}] ${mdText(f.title)} (${mdText(f.id)})`);
  const tags = [confidenceLabel(f.confidence, t)];
  if (f.estimate) tags.push(t("Estimate"));
  if (f.categories.length) tags.push(`${t("Categories")}: ${mdText(f.categories.join(", "))}`);
  out.push(tags.join(" · "));
  if (f.observation) out.push(`**${t("Observation")}:** ${mdText(f.observation)}`);
  if (f.facts.length) out.push(mdTable([t("Fact"), t("Value")], f.facts.map((x) => [x.label, x.value])));
  if (f.table && f.table.columns.length) out.push(mdTable(f.table.columns, f.table.rows));
  if (f.impact) out.push(`**${t("Impact")}:** ${mdText(f.impact)}`);
  if (f.hypotheses.length) out.push(`**${t("Hypotheses (not verified)")}:**\n\n${list(f.hypotheses)}`);
  if (f.recommendations.length) out.push(`**${t("Recommendations")}:**\n\n${list(f.recommendations)}`);
  if (f.nextSteps.length) out.push(`**${t("Next steps")}:**\n\n${list(f.nextSteps)}`);
  if (f.threshold) out.push(`**${t("Threshold")}:** ${mdText(f.threshold)}`);
  if (f.operation) {
    const op = r.operations.find((o) => o.id === f.operation);
    out.push(`**${t("Operation")}:** ${mdText(op?.label || f.operation)}`);
  }
  if (f.sessions.length) {
    const shown = f.sessions.slice(0, maxIds).map((id) => `#${id}`).join(", ");
    out.push(`**${t("Affected sessions")}:** ${fmtInt(f.sessions.length)} (${shown}${f.sessions.length > maxIds ? ", …" : ""})`);
  }
  return out.join("\n\n");
}

/** Markdown for pasting into an AI assistant: a short request, then the report. */
export function toAiPrompt(r: DiagReport, t: Translate): string {
  const preface = t(
    "Below is a network diagnostics report of recorded HTTP traffic, created locally by Quena. Tokens, cookie values and sensitive URL parameters were removed before the analysis; URLs, host names and header names remain. Statements marked as estimate are modelled, not measured. Please explain the likely causes of the findings, prioritise them by impact on the user, and suggest concrete next steps. Point out where the data is not sufficient for a conclusion.",
  );
  return `${preface}\n\n---\n\n${toMarkdown(r, t, { limit: 60, sessionIds: 10 })}`;
}

// ------------------------------------------------------------------ comparison

export type Trend = "better" | "worse" | "same" | "neutral";

export interface MetricDelta {
  key: string;
  label: string;
  unit: string;
  before: number | string | null;
  after: number | string | null;
  delta: number | null;
  trend: Trend;
}

export interface Comparison {
  severity: MetricDelta[];
  metrics: MetricDelta[];
  /** Findings of `b` whose key is not in `a`. */
  added: DiagFinding[];
  /** Findings of `a` whose key is not in `b`. */
  resolved: DiagFinding[];
  /** Same key, different severity. */
  changed: { before: DiagFinding; after: DiagFinding }[];
  unchanged: number;
}

/** Which direction of a metric is an improvement: -1 lower is better, 1 higher, 0 unknown. */
export function direction(key: string, unit: string): -1 | 0 | 1 {
  if (unit === "text") return 0;
  if (/un(cached|compressed)|miss/i.test(key)) return -1;
  if (/(hit|cached|compress|reuse|parallel|throughput|success)/i.test(key)) return 1;
  if (/(request|bytes|transfer|size|error|fail|duplicate|redundant|redirect|retr|slow|large|timeout|abort|4xx|5xx|critical|warning|latency|wait|duration|ttfb|preflight|roundtrip|chain|sequential)/i.test(key)) return -1;
  return unit === "ms" ? -1 : 0;
}

function delta(key: string, label: string, unit: string, before: number | string | null, after: number | string | null): MetricDelta {
  const d = typeof before === "number" && typeof after === "number" ? after - before : null;
  let trend: Trend = "neutral";
  if (d != null) {
    const dir = direction(key, unit);
    const same = Math.abs(d) <= 1e-9 * Math.max(1, Math.abs(before as number));
    trend = same ? "same" : dir === 0 ? "neutral" : Math.sign(d) === dir ? "better" : "worse";
  } else if (before === after) trend = "same";
  return { key, label, unit, before, after, delta: d, trend };
}

const keyOf = (f: DiagFinding) => f.key || f.id;

/** Compare a baseline report `a` (before) with `b` (after). Findings match by `key`. */
export function compare(a: DiagReport, b: DiagReport): Comparison {
  const severity = SEVERITIES.map((s) => delta(s, s, "count", a.summary[s], b.summary[s]));
  const am = new Map(a.metrics.map((m) => [m.key || m.label, m]));
  const bm = new Map(b.metrics.map((m) => [m.key || m.label, m]));
  const metrics: MetricDelta[] = [];
  for (const [k, m] of bm) {
    const o = am.get(k);
    metrics.push(delta(k, m.label, m.unit, o?.value ?? null, m.value));
  }
  for (const [k, o] of am) if (!bm.has(k)) metrics.push(delta(k, o.label, o.unit, o.value, null));

  const af = new Map<string, DiagFinding>();
  for (const f of a.findings) if (!af.has(keyOf(f))) af.set(keyOf(f), f);
  const bf = new Map<string, DiagFinding>();
  for (const f of b.findings) if (!bf.has(keyOf(f))) bf.set(keyOf(f), f);
  const added: DiagFinding[] = [];
  const changed: Comparison["changed"] = [];
  let unchanged = 0;
  for (const [k, f] of bf) {
    const o = af.get(k);
    if (!o) added.push(f);
    else if (o.severity !== f.severity) changed.push({ before: o, after: f });
    else unchanged++;
  }
  const resolved = [...af].filter(([k]) => !bf.has(k)).map(([, f]) => f);
  return { severity, metrics, added, resolved, changed, unchanged };
}
