import { describe, expect, it } from "vitest";
import { compare, direction, fmtDelta, fmtValue, mdText, normalizeReport, parseDescribe, parseReport, scopeLabel, toAiPrompt, toMarkdown, type DiagReport } from "./diagReport";

const t = (en: string, vars?: Record<string, string | number>) => (vars ? en.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m)) : en);

const SAMPLE = {
  schema: 1,
  tool: { id: "io.github.hkiam.webdiag", version: "0.1.0" },
  profile: { id: "performance", name: "Performance" },
  lang: "en",
  range: { from: 1727690000000000, to: 1727690060000000, sessions: 10 },
  summary: { critical: 1, warning: 1, info: 0, headline: ["Sequential API communication adds latency."] },
  metrics: [
    { key: "requests", label: "HTTP requests", value: 100, unit: "count" },
    { key: "bytes", label: "Transferred", value: 2048, unit: "bytes" },
    { key: "duplicateShare", label: "Duplicate requests", value: 0.31, unit: "ratio" },
  ],
  operations: [{ id: "op-3", label: "GET /odata/Cases(42)", start: 1727690001000000, end: 1727690007800000, sessions: [1, 2], metrics: [{ key: "requests", label: "Requests", value: 2, unit: "count" }] }],
  findings: [
    { id: "INFO-X", key: "INFO-X|a", title: "Info thing", severity: "warning", score: 10 },
    {
      id: "PERF-SEQ",
      key: "PERF-SEQ|op-3",
      title: "Latency | chain",
      severity: "critical",
      confidence: "high",
      categories: ["performance"],
      score: 72,
      observation: "42 requests ran one after another.",
      hypotheses: ["Could run concurrently."],
      recommendations: ["Parallelise."],
      estimate: true,
      facts: [{ label: "Levels", value: "42" }],
      table: { columns: ["Network", "RTT"], rows: [["Good WAN", "20 ms"]] },
      sessions: [1, 2, 3],
      operation: "op-3",
      futureField: { anything: true },
    },
  ],
  scope: { kind: "selection", sessions: 10 },
  generatedAt: 1727690070000000,
  unknownTopLevel: 42,
};

describe("diagnostics report", () => {
  it("parses a report and sorts findings by severity, then score", () => {
    const { report } = parseReport(JSON.stringify(SAMPLE));
    expect(report.findings.map((f) => f.id)).toEqual(["PERF-SEQ", "INFO-X"]);
    expect(report.findings[0].table?.rows).toEqual([["Good WAN", "20 ms"]]);
    expect(report.findings[1].confidence).toBe("medium");
    expect(report.findings[1].sessions).toEqual([]);
    expect(report.scope).toEqual({ kind: "selection", sessions: 10, processes: [], hosts: [] });
  });

  it("tolerates missing fields and rejects other schemas", () => {
    const r = normalizeReport({ schema: 1, findings: [{ severity: "bogus" }, null, { title: 5 }] })!;
    expect(r.findings).toHaveLength(3);
    expect(r.findings.every((f) => f.severity === "info")).toBe(true);
    expect(r.summary.info).toBe(3);
    expect(r.metrics).toEqual([]);
    expect(normalizeReport({ schema: 2 })).toBeNull();
    expect(normalizeReport([])).toBeNull();
    expect(() => parseReport("not json")).toThrow();
    expect(() => parseReport('{"schema": 3}')).toThrow();
  });

  it("formats values by unit", () => {
    expect(fmtValue(1234, "count")).toBe("1,234");
    expect(fmtValue(2048, "bytes")).toBe("2.00 KB");
    expect(fmtValue(1500, "ms")).toBe("1.50 s");
    expect(fmtValue(0.31, "ratio")).toBe("31 %");
    expect(fmtValue(2.5, "rate")).toBe("2.5/s");
    expect(fmtValue("n/a", "text")).toBe("n/a");
    expect(fmtValue(null, "count")).toBe("–");
    expect(fmtDelta(-3, "count")).toBe("−3");
    expect(fmtDelta(0.05, "ratio")).toBe("+5 pp");
  });

  it("writes Markdown with all sections and escaped table cells", () => {
    const { report } = parseReport(JSON.stringify(SAMPLE));
    const md = toMarkdown(report, t);
    expect(md).toContain("# Diagnostics report: Performance");
    expect(md).toContain("## Key metrics");
    expect(md).toContain("| Duplicate requests | 31 % |");
    expect(md).toContain("### [Critical] Latency \\| chain (PERF-SEQ)");
    expect(md).toContain("High confidence · Estimate · Categories: performance");
    expect(md).toContain("**Hypotheses (not verified):**");
    expect(md).toContain("| Good WAN | 20 ms |");
    expect(md).toContain("**Operation:** GET /odata/Cases(42)");
    expect(md).toContain("**Affected sessions:** 3 (#1, #2, #3)");
    expect(md).toContain("## Operations");
    const capped = toMarkdown(report, t, { limit: 0 });
    expect(capped).toContain("1 more findings of this severity not shown.");
    expect(toAiPrompt(report, t)).toMatch(/^Below is a network diagnostics report.*removed/s);
  });

  it("keeps traffic-derived texts from forming Markdown structure or HTML", () => {
    expect(mdText("Slow\n# injected heading")).toBe("Slow # injected heading");
    expect(mdText("# top")).toBe("\\# top");
    expect(mdText("- item")).toBe("\\- item");
    expect(mdText("1. first")).toBe("1\\. first");
    expect(mdText("<img src=x onerror=alert(1)>")).toBe("\\<img src=x onerror=alert(1)\\>");
    expect(mdText("`/x` *b* _i_ [l](u) a|b ~s~ c\\")).toBe("\\`/x\\` \\*b\\* \\_i\\_ \\[l\\](u) a\\|b \\~s\\~ c\\\\");
    const report = normalizeReport({
      schema: 1,
      findings: [
        {
          id: "A",
          title: "Slow\n# injected heading",
          severity: "warning",
          observation: "line1\n\n## Fake section",
          hypotheses: ["one\n### two"],
          table: { columns: ["Path", "x"], rows: [["/a\\|b", "c\\"], ["`/x", "<img src=x>"]] },
        },
      ],
    })!;
    const md = toMarkdown(report, t);
    expect(md).toContain("### [Warning] Slow # injected heading (A)");
    expect(md).toContain("**Observation:** line1 ## Fake section");
    expect(md.split("\n").filter((l) => /^#{1,6} /.test(l))).toEqual(["# Diagnostics report", "## Summary", "## Findings", "### [Warning] Slow # injected heading (A)"]);
    expect(md).toContain("- one ### two");
    expect(md).toContain("| /a\\\\\\|b | c\\\\ |");
    expect(md).toContain("| \\`/x | \\<img src=x\\> |");
    expect(md).not.toMatch(/(^|[^\\])<img/);
  });

  it("compares two reports by finding key and metric direction", () => {
    const a = parseReport(JSON.stringify(SAMPLE)).report;
    const b: DiagReport = structuredClone(a);
    b.metrics = [
      { key: "requests", label: "HTTP requests", value: 80, unit: "count" },
      { key: "bytes", label: "Transferred", value: 4096, unit: "bytes" },
      { key: "newThing", label: "New", value: 1, unit: "count" },
    ];
    b.findings = [
      { ...a.findings[0], severity: "warning" },
      { ...a.findings[1], key: "OTHER|x", id: "OTHER" },
    ];
    b.summary = { ...a.summary, critical: 0, warning: 2 };
    const c = compare(a, b);
    const m = Object.fromEntries(c.metrics.map((d) => [d.key, d]));
    expect(m.requests).toMatchObject({ before: 100, after: 80, delta: -20, trend: "better" });
    expect(m.bytes.trend).toBe("worse");
    expect(m.newThing).toMatchObject({ before: null, after: 1, trend: "neutral" });
    expect(m.duplicateShare).toMatchObject({ before: 0.31, after: null });
    expect(c.severity.find((s) => s.key === "critical")?.trend).toBe("better");
    expect(c.changed.map((x) => [x.before.severity, x.after.severity])).toEqual([["critical", "warning"]]);
    expect(c.added.map((f) => f.id)).toEqual(["OTHER"]);
    expect(c.resolved.map((f) => f.id)).toEqual(["INFO-X"]);
    expect(c.unchanged).toBe(0);
  });

  it("knows the obvious metric directions", () => {
    expect(direction("requests", "count")).toBe(-1);
    expect(direction("errorRate", "ratio")).toBe(-1);
    expect(direction("cacheHitRatio", "ratio")).toBe(1);
    expect(direction("uncompressedBytes", "bytes")).toBe(-1);
    expect(direction("connectionReuse", "ratio")).toBe(1);
    expect(direction("p95", "ms")).toBe(-1);
    expect(direction("hosts", "count")).toBe(0);
  });

  it("reads describe() with defaults", () => {
    const d = parseDescribe(JSON.stringify({ schema: 1, profiles: [{ id: "full", name: "Full" }, { id: "perf", name: "Perf", default: true }], options: { slowMs: 800 } }));
    expect(d.options.profile).toBe("perf");
    expect(d.options.slowMs).toBe(800);
    expect(d.options.ttfbMs).toBe(500);
    expect(d.options.networks).toHaveLength(5);
    expect(parseDescribe("garbage").profiles).toEqual([]);
  });
  it("names the narrowed scope", () => {
    const { report } = parseReport(JSON.stringify({ schema: 1, findings: [], scope: { kind: "visible", sessions: 3, processes: ["chrome"], hosts: ["*.example.com"] } }));
    expect(scopeLabel(report, (s: string, v?: Record<string, string | number>) => s.replace(/\{(\w+)\}/g, (_, k) => String(v?.[k])))).toBe("Visible sessions · Process: chrome · Host: *.example.com");
  });
  it("ignores invalid summary counts of a foreign report", () => {
    const { report } = parseReport(JSON.stringify({ schema: 1, summary: { warning: -5, critical: 1.7, info: "x" }, findings: [{ id: "A", key: "A", title: "a", severity: "warning" }] }));
    expect(report.summary.warning).toBe(1);
    expect(report.summary.critical).toBe(1);
    expect(report.summary.info).toBe(0);
  });
});
