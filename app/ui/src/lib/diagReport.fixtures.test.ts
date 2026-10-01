// Fixtures shared with the Rust port (crates/quena-report): the UI and `quena-cli diagnose`
// must compare reports and write Markdown identically.
import { describe, expect, it } from "vitest";
import basic from "../../../../crates/quena-report/tests/fixtures/compare-basic.json";
import edge from "../../../../crates/quena-report/tests/fixtures/compare-edge.json";
import markdown from "../../../../crates/quena-report/tests/fixtures/markdown-basic.json";
import { t } from "../i18n";
import { compare, normalizeReport, toMarkdown } from "./diagReport";

const fixtures: Record<string, { a: unknown; b: unknown; expected: unknown }> = { "compare-basic": basic, "compare-edge": edge };

describe("shared report fixtures", () => {
  for (const [name, f] of Object.entries(fixtures)) {
    it(name, () => {
      const c = compare(normalizeReport(f.a)!, normalizeReport(f.b)!);
      expect(JSON.parse(JSON.stringify(c))).toEqual(f.expected);
    });
  }

  it("markdown-basic (English; the German text is checked on the Rust side)", () => {
    const r = normalizeReport(markdown.report)!;
    expect(toMarkdown(r, t)).toBe(markdown.en);
    expect(toMarkdown(r, t, { limit: 1, sessionIds: 10 })).toBe(markdown.enLimited);
  });
});
