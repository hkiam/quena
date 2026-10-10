// The command field's answers come from the backend in English; this turns the known ones
// into the UI language. Anything else (e.g. a filter expression's syntax error) stays as sent.
import { plural, t } from "../i18n";

const COUNTED: [RegExp, (n: number) => string][] = [
  [/^(\d+) session\(s\) selected$/, (n) => plural(n, "{n} session selected", "{n} sessions selected")],
  [/^(\d+) session\(s\) removed$/, (n) => plural(n, "{n} session removed", "{n} sessions removed")],
  [/^Resumed (\d+) session\(s\)$/, (n) => plural(n, "Resumed {n} session", "Resumed {n} sessions")],
];

const FIXED: Record<string, () => string> = {
  "Filter removed": () => t("Filter removed"),
  "All sessions removed": () => t("All sessions removed"),
  Capturing: () => t("Capturing"),
  "Capture stopped": () => t("Capture stopped"),
  "breakpoints unavailable": () => t("Breakpoints are not available"),
  "empty command": () => t("Empty command"),
  "expected size, e.g. >10k": () => t("Expected a size, e.g. >10k"),
  "select needs a content type": () => t("select needs a content type, e.g. select image"),
  "keeponly needs a content type": () => t("keeponly needs a content type, e.g. keeponly json"),
  "tail needs a number": () => t("tail needs a number, e.g. tail 100"),
  "bps needs a status code": () => t("bps needs a status code, e.g. bps 404"),
  "unknown command – type help": () => t("Unknown command – type help, or filter EXPRESSION to filter"),
};

export function quickexecText(msg: string): string {
  const fixed = FIXED[msg];
  if (fixed) return fixed();
  for (const [re, f] of COUNTED) {
    const m = re.exec(msg);
    if (m) return f(Number(m[1]));
  }
  let m = /^Filter: (.*)$/s.exec(msg);
  if (m) return t("Filter: {expr}", { expr: m[1] });
  m = /^Breakpoints: (.*)$/s.exec(msg);
  if (m) return t("Breakpoints: {list}", { list: m[1] });
  m = /^(\w+): breakpoints cleared$/.exec(msg);
  if (m) return t("{name}: breakpoints cleared", { name: m[1] });
  return msg;
}
