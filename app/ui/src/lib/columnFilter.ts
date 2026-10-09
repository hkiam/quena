// Column filters: a value typed for a list column becomes a clause of the filter expression
// (`host ~ example`, `status >= 400`, `resheader.server == nginx`).
import type { ColumnKey } from "../store";

type HeaderColumn = { response: boolean; name: string };

const FIELDS: Partial<Record<ColumnKey, string>> = {
  id: "id",
  result: "status",
  protocol: "protocol",
  host: "host",
  url: "path",
  body: "size",
  contentType: "type",
  process: "process",
  comments: "comment",
  custom: "custom",
  method: "method",
  duration: "duration",
  via: "via",
  cert: "certdays",
  llm: "llm",
  tokens: "tokens",
  tls: "tls",
  remoteIp: "ip",
  http: "http",
};
const NUMERIC = new Set(["id", "status", "size", "duration", "certdays", "tokens"]);

/** The filter field of a column (`null`: it cannot be filtered). */
export function fieldOf(key: ColumnKey, headerColumns?: HeaderColumn[]): string | null {
  const i = key === "header1" ? 0 : key === "header2" ? 1 : key === "header3" ? 2 : -1;
  if (i >= 0) {
    const h = headerColumns?.[i];
    return h ? `${h.response ? "resheader" : "reqheader"}.${h.name.toLowerCase()}` : null;
  }
  return FIELDS[key] ?? null;
}

const OPS = [">=", "<=", "!=", "==", "!~", "=~", "~=", ">", "<", "=", "~"];

/** A clause for `field` from what was typed: an operator first (`>= 400`, `!= 200`, `=~ ^v2`)
 * or just a value (numbers: equal; text with `*`: glob; other text: contains). */
export function clause(field: string, input: string): string | null {
  let v = input.trim();
  if (!v) return null;
  let op = OPS.find((o) => v.startsWith(o));
  if (op) v = v.slice(op.length).trim();
  if (!v && op !== "==" && op !== "!=") return null;
  if (op === "=") op = "==";
  if (!op) op = NUMERIC.has(field) ? "==" : v.includes("*") || v.includes("?") ? "~=" : "~";
  const numeric = NUMERIC.has(field) && /^[0-9]+(\.[0-9]+)?([kmg]b?|ms|s|xx)?$/i.test(v);
  // Typed in quotes: taken as it is (`""` for an empty value).
  const quoted = v.length >= 2 && v.startsWith('"') && v.endsWith('"');
  const value = numeric || quoted ? v : `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  return `${field} ${op} ${value}`;
}

/** `expr` and `c` (both kept, `c` last). */
export function addClause(expr: string, c: string): string {
  const e = expr.trim();
  if (!e) return c;
  return /\bor\b|\|\|/i.test(e) ? `(${e}) and ${c}` : `${e} and ${c}`;
}

/** Whether the expression filters on `field` (for the column's funnel). */
export function filtersOn(expr: string, field: string | null): boolean {
  if (!field || !expr) return false;
  const f = field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[\\s(!])${f}\\s*(==|!=|~=|=~|!~|<=|>=|<|>|~|=)`, "i").test(expr);
}
