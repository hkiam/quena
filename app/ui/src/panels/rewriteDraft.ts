// Editing rewrite operations: a form-friendly draft per operation (all fields as text) and
// the conversion back, with the checks the form shows before the backend validates.
import type { RwOp } from "../api";
import { t } from "../i18n";

export type OpKind = RwOp["op"];

/** Operations in the order the editor offers them, with their labels. */
export const OP_KINDS: [OpKind, string][] = [
  ["jsonSet", t("JSON: set value")],
  ["jsonRemove", t("JSON: remove")],
  ["jsonAppend", t("JSON: append element")],
  ["jsonAppendAll", t("JSON: append to every array")],
  ["regexReplace", t("Text: replace (regex)")],
  ["setHeader", t("Header: set")],
  ["removeHeader", t("Header: remove")],
  ["setStatus", t("Status: set")],
];

export interface OpDraft {
  op: OpKind;
  path: string;
  /** JSON text of `value` (jsonSet, jsonAppend, jsonAppendAll). */
  valueText: string;
  pattern: string;
  replacement: string;
  name: string;
  headerValue: string;
  code: string;
}

export function emptyDraft(op: OpKind = "jsonSet"): OpDraft {
  return { op, path: "$.", valueText: "", pattern: "", replacement: "", name: "", headerValue: "", code: "503" };
}

export function toDraft(o: RwOp): OpDraft {
  const d = emptyDraft(o.op);
  switch (o.op) {
    case "jsonSet":
      return { ...d, path: o.path, valueText: JSON.stringify(o.value) };
    case "jsonRemove":
      return { ...d, path: o.path };
    case "jsonAppend":
      return { ...d, path: o.path, valueText: o.value === undefined ? "" : JSON.stringify(o.value) };
    case "jsonAppendAll":
      return { ...d, valueText: o.value === undefined ? "" : JSON.stringify(o.value) };
    case "regexReplace":
      return { ...d, pattern: o.pattern, replacement: o.replacement };
    case "setHeader":
      return { ...d, name: o.name, headerValue: o.value };
    case "removeHeader":
      return { ...d, name: o.name };
    case "setStatus":
      return { ...d, code: String(o.code) };
  }
}

function json(text: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false };
  }
}

/** The operation, or what is wrong with the form. */
export function fromDraft(d: OpDraft): { op: RwOp } | { error: string } {
  const path = d.path.trim();
  const needPath = () => (path.startsWith("$") ? null : t("A JSONPath starts with $, e.g. $.items[0].name"));
  switch (d.op) {
    case "jsonSet": {
      const e = needPath();
      if (e) return { error: e };
      const v = json(d.valueText);
      if (!v.ok) return { error: t("The value is not valid JSON (text needs quotes: \"text\")") };
      return { op: { op: "jsonSet", path, value: v.value } };
    }
    case "jsonRemove": {
      const e = needPath();
      return e ? { error: e } : { op: { op: "jsonRemove", path } };
    }
    case "jsonAppend":
    case "jsonAppendAll": {
      if (d.op === "jsonAppend") {
        const e = needPath();
        if (e) return { error: e };
      }
      let value: unknown;
      if (d.valueText.trim()) {
        const v = json(d.valueText);
        if (!v.ok) return { error: t("The value is not valid JSON (text needs quotes: \"text\")") };
        value = v.value;
      }
      const base = value === undefined ? {} : { value };
      return d.op === "jsonAppend" ? { op: { op: "jsonAppend", path, ...base } } : { op: { op: "jsonAppendAll", ...base } };
    }
    case "regexReplace":
      // The pattern's syntax (Rust regex) is checked by the backend when saving.
      if (!d.pattern) return { error: t("Enter a regular expression") };
      return { op: { op: "regexReplace", pattern: d.pattern, replacement: d.replacement } };
    case "setHeader":
      if (!d.name.trim()) return { error: t("Enter a header name") };
      return { op: { op: "setHeader", name: d.name.trim(), value: d.headerValue } };
    case "removeHeader":
      if (!d.name.trim()) return { error: t("Enter a header name") };
      return { op: { op: "removeHeader", name: d.name.trim() } };
    case "setStatus": {
      const code = Number(d.code);
      if (!Number.isInteger(code) || code < 100 || code > 999 || code === 101) return { error: t("A status code from 100 to 999 (not 101)") };
      return { op: { op: "setStatus", code } };
    }
  }
}

/** Short text of an operation for the rule list. */
export function describeOp(o: RwOp): string {
  switch (o.op) {
    case "jsonSet":
      return `${o.path} = ${JSON.stringify(o.value)}`;
    case "jsonRemove":
      return `− ${o.path}`;
    case "jsonAppend":
      return `+ ${o.path}[]`;
    case "jsonAppendAll":
      return "+ [*][]";
    case "regexReplace":
      return `s/${o.pattern}/${o.replacement}/`;
    case "setHeader":
      return `${o.name}: ${o.value}`;
    case "removeHeader":
      return `− ${o.name}:`;
    case "setStatus":
      return `→ ${o.code}`;
  }
}
