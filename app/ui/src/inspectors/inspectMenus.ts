// Context menus of the inspector views: copying values, paths and bodies, and rewrite rules
// made from a value of the JSON tree.
import { api, type Detail, type Part } from "../api";
import { actions, copyText } from "../actions";
import { confirmAsk, promptText, say, set } from "../store";
import type { MenuItem } from "../components/ContextMenu";
import { loadText } from "../lib/bodytext";
import { t } from "../i18n";

/** Bodies up to this size are copied whole; larger ones are saved to a file instead. */
const COPY_LIMIT = 16 << 20;

export const copyItem = (label: string, text: string, disabled = false): MenuItem => ({ label, disabled: disabled || !text, action: () => void copyText(text) });

/** Copy body, Save body…: for every view that shows a message body. */
export function bodyItems(detail: Detail, part: Part): MenuItem[] {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  return [
    {
      label: t("Copy Body"),
      disabled: !info.len || !info.isText || info.len > COPY_LIMIT,
      action: () => void loadText(detail.summary.id, part, info, COPY_LIMIT).then(copyText),
    },
    { label: t("Save Body…"), disabled: !info.len, action: () => actions.menu(part === "request" ? "file.save-request-body" : "file.save-response-body") },
  ];
}

/** A table row: copy its value, the row, all rows (tab-separated). */
export function tableItems(row: string[], rows: string[][], head?: string[]): MenuItem[] {
  const tsv = (r: string[]) => r.join("\t");
  return [
    copyItem(t("Copy Value"), row[1] ?? row[0] ?? ""),
    copyItem(t("Copy Row"), tsv(row)),
    copyItem(t("Copy All"), [...(head ? [tsv(head)] : []), ...rows.map(tsv)].join("\n")),
  ];
}

/** `$.items[0].name`, `$['odd key']` — JSONPath of a member below `parent`. */
export function jsonPath(parent: string, key: string, index: boolean): string {
  if (index) return `${parent}[${key}]`;
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) return `${parent}.${key}`;
  // RFC 9535 string literal: backslash, quote and control characters escaped.
  const esc = key.replace(/[\\'\u0000-\u001f]/g, (c) => {
    const named: Record<string, string> = { "\\": "\\\\", "'": "\\'", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t" };
    return named[c] ?? `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`;
  });
  return `${parent}['${esc}']`;
}

/** `/orders/order[2]/id`; positions only where siblings share the name. Elements in a
 * namespace become `*[local-name()='Envelope']`, which works without namespace bindings. */
export function xpath(el: Element): string {
  const steps: string[] = [];
  for (let n: Element | null = el; n; n = n.parentElement) {
    const same = n.parentElement ? Array.from(n.parentElement.children).filter((c) => c.localName === n!.localName && c.namespaceURI === n!.namespaceURI) : [n];
    const name = n.namespaceURI ? `*[local-name()='${n.localName}']` : n.localName;
    steps.unshift(same.length > 1 ? `${name}[${same.indexOf(n) + 1}]` : name);
  }
  return "/" + steps.join("/");
}

type Op = { op: string } & Record<string, unknown>;

/** Add a rewrite rule for this URL and side. Rewriting switched off is switched on only when
 * that does not wake other rules up, or the user agrees. */
async function addRewrite(detail: Detail, part: Part, op: Op, comment: string) {
  try {
    const state = await api.rwGet();
    if (!state.enabled) {
      const others = state.rules.filter((r) => r.enabled).length;
      if (others && !(await confirmAsk(t("Switch rewriting on?"), t("Rewriting is switched off. Switching it on also applies {n} other enabled rules.", { n: others }), t("Switch on")))) return;
      state.enabled = true;
    }
    state.rules.push({ id: 0, enabled: true, match: `exact:${detail.request.url}`, phase: part, status: "", contentType: "", ops: [op], comment, hits: 0 });
    await api.rwSet(state);
    set({ arNonce: Date.now() }); // the Mock Rules panel reloads
    say(t("Rewrite rule added: {rule}. Mock Rules lists it.", { rule: comment }));
  } catch (e) {
    say(t("Could not add the rewrite rule: {error}", { error: String(e) }), "error");
  }
}

const shortJson = (v: unknown) => {
  const s = JSON.stringify(v);
  return s.length > 40 ? `${s.slice(0, 39)}…` : s;
};

/** A value of the JSON tree: copy it, its key or path; change it in future messages. */
export function jsonItems(detail: Detail, part: Part, path: string, key: string | null, v: unknown, expand: (all: boolean) => void, rewrite = true): MenuItem[] {
  const isObj = v !== null && typeof v === "object";
  const where = part === "request" ? t("in requests to this URL") : t("in responses from this URL");
  return [
    copyItem(t("Copy Value"), typeof v === "string" ? v : JSON.stringify(v, null, isObj ? 2 : undefined)),
    copyItem(t("Copy Key"), key ?? ""),
    copyItem(t("Copy JSONPath"), path),
    { separator: true },
    { label: t("Expand All"), action: () => expand(true) },
    { label: t("Collapse All"), action: () => expand(false) },
    ...(rewrite ? rewriteItems(detail, part, path, v, where) : []),
  ];
}

/** Rewrite rules for a value: only for plain JSON bodies (not NDJSON or JSONP, whose paths
 * the rewriter cannot follow). */
function rewriteItems(detail: Detail, part: Part, path: string, v: unknown, where: string): MenuItem[] {
  return [
    { separator: true },
    {
      label: t("Change Value {where}…", { where }),
      disabled: path === "$",
      action: async () => {
        const text = await promptText(t("Change value"), t("New value of {path} (JSON; plain text becomes a string)", { path }), JSON.stringify(v));
        if (text == null) return;
        let value: unknown;
        try {
          value = JSON.parse(text);
        } catch {
          value = text;
        }
        await addRewrite(detail, part, { op: "jsonSet", path, value }, `${path} = ${shortJson(value)}`);
      },
    },
    { label: t("Remove Value {where}", { where }), disabled: path === "$", action: () => void addRewrite(detail, part, { op: "jsonRemove", path }, t("remove {path}", { path })) },
    ...(Array.isArray(v) ? [{ label: t("Append Broken Element {where}", { where }), action: () => void addRewrite(detail, part, { op: "jsonAppend", path }, t("broken element in {path}", { path })) }] : []),
  ];
}

/** An element of an XML tree (also SOAP and Atom): copy its text, path or markup. */
export function xmlItems(el: Element, expand: (all: boolean) => void): MenuItem[] {
  return [
    copyItem(t("Copy Text"), el.textContent?.trim() ?? ""),
    copyItem(t("Copy XPath"), xpath(el)),
    copyItem(t("Copy Element as XML"), new XMLSerializer().serializeToString(el)),
    { separator: true },
    { label: t("Expand All"), action: () => expand(true) },
    { label: t("Collapse All"), action: () => expand(false) },
  ];
}
