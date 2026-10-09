// Rule templates: common changes in one click (rewrite rules, and a mock rule where an answer
// is needed), added as a group of their own so they can be switched off together.
import { api, type ArRule, type RwOp, type RwRule } from "../api";
import { confirmAsk, promptText, say, set } from "../store";
import { t } from "../i18n";

export interface Template {
  key: string;
  label: string;
  /** Asked for before adding: what `arg` holds. */
  ask?: { title: string; label: string; initial: string };
  rewrite: (arg: string) => { match: string; phase: RwRule["phase"]; status?: string; ops: RwOp[] }[];
  mock?: (arg: string) => { match: string; action: string }[];
}

export const TEMPLATES: Template[] = [
  {
    key: "cors",
    label: t("Bypass CORS"),
    rewrite: () => [
      {
        match: "*",
        phase: "response",
        ops: [
          { op: "setHeader", name: "Access-Control-Allow-Origin", value: "*" },
          { op: "setHeader", name: "Access-Control-Allow-Methods", value: "*" },
          { op: "setHeader", name: "Access-Control-Allow-Headers", value: "*" },
          { op: "setHeader", name: "Access-Control-Expose-Headers", value: "*" },
        ],
      },
    ],
    mock: () => [{ match: "METHOD:OPTIONS *", action: "*CORSPreflightAllow" }],
  },
  {
    key: "no-cookies",
    label: t("Block cookies"),
    rewrite: () => [
      { match: "*", phase: "request", ops: [{ op: "removeHeader", name: "Cookie" }] },
      { match: "*", phase: "response", ops: [{ op: "removeCookie", name: "*" }] },
    ],
  },
  {
    key: "no-cache",
    label: t("Disable caching"),
    rewrite: () => [
      {
        match: "*",
        phase: "request",
        ops: [
          { op: "removeHeader", name: "If-None-Match" },
          { op: "removeHeader", name: "If-Modified-Since" },
          { op: "setHeader", name: "Cache-Control", value: "no-cache" },
          { op: "setHeader", name: "Pragma", value: "no-cache" },
        ],
      },
      {
        match: "*",
        phase: "response",
        ops: [
          { op: "setHeader", name: "Cache-Control", value: "no-store" },
          { op: "removeHeader", name: "ETag" },
          { op: "removeHeader", name: "Last-Modified" },
          { op: "removeHeader", name: "Expires" },
        ],
      },
    ],
  },
  {
    key: "user-agent",
    label: t("Change User-Agent…"),
    ask: { title: t("Change User-Agent"), label: t("User-Agent to send"), initial: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1" },
    rewrite: (ua) => [{ match: "*", phase: "request", ops: [{ op: "setHeader", name: "User-Agent", value: ua }] }],
  },
  {
    key: "mark-errors",
    label: t("Mark errors red"),
    rewrite: () => [{ match: "*", phase: "response", status: "400-599", ops: [{ op: "mark", color: "red" }] }],
  },
  {
    key: "block-host",
    label: t("Block a host…"),
    ask: { title: t("Block a host"), label: t("Host (requests to it are answered with 404)"), initial: "ads.example.com" },
    rewrite: () => [],
    mock: (host) => [{ match: `regex:(?i)^https?://([^/]*\\.)?${host.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(:\\d+)?(/|$)`, action: "*404" }],
  },
  {
    key: "only-host",
    label: t("Allow only one host…"),
    ask: { title: t("Allow only one host"), label: t("Host (requests whose URL does not contain it are dropped)"), initial: "api.example.com" },
    rewrite: () => [],
    // NOT: takes a part of the URL.
    mock: (host) => [{ match: `NOT:${host}`, action: "*drop" }],
  },
];

/** Add template `tpl` (asking for its value first, if it needs one). */
export async function addTemplate(tpl: Template) {
  let arg = "";
  if (tpl.ask) {
    const v = await promptText(tpl.ask.title, tpl.ask.label, tpl.ask.initial);
    if (!v?.trim()) return;
    arg = v.trim();
  }
  const group = tpl.label.replace(/…$/, "") + (arg ? `: ${arg}` : "");
  try {
    const rw = tpl.rewrite(arg);
    if (rw.length) {
      const state = await api.rwGet();
      const rules: RwRule[] = rw.map((r) => ({ id: 0, enabled: true, match: r.match, phase: r.phase, status: r.status ?? "", contentType: "", ops: r.ops, comment: group, group, hits: 0 }));
      await api.rwSet({ ...state, enabled: true, rules: [...state.rules, ...rules] });
    }
    const mocks = tpl.mock?.(arg) ?? [];
    if (mocks.length) {
      const ar = await api.arGet();
      const rules: ArRule[] = mocks.map((m) => ({ id: 0, enabled: true, match: m.match, action: m.action, latencyMs: 0, matchOnce: false, comment: group, hits: 0 }));
      // Mock rules that are off would not answer; turning them on also turns on the others.
      const others = ar.rules.filter((r) => r.enabled).length;
      const on = ar.enabled || !others || (await confirmAsk(t("Turn on Mock Rules?"), t("The template needs Mock Rules on; this also turns on the {n} other active mock rule(s).", { n: others }), t("Turn on")));
      await api.arSet({ ...ar, enabled: on, rules: [...rules, ...ar.rules] });
      if (!on) say(t("Added; Mock Rules stay off until they are turned on"));
    }
    set({ arNonce: Date.now() });
    say(t("Template added: {name}", { name: group }));
  } catch (e) {
    say(String(e), "error");
  }
}
