import { api, type SessionSummary } from "../api";
import { confirmAsk, get, say, set } from "../store";
import { rowCache } from "../grid/SessionGrid";
import { actions } from "../actions";
import { t } from "../i18n";

function focused(): SessionSummary | undefined {
  const i = get().focusIndex;
  return i == null ? undefined : rowCache.get(i);
}

function hostOf(r: SessionSummary) {
  const h = r.kind === "tunnel" ? r.url : r.host;
  return h.replace(/:\d+$/, "");
}

export async function filterNow(kind: "hideHost" | "onlyHost" | "hideUrl" | "hideProcess" | "onlyProcess") {
  const r = focused();
  if (!r) return;
  const f = { ...(await api.getFilters()), enabled: true };
  const add = (list: string, v: string) => (list.trim() ? `${list}; ${v}` : v);
  switch (kind) {
    case "hideHost":
      if (f.hostMode === "showOnly") f.hosts = "";
      f.hostMode = "hide";
      f.hosts = add(f.hostMode === "hide" ? f.hosts : "", hostOf(r));
      break;
    case "onlyHost":
      f.hostMode = "showOnly";
      f.hosts = hostOf(r);
      break;
    case "hideUrl":
      f.urlHide = add(f.urlHide, r.url.split("?")[0]);
      break;
    case "hideProcess":
      if (r.process) f.hideProcesses = add(f.hideProcesses, r.process.split(":")[0]);
      break;
    case "onlyProcess":
      if (r.process) f.processOnly = r.process.split(":")[0];
      break;
  }
  await api.setFilters(f);
  set({ filters: f });
  say(t("Filter updated"));
}

export async function selectSimilar(field: "host" | "process" | "url") {
  const r = focused();
  if (!r) return;
  const q = (v: string) => `"${v.replace(/"/g, '\\"')}"`;
  const expr = field === "host" ? `host == ${q(hostOf(r))}` : field === "process" ? `process == ${q(r.process)}` : `url == ${q(r.kind === "tunnel" ? r.url : `${r.protocol.startsWith("HTTPS") || r.protocol === "HTTP/2" ? "https" : "http"}://${r.host}${r.url}`)} and method == ${r.method || "GET"}`;
  await actions.quickexec(`find ${expr}`);
}

/** Keep the focused session's host away from Quena (Settings → Connections → Do not capture). */
export async function bypassHost() {
  const r = focused();
  const st = get().settings;
  if (!r || !st) return;
  const host = hostOf(r).replace(/^\[|\]$/g, "");
  const list = st.proxy.bypassHosts ?? "";
  if (list.split(/[;,\s]+/).some((h) => h.toLowerCase() === host.toLowerCase())) return say(t("{host} is not captured already", { host }));
  if (!(await confirmAsk(t("Do not capture {host}?", { host }), t("Requests to {host} will not go through Quena (system proxy and started browsers). Settings → Connections lists the hosts.", { host }), t("Do not capture")))) return;
  const next = { ...st, proxy: { ...st.proxy, bypassHosts: list.trim() ? `${list.trim()}; ${host}` : host } };
  try {
    await api.settingsSet(next);
    set({ settings: next });
    say(t("{host} is no longer captured", { host }));
  } catch (e) {
    say(String(e), "error");
  }
}
