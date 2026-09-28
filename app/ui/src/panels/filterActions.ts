import { api, type SessionSummary } from "../api";
import { get, say, set } from "../store";
import { rowCache } from "../grid/SessionGrid";
import { actions } from "../actions";

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
  say("Filter updated");
}

export async function selectSimilar(field: "host" | "process" | "url") {
  const r = focused();
  if (!r) return;
  const q = (v: string) => `"${v.replace(/"/g, '\\"')}"`;
  const expr = field === "host" ? `host == ${q(hostOf(r))}` : field === "process" ? `process == ${q(r.process)}` : `url == ${q(r.kind === "tunnel" ? r.url : `${r.protocol.startsWith("HTTPS") || r.protocol === "HTTP/2" ? "https" : "http"}://${r.host}${r.url}`)} and method == ${r.method || "GET"}`;
  await actions.quickexec(`find ${expr}`);
}
