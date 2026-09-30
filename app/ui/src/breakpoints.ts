import { api } from "./api";
import { say } from "./store";
import { plural, t } from "./i18n";

export async function goAll() {
  const n = await api.bpGo();
  say(plural(n, "Resumed {n} session", "Resumed {n} sessions"));
}

export async function setAuto(mode: "before" | "after" | "off") {
  const b = await api.bpGet();
  if (mode === "off") {
    b.allRequests = false;
    b.allResponses = false;
  } else if (mode === "before") b.allRequests = !b.allRequests;
  else b.allResponses = !b.allResponses;
  await api.bpSet(b);
  const state = (on: boolean) => (on ? t("on") : t("off"));
  say(mode === "off" ? t("Automatic breakpoints disabled") : mode === "before" ? t("Break before requests: {state}", { state: state(b.allRequests) }) : t("Break after responses: {state}", { state: state(b.allResponses) }));
}
