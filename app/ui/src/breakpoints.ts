import { api } from "./api";
import { say } from "./store";
import { plural, t } from "./i18n";

export async function goAll() {
  const n = await api.bpGo();
  say(plural(n, "Resumed {n} session", "Resumed {n} sessions"));
}

/** Break before every LLM request, or no longer (conditions: `bpllm` in the command field). */
export async function toggleLlm() {
  const b = await api.bpGet();
  b.llm = b.llm ? null : { model: "", tool: "", minTokens: 0 };
  await api.bpSet(b);
  say(t("Break before LLM requests: {state}", { state: b.llm ? t("on") : t("off") }));
}

export async function setAuto(mode: "before" | "after" | "off") {
  const b = await api.bpGet();
  if (mode === "off") {
    b.allRequests = false;
    b.allResponses = false;
    b.llm = null;
  } else if (mode === "before") b.allRequests = !b.allRequests;
  else b.allResponses = !b.allResponses;
  await api.bpSet(b);
  const state = (on: boolean) => (on ? t("on") : t("off"));
  say(mode === "off" ? t("Automatic breakpoints disabled") : mode === "before" ? t("Break before requests: {state}", { state: state(b.allRequests) }) : t("Break after responses: {state}", { state: state(b.allResponses) }));
}
