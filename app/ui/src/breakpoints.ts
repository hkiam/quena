import { api } from "./api";
import { say } from "./store";

export async function goAll() {
  const n = await api.bpGo();
  say(`Resumed ${n} session(s)`);
}

export async function setAuto(mode: "before" | "after" | "off") {
  const b = await api.bpGet();
  if (mode === "off") {
    b.allRequests = false;
    b.allResponses = false;
  } else if (mode === "before") b.allRequests = !b.allRequests;
  else b.allResponses = !b.allResponses;
  await api.bpSet(b);
  say(mode === "off" ? "Automatic breakpoints disabled" : `Break ${mode === "before" ? "before requests" : "after responses"}: ${mode === "before" ? (b.allRequests ? "on" : "off") : b.allResponses ? "on" : "off"}`);
}
