import { api } from "../api";
import { get, say, set } from "../store";

export async function addRulesFromSelection(exact = false) {
  const ids = [...get().selection].sort((a, b) => a - b);
  if (!ids.length) return;
  const n = await api.arAddSessions(ids, exact);
  say(`${n} AutoResponder rule(s) added`);
  set({ activeTab: "autoresponder", arNonce: Date.now() });
}
