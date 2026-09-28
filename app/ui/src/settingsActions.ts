import { api, type Settings } from "./api";
import { get, say, set } from "./store";

export async function patchSettings(p: (s: Settings) => void) {
  const s = get().settings;
  if (!s) return;
  const next = structuredClone(s);
  p(next);
  set({ settings: next });
  try {
    await api.settingsSet(next);
  } catch (e) {
    say(String(e), "error");
  }
}
