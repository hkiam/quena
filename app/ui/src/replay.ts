import { api } from "./api";
import { get, say, set } from "./store";
import { actions } from "./actions";
import { plural, t } from "./i18n";

export interface ReplayOptions {
  unconditional?: boolean;
  repeat?: boolean;
  breakpoint?: boolean;
}

export async function replaySelected(o: ReplayOptions) {
  const ids = [...get().selection].sort((a, b) => a - b);
  if (!ids.length) return;
  if (o.repeat) {
    set({ dialog: { kind: "replay", ids } });
    return;
  }
  await startReplay(ids, { unconditional: !!o.unconditional, count: 1, breakpoint: !!o.breakpoint });
}

/** Start a replay; repeats can be stopped from the message. */
export async function startReplay(ids: number[], o: { unconditional?: boolean; count: number; breakpoint?: boolean; sequential?: boolean; parallel?: number }) {
  try {
    const n = await api.replay(ids, o);
    const text = n ? plural(n, "Replaying {n} request", "Replaying {n} requests") : t("Nothing to replay (tunnels cannot be replayed)");
    if (n > 1 && o.count > 1) say(text, "info", { label: t("Stop"), run: () => void stopReplay() });
    else say(text);
  } catch (e) {
    say(String(e), "error");
  }
}

export async function stopReplay() {
  await api.replayStop();
  say(t("Replay stopped (requests on the way still finish)"));
}

export async function toComposer(id?: number) {
  const sid = id ?? get().focusId;
  if (sid == null) return;
  set({ composerLoad: { id: sid, nonce: Date.now() } });
  actions.showTab("composer");
}
