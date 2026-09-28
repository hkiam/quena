import { api } from "./api";
import { get, promptText, say, set } from "./store";
import { actions } from "./actions";

export interface ReplayOptions {
  unconditional?: boolean;
  repeat?: boolean;
  breakpoint?: boolean;
}

export async function replaySelected(o: ReplayOptions) {
  const ids = [...get().selection].sort((a, b) => a - b);
  if (!ids.length) return;
  let count = 1;
  if (o.repeat) {
    const v = await promptText("Reissue Sequentially", "Repeat count", "5");
    if (!v) return;
    count = Math.max(1, Math.min(10000, Number(v) || 1));
  }
  try {
    const n = await api.replay(ids, { unconditional: !!o.unconditional, count, breakpoint: !!o.breakpoint, sequential: count > 1 });
    say(n ? `Replaying ${n} request(s)` : "Nothing to replay (tunnels cannot be replayed)");
  } catch (e) {
    say(String(e), "error");
  }
}

export async function toComposer(id?: number) {
  const sid = id ?? get().focusId;
  if (sid == null) return;
  set({ composerLoad: { id: sid, nonce: Date.now() } });
  actions.showTab("composer");
}
