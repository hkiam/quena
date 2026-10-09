import { api } from "../api";
import { get, set } from "../store";
import { rawRequestText, rawResponseHead } from "../lib/http";
import { loadText } from "../lib/bodytext";

export async function compareSelected() {
  const ids = [...get().selection].sort((a, b) => a - b);
  if (ids.length !== 2) return;
  await compareSessions(ids[0], ids[1]);
}

/** The text diff of two sessions (request and response, side by side). */
export async function compareSessions(idA: number, idB: number) {
  const [a, b] = await Promise.all([idA, idB].map((id) => api.detail(id)));
  if (!a || !b) return;
  const text = async (d: NonNullable<typeof a>) => {
    const req = await loadText(d.summary.id, "request", d.requestBody, 256 * 1024);
    const resp = d.response ? await loadText(d.summary.id, "response", d.responseBody, 256 * 1024) : "";
    return rawRequestText(d, req) + "\n\n" + rawResponseHead(d) + resp;
  };
  const [ta, tb] = await Promise.all([text(a), text(b)]);
  set({ dialog: { kind: "compare", a: ta, b: tb, titleA: `#${a.summary.id}`, titleB: `#${b.summary.id}` } });
}
