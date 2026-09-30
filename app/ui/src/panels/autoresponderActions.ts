import { api } from "../api";
import { get, say, set } from "../store";

export async function addRulesFromSelection(exact = false) {
  const ids = [...get().selection].sort((a, b) => a - b);
  if (!ids.length) return;
  const n = await api.arAddSessions(ids, exact);
  say(`${n} AutoResponder rule(s) added`);
  set({ activeTab: "autoresponder", arNonce: Date.now() });
}

// ---- Map Remote / Map Local: plain mock rules built from two small forms.

export type MappingKind = "remote" | "local";

/** A rule (match + action) made by the "Add mapping…" forms, or an error to show. */
export type MappingRule = { match: string; action: string; comment: string } | { error: string };

const hasScheme = (u: string) => /^https?:\/\/[^/?#]+/i.test(u);
// "https://host/api/*" and "https://host/api/" mean the same prefix.
const cleanPrefix = (u: string) => u.trim().replace(/\*+$/, "");

/** Map Remote: everything under `from` goes to `to`, keeping the rest of the path and the query. */
export function mapRemoteRule(fromIn: string, toIn: string): MappingRule {
  const from = cleanPrefix(fromIn);
  let to = cleanPrefix(toIn);
  if (!hasScheme(from)) return { error: "From must start with http:// or https:// and a host" };
  if (!hasScheme(to)) return { error: "To must start with http:// or https:// and a host" };
  // Keep the slash in step, so /api/users does not become /v2users.
  if (from.endsWith("/") && !to.endsWith("/") && /^https?:\/\/[^/]+\/./i.test(to)) to += "/";
  return { match: `prefix:${from}`, action: to, comment: "Map Remote" };
}

/** Map Local: files under `folder` answer requests under the URL prefix `from`. */
export function mapLocalRule(fromIn: string, folderIn: string): MappingRule {
  const from = cleanPrefix(fromIn);
  const folder = folderIn.trim();
  if (!hasScheme(from)) return { error: "From must start with http:// or https:// and a host" };
  if (!folder) return { error: "Choose a folder" };
  if (!/^(\/|[a-zA-Z]:[\\/]|\\\\)/.test(folder)) return { error: "The folder must be an absolute path" };
  return { match: `prefix:${from}`, action: `dir:${folder}`, comment: "Map Local" };
}
