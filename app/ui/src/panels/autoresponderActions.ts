import { api } from "../api";
import { get, say, set } from "../store";
import { plural, t } from "../i18n";

export async function addRulesFromSelection(exact = false) {
  const ids = [...get().selection].sort((a, b) => a - b);
  if (!ids.length) return;
  const n = await api.arAddSessions(ids, exact);
  say(plural(n, "{n} mock rule added", "{n} mock rules added"));
  set({ activeTab: "autoresponder", arNonce: Date.now() });
}

/** The Mocks dialog (selected or visible sessions). */
export function mocksFromSelection(target?: "apply" | "package" | "wiremock") {
  set({ dialog: { kind: "mocks", selected: [...get().selection].sort((a, b) => a - b), target } });
}

// ---- Quena mock packages (.quena-mocks)

export const isMockPackageName = (name: string) => /\.quena-mocks$/i.test(name);

/** Largest package accepted by drag and drop (sent in one piece). */
const MAX_DROPPED_PACKAGE = 512 << 20;

/** Import dropped package files (added on top of the rules). */
export async function importMockPackageFiles(files: File[]) {
  for (const f of files) {
    if (f.size > MAX_DROPPED_PACKAGE) {
      say(t("{name}: too large to drop, use Import package… instead", { name: f.name }), "error");
      continue;
    }
    try {
      const pkg = await api.mockImportPackageData(f.name, new Uint8Array(await f.arrayBuffer()), false);
      say(t("Package {name}: {n} rules imported", { name: pkg.name, n: pkg.rules }));
    } catch (e) {
      say(`${f.name}: ${e}`, "error");
    }
  }
  set({ activeTab: "autoresponder", arNonce: Date.now() });
}

/** Yes/no question in the app's confirm dialog. */
export function confirmText(title: string, message: string, confirm: string): Promise<boolean> {
  return new Promise((resolve) => set({ dialog: { kind: "confirm", title, message, confirm, resolve } }));
}

// ---- Map Remote / Map Local: plain mock rules built from two small forms.

export type MappingKind = "remote" | "local";

/** A rule (match + action) made by the "Add mapping…" forms, or an error to show. */
export type MappingRule = { match: string; action: string; comment: string } | { error: string };

const hasScheme = (u: string) => /^https?:\/\/[^/?#]+/i.test(u);
// "https://host/api/*" and "https://host/api/" mean the same prefix.
const cleanPrefix = (u: string) => u.trim().replace(/\*+$/, "");

/**
 * Map Remote: everything under `from` goes to `to`, keeping the rest of the path and the query.
 * `noCreds` appends the ` *nocreds` modifier: Cookie and Authorization are removed when the
 * request goes to another host (or from https to http).
 */
export function mapRemoteRule(fromIn: string, toIn: string, noCreds = false): MappingRule {
  const from = cleanPrefix(fromIn);
  let to = cleanPrefix(toIn);
  if (!hasScheme(from)) return { error: t("From must start with http:// or https:// and a host") };
  if (!hasScheme(to)) return { error: t("To must start with http:// or https:// and a host") };
  // Keep the slash in step, so /api/users does not become /v2users.
  if (from.endsWith("/") && !to.endsWith("/") && /^https?:\/\/[^/]+\/./i.test(to)) to += "/";
  return { match: `prefix:${from}`, action: noCreds ? `${to} *nocreds` : to, comment: "Map Remote" };
}

/** Map Local: files under `folder` answer requests under the URL prefix `from`. */
export function mapLocalRule(fromIn: string, folderIn: string): MappingRule {
  const from = cleanPrefix(fromIn);
  const folder = folderIn.trim();
  if (!hasScheme(from)) return { error: t("From must start with http:// or https:// and a host") };
  if (!folder) return { error: t("Choose a folder") };
  if (!/^(\/|[a-zA-Z]:[\\/]|\\\\)/.test(folder)) return { error: t("The folder must be an absolute path") };
  return { match: `prefix:${from}`, action: `dir:${folder}`, comment: "Map Local" };
}
