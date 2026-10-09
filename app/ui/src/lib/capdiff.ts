// Comparing captures: labels and the Markdown summary (for a ticket or a pull request).
import type { CaptureDiff, DiffEntry } from "../api";
import { t } from "../i18n";

export const MARK: Record<DiffEntry["kind"], string> = { changed: "~", added: "+", removed: "−", same: "=" };

/** `200 → 500`, or the one status there is. */
export function statusText(e: DiffEntry): string {
  if (e.statusA != null && e.statusB != null && e.statusA !== e.statusB) return `${e.statusA} → ${e.statusB}`;
  return String(e.statusB ?? e.statusA ?? "");
}

export function toMarkdown(d: CaptureDiff, a: string, b: string, all = false): string {
  const c = d.counts;
  const head = `## ${a} → ${b}\n\n${t("{changed} changed · {added} new · {removed} gone · {same} same", { changed: c.changed, added: c.added, removed: c.removed, same: c.same })}${c.newErrors ? ` · **${t("{n} now fail", { n: c.newErrors })}**` : ""}\n\n`;
  const rows = d.entries
    .filter((e) => all || e.kind !== "same")
    .map((e) => `| ${MARK[e.kind]} | \`${e.method} ${e.key.replace(/\|/g, "\\|")}\` | ${statusText(e)} | ${e.changes.join("; ").replace(/\|/g, "\\|")} |`);
  return `${head}| | ${t("Request")} | Status | ${t("Changes")} |\n|---|---|---|---|\n${rows.join("\n")}\n`;
}
