// Texts for the codes the core sends about agent conversations: context categories, why the
// prompt cache missed, hints where tokens go to waste, and how a turn differs from the last.
import type { CodeNote, ConvHint, ConvSummary, TurnDiff } from "../api";
import { fmtInt } from "./format";
import { plural, t } from "../i18n";

export const CATEGORIES: Record<string, string> = {
  system: t("System prompt"),
  tools: t("Tool definitions"),
  instructions: t("Instruction files"),
  skills: t("Skills list"),
  reminders: t("Reminders"),
  context: t("Environment"),
  user: t("User messages"),
  assistant: t("Assistant messages"),
  thinking: t("Thinking"),
  toolCalls: t("Tool calls"),
  toolResults: t("Tool results"),
  images: t("Images"),
  other: t("Other"),
};

/** The category's name, with the slice's label (tool, file) when it has one. */
export function sliceName(category: string, label: string): string {
  const c = CATEGORIES[category] ?? category;
  return label ? `${c}: ${label}` : c;
}

const a = (n: CodeNote, k: string) => n.args?.[k] ?? "";
const num = (n: CodeNote, k: string) => fmtInt(Number(n.args?.[k] ?? 0));

export function cacheText(n: CodeNote): string {
  switch (n.code) {
    case "miss":
      return t("Cache missed: {tokens} tokens were processed again without it", { tokens: num(n, "tokens") });
    case "expired":
      return t("Cache expired: {minutes} min since the previous turn (lifetime {ttl} min)", { minutes: a(n, "minutes"), ttl: a(n, "ttl") });
    case "systemChanged":
      return t("The system prompt changed");
    case "toolsChanged":
      return t("The tool definitions changed (+{added} −{removed}, {changed} changed; or their order)", { added: a(n, "added"), removed: a(n, "removed"), changed: a(n, "changed") });
    case "messageChanged":
      return t("Message {n} of {of} changed: everything from it on is new to the cache", { n: a(n, "n"), of: a(n, "of") });
    case "modelChanged":
      return t("The model changed from {from} to {to} (each model has its own cache)", { from: a(n, "from"), to: a(n, "to") });
    case "noMarks":
      return t("The request sets no cache_control breakpoint: Anthropic caches marked prefixes only");
    case "short":
      return t("Shorter than {min} tokens: OpenAI does not cache it", { min: num(n, "min") });
    case "unknown":
      return t("Reason not known (another server, the cache was evicted, or the provider does not report cached tokens)");
    default:
      return n.code;
  }
}

export function hintText(h: ConvHint): string {
  switch (h.code) {
    case "dupResult":
      return t("The same {tool} result is in the context {n} times", { tool: a(h, "tool") || "?", n: a(h, "n") });
    case "bigResult":
      return t("A large {tool} result", { tool: a(h, "tool") || "?" });
    case "repeatCall":
      return t("{tool} called {n} times with the same arguments: {args}", { tool: a(h, "tool") || "?", n: a(h, "n"), args: a(h, "args") });
    case "dupReminder":
      return t("The same reminder {n} times: {text}", { n: a(h, "n"), text: a(h, "text") });
    case "unusedTools":
      return t("{n} of {of} tools never called in {turns} turns: {names}", { n: a(h, "n"), of: a(h, "of"), turns: a(h, "turns"), names: a(h, "names") });
    case "window":
      return t("The context fills {pct} % of the window ({window} tokens)", { pct: a(h, "pct"), window: num(h, "window") });
    case "cacheMisses":
      return t("The cache missed in {n} of {turns} turns", { n: a(h, "n"), turns: a(h, "turns") });
    default:
      return h.code;
  }
}

/** What the tokens of a hint mean. */
export function hintTokens(h: ConvHint): string {
  const n = fmtInt(h.tokens);
  switch (h.code) {
    case "unusedTools":
      return t("{n} tokens in every request", { n });
    case "window":
      return t("{n} tokens input", { n });
    case "cacheMisses":
      return t("{n} tokens without the cache", { n });
    default:
      return t("≈ {n} tokens per request", { n });
  }
}

/** A turn's change from the one before, in a few words. */
export function diffText(d: TurnDiff): string {
  const parts: string[] = [];
  switch (d.kind) {
    case "first":
      parts.push(t("first turn"));
      break;
    case "append":
      parts.push(plural(d.added, "+{n} message", "+{n} messages"));
      break;
    case "same":
      parts.push(t("sent again"));
      break;
    case "changed":
      parts.push(t("message {n} changed", { n: (d.at ?? 0) + 1 }));
      break;
  }
  if (d.systemChanged) parts.push(t("system prompt changed"));
  const tools = (d.toolsAdded?.length ?? 0) + (d.toolsRemoved?.length ?? 0) + (d.toolsChanged?.length ?? 0);
  if (tools || d.toolsReordered) parts.push(t("tools changed"));
  if (d.modelChanged) parts.push(t("model changed"));
  return parts.join(" · ");
}

/** Whether a turn's change breaks the cached prefix. */
export function breaksCache(d: TurnDiff): boolean {
  return d.kind === "changed" || d.systemChanged || d.modelChanged || d.toolsReordered || !!(d.toolsAdded?.length || d.toolsRemoved?.length || d.toolsChanged?.length);
}

/** Conversations in a tree: subagents under the conversation that started them. */
export function convTree(list: ConvSummary[]): { c: ConvSummary; depth: number }[] {
  const keys = new Set(list.map((c) => c.key));
  const kids = new Map<string, ConvSummary[]>();
  for (const c of list) if (c.parent && keys.has(c.parent)) kids.set(c.parent, [...(kids.get(c.parent) ?? []), c]);
  const out: { c: ConvSummary; depth: number }[] = [];
  const seen = new Set<string>();
  const walk = (c: ConvSummary, depth: number) => {
    if (seen.has(c.key)) return;
    seen.add(c.key);
    out.push({ c, depth });
    for (const k of (kids.get(c.key) ?? []).slice().sort((a, b) => a.started - b.started)) walk(k, depth + 1);
  };
  for (const c of list) if (!c.parent || !keys.has(c.parent)) walk(c, 0);
  // A loop of parents (should not happen) still shows every conversation.
  for (const c of list) walk(c, 0);
  return out;
}
