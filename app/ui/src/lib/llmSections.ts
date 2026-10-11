// The prompt parts of an LLM call as the LLM view names them: titles, kinds, a preview line, and
// where a long text is cut until "Show all".
import type { LlmSection } from "../api";
import { t } from "../i18n";

/** Lines (and characters) of a text shown before "Show all": one scroll area for the whole
 * view instead of a scroll box per text. */
export const LINES = 300;
export const CHARS = 30000;

/** Where `text` is cut until "Show all" (`null`: shown whole; a little over the limit is not
 * worth a button). */
export function cutAt(text: string): number | null {
  if (text.length <= CHARS && text.split("\n", LINES + 51).length <= LINES + 50) return null;
  let end = -1;
  for (let n = 0; n < LINES; n++) {
    end = text.indexOf("\n", end + 1);
    if (end < 0) break;
  }
  return Math.min(end < 0 ? text.length : end, CHARS);
}

export const KIND: Record<LlmSection["kind"], string> = {
  base: t("agent prompt"),
  prompt: t("agent prompt"),
  text: t("written"),
  instructions: t("instructions file"),
  skills: t("skills"),
  context: t("context"),
  reminder: t("reminder"),
  summary: t("summary"),
};

/** Names of the tags agents put around what they add. */
const TAG_TITLE: Record<string, string> = {
  skills_instructions: t("Skills"),
  "permissions instructions": t("Permissions (sandbox and approvals)"),
  collaboration_mode: t("Collaboration mode"),
  apps_instructions: t("Apps (connectors)"),
  plugins_instructions: t("Plugins"),
  recommended_plugins: t("Recommended plugins"),
  multi_agent_mode: t("Multi-agent mode"),
  model_switch: t("Model switch"),
  environment_context: t("Environment"),
  environment_details: t("Environment"),
  ide_opened_file: t("File open in the IDE"),
  ide_selection: t("Selection in the IDE"),
  "system-reminder": t("Reminder"),
  "command-name": t("Slash command"),
  "command-args": t("Slash command arguments"),
  "local-command-stdout": t("Command output"),
  "local-command-stderr": t("Command errors"),
  "bash-input": t("Shell command"),
  "bash-stdout": t("Shell output"),
  "bash-stderr": t("Shell errors"),
  user_shell_command: t("Shell command"),
  current_time_reminder: t("Current time"),
  turn_aborted: t("Turn aborted"),
};

/** The first line of the text that says something, without tags (and other than `skip`, the
 * title): what a collapsed section shows of itself. */
export function preview(s: LlmSection, skip = ""): string {
  for (const l of s.text.split("\n")) {
    const x = l.replace(/<\/?[\w -]+>/g, " ").replace(/\s+/g, " ").trim();
    if (x && x.replace(/^#+\s*/, "") !== skip) return x.slice(0, 140);
  }
  return "";
}

export function sectionTitle(s: LlmSection): string {
  switch (s.kind) {
    case "base":
      return t("Base prompt");
    case "skills":
      return t("Skills");
    case "summary":
      return t("Summary of the earlier conversation");
    case "instructions":
      return s.label || t("Instructions");
    case "prompt":
      return preview(s).slice(0, 60) || t("Prompt text");
    default:
      return TAG_TITLE[s.label] ?? (s.label ? `<${s.label}>` : t("Note"));
  }
}
