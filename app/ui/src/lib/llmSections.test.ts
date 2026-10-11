import { describe, expect, it } from "vitest";
import type { LlmSection } from "../api";
import { CHARS, LINES, cutAt, preview, sectionTitle } from "./llmSections";

const sec = (kind: LlmSection["kind"], label: string, text: string): LlmSection => ({ kind, label, text, tokens: 1 });

describe("prompt sections", () => {
  it("are named by their tag, file or kind", () => {
    expect(sectionTitle(sec("base", "", "You are Codex."))).toBe("Base prompt");
    expect(sectionTitle(sec("skills", "skills_instructions", "<skills_instructions>\n## Skills"))).toBe("Skills");
    expect(sectionTitle(sec("context", "permissions instructions", "<permissions instructions>\nsandbox"))).toBe("Permissions (sandbox and approvals)");
    expect(sectionTitle(sec("instructions", "/repo/CLAUDE.md", "Contents of /repo/CLAUDE.md"))).toBe("/repo/CLAUDE.md");
    expect(sectionTitle(sec("context", "new_tag", "<new_tag>x</new_tag>"))).toBe("<new_tag>");
    // More text in the agent's own role: its first line.
    expect(sectionTitle(sec("prompt", "", "\nYou are `/root`, the primary agent in a team"))).toBe("You are `/root`, the primary agent in a team");
  });

  it("preview the first line that says something", () => {
    expect(preview(sec("skills", "skills_instructions", "<skills_instructions>\n## Skills\nA skill is"))).toBe("## Skills");
    expect(preview(sec("context", "collaboration_mode", "<collaboration_mode># Collaboration Mode: Default\n"))).toBe("# Collaboration Mode: Default");
    expect(preview(sec("reminder", "system-reminder", "<system-reminder>\n</system-reminder>"))).toBe("");
    expect(preview(sec("context", "environment_context", "<environment_context>\n  <cwd>/Users/me</cwd>\n"))).toBe("/Users/me");
    // Not the title again.
    expect(preview(sec("instructions", "AGENTS.md instructions", "# AGENTS.md instructions\n\n<INSTRUCTIONS>\nRun tests."), "AGENTS.md instructions")).toBe("Run tests.");
  });

  it("cut long texts after the first lines, short ones not at all", () => {
    expect(cutAt("short")).toBeNull();
    expect(cutAt("x\n".repeat(LINES + 20))).toBeNull();
    const long = Array.from({ length: 1000 }, (_, i) => `line ${i}`).join("\n");
    const at = cutAt(long)!;
    expect(long.slice(0, at).split("\n")).toHaveLength(LINES);
    expect(cutAt("y".repeat(CHARS * 2))).toBe(CHARS);
  });
});
