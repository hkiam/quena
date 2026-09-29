// Header inspector plugin results: the plugin API delivers a flattened tree
// (`depth` = nesting level, see wit/plugin.wit); this rebuilds it for rendering.
import type { InspectNode } from "../api";

export interface InspectSection {
  title: string;
  fields: [string, string][];
  notes: string[];
  code: { caption: string; text: string }[];
  children: InspectSection[];
}

const section = (title: string): InspectSection => ({ title, fields: [], notes: [], code: [], children: [] });

/**
 * Sections open at their `depth`; fields, notes and code belong to the nearest
 * open section at or above their depth. Content before any section (or deeper
 * than the open sections) is attached to the deepest open section, or to an
 * untitled top-level section.
 */
export function nodesToTree(nodes: InspectNode[]): InspectSection[] {
  const roots: InspectSection[] = [];
  const stack: InspectSection[] = [];
  const container = (depth: number): InspectSection => {
    if (stack.length === 0) {
      const s = section("");
      roots.push(s);
      stack.push(s);
    }
    return stack[Math.min(depth, stack.length - 1)];
  };
  for (const n of nodes) {
    if (n.kind === "section") {
      const d = Math.min(n.depth, stack.length);
      stack.length = d;
      const s = section(n.name);
      (d === 0 ? roots : stack[d - 1].children).push(s);
      stack.push(s);
    } else if (n.kind === "field") container(n.depth).fields.push([n.name, n.value]);
    else if (n.kind === "note") container(n.depth).notes.push(n.value);
    else container(n.depth).code.push({ caption: n.name, text: n.value });
  }
  return roots;
}
