// A CodeMirror view as an edit target for the context menu (see editTargets.ts).
import type { EditorView } from "@codemirror/view";
import { redo, selectAll, undo } from "@codemirror/commands";
import { registerEditTarget } from "./editTargets";

export function registerEditor(view: EditorView): () => void {
  return registerEditTarget(view.dom, {
    readOnly: () => view.state.readOnly,
    selectedText: () =>
      view.state.selection.ranges
        .filter((r) => !r.empty)
        .map((r) => view.state.sliceDoc(r.from, r.to))
        .join("\n"),
    selectAll: () => {
      view.focus();
      selectAll(view);
    },
    replaceSelection: (text) => {
      if (view.state.readOnly) return;
      view.focus();
      view.dispatch(view.state.replaceSelection(text), { userEvent: text ? "input.paste" : "delete.cut", scrollIntoView: true });
    },
    undo: () => void undo(view),
    redo: () => void redo(view),
  });
}
