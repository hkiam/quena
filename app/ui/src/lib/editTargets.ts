// Editors that are not plain inputs (CodeMirror) register here, so the context menu can
// cut, copy, paste and select in them without loading the editor code itself.

export interface EditTarget {
  readOnly(): boolean;
  selectedText(): string;
  selectAll(): void;
  /** Replace the selection (cut: with nothing, paste: with the text). */
  replaceSelection(text: string): void;
  undo(): void;
  redo(): void;
}

const targets = new WeakMap<Element, EditTarget>();

export function registerEditTarget(el: Element, t: EditTarget): () => void {
  targets.set(el, t);
  return () => targets.delete(el);
}

/** The registered editor `node` is in, if any. */
export function editTargetFor(node: Element | null): EditTarget | null {
  for (let el = node; el; el = el.parentElement) {
    const t = targets.get(el);
    if (t) return t;
  }
  return null;
}
