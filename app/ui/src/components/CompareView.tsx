import { useEffect, useRef } from "react";
import { MergeView } from "@codemirror/merge";
import { EditorView, lineNumbers } from "@codemirror/view";
import { EditorState } from "@codemirror/state";

export function CompareView({ a, b }: { a: string; b: string }) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const ext = [lineNumbers(), EditorState.readOnly.of(true), EditorView.lineWrapping];
    const mv = new MergeView({ a: { doc: a, extensions: ext }, b: { doc: b, extensions: ext }, parent: host.current!, collapseUnchanged: { margin: 3, minSize: 6 } });
    return () => mv.destroy();
  }, [a, b]);
  return <div className="compare" ref={host} />;
}
