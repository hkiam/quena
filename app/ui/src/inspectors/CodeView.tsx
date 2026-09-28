// CodeMirror 6 wrapper for small and medium bodies (read-only unless editable).
import { useEffect, useRef } from "react";
import { EditorState, Compartment, type Extension } from "@codemirror/state";
import { EditorView, lineNumbers, highlightActiveLine, keymap, drawSelection } from "@codemirror/view";
import { defaultHighlightStyle, syntaxHighlighting, bracketMatching, foldGutter, foldKeymap } from "@codemirror/language";
import { searchKeymap, highlightSelectionMatches, search } from "@codemirror/search";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { json } from "@codemirror/lang-json";
import { xml } from "@codemirror/lang-xml";
import { html } from "@codemirror/lang-html";
import { javascript } from "@codemirror/lang-javascript";
import { css } from "@codemirror/lang-css";

export type Lang = "json" | "xml" | "html" | "js" | "css" | "text";

export function langFor(contentType: string | null | undefined): Lang {
  const ct = (contentType ?? "").toLowerCase();
  if (ct.includes("json")) return "json";
  if (ct.includes("html")) return "html";
  if (ct.includes("xml") || ct.includes("soap")) return "xml";
  if (ct.includes("javascript") || ct.includes("ecmascript")) return "js";
  if (ct.includes("css")) return "css";
  return "text";
}

function langExt(l: Lang): Extension {
  switch (l) {
    case "json":
      return json();
    case "xml":
      return xml();
    case "html":
      return html();
    case "js":
      return javascript();
    case "css":
      return css();
    default:
      return [];
  }
}

const theme = EditorView.theme({
  "&": { height: "100%", fontSize: "12px", backgroundColor: "var(--panel-bg)", color: "var(--fg)" },
  ".cm-scroller": { fontFamily: "var(--mono)", lineHeight: "1.45" },
  ".cm-gutters": { backgroundColor: "var(--gutter-bg)", color: "var(--muted)", borderRight: "1px solid var(--border)" },
  ".cm-activeLine": { backgroundColor: "var(--active-line)" },
  ".cm-activeLineGutter": { backgroundColor: "var(--active-line)" },
  "&.cm-focused": { outline: "none" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": { backgroundColor: "var(--text-sel) !important" },
  ".cm-searchMatch": { backgroundColor: "var(--search-hit)" },
  ".cm-panels": { backgroundColor: "var(--toolbar-bg)", color: "var(--fg)" },
  ".cm-cursor": { borderLeftColor: "var(--fg)" },
});

export function CodeView({
  text,
  lang = "text",
  wrap = false,
  editable = false,
  highlight = true,
  onChange,
}: {
  text: string;
  lang?: Lang;
  wrap?: boolean;
  editable?: boolean;
  highlight?: boolean;
  onChange?: (t: string) => void;
}) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const comp = useRef({ lang: new Compartment(), wrap: new Compartment(), edit: new Compartment() });
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  useEffect(() => {
    const c = comp.current;
    const state = EditorState.create({
      doc: text,
      extensions: [
        lineNumbers(),
        foldGutter(),
        drawSelection(),
        highlightActiveLine(),
        highlightSelectionMatches(),
        bracketMatching(),
        history(),
        search({ top: true }),
        keymap.of([...searchKeymap, ...foldKeymap, ...defaultKeymap, ...historyKeymap]),
        syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
        c.lang.of(highlight ? langExt(lang) : []),
        c.wrap.of(wrap ? EditorView.lineWrapping : []),
        c.edit.of([EditorState.readOnly.of(!editable), EditorView.editable.of(true)]),
        theme,
        EditorView.updateListener.of((u) => {
          if (u.docChanged && onChangeRef.current) onChangeRef.current(u.state.doc.toString());
        }),
      ],
    });
    view.current = new EditorView({ state, parent: host.current! });
    return () => view.current?.destroy();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const v = view.current;
    if (!v) return;
    if (v.state.doc.toString() !== text) {
      v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: text } });
    }
  }, [text]);

  useEffect(() => {
    view.current?.dispatch({ effects: comp.current.lang.reconfigure(highlight ? langExt(lang) : []) });
  }, [lang, highlight]);
  useEffect(() => {
    view.current?.dispatch({ effects: comp.current.wrap.reconfigure(wrap ? EditorView.lineWrapping : []) });
  }, [wrap]);
  useEffect(() => {
    view.current?.dispatch({ effects: comp.current.edit.reconfigure([EditorState.readOnly.of(!editable), EditorView.editable.of(true)]) });
  }, [editable]);

  return <div className="codeview" ref={host} />;
}
