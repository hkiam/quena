// CodeMirror 6 editor behind CodeView (loaded on first use, see CodeView.tsx).
import { useEffect, useRef } from "react";
import { EditorState, Compartment, type Extension } from "@codemirror/state";
import { EditorView, lineNumbers, highlightActiveLine, keymap, drawSelection } from "@codemirror/view";
import { defaultHighlightStyle, syntaxHighlighting, bracketMatching, foldGutter, foldKeymap } from "@codemirror/language";
import { searchKeymap, highlightSelectionMatches, search } from "@codemirror/search";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";

import type { Lang } from "./CodeView";
import { t } from "../i18n";

// CodeMirror's own texts (search panel, folding, go to line).
const phrases = EditorState.phrases.of({
  Find: t("Find"),
  Replace: t("Replace"),
  next: t("next"),
  previous: t("previous"),
  all: t("all"),
  "match case": t("match case"),
  regexp: t("regexp"),
  "by word": t("by word"),
  replace: t("replace"),
  "replace all": t("replace all"),
  close: t("close"),
  "current match": t("current match"),
  "on line": t("on line"),
  "replaced match on line $": t("replaced match on line $"),
  "replaced $ matches": t("replaced $ matches"),
  "Go to line": t("Go to line"),
  go: t("go"),
  "Folded lines": t("Folded lines"),
  "Unfolded lines": t("Unfolded lines"),
  "folded code": t("folded code"),
  unfold: t("unfold"),
  "Fold line": t("Fold line"),
  "Unfold line": t("Unfold line"),
});

// Language packs are loaded on first use, so they are not part of the startup bundle.
const langCache = new Map<Lang, Promise<Extension>>();
function loadLang(l: Lang): Promise<Extension> {
  let p = langCache.get(l);
  if (!p) {
    switch (l) {
      case "json":
        p = import("@codemirror/lang-json").then((m) => m.json());
        break;
      case "xml":
        p = import("@codemirror/lang-xml").then((m) => m.xml());
        break;
      case "html":
        p = import("@codemirror/lang-html").then((m) => m.html());
        break;
      case "js":
        p = import("@codemirror/lang-javascript").then((m) => m.javascript());
        break;
      case "css":
        p = import("@codemirror/lang-css").then((m) => m.css());
        break;
      default:
        p = Promise.resolve([]);
    }
    p = p.catch(() => [] as Extension);
    langCache.set(l, p);
  }
  return p;
}

const theme = EditorView.theme({
  "&": { height: "100%", fontSize: "13px", backgroundColor: "var(--panel-bg)", color: "var(--fg)" },
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
        c.lang.of([]),
        c.wrap.of(wrap ? EditorView.lineWrapping : []),
        c.edit.of([EditorState.readOnly.of(!editable), EditorView.editable.of(true)]),
        theme,
        phrases,
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
    let current = true;
    if (!highlight) {
      view.current?.dispatch({ effects: comp.current.lang.reconfigure([]) });
      return;
    }
    loadLang(lang).then((ext) => {
      if (current) view.current?.dispatch({ effects: comp.current.lang.reconfigure(ext) });
    });
    return () => {
      current = false;
    };
  }, [lang, highlight]);
  useEffect(() => {
    view.current?.dispatch({ effects: comp.current.wrap.reconfigure(wrap ? EditorView.lineWrapping : []) });
  }, [wrap]);
  useEffect(() => {
    view.current?.dispatch({ effects: comp.current.edit.reconfigure([EditorState.readOnly.of(!editable), EditorView.editable.of(true)]) });
  }, [editable]);

  return <div className="codeview" ref={host} />;
}
