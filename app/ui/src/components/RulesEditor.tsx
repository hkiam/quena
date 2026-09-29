// Customize Rules (M14): a CodeMirror JS editor for the rules script, with a
// live enable toggle, hot reload on save, a compile-error banner and the
// script's console output.
import { useEffect, useRef, useState } from "react";
import { EditorState } from "@codemirror/state";
import { EditorView, lineNumbers, highlightActiveLine, keymap, drawSelection } from "@codemirror/view";
import { defaultHighlightStyle, syntaxHighlighting, bracketMatching, indentOnInput } from "@codemirror/language";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { closeBrackets, closeBracketsKeymap } from "@codemirror/autocomplete";
import { javascript } from "@codemirror/lang-javascript";
import { api, type ScriptState, type ScriptLog } from "../api";
import { say } from "../store";
import { modKey } from "../lib/format";

const editorTheme = EditorView.theme({
  "&": { height: "100%", fontSize: "12px", backgroundColor: "var(--panel-bg)", color: "var(--fg)" },
  ".cm-scroller": { fontFamily: "var(--mono)", lineHeight: "1.5" },
  ".cm-gutters": { backgroundColor: "var(--gutter-bg)", color: "var(--muted)", borderRight: "1px solid var(--border)" },
  ".cm-activeLine": { backgroundColor: "var(--active-line)" },
  ".cm-activeLineGutter": { backgroundColor: "var(--active-line)" },
  "&.cm-focused": { outline: "none" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": { backgroundColor: "var(--text-sel) !important" },
  ".cm-cursor": { borderLeftColor: "var(--fg)" },
});

export function RulesEditor() {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const [state, setState] = useState<ScriptState | null>(null);
  const [dirty, setDirty] = useState(false);
  const [logs, setLogs] = useState<ScriptLog[]>([]);
  const [showTypes, setShowTypes] = useState(false);
  const saveRef = useRef<() => void>(() => {});

  const save = async () => {
    const v = view.current;
    if (!v) return;
    const src = v.state.doc.toString();
    const s = await api.scriptSet(src);
    setState(s);
    setDirty(false);
    setLogs(await api.scriptLogs());
    if (s.error) say("Rules script has errors — see the editor", "error");
    else say("Rules script saved and reloaded");
  };
  saveRef.current = save;

  // Build the editor once we have the initial source.
  useEffect(() => {
    let cancelled = false;
    api.scriptGet().then((s) => {
      if (cancelled || !host.current) return;
      setState(s);
      const startState = EditorState.create({
        doc: s.source,
        extensions: [
          lineNumbers(),
          highlightActiveLine(),
          drawSelection(),
          history(),
          bracketMatching(),
          closeBrackets(),
          indentOnInput(),
          syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
          javascript(),
          keymap.of([
            { key: "Mod-s", preventDefault: true, run: () => (saveRef.current(), true) },
            indentWithTab,
            ...closeBracketsKeymap,
            ...defaultKeymap,
            ...historyKeymap,
          ]),
          editorTheme,
          EditorView.updateListener.of((u) => {
            if (u.docChanged) setDirty(true);
          }),
        ],
      });
      view.current = new EditorView({ state: startState, parent: host.current });
    });
    return () => {
      cancelled = true;
      view.current?.destroy();
      view.current = null;
    };
  }, []);

  // Poll the script's console output while the editor is open.
  useEffect(() => {
    const t = setInterval(async () => setLogs(await api.scriptLogs()), 1000);
    return () => clearInterval(t);
  }, []);

  const toggleEnabled = async () => {
    const s = await api.scriptSetEnabled(!(state?.enabled ?? false));
    setState(s);
    if (s.enabled && s.error) say("Script enabled but has errors", "error");
  };

  const revert = async () => {
    const s = await api.scriptGet();
    const v = view.current;
    if (v) v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: s.source } });
    setState(s);
    setDirty(false);
  };

  return (
    <div className="rules-editor">
      <div className="rules-toolbar">
        <label className="chk">
          <input type="checkbox" checked={state?.enabled ?? false} onChange={toggleEnabled} /> Enable rules script
        </label>
        <span className={`rules-status ${state?.loaded ? "ok" : "off"}`}>
          {state?.error ? "error" : state?.loaded ? "loaded" : "not loaded"}
        </span>
        <span className="spacer" />
        <button onClick={() => setShowTypes((x) => !x)}>{showTypes ? "Hide API" : "API reference"}</button>
        <button onClick={revert} disabled={!dirty}>
          Revert
        </button>
        <button className="primary" onClick={save} disabled={!dirty}>
          Save &amp; Reload ({modKey}S)
        </button>
      </div>
      {state?.error && <pre className="rules-error">{state.error}</pre>}
      <div className="rules-main">
        <div className="rules-cm" ref={host} />
        {showTypes && <pre className="rules-types">{state?.types ?? ""}</pre>}
      </div>
      <div className="rules-log">
        <div className="rules-log-head">
          Console
          <button
            onClick={async () => {
              await api.scriptClearLogs();
              setLogs([]);
            }}
          >
            Clear
          </button>
        </div>
        <div className="rules-log-body">
          {logs.length === 0 ? (
            <div className="muted">No output. Use console.log() in your script.</div>
          ) : (
            logs.map((l, i) => (
              <div key={i} className={`log-line log-${l.level}`}>
                {l.message}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
