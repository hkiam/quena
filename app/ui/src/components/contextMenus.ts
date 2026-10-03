// Right-clicks everywhere: views with a menu of their own show it (and prevent the default);
// everywhere else Quena shows an Edit menu in text fields and editors, Copy for selected
// text, and nothing otherwise — never the browser's menu (Reload, Inspect Element …).
// While developing (`npm run dev` / `tauri dev`), Shift+right-click still opens the
// browser's menu.
import { showContextMenu, type MenuItem } from "./ContextMenu";
import { copyText } from "../actions";
import { isTauri } from "../api";
import { editTargetFor, type EditTarget } from "../lib/editTargets";
import { modKey } from "../lib/format";
import { t } from "../i18n";

export async function readClipboard(): Promise<string> {
  if (isTauri) {
    const { readText } = await import("@tauri-apps/plugin-clipboard-manager");
    return (await readText()) ?? "";
  }
  return navigator.clipboard.readText();
}

const TEXT_INPUTS = new Set(["text", "search", "url", "email", "tel", "password", ""]);

/** An input or textarea whose text can be selected and edited. */
export function textField(el: Element | null): HTMLInputElement | HTMLTextAreaElement | null {
  const f = el?.closest("input, textarea");
  if (f instanceof HTMLTextAreaElement) return f;
  if (f instanceof HTMLInputElement && TEXT_INPUTS.has(f.type)) return f;
  return null;
}

const keys = (k: string) => `${modKey}${k}`;

/** Undo, Cut, Copy, Paste, Select All for an input or textarea. */
export function fieldMenu(f: HTMLInputElement | HTMLTextAreaElement): MenuItem[] {
  const [s, e] = [f.selectionStart ?? 0, f.selectionEnd ?? 0];
  const selected = f.value.slice(s, e);
  const secret = f instanceof HTMLInputElement && f.type === "password";
  const editable = !f.readOnly && !f.disabled;
  // Through execCommand, so the change lands in the field's undo history and fires `input`.
  const replace = (text: string) => {
    f.focus();
    f.setSelectionRange(s, e);
    if (!document.execCommand(text ? "insertText" : "delete", false, text)) {
      f.setRangeText(text, s, e, "end");
      f.dispatchEvent(new Event("input", { bubbles: true }));
    }
  };
  const run = (cmd: string) => () => {
    f.focus();
    document.execCommand(cmd);
  };
  return [
    { label: t("Undo"), shortcut: keys("Z"), disabled: !editable, action: run("undo") },
    { label: t("Redo"), shortcut: keys("⇧Z"), disabled: !editable, action: run("redo") },
    { separator: true },
    { label: t("Cut"), shortcut: keys("X"), disabled: !editable || !selected || secret, action: () => void copyText(selected).then(() => replace("")) },
    { label: t("Copy"), shortcut: keys("C"), disabled: !selected || secret, action: () => void copyText(selected) },
    { label: t("Paste"), shortcut: keys("V"), disabled: !editable, action: () => void readClipboard().then((text) => text && replace(text)) },
    { separator: true },
    {
      label: t("Select All"),
      shortcut: keys("A"),
      disabled: !f.value,
      action: () => {
        f.focus();
        f.select();
      },
    },
  ];
}

/** The same for an editor (CodeMirror). */
export function editorMenu(ed: EditTarget): MenuItem[] {
  const selected = ed.selectedText();
  const editable = !ed.readOnly();
  const items: MenuItem[] = [];
  if (editable)
    items.push(
      { label: t("Undo"), shortcut: keys("Z"), action: () => ed.undo() },
      { label: t("Redo"), shortcut: keys("⇧Z"), action: () => ed.redo() },
      { separator: true },
      { label: t("Cut"), shortcut: keys("X"), disabled: !selected, action: () => void copyText(selected).then(() => ed.replaceSelection("")) },
    );
  items.push({ label: t("Copy"), shortcut: keys("C"), disabled: !selected, action: () => void copyText(selected) });
  if (editable) items.push({ label: t("Paste"), shortcut: keys("V"), action: () => void readClipboard().then((text) => text && ed.replaceSelection(text)) });
  items.push({ separator: true }, { label: t("Select All"), shortcut: keys("A"), action: () => ed.selectAll() });
  return items;
}

/** Text selected in the page (outside fields and editors) under `target`'s view. */
function selectedText(): string {
  const sel = window.getSelection();
  return sel && !sel.isCollapsed ? sel.toString() : "";
}

/** The menu for a right-click nobody handled: Edit in fields and editors, Copy for a
 * selection, else none. */
export function defaultMenu(target: Element | null): MenuItem[] {
  const f = textField(target);
  if (f) return fieldMenu(f);
  const ed = editTargetFor(target);
  if (ed) return editorMenu(ed);
  const text = selectedText();
  if (text) return [{ label: t("Copy"), shortcut: keys("C"), action: () => void copyText(text) }];
  return [];
}

/** Menu items followed by a separator and the Edit items of a selection, if there is one:
 * for views with their own menu that also show selectable text. */
export function withSelection(items: MenuItem[], target: Element | null): MenuItem[] {
  const edit = defaultMenu(target);
  return edit.length ? [...edit, { separator: true }, ...items] : items;
}

/** Show `items` for a right-click (React handler); nothing when the list is empty. */
export function openMenu(e: { clientX: number; clientY: number; preventDefault(): void }, items: MenuItem[]) {
  e.preventDefault();
  if (items.length) showContextMenu(e.clientX, e.clientY, items);
}

export function installContextMenus() {
  document.addEventListener("contextmenu", (e) => {
    if (e.defaultPrevented) return; // a view showed its own menu
    if (import.meta.env.DEV && e.shiftKey) return; // the browser's, for Inspect Element
    e.preventDefault();
    const items = defaultMenu(e.target instanceof Element ? e.target : null);
    if (items.length) showContextMenu(e.clientX, e.clientY, items);
  });
}
