// Central command dispatcher shared by menu, toolbar, keyboard, context menu
// and the command field. Every action returns immediately (optimistic UI, R11); the
// core confirms asynchronously.
import { api, isTauri, type Detail, type GroupBy, type NavScope, type MarkColor, type SessionId, type Sort } from "./api";
import { confirmAsk, get, say, set, PRESETS, type LayoutPreset, type RightTab } from "./store";
import { grid, idAtIndex, rowCache } from "./grid/SessionGrid";
import { buildCurl, buildFetch, buildPowerShell, buildPython, rawRequestText, rawResponseHead } from "./lib/http";
import { plural, t } from "./i18n";

const MARKS: MarkColor[] = ["red", "blue", "gold", "green", "orange", "purple"];

export async function copyText(text: string) {
  try {
    // Through the app under Tauri: works after an await too (WebKit drops the user gesture).
    if (isTauri) await (await import("@tauri-apps/plugin-clipboard-manager")).writeText(text);
    else await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
}

async function details(ids: SessionId[], limit = 200): Promise<Detail[]> {
  const out: Detail[] = [];
  for (const id of ids.slice(0, limit)) {
    const d = await api.detail(id);
    if (d) out.push(d);
  }
  return out;
}

/** Ask before sessions are removed (removal cannot be undone). */
function confirmRemove(title: string): Promise<boolean> {
  return confirmAsk(title, t("They are removed from the list and from the recorded data. This cannot be undone."), t("Remove"));
}

/** Narrowing changes in flight, run in order (see `actions.setScope`). */
let scopeChain: Promise<unknown> = Promise.resolve();
let scopePending = 0;

export const actions = {
  // ---------------------------------------------------------------- selection
  async selectIndex(i: number, mode: "single" | "toggle" | "range") {
    const id = await idAtIndex(i);
    if (id === undefined) return;
    const s = get();
    if (mode === "single") {
      set({ selection: new Set([id]), focusIndex: i, focusId: id, anchorIndex: i });
    } else if (mode === "toggle") {
      const sel = new Set(s.selection);
      if (sel.has(id)) sel.delete(id);
      else sel.add(id);
      set({ selection: sel, focusIndex: i, focusId: id, anchorIndex: i });
    } else {
      const a = s.anchorIndex ?? i;
      const [lo, hi] = a < i ? [a, i] : [i, a];
      const ids = rowCache.idsIfCached(lo, hi) ?? (await api.viewIds(lo, hi - lo + 1));
      set({ selection: new Set(ids), focusIndex: i, focusId: id });
    }
    grid.scrollToIndex(i);
  },

  clearSelection() {
    set({ selection: new Set(), focusId: null, focusIndex: null });
  },

  async selectIds(ids: SessionId[]) {
    if (!ids.length) {
      actions.clearSelection();
      return;
    }
    const first = ids[0];
    const pos = await api.positionOf(first);
    set({ selection: new Set(ids), focusId: first, focusIndex: pos, anchorIndex: pos });
    if (pos != null) grid.scrollToIndex(pos, "center");
  },

  async selectAll() {
    const total = get().listTotal;
    const ids = await api.viewIds(0, total);
    set({ selection: new Set(ids) });
  },

  async moveFocus(delta: number | "home" | "end", extend: boolean) {
    const s = get();
    const total = s.listTotal;
    if (!total) return;
    let i: number;
    if (delta === "home") i = 0;
    else if (delta === "end") i = total - 1;
    else i = Math.max(0, Math.min(total - 1, (s.focusIndex ?? (delta > 0 ? -1 : total)) + delta));
    await actions.selectIndex(i, extend ? "range" : "single");
  },

  /** Keep focus/selection stable when the view changes (sort/filter). */
  async refocus() {
    const id = get().focusId;
    if (id == null) return;
    const pos = await api.positionOf(id);
    set({ focusIndex: pos });
    if (pos != null) grid.scrollToIndex(pos, "center");
  },

  // ------------------------------------------------------------------- view
  showTab(tab: RightTab) {
    set({ activeTab: tab });
  },

  async setSort(sort: Sort) {
    set({ sort });
    await api.setSort(sort);
    setTimeout(() => actions.refocus(), 80);
  },

  /** Group the session list (kept with the layout). */
  async setGroup(groupBy: GroupBy) {
    // A navigator group of the old group-by means nothing under the new one.
    const scope = get().scope?.scope;
    if (scope?.kind === "group" && scope.by !== groupBy) await actions.setScope(null);
    set((s) => ({ layout: { ...s.layout, groupBy } }));
    actions.saveLayout();
    await api.setGroup(groupBy);
    setTimeout(() => actions.refocus(), 80);
  },

  /** Narrow the list to a navigator group or path (`null`: all sessions again). Changes run
   * one after the other, so a quick click and "show all" (or hiding the navigator) end with
   * the last one, in the backend and in the list. */
  async setScope(scope: NavScope | null, label = "") {
    if (!scope && !get().scope && scopePending === 0) return; // nothing to widen: keep the list as it is
    scopePending++;
    const run = scopeChain.then(async () => {
      await api.setScope(scope);
      set({ scope: scope ? { scope, label } : null });
      rowCache.clear();
      set((s) => ({ gridNonce: s.gridNonce + 1 }));
    });
    scopeChain = run.catch(() => {});
    try {
      await run;
    } finally {
      scopePending--;
    }
  },

  /** Show or hide the navigator (`mode`: also switch it to structure or groups). */
  showNavigator(open: boolean, mode?: "structure" | "groups") {
    set((s) => ({ layout: { ...s.layout, navOpen: open, ...(mode ? { navMode: mode } : {}) } }));
    actions.saveLayout();
    // Hidden, it must not keep narrowing the list unseen (also a narrowing still on its way).
    if (!open && (get().scope || scopePending > 0)) void actions.setScope(null);
  },

  /** Collapse or expand the group of the row at a list position. */
  async toggleGroupAt(index: number) {
    const r = rowCache.get(index);
    if (r) await api.toggleGroup(r.id);
  },

  async collapseGroups(collapse: boolean) {
    await api.collapseGroups(collapse);
  },

  /** Select all sessions of the focused session's group. */
  async selectGroup() {
    const s = get();
    const id = s.focusId ?? [...s.selection][0];
    if (id == null) return;
    await actions.selectIds(await api.groupIds(id));
  },

  resetColumns() {
    set((s) => ({ layout: { ...s.layout, columns: PRESETS[s.layout.preset].columns } }));
    actions.saveLayout();
  },

  /** Switch the arrangement (list/inspector split, stacking, columns) to a preset. */
  applyLayoutPreset(preset: LayoutPreset) {
    set((s) => ({ layout: { ...s.layout, ...PRESETS[preset], columns: [...PRESETS[preset].columns], preset } }));
    rowCache.clear();
    set((s) => ({ gridNonce: s.gridNonce + 1 }));
    actions.saveLayout();
  },

  saveLayout() {
    window.clearTimeout((actions as any)._layoutTimer);
    (actions as any)._layoutTimer = window.setTimeout(() => {
      api.saveUiPrefs({ layout: get().layout }).catch(() => {});
    }, 400);
  },

  // ---------------------------------------------------------------- editing
  async removeSelected() {
    const ids = [...get().selection];
    if (!ids.length) return;
    const ok = await confirmRemove(plural(ids.length, "Remove {n} session?", "Remove {n} sessions?"));
    if (!ok) return;
    const fi = get().focusIndex;
    set({ selection: new Set(), focusId: null });
    await api.remove(ids);
    // Select the row that took the place of the first removed one.
    if (fi != null) setTimeout(() => actions.selectIndex(Math.min(fi, Math.max(0, get().listTotal - 1)), "single"), 60);
  },

  async removeUnselected() {
    const ids = [...get().selection];
    const n = Math.max(0, get().listCount - ids.length);
    if (!n) return;
    const ok = await confirmRemove(plural(n, "Remove {n} unselected session?", "Remove {n} unselected sessions?"));
    if (!ok) return;
    await api.removeExcept(ids);
  },

  async removeAll() {
    const n = get().listCount;
    if (!n) return;
    const ok = await confirmRemove(plural(n, "Remove {n} session?", "Remove all {n} sessions?"));
    if (!ok) return;
    await actions.clearSessions();
    say(t("All sessions removed"));
  },

  /** Remove every session, without asking. */
  async clearSessions() {
    set({ selection: new Set(), focusId: null, focusIndex: null });
    rowCache.clear();
    await api.removeAll();
  },

  async mark(color: MarkColor | null) {
    const ids = [...get().selection];
    if (!ids.length) return;
    await api.mark(ids, color);
    set((s) => ({ gridNonce: s.gridNonce + 1 }));
  },

  comment() {
    const ids = [...get().selection];
    if (!ids.length) return;
    const fid = get().focusId;
    const r = fid != null ? findCached(fid) : undefined;
    set({ dialog: { kind: "comment", ids, initial: r?.comment ?? "" } });
  },

  async setComment(ids: SessionId[], text: string) {
    await api.comment(ids, text);
    set((s) => ({ gridNonce: s.gridNonce + 1 }));
  },

  /** Run a script-registered menu command over the current selection. */
  async runScriptMenu(index: number) {
    const ids = [...get().selection];
    if (!ids.length) return;
    try {
      const n = await api.scriptRunMenu(index, ids);
      rowCache.clear();
      set((s) => ({ gridNonce: s.gridNonce + 1 }));
      if (n > 0) say(plural(n, "Script updated {n} session", "Script updated {n} sessions"));
    } catch (err) {
      say(t("Script command failed: {error}", { error: String(err) }), "error");
    }
  },

  /** Refresh the cached list of script-registered menu commands. */
  async refreshScriptMenus() {
    try {
      set({ scriptMenus: await api.scriptMenus() });
    } catch {
      set({ scriptMenus: [] });
    }
  },

  async copySessions(kind: "url" | "summary" | "headers" | "full" | "curl" | "fetch" | "powershell" | "python") {
    const ids = [...get().selection].sort((a, b) => a - b);
    if (!ids.length) return;
    const ds = await details(ids);
    let text = "";
    switch (kind) {
      case "url":
        text = ds.map((d) => d.request.url).join("\n");
        break;
      case "summary":
        text = ds
          .map((d) => {
            const r = d.response;
            const ct = d.summary.contentType ? ` (${d.summary.contentType})` : "";
            return `${d.request.method} ${d.request.url}\n${r ? `${r.status} ${r.reason}` : "(no response)"}${ct}`;
          })
          .join("\n\n");
        break;
      case "headers":
        text = ds.map((d) => rawRequestText(d, "") + "\n" + (d.response ? rawResponseHead(d) : "")).join("\n------------------------------------------------------------------\n\n");
        break;
      case "full": {
        const parts: string[] = [];
        for (const d of ds.slice(0, 20)) {
          const { loadText } = await import("./lib/bodytext");
          const req = await loadText(d.summary.id, "request", d.requestBody, 1 << 20);
          const resp = d.response ? await loadText(d.summary.id, "response", d.responseBody, 1 << 20) : "";
          parts.push(rawRequestText(d, req) + "\n\n" + (d.response ? rawResponseHead(d) + resp : ""));
        }
        text = parts.join("\n\n------------------------------------------------------------------\n\n");
        break;
      }
      case "curl":
      case "fetch":
      case "powershell":
      case "python": {
        const { snippetBody } = await import("./lib/bodytext");
        const build = { curl: buildCurl, fetch: buildFetch, powershell: buildPowerShell, python: buildPython }[kind];
        const out: string[] = [];
        for (const d of ds.slice(0, 50)) {
          // Text bodies up to 1 MB are inlined (as the bytes sent); binary or larger ones are referenced as a file.
          const body = await snippetBody(d);
          out.push(build(d, body?.text ?? null, body?.bytes));
        }
        text = out.join("\n\n");
        break;
      }
    }
    await copyText(text);
    say(plural(ids.length, "Copied session ({kind})", "Copied {n} sessions ({kind})", { kind }));
  },

  // ---------------------------------------------------------------- capture
  async toggleCapture() {
    if (get().captureBusy) return;
    // Flip the switch right away; the core confirms through the status.
    set({ captureBusy: get().status?.engine.capturing ? "stopping" : "starting" });
    try {
      const on = await api.toggleCapture();
      set({ status: await api.status() });
      say(on ? t("Capturing") : t("Capture stopped"));
      return on;
    } catch (e) {
      say(String(e), "error");
    } finally {
      set({ captureBusy: null });
    }
  },

  // -------------------------------------------------------------- quickexec
  async quickexec(input: string): Promise<boolean> {
    const r = await api.quickexec(input);
    if (r.error) {
      say(r.error, "error");
      return false;
    }
    if (r.select) await actions.selectIds(r.select);
    if (r.action === "help") set({ dialog: { kind: "help", topic: "quickexec" } });
    if (r.action === "dump") await actions.menu("file.save-all");
    if (r.message && r.action !== "help") say(r.message);
    if (r.engineCommand && !r.message) say(t("'{name}' is not available yet", { name: input }), "error");
    return true;
  },

  // ----------------------------------------------------------------- keyboard
  /** Keyboard handling while the session list has focus. Returns true if handled. */
  gridKey(e: KeyboardEvent): boolean {
    const mod = e.metaKey || e.ctrlKey;
    const k = e.key;
    const page = Math.max(1, grid.visibleCount() - 1);
    // Grouped list: ← collapses, → expands the focused row's group.
    const fi = get().focusIndex;
    if ((k === "ArrowLeft" || k === "ArrowRight") && !mod && fi != null) {
      const g = rowCache.group(fi);
      if (g && g.collapsed === (k === "ArrowRight")) void actions.toggleGroupAt(fi);
      return !!g;
    }
    switch (k) {
      case "ArrowDown":
        actions.moveFocus(1, e.shiftKey);
        return true;
      case "ArrowUp":
        actions.moveFocus(-1, e.shiftKey);
        return true;
      case "PageDown":
        actions.moveFocus(page, e.shiftKey);
        return true;
      case "PageUp":
        actions.moveFocus(-page, e.shiftKey);
        return true;
      case "Home":
        actions.moveFocus("home", e.shiftKey);
        return true;
      case "End":
        actions.moveFocus("end", e.shiftKey);
        return true;
      case "Delete":
      case "Backspace":
        if (e.shiftKey) actions.removeUnselected();
        else actions.removeSelected();
        return true;
      case "Enter":
        actions.showTab("inspectors");
        return true;
      case "Escape":
        actions.clearSelection();
        return true;
    }
    if (mod && (k === "a" || k === "A")) {
      actions.selectAll();
      return true;
    }
    // Ctrl+X on every platform removes all (Cmd+X arrives as a cut event on macOS).
    if (e.ctrlKey && (k === "x" || k === "X")) {
      actions.removeAll();
      return true;
    }
    if (mod && k >= "1" && k <= "6") {
      actions.mark(MARKS[Number(k) - 1]);
      return true;
    }
    if (mod && k === "0") {
      actions.mark(null);
      return true;
    }
    if (!mod && !e.altKey) {
      if (k === "m" || k === "M") {
        actions.comment();
        return true;
      }
      if (k === "r" || k === "R" || k === "u" || k === "U") {
        import("./replay").then((m) => m.replaySelected({ unconditional: k === "u" || k === "U", repeat: e.shiftKey && (k === "R") }));
        return true;
      }
      if (k === "/" || k === "?") {
        document.querySelector<HTMLInputElement>(".cmdfield input")?.focus();
        return true;
      }
    }
    return false;
  },

  // ------------------------------------------------------------------- menu
  async menu(id: string) {
    const { handleMenu } = await import("./menuHandlers");
    await handleMenu(id);
  },
};

function findCached(id: SessionId) {
  const i = get().focusIndex;
  if (i == null) return undefined;
  const r = rowCache.get(i);
  return r && r.id === id ? r : undefined;
}
