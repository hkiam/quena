// Header columns: up to three request or response headers shown in the session list.
import { api } from "./api";
import { actions } from "./actions";
import { get, say, set, type ColumnKey } from "./store";
import { t } from "./i18n";

const KEYS: ColumnKey[] = ["header1", "header2", "header3"];

async function save(cols: { response: boolean; name: string }[]) {
  const s = get().settings;
  if (!s) return;
  const next = { ...s, headerColumns: cols };
  await api.settingsSet(next);
  set({ settings: next });
  // A column shows for each configured header, none for the others.
  set((st) => ({ layout: { ...st.layout, columns: st.layout.columns.map((c) => (KEYS.includes(c.key) ? { ...c, visible: KEYS.indexOf(c.key) < cols.length } : c)) } }));
  actions.saveLayout();
}

/** Show header `name` of the request or the response as a list column. */
export async function addHeaderColumn(response: boolean, name: string) {
  const cols = get().settings?.headerColumns ?? [];
  if (cols.some((c) => c.response === response && c.name.toLowerCase() === name.toLowerCase())) return say(t("{name} is a column already", { name }));
  if (cols.length >= KEYS.length) return say(t("At most three header columns; remove one first (right-click the column headers)."), "error");
  try {
    await save([...cols, { response, name }]);
    say(t("Column {name} added", { name }));
  } catch (e) {
    say(String(e), "error");
  }
}

/** Remove the header column shown as `key`. */
export async function removeHeaderColumn(key: ColumnKey) {
  const i = KEYS.indexOf(key);
  const cols = get().settings?.headerColumns ?? [];
  if (i < 0 || i >= cols.length) return;
  try {
    await save(cols.filter((_, j) => j !== i));
  } catch (e) {
    say(String(e), "error");
  }
}

export const isHeaderColumn = (key: ColumnKey) => KEYS.includes(key);
