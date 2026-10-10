// File → Snapshot Library: archives kept in the data folder, in folders. Open one (it becomes
// a source of its own in the navigator), save sessions as a new snapshot or add them to one.
import { useEffect, useState } from "react";
import { api, type LibraryEntry } from "../api";
import { get, promptText, say, set } from "../store";
import { actions } from "../actions";
import { importWithPassword, newPassword } from "../fileActions";
import { prepareImport } from "../lib/importPrep";
import { fmtBytes } from "../lib/format";
import { plural, t } from "../i18n";

export function LibraryPanel() {
  const [list, setList] = useState<LibraryEntry[]>([]);
  const [sel, setSel] = useState<string | null>(null);
  const load = () => api.libraryList().then(setList, (e) => say(String(e), "error"));
  useEffect(() => {
    void load();
  }, []);
  const entry = list.find((e) => e.path === sel) ?? null;
  // Where new things go: the chosen folder, or the folder of the chosen archive.
  const folder = entry ? (entry.folder ? entry.path : entry.path.split("/").slice(0, -1).join("/")) : "";
  const selected = () => [...get().selection].sort((a, b) => a - b);
  const act = async (f: () => Promise<unknown>, ok?: string) => {
    try {
      await f();
      if (ok) say(ok);
      await load();
    } catch (e) {
      say(String(e), "error");
    }
  };
  const open = async (e: LibraryEntry) => {
    if (e.folder) return;
    const path = await api.libraryFile(e.path);
    if (!(await prepareImport(e.name))) return;
    try {
      await importWithPassword(e.name, (pw) => api.importArchive(path, pw));
      // Each snapshot is a source of its own: the navigator lists them.
      await actions.setGroup("source");
      set({ dialog: null });
      say(t("Loading {name}; Navigator → Source shows it apart from the live capture", { name: e.name }));
    } catch (err) {
      say(String(err), "error");
    }
  };
  const save = async (protect: boolean) => {
    const ids = selected();
    const name = await promptText(t("Save snapshot"), ids.length > 1 ? plural(ids.length, "Name for the {n} selected session", "Name for the {n} selected sessions") : t("Name for all sessions in the list"), "");
    if (!name?.trim()) return;
    const password = protect ? await newPassword() : undefined;
    if (protect && !password) return;
    await act(async () => {
      const rel = await api.librarySave(ids.length > 1 ? ids : [], folder, name.trim(), password ?? undefined);
      setSel(rel);
    }, t("Saving the snapshot"));
  };
  return (
    <div className="library">
      <p className="muted small">{t("Snapshots are session archives in the library folder of the data folder. Opening one loads it into the list as a source of its own (Navigator → Source), next to what is recorded live.")}</p>
      <div className="library-list">
        {list.length === 0 && <div className="muted small">{t("The library is empty. Save sessions as a snapshot to start.")}</div>}
        {list.map((e) => (
          <div
            key={e.path}
            className={`library-row ${sel === e.path ? "active" : ""}`}
            style={{ paddingLeft: 6 + e.depth * 16 }}
            onClick={() => setSel(e.path)}
            onDoubleClick={() => void open(e)}
            title={e.path}
          >
            <span className="library-icon">{e.folder ? "📁" : "🗂"}</span>
            <span className="library-name">{e.name}</span>
            {!e.folder && <span className="muted small">{fmtBytes(e.size)}</span>}
            <span className="muted small">{e.modified ? new Date(e.modified * 1000).toLocaleString() : ""}</span>
          </div>
        ))}
      </div>
      <div className="btn-row library-buttons">
        <button className="primary" disabled={!entry || entry.folder} onClick={() => entry && void open(entry)}>
          {t("Open")}
        </button>
        <button onClick={() => void save(false)} title={t("Selected sessions, or all in the list")}>
          {t("Save as snapshot…")}
        </button>
        <button onClick={() => void save(true)}>{t("Save with password…")}</button>
        <button
          disabled={!entry || entry.folder || !entry.name.toLowerCase().endsWith(".saz")}
          title={t("Add the selected sessions to this snapshot")}
          onClick={() => {
            const ids = selected();
            if (!entry || !ids.length) return say(t("Select the sessions to add first"), "error");
            void act(() => api.libraryAdd(ids, entry.path), plural(ids.length, "Adding {n} session to {name}", "Adding {n} sessions to {name}", { name: entry.name }));
          }}
        >
          {t("Add selected sessions")}
        </button>
        <button
          onClick={async () => {
            const name = await promptText(t("New folder"), t("Folder name"), "");
            if (name?.trim()) await act(() => api.libraryMkdir(folder ? `${folder}/${name.trim()}` : name.trim()));
          }}
        >
          {t("New folder…")}
        </button>
        <button
          disabled={!entry}
          onClick={async () => {
            if (!entry) return;
            const name = await promptText(t("Rename"), t("New name"), entry.folder ? entry.name : entry.name.replace(/\.(saz|har)$/i, ""));
            if (name?.trim()) await act(async () => setSel(await api.libraryRename(entry.path, name.trim())));
          }}
        >
          {t("Rename…")}
        </button>
        <button disabled={!entry} onClick={() => entry && void act(() => api.libraryDelete(entry.path), t("Deleted {name}", { name: entry.name }))}>
          {t("Delete")}
        </button>
        <button className="linklike" onClick={() => void api.libraryReveal().catch((e) => say(String(e), "error"))}>
          {t("Open folder")}
        </button>
      </div>
    </div>
  );
}
