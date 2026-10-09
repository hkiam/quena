// Load .saz/.har archives and .pcap/.pcapng captures dropped onto the window. The webview only has the files' bytes (no
// paths), so they are sent to the backend in chunks and imported from a temporary copy.
import { api, isTauri } from "../api";
import { say } from "../store";
import { plural, t } from "../i18n";
import { isImportableName } from "./importFormats";
import { prepareImport } from "./importPrep";

const CHUNK = 4 << 20;

// What happened to the last drop, for end-to-end tests (window.__quenaDrop).
function trace(step: string, detail?: unknown) {
  const w = window as unknown as { __quenaDrop?: { step: string; detail?: string }[] };
  (w.__quenaDrop ??= []).push({ step, detail: detail === undefined ? undefined : String(detail) });
}

async function send(file: File, id: string) {
  let offset = 0;
  do {
    const end = Math.min(offset + CHUNK, file.size);
    const data = new Uint8Array(await file.slice(offset, end).arrayBuffer());
    await api.dropChunk(id, file.name, offset, data, end >= file.size);
    offset = end;
  } while (offset < file.size);
}

export async function importDropped(files: File[]) {
  // Mock packages go to Mock Rules.
  const packages = files.filter((f) => /\.quena-mocks$/i.test(f.name));
  if (packages.length) {
    files = files.filter((f) => !packages.includes(f));
    await import("../panels/autoresponderActions").then((m) => m.importMockPackageFiles(packages));
    if (!files.length) return;
  }
  const ok = files.filter((f) => isImportableName(f.name));
  const skipped = files.length - ok.length;
  if (ok.length && !(await prepareImport(ok.length === 1 ? ok[0].name : plural(ok.length, "{n} file", "{n} files")))) return;
  if (skipped) say(plural(skipped, "{n} file skipped: only session archives (.saz, .har) and packet captures (.pcap, .pcapng, .cap) can be dropped", "{n} files skipped: only session archives (.saz, .har) and packet captures (.pcap, .pcapng, .cap) can be dropped"), ok.length ? undefined : "error");
  for (const f of ok) {
    try {
      say(t("Loading {path}", { path: f.name }));
      trace("send", `${f.name} ${f.size}`);
      const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
      try {
        await send(f, id);
      } catch (e) {
        // A protected archive waits on the backend for its password.
        if (!/protected with a password/.test(String(e))) throw e;
        const { importWithPassword } = await import("../fileActions");
        await importWithPassword(f.name, async (pw) => {
          if (pw === undefined) throw e;
          await api.importDropped(id, f.name, pw);
        });
      }
      trace("sent");
    } catch (e) {
      trace("error", e);
      say(`${f.name}: ${e}`, "error");
    }
  }
}

const hasFiles = (e: DragEvent) => !!e.dataTransfer && [...e.dataTransfer.types].includes("Files");

/** Accept files dropped anywhere on the window; returns the cleanup function. */
export function installFileDrop(): () => void {
  if (!isTauri) return () => {};
  let depth = 0;
  const mark = (on: boolean) => document.body.classList.toggle("file-drop", on);
  const enter = (e: DragEvent) => {
    if (!hasFiles(e)) return;
    depth++;
    mark(true);
  };
  const over = (e: DragEvent) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    e.dataTransfer!.dropEffect = "copy";
  };
  const leave = (e: DragEvent) => {
    if (!hasFiles(e)) return;
    depth = Math.max(0, depth - 1);
    if (!depth) mark(false);
  };
  const drop = (e: DragEvent) => {
    trace("drop", e.dataTransfer ? [...e.dataTransfer.types].join(",") + ` files=${e.dataTransfer.files.length}` : "no dataTransfer");
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth = 0;
    mark(false);
    void importDropped([...(e.dataTransfer?.files ?? [])]);
  };
  window.addEventListener("dragenter", enter);
  window.addEventListener("dragover", over);
  window.addEventListener("dragleave", leave);
  window.addEventListener("drop", drop);
  return () => {
    window.removeEventListener("dragenter", enter);
    window.removeEventListener("dragover", over);
    window.removeEventListener("dragleave", leave);
    window.removeEventListener("drop", drop);
  };
}
