// Load .saz/.har files dropped onto the window. The webview only has the files' bytes (no
// paths), so they are sent to the backend in chunks and imported from a temporary copy.
import { api, isTauri } from "../api";
import { say } from "../store";

const CHUNK = 4 << 20;
const ARCHIVE = /\.(saz|har|zip|json)$/i;

export const isArchiveName = (name: string) => ARCHIVE.test(name);

async function send(file: File) {
  const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  let offset = 0;
  do {
    const end = Math.min(offset + CHUNK, file.size);
    const data = new Uint8Array(await file.slice(offset, end).arrayBuffer());
    await api.dropChunk(id, file.name, offset, data, end >= file.size);
    offset = end;
  } while (offset < file.size);
}

export async function importDropped(files: File[]) {
  const ok = files.filter((f) => isArchiveName(f.name));
  const skipped = files.length - ok.length;
  if (skipped) say(`${skipped} file(s) skipped: only .saz and .har archives can be dropped`, ok.length ? undefined : "error");
  for (const f of ok) {
    try {
      say(`Loading ${f.name}`);
      await send(f);
    } catch (e) {
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
