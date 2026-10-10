// File menu: archives (SAZ/HAR, packet captures to import), bodies, cURL scripts.
import { open, save } from "@tauri-apps/plugin-dialog";
import { api, type CaptureImport } from "./api";
import { get, promptText, say, set } from "./store";
import { buildCurl } from "./lib/http";
import { snippetBody } from "./lib/bodytext";
import { plural, t } from "./i18n";
import { ARCHIVE_EXTENSIONS, CAPTURE_EXTENSIONS, baseName, keyLogFilters } from "./lib/importFormats";
import { prepareImport } from "./lib/importPrep";

const ARCHIVES = [
  { name: t("Session Archive"), extensions: ARCHIVE_EXTENSIONS },
  { name: t("SAZ Session Archive"), extensions: ["saz"] },
  { name: t("HTTP Archive (HAR)"), extensions: ["har"] },
];
const CAPTURES = { name: t("Packet Capture"), extensions: CAPTURE_EXTENSIONS };

function stamp() {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}`;
}

/** Ask for a new archive password twice; `null` when cancelled or not the same. */
export async function newPassword(): Promise<string | null> {
  const a = await promptText(t("Archive password"), t("Password (7-Zip and WinZip open the archive with it as well)"), "", true);
  if (!a) return null;
  const b = await promptText(t("Archive password"), t("Repeat the password"), "", true);
  if (b !== a) {
    say(t("The passwords differ"), "error");
    return null;
  }
  return a;
}

/** Import an archive; a protected one asks for its password (again while it is wrong). */
export async function importWithPassword(name: string, run: (password?: string) => Promise<unknown>) {
  let password: string | undefined;
  for (;;) {
    try {
      await run(password);
      return;
    } catch (e) {
      const msg = String(e);
      if (!/protected with a password|wrong password/.test(msg)) throw e;
      const pw = await promptText(t("Password"), /wrong password/.test(msg) ? t("Wrong password for {name}. Try again:", { name }) : t("{name} is protected with a password:", { name }), "", true);
      if (pw == null) return;
      password = pw;
    }
  }
}

async function saveArchive(ids: number[], ext: "saz" | "har", password?: string) {
  if (!get().listTotal) {
    say(t("There are no sessions to save"), "error");
    return;
  }
  const path = await save({ defaultPath: `quena_${stamp()}.${ext}`, filters: ext === "saz" ? [ARCHIVES[1], ARCHIVES[2]] : [ARCHIVES[2], ARCHIVES[1]] });
  if (!path) return;
  try {
    await api.exportArchive(ids, path, password);
    say(ids.length ? plural(ids.length, "Saving {n} session to {path}", "Saving {n} sessions to {path}", { path }) : t("Saving all sessions to {path}", { path }));
  } catch (e) {
    say(String(e), "error");
  }
}

async function loadArchive(captures = false) {
  const all = { name: t("Session Archive or Packet Capture"), extensions: [...ARCHIVE_EXTENSIONS, ...CAPTURE_EXTENSIONS] };
  const path = await open({ multiple: false, filters: captures ? [CAPTURES, all] : [all, ...ARCHIVES, CAPTURES] });
  if (typeof path !== "string") return;
  if (!(await prepareImport(baseName(path)))) return;
  try {
    await importWithPassword(baseName(path), async (pw) => {
      await api.importArchive(path, pw);
      say(t("Loading {path}", { path }));
    });
  } catch (e) {
    say(String(e), "error");
  }
}

/** After a packet capture import: report decrypted TLS, and offer a key log for the rest. */
export function captureImported(r: CaptureImport) {
  const name = baseName(r.name);
  if (r.noKeys > 0) {
    say(
      plural(r.noKeys, "{name}: {n} TLS connection could not be decrypted (no secrets in the key log)", "{name}: {n} TLS connections could not be decrypted (no secrets in the key log)", { name }),
      "info",
      { label: t("Choose key log file…"), run: () => void chooseKeyLog(r) },
    );
  } else if (r.decrypted > 0) {
    say(plural(r.decrypted, "{name}: {n} TLS connection decrypted", "{name}: {n} TLS connections decrypted", { name }));
  }
}

async function chooseKeyLog(r: CaptureImport) {
  const keylog = await open({ multiple: false, filters: keyLogFilters() });
  if (typeof keylog !== "string") return;
  try {
    await api.importCapture(r.path, r.name, keylog, r.ids, r.numbering);
    say(t("Loading {path}", { path: baseName(r.name) }));
  } catch (e) {
    say(String(e), "error");
  }
}

export async function handleFileMenu(id: string): Promise<boolean> {
  const selected = [...get().selection].sort((a, b) => a - b);
  switch (id) {
    case "file.load":
    case "file.import-saz":
    case "file.import-har":
      await loadArchive();
      return true;
    case "file.import-pcap":
      await loadArchive(true);
      return true;
    case "file.library":
      set({ dialog: { kind: "library" } });
      return true;
    case "file.import-netxml": {
      const path = await open({ multiple: false, filters: [{ name: t("Internet Explorer network capture (NetXML)"), extensions: ["xml"] }] });
      if (typeof path !== "string" || !(await prepareImport(baseName(path)))) return true;
      try {
        await api.importArchive(path);
      } catch (e) {
        say(String(e), "error");
      }
      return true;
    }
    case "file.export-wcat": {
      if (!get().listTotal) {
        say(t("There are no sessions to save"), "error");
        return true;
      }
      const path = await save({ defaultPath: `quena_${stamp()}.wcat`, filters: [{ name: t("WCAT load test script"), extensions: ["wcat"] }] });
      if (!path) return true;
      try {
        await api.exportArchive(selected.length > 1 ? selected : [], path);
        say(t("Saving a WCAT script to {path}", { path }));
      } catch (e) {
        say(String(e), "error");
      }
      return true;
    }
    case "file.save-all":
    case "file.export-saz":
      await saveArchive(id === "file.export-saz" && selected.length > 1 ? selected : [], "saz");
      return true;
    case "file.export-saz-protected": {
      if (!get().listTotal) {
        say(t("There are no sessions to save"), "error");
        return true;
      }
      const pw = await newPassword();
      if (pw) await saveArchive(selected.length > 1 ? selected : [], "saz", pw);
      return true;
    }
    case "file.save-selected":
      if (!selected.length) say(t("Select sessions first"), "error");
      else await saveArchive(selected, "saz");
      return true;
    case "file.export-har":
      await saveArchive(selected.length > 1 ? selected : [], "har");
      return true;
    case "file.export-curl": {
      const ids = selected.length ? selected : await api.viewIds(0, Math.min(get().listTotal, 500));
      const path = await save({ defaultPath: `quena_${stamp()}.sh`, filters: [{ name: t("Shell script"), extensions: ["sh"] }] });
      if (!path) return true;
      const parts = ["#!/bin/sh", "# Generated by Quena"];
      for (const sid of ids.slice(0, 500)) {
        const d = await api.detail(sid);
        if (!d || d.summary.kind === "tunnel") continue;
        const body = await snippetBody(d);
        parts.push(`# #${sid}`, buildCurl(d, body?.text ?? null, body?.bytes));
      }
      await api.writeTextFile(path, parts.join("\n\n") + "\n");
      say(t("cURL script written to {path}", { path }));
      return true;
    }
    case "file.export-mocks":
      // File → Export Sessions → Mocks…: a file to share; Mock Rules "Create from sessions…"
      // and the session menu start with "Create Mock Rules now".
      set({ dialog: { kind: "mocks", selected, target: "package" } });
      return true;
    case "mocks.from-sessions":
      set({ dialog: { kind: "mocks", selected } });
      return true;
    case "file.export-sanitized":
    case "file.export-sanitized-selection":
      if (!get().listTotal) say(t("There are no sessions to save"), "error");
      else
        set({
          dialog: {
            kind: "sanitize",
            selected,
            // The session menu means the sessions it was opened on, even a single one; the File
            // menu works like the other exports: a multiple selection, else the whole list.
            scope: (id === "file.export-sanitized-selection" ? selected.length > 0 : selected.length > 1) ? "selected" : "all",
          },
        });
      return true;
    case "file.save-response-body":
    case "file.save-request-body": {
      const sid = get().focusId;
      if (sid == null) return true;
      const part = id === "file.save-request-body" ? "request" : "response";
      const d = await api.detail(sid);
      if (!d) return true;
      const info = part === "request" ? d.requestBody : d.responseBody;
      const name = (d.request.url.split("?")[0].split("/").pop() || `body-${sid}`).replace(/[^\w.-]/g, "_");
      const path = await save({ defaultPath: name || `body-${sid}.bin` });
      if (!path) return true;
      const variant = get().settings?.decode && info.variants.includes("decoded") ? "decoded" : "raw";
      await api.saveBody(sid, part, variant, path);
      say(part === "request" ? t("Saving request body to {path}", { path }) : t("Saving response body to {path}", { path }));
      return true;
    }
  }
  return false;
}
