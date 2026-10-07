// File types Quena imports, by extension. The backend decides the same way
// (quena-app-core archive.rs, format_of).
import { t } from "../i18n";

/// Session archives offered in file dialogs.
export const ARCHIVE_EXTENSIONS = ["saz", "har"];
/// Packet captures (import only).
export const CAPTURE_EXTENSIONS = ["pcap", "pcapng", "cap"];
/// Everything that loads, also SAZ as .zip and HAR as .json.
const IMPORTABLE = new Set([...ARCHIVE_EXTENSIONS, "zip", "json", ...CAPTURE_EXTENSIONS]);

export const isImportableName = (name: string) => IMPORTABLE.has(name.split(".").pop()?.toLowerCase() ?? "");

/** File dialog filters for a TLS key log (SSLKEYLOGFILE has no fixed extension). */
export const keyLogFilters = () => [
  { name: t("TLS key log"), extensions: ["log", "keys", "keylog", "txt"] },
  { name: t("All files"), extensions: ["*"] },
];

/** The file name of a path (either separator). */
export const baseName = (path: string) => path.split(/[\\/]/).pop() || path;
