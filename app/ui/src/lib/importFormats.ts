// File types Quena imports, by extension. The backend decides the same way
// (quena-app-core archive.rs, format_of).

/// Session archives offered in file dialogs.
export const ARCHIVE_EXTENSIONS = ["saz", "har"];
/// Packet captures (import only).
export const CAPTURE_EXTENSIONS = ["pcap", "pcapng", "cap"];
/// Everything that loads, also SAZ as .zip and HAR as .json.
const IMPORTABLE = new Set([...ARCHIVE_EXTENSIONS, "zip", "json", ...CAPTURE_EXTENSIONS]);

export const isImportableName = (name: string) => IMPORTABLE.has(name.split(".").pop()?.toLowerCase() ?? "");
