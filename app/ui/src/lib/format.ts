export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 2 : 1)} ${u[i]}`;
}

const nf = new Intl.NumberFormat("en-US");
export function fmtInt(n: number): string {
  return nf.format(n);
}

export function fmtTime(us: number | null | undefined): string {
  if (!us) return "";
  const d = new Date(us / 1000);
  const p = (x: number, w = 2) => String(x).padStart(w, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

export function fmtDateTime(us: number | null | undefined): string {
  if (!us) return "";
  const d = new Date(us / 1000);
  return `${d.toLocaleDateString()} ${fmtTime(us)}`;
}

export function fmtMs(ms: number | null | undefined): string {
  if (ms == null) return "";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(ms < 10000 ? 2 : 1)} s`;
}

export function headerValue(h: [string, string][] | undefined, name: string): string | undefined {
  if (!h) return undefined;
  const n = name.toLowerCase();
  return h.find(([k]) => k.toLowerCase() === n)?.[1];
}

/** Decode Latin-1 header strings that actually carry UTF-8 bytes. */
export function latin1ToUtf8(s: string): string {
  if (!/[\u0080-ÿ]/.test(s)) return s;
  const bytes = new Uint8Array([...s].map((c) => c.charCodeAt(0) & 0xff));
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return s;
  }
}

export const isMac = typeof navigator !== "undefined" && /Mac/.test(navigator.platform);
export const isWindows = typeof navigator !== "undefined" && /Win/.test(navigator.platform);
export const isLinux = !isMac && !isWindows;

/** Where the OS keeps trusted roots and secrets, in the words users know. */
export const osNames = isMac
  ? { os: "macOS", trustStore: "your login keychain", prompt: "macOS asks for your password.", machine: "this Mac", secrets: "the macOS keychain" }
  : isWindows
    ? { os: "Windows", trustStore: "your Windows certificate store", prompt: "Windows asks for confirmation.", machine: "this PC", secrets: "the Windows Credential Manager" }
    : {
        os: "this system",
        trustStore: "the browsers' certificate databases (Chrome, Firefox) and the system trust store",
        prompt: "Updating the system store asks for your password.",
        machine: "this computer",
        secrets: "the desktop keyring",
      };
export const modKey = isMac ? "⌘" : "Ctrl+";
