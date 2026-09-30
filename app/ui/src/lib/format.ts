import { currentLang, t } from "../i18n";

/** Decimal number with a fixed number of fraction digits, in the UI language (1.50 / 1,50). */
function fixed(v: number, digits: number): string {
  const s = v.toFixed(digits);
  return currentLang() === "de" ? s.replace(".", ",") : s;
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${fmtInt(n)} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${fixed(v, v < 10 ? 2 : 1)} ${u[i]}`;
}

let nf: Intl.NumberFormat | null = null;
/** Integer with thousands separators in the UI language (1,234 / 1.234). */
export function fmtInt(n: number): string {
  nf ??= new Intl.NumberFormat(currentLang() === "de" ? "de-DE" : "en-US");
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
  if (ms < 1000) return `${fmtInt(ms)} ms`;
  return `${fixed(ms / 1000, ms < 10000 ? 2 : 1)} s`;
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

/** Where the OS keeps trusted roots and secrets, in the words users know.
 * German forms: `os`, `trustStore` and `secrets` without article (used after "in:" / in
 * parentheses), `machine` accusative ("verlässt nie {machine}"). */
export const osNames = isMac
  ? { os: "macOS", trustStore: t("your login keychain"), prompt: t("macOS asks for your password."), machine: t("this Mac"), secrets: t("the macOS keychain") }
  : isWindows
    ? { os: "Windows", trustStore: t("your Windows certificate store"), prompt: t("Windows asks for confirmation."), machine: t("this PC"), secrets: t("the Windows Credential Manager") }
    : {
        os: t("this system"),
        trustStore: t("the browsers' certificate databases (Chrome, Firefox) and the system trust store"),
        prompt: t("Updating the system store asks for your password."),
        machine: t("this computer"),
        secrets: t("the desktop keyring"),
      };
export const modKey = isMac ? "⌘" : "Ctrl+";
