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

const nf = new Map<string, Intl.NumberFormat>();
/** Integer with thousands separators in the UI language (1,234 / 1.234). */
export function fmtInt(n: number): string {
  const lang = currentLang();
  let f = nf.get(lang);
  if (!f) nf.set(lang, (f = new Intl.NumberFormat(lang === "de" ? "de-DE" : "en-US")));
  return f.format(n);
}

export function fmtTime(us: number | null | undefined): string {
  if (!us) return "";
  const d = new Date(us / 1000);
  const p = (x: number, w = 2) => String(x).padStart(w, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

/** An estimated amount in US dollars: small amounts with enough digits to be useful. */
export function fmtUsd(usd: number): string {
  const digits = usd >= 1 ? 2 : usd >= 0.01 ? 4 : 6;
  return `$${usd.toLocaleString(currentLang() === "de" ? "de-DE" : "en-US", { minimumFractionDigits: digits, maximumFractionDigits: digits })}`;
}

/** Date of a microsecond timestamp, in the UI language. */
export function fmtDate(us: number | null | undefined): string {
  if (!us) return "";
  return new Date(us / 1000).toLocaleDateString(currentLang() === "de" ? "de-DE" : undefined);
}

export function fmtDateTime(us: number | null | undefined): string {
  if (!us) return "";
  const d = new Date(us / 1000);
  return `${d.toLocaleDateString(currentLang() === "de" ? "de-DE" : undefined)} ${fmtTime(us)}`;
}

export function fmtMs(ms: number | null | undefined): string {
  if (ms == null) return "";
  if (ms < 1000) return `${fmtInt(ms)} ms`;
  return `${fixed(ms / 1000, ms < 10000 ? 2 : 1)} s`;
}

/** A longer duration: `850 ms`, `12.4 s`, `3 min 05 s`, `1 h 12 min`. */
export function fmtDuration(ms: number | null | undefined): string {
  if (ms == null) return "";
  if (ms < 60_000) return fmtMs(Math.round(ms));
  const s = Math.round(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h} h ${String(m).padStart(2, "0")} min`;
  return `${m} min ${String(s % 60).padStart(2, "0")} s`;
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
