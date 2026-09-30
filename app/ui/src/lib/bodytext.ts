// Body bytes → text in the right charset. The core determines each body's charset
// (quena_body::charset: BOM, Content-Type, document declaration, default of the type) and
// reports it in BodyInfo.charset; the user can override it per body. Bytes are decoded with
// the webview's TextDecoder, which knows every WHATWG label.
//
// Variants whose bytes are not in the body's charset say so: the core transcodes UTF-16 (and
// other charsets that are not ASCII compatible) to UTF-8 for the `text:<charset>` variant and
// for formatted UTF-16 bodies, and sends `X-Quena-Charset: UTF-8` with them.
import { fetchBody, type BodyInfo, type Detail, type Part, type SessionId, type Variant } from "../api";

/** Charsets offered for overriding the detected one (WHATWG names). */
export const CHARSETS = ["UTF-8", "windows-1252", "ISO-8859-15", "ISO-8859-2", "UTF-16LE", "UTF-16BE", "Shift_JIS", "GB18030", "KOI8-R"];

const decoders = new Map<string, TextDecoder>();

function decoder(charset: string | null | undefined): TextDecoder {
  const key = (charset || "utf-8").toLowerCase();
  let d = decoders.get(key);
  if (!d) {
    try {
      d = new TextDecoder(key);
    } catch {
      // Unknown label (or "replacement"): UTF-8, as the core falls back for display.
      d = decoders.get("utf-8") ?? new TextDecoder("utf-8");
    }
    decoders.set(key, d);
  }
  return d;
}

/** Canonical (lower-case WHATWG) name of a charset label, or null if unknown. */
export function canonical(charset: string | null | undefined): string | null {
  if (!charset) return null;
  try {
    return new TextDecoder(charset.trim()).encoding;
  } catch {
    return null;
  }
}

/** Charsets whose bytes cannot be processed byte-wise (the core transcodes them). */
const NOT_ASCII_COMPATIBLE = new Set(["utf-16le", "utf-16be", "iso-2022-jp"]);

export function needsTranscoding(charset: string | null | undefined): boolean {
  return NOT_ASCII_COMPATIBLE.has(canonical(charset) ?? "");
}

export function sameCharset(a: string | null | undefined, b: string | null | undefined): boolean {
  return (canonical(a) ?? "utf-8") === (canonical(b) ?? "utf-8");
}

/** Decode bytes in `charset` (default UTF-8). A matching BOM is dropped; malformed sequences
 * become U+FFFD, as in browsers. */
export function decodeBytes(data: Uint8Array, charset?: string | null): string {
  return decoder(charset).decode(data);
}

/** The charset a body is shown in: the user's choice, else the detected one, else UTF-8. */
export function effectiveCharset(info: BodyInfo, override?: string | null): string {
  return override || info.charset?.name || "UTF-8";
}

/**
 * The variant to fetch for showing `want` of a body in its effective charset:
 * UTF-16 & co. come transcoded (`text:<charset>`; formatted UTF-16 is transcoded by the core
 * already), and an override away from a transcoded charset reads the untranscoded bytes.
 */
export function textVariant(info: BodyInfo, want: Variant, override?: string | null): Variant {
  if (want.startsWith("plugin:") || want.startsWith("text:")) return want;
  const detected = info.charset?.name ?? "UTF-8";
  const ov = override && !sameCharset(override, detected) ? override : null;
  const cs = ov ?? detected;
  if (needsTranscoding(cs)) return want === "pretty" && !ov ? "pretty" : `text:${cs}`;
  // Formatted output of a transcoded body is UTF-8, not in the charset chosen now.
  if (want === "pretty" && ov && needsTranscoding(detected)) return info.variants.includes("decoded") ? "decoded" : "raw";
  return want;
}

export function preferredVariant(info: BodyInfo, decode: boolean): Variant {
  if (decode && info.variants.includes("decoded")) return "decoded";
  return "raw";
}

export interface LoadedBody {
  text: string;
  /** Bytes as fetched (in `charset`). */
  bytes: Uint8Array;
  /** Charset the bytes were decoded from. */
  charset: string;
  variant: Variant;
}

/** Load up to `limit` bytes of a body and decode them in the effective charset. */
export async function loadBody(id: SessionId, part: Part, info: BodyInfo, limit: number, variant?: Variant, override?: string | null): Promise<LoadedBody> {
  const cs = effectiveCharset(info, override);
  const v = textVariant(info, variant ?? (info.variants.includes("decoded") ? "decoded" : "raw"), override);
  if (info.len === 0) return { text: "", bytes: new Uint8Array(), charset: cs, variant: v };
  // Derived variants are produced by a background job; wait briefly for completion.
  for (let i = 0; ; i++) {
    const r = await fetchBody(id, part, v, 0, limit);
    if (r.complete || r.data.length >= limit || i >= 100) {
      const charset = r.charset ?? cs;
      return { text: decodeBytes(r.data, charset), bytes: r.data, charset, variant: v };
    }
    await new Promise((res) => setTimeout(res, 40));
  }
}

/** Load up to `limit` bytes of a body as text (decoded if possible) in its charset. */
export async function loadText(id: SessionId, part: Part, info: BodyInfo, limit: number, variant?: Variant, override?: string | null): Promise<string> {
  return (await loadBody(id, part, info, limit, variant, override)).text;
}

const encodeTables = new Map<string, Map<string, number> | null>();

/** Reverse table of a single-byte charset (null for multi-byte ones). */
function singleByteTable(cs: string): Map<string, number> | null {
  if (encodeTables.has(cs)) return encodeTables.get(cs)!;
  let table: Map<string, number> | null = null;
  if (!["utf-8", "utf-16le", "utf-16be", "shift_jis", "gb18030", "gbk", "big5", "euc-jp", "euc-kr", "iso-2022-jp"].includes(cs)) {
    table = new Map();
    const d = new TextDecoder(cs);
    for (let b = 0; b < 256; b++) {
      const ch = d.decode(Uint8Array.of(b));
      if (ch !== "�" && !table.has(ch)) table.set(ch, b);
    }
  }
  encodeTables.set(cs, table);
  return table;
}

/** Encode text in a charset: UTF-8, UTF-16 and single-byte charsets. Null if the charset is
 * not supported here or a character cannot be represented in it. */
export function encodeText(text: string, charset: string): Uint8Array | null {
  const cs = canonical(charset);
  if (!cs || cs === "utf-8") return new TextEncoder().encode(text);
  if (cs === "utf-16le" || cs === "utf-16be") {
    const out = new Uint8Array(text.length * 2);
    for (let i = 0; i < text.length; i++) {
      const u = text.charCodeAt(i);
      out[2 * i + (cs === "utf-16le" ? 0 : 1)] = u & 0xff;
      out[2 * i + (cs === "utf-16le" ? 1 : 0)] = u >> 8;
    }
    return out;
  }
  const table = singleByteTable(cs);
  if (!table) return null;
  const out: number[] = [];
  for (const ch of text) {
    const b = table.get(ch);
    if (b === undefined) return null;
    out.push(b);
  }
  return Uint8Array.from(out);
}

/** Is `text` exactly what these bytes are in UTF-8 (so a snippet can carry it as a string)? */
export function isUtf8Of(text: string, bytes: Uint8Array): boolean {
  const e = new TextEncoder().encode(text);
  return e.length === bytes.length && e.every((b, i) => b === bytes[i]);
}

/** A request body for a code snippet (Copy as cURL …): its text, plus the exact bytes when
 * the text in UTF-8 is not what was sent (another charset, a BOM, invalid sequences, a
 * content coding). Null for empty, binary and large bodies (the snippet references a file). */
export async function snippetBody(d: Detail, limit = 1 << 20): Promise<{ text: string; bytes?: Uint8Array } | null> {
  const info = d.requestBody;
  if (!info.len || info.len >= limit || !info.isText) return null;
  const r = await fetchBody(d.summary.id, "request", "raw", 0, limit);
  const text = decodeBytes(r.data, info.charset?.name);
  return { text, bytes: isUtf8Of(text, r.data) ? undefined : r.data };
}
