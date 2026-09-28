import { fetchBody, type BodyInfo, type Part, type SessionId, type Variant } from "../api";

const dec = new TextDecoder("utf-8", { fatal: false });

export function preferredVariant(info: BodyInfo, decode: boolean): Variant {
  if (decode && info.variants.includes("decoded")) return "decoded";
  return "raw";
}

/** Load up to `limit` bytes of a body as text (decoded if possible). */
export async function loadText(id: SessionId, part: Part, info: BodyInfo, limit: number, variant?: Variant): Promise<string> {
  if (info.len === 0) return "";
  const v = variant ?? (info.variants.includes("decoded") ? "decoded" : "raw");
  // Derived variants are produced by a background job; wait briefly for completion.
  for (let i = 0; ; i++) {
    const r = await fetchBody(id, part, v, 0, limit);
    if (r.complete || r.data.length >= limit || i >= 100) return dec.decode(r.data);
    await new Promise((res) => setTimeout(res, 40));
  }
}

export function decodeText(data: Uint8Array): string {
  return dec.decode(data);
}
