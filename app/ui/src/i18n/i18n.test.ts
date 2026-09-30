/// <reference types="vite/client" />
// Every text passed to t()/plural() in the UI has a German translation, every translation is
// still used, and translations keep the placeholders of the English text.
import { describe, expect, it } from "vitest";
import { de } from "./de";

// All UI sources as text (tests and the translations themselves excluded).
const sources = Object.entries(import.meta.glob(["../**/*.ts", "../**/*.tsx", "!../**/*.test.ts", "!../i18n/**"], { query: "?raw", import: "default", eager: true }) as Record<string, string>);

// String literals in t("…") / t('…') and in the text arguments of plural(n, "…", "…").
const LIT = String.raw`"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'`;
const unq = (m: RegExpMatchArray, i: number) => JSON.parse(`"${(m[i] ?? m[i + 1]).replace(/\\'/g, "'").replace(/(?<!\\)"/g, '\\"')}"`) as string;

function used(): Map<string, string> {
  const out = new Map<string, string>();
  for (const [f, src] of sources) {
    for (const m of src.matchAll(new RegExp(String.raw`\bt\(\s*(?:${LIT})`, "g"))) out.set(unq(m, 1), f);
    for (const m of src.matchAll(new RegExp(String.raw`\bplural\([^,]+,\s*(?:${LIT})\s*,\s*(?:${LIT})`, "g"))) {
      out.set(unq(m, 1), f);
      out.set(unq(m, 3), f);
    }
  }
  return out;
}

const holes = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

describe("German translation", () => {
  const keys = used();
  it("covers every UI text", () => {
    const missing = [...keys].filter(([k]) => !(k in de)).map(([k, f]) => `${f}: ${k}`);
    expect(missing).toEqual([]);
  });
  it("has no unused entries", () => {
    expect(Object.keys(de).filter((k) => !keys.has(k))).toEqual([]);
  });
  it("keeps the placeholders", () => {
    expect(Object.entries(de).filter(([en, g]) => holes(en).join() !== holes(g).join())).toEqual([]);
  });
});
