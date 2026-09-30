import { describe, expect, it } from "vitest";
import type { BodyInfo, Charset, Detail } from "../api";
import { canonical, decodeBytes, effectiveCharset, encodeText, isUtf8Of, needsTranscoding, textVariant } from "./bodytext";
import { buildCurl, buildFetch, buildPython, extParams, formCharset, parseForm, parseQuery } from "./http";

const bytes = (...b: number[]) => Uint8Array.from(b);
const info = (charset: Charset | null, variants: BodyInfo["variants"] = ["raw"]): BodyInfo => ({
  bodyId: 1,
  len: 10,
  wireLen: 10,
  complete: true,
  truncated: false,
  contentType: "text/plain",
  contentEncoding: null,
  transferEncoding: null,
  isText: true,
  isImage: false,
  variants,
  plugins: [],
  charset,
});

describe("decoding body bytes", () => {
  const grusse = bytes(0x47, 0x72, 0xfc, 0xdf, 0x65); // "Grüße" in ISO-8859-1 / windows-1252
  it("uses the charset", () => {
    expect(decodeBytes(grusse, "windows-1252")).toBe("Grüße");
    expect(decodeBytes(grusse, "ISO-8859-1")).toBe("Grüße"); // a windows-1252 label, as in browsers
    expect(decodeBytes(bytes(0x80), "windows-1252")).toBe("€");
    expect(decodeBytes(bytes(0xa4), "ISO-8859-15")).toBe("€");
    expect(decodeBytes(new TextEncoder().encode("Grüße 😀"), "UTF-8")).toBe("Grüße 😀");
  });
  it("replaces malformed UTF-8 with U+FFFD", () => {
    expect(decodeBytes(grusse, "UTF-8")).toBe("Gr��e");
    expect(decodeBytes(grusse)).toBe("Gr��e");
  });
  it("drops a matching BOM", () => {
    expect(decodeBytes(bytes(0xef, 0xbb, 0xbf, 0x61), "UTF-8")).toBe("a");
    expect(decodeBytes(bytes(0xff, 0xfe, 0xe4, 0x00), "UTF-16LE")).toBe("ä");
    expect(decodeBytes(bytes(0x00, 0xe4), "UTF-16BE")).toBe("ä");
  });
  it("falls back to UTF-8 for unknown labels", () => {
    expect(decodeBytes(new TextEncoder().encode("ä"), "x-klingon")).toBe("ä");
    expect(canonical("x-klingon")).toBeNull();
    expect(canonical("latin1")).toBe("windows-1252");
  });
});

describe("variant and charset for a view", () => {
  const w1252 = info({ name: "windows-1252", source: "header", header: "ISO-8859-1" }, ["raw", "pretty"]);
  const u16 = info({ name: "UTF-16LE", source: "bom" }, ["raw", "pretty"]);
  it("keeps byte variants for ASCII-compatible charsets", () => {
    expect(textVariant(w1252, "pretty")).toBe("pretty");
    expect(textVariant(w1252, "raw", "UTF-8")).toBe("raw");
    expect(effectiveCharset(w1252)).toBe("windows-1252");
    expect(effectiveCharset(w1252, "KOI8-R")).toBe("KOI8-R");
    expect(effectiveCharset(info(null))).toBe("UTF-8");
  });
  it("uses transcoded text for UTF-16", () => {
    expect(needsTranscoding("utf-16le")).toBe(true);
    expect(needsTranscoding("Shift_JIS")).toBe(false);
    expect(textVariant(u16, "raw")).toBe("text:UTF-16LE");
    expect(textVariant(u16, "pretty")).toBe("pretty"); // the core formats transcoded text
    expect(textVariant(w1252, "raw", "UTF-16BE")).toBe("text:UTF-16BE");
    expect(textVariant(w1252, "pretty", "UTF-16BE")).toBe("text:UTF-16BE");
    // Away from UTF-16: the untranscoded bytes, not the formatted UTF-8.
    expect(textVariant(u16, "pretty", "windows-1252")).toBe("raw");
    expect(textVariant(u16, "pretty", "UTF-16LE")).toBe("pretty"); // same as detected: no override
    expect(textVariant(u16, "plugin:2")).toBe("plugin:2");
  });
});

describe("encoding text", () => {
  it("encodes single-byte charsets and UTF-16", () => {
    expect([...encodeText("Grüße €", "windows-1252")!]).toEqual([0x47, 0x72, 0xfc, 0xdf, 0x65, 0x20, 0x80]);
    expect([...encodeText("€", "ISO-8859-15")!]).toEqual([0xa4]);
    expect(encodeText("€", "ISO-8859-2")).toBeNull();
    expect([...encodeText("ä😀", "UTF-16LE")!]).toEqual([0xe4, 0x00, 0x3d, 0xd8, 0x00, 0xde]);
    expect(encodeText("x", "Shift_JIS")).toBeNull(); // multi-byte legacy charsets: not here
    expect(isUtf8Of("ä", new TextEncoder().encode("ä"))).toBe(true);
    expect(isUtf8Of("ä", bytes(0xe4))).toBe(false);
  });
});

describe("forms and parameters", () => {
  const enc = (s: string) => new TextEncoder().encode(s);
  it("percent-decodes form bodies in their charset", () => {
    expect(parseForm(enc("name=Gr%C3%BC%C3%9Fe&city=K%C3%B6ln+Mitte&x"), "UTF-8")).toEqual([
      ["name", "Grüße"],
      ["city", "Köln Mitte"],
      ["x", ""],
    ]);
    expect(parseForm(enc("name=Gr%FC%DFe&euro=%80"), "windows-1252")).toEqual([
      ["name", "Grüße"],
      ["euro", "€"],
    ]);
    // Unescaped bytes are in the charset too.
    expect(parseForm(bytes(0x61, 0x3d, 0xfc), "windows-1252")).toEqual([["a", "ü"]]);
  });
  it("finds the form charset", () => {
    expect(formCharset("application/x-www-form-urlencoded; charset=ISO-8859-1", enc("a=1"))).toMatchObject({ name: "windows-1252", source: "header" });
    expect(formCharset("application/x-www-form-urlencoded", enc("_charset_=windows-1252&a=1"))).toMatchObject({ name: "windows-1252", source: "document" });
    expect(formCharset("application/x-www-form-urlencoded", enc("a=1"))).toEqual({ name: "UTF-8", source: "default" });
  });
  it("decodes query strings as UTF-8, legacy bytes as windows-1252", () => {
    expect(parseQuery("?q=Gr%C3%BC%C3%9Fe&w=Gr%FC%DFe")).toEqual([
      ["q", "Grüße"],
      ["w", "Grüße"],
    ]);
  });
  it("decodes RFC 8187 parameters", () => {
    expect(extParams(`attachment; filename="EUR rates.pdf"; filename*=UTF-8''%E2%82%AC%20rates.pdf`)).toEqual([{ name: "filename", language: "", value: "€ rates.pdf" }]);
    expect(extParams(`attachment; filename*=iso-8859-1'de'Gr%FC%DFe.txt`)).toEqual([{ name: "filename", language: "de", value: "Grüße.txt" }]);
    expect(extParams(`attachment; filename="a.txt"`)).toEqual([]);
  });
});

describe("snippets carry the bytes of non-UTF-8 bodies", () => {
  const d = {
    summary: { id: 7, kind: "http" },
    request: { method: "POST", url: "https://x.test/", version: "HTTP/1.1", headers: [["Content-Type", "text/plain; charset=ISO-8859-1"]] },
    requestBody: info({ name: "windows-1252", source: "header" }),
  } as unknown as Detail;
  const latin = bytes(0x47, 0x72, 0xfc, 0xdf, 0x65);
  it("curl", () => {
    expect(buildCurl(d, "Grüße", latin)).toContain(`--data-binary $'Gr\\xfc\\xdfe'`);
    expect(buildCurl(d, "Grüße")).toContain(`--data-binary 'Grüße'`);
  });
  it("fetch and Python", () => {
    expect(buildFetch(d, "Grüße", latin)).toContain("body: new Uint8Array([71, 114, 252, 223, 101])");
    expect(buildPython(d, "Grüße", latin)).toContain(`data=b"Gr\\xfc\\xdfe"`);
  });
});
