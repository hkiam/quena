// A capture of bodies in many character encodings for the encoding e2e test (generated at
// test time). HAR `content.text` is a JavaScript string, so every body goes in as base64 with
// its exact bytes.
const T0 = Date.parse("2026-09-30T10:00:00.000Z");

const utf8 = (s) => Buffer.from(s, "utf8");
const latin1 = (s) => Buffer.from(s, "latin1");
/** windows-1252 for the few characters used here beyond Latin-1. */
const cp1252 = (s) => Buffer.from([...s].map((c) => ({ "€": 0x80, "–": 0x96, "„": 0x84, "“": 0x93 })[c] ?? c.charCodeAt(0)));
const iso885915 = (s) => Buffer.from([...s].map((c) => (c === "€" ? 0xa4 : c.charCodeAt(0))));
const utf16le = (s) => Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(s, "utf16le")]);

function entry(n, url, { type, body, reqType, reqBody }) {
  const b64 = (b) => b.toString("base64");
  return {
    startedDateTime: new Date(T0 + n * 100).toISOString(),
    time: 20,
    request: {
      method: reqBody ? "POST" : "GET",
      url,
      httpVersion: "HTTP/1.1",
      cookies: [],
      headers: [{ name: "User-Agent", value: "quena-e2e" }, ...(reqType ? [{ name: "Content-Type", value: reqType }] : [])],
      queryString: [],
      headersSize: -1,
      bodySize: reqBody ? reqBody.length : 0,
      ...(reqBody ? { postData: { mimeType: reqType, text: b64(reqBody), encoding: "base64" } } : {}),
    },
    response: {
      status: 200,
      statusText: "OK",
      httpVersion: "HTTP/1.1",
      cookies: [],
      headers: type ? [{ name: "Content-Type", value: type }] : [],
      content: { size: body.length, mimeType: type ?? "", text: b64(body), encoding: "base64" },
      redirectURL: "",
      headersSize: -1,
      bodySize: body.length,
    },
    cache: {},
    timings: { blocked: -1, dns: -1, connect: -1, ssl: -1, send: 1, wait: 15, receive: 4 },
  };
}

const MULTIPART =
  "--B\r\nContent-Type: text/plain; charset=ISO-8859-1\r\n\r\n" +
  "LATIN1_PART\r\n--B\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nUTF8_PART\r\n--B--\r\n";

/** The sessions, in list order, with what the test expects to see. */
export const CASES = [
  { path: "json-utf8", text: "Grüße aus Köln 😀", charset: "UTF-8 · default" },
  { path: "plain-latin1", text: "Grüße aus München", charset: "windows-1252 · header" },
  { path: "html-meta", text: "Preis: 5 € – Grüße", charset: "windows-1252 · document" },
  { path: "xml-8859-15", text: "<preis>100 €</preis>", charset: "ISO-8859-15 · document" },
  { path: "utf16le-bom", text: "Grüße in UTF-16 😀", charset: "UTF-16LE · BOM" },
  { path: "utf8-bom", text: "Grüße mit BOM", charset: "UTF-8 · BOM" },
  { path: "form-utf8", form: [["name", "Grüße"], ["city", "Köln"]], charset: "UTF-8 · default" },
  { path: "form-1252", form: [["name", "Grüße"], ["price", "5 €"]], charset: "windows-1252 · header" },
  { path: "multipart", parts: ["Grüße latin1", "Grüße utf8"] },
  { path: "mislabeled", text: "Gr��e falsch deklariert", fixed: "Grüße falsch deklariert", charset: "UTF-8 · header" },
];

export function encodingHar() {
  const u = (p) => `https://enc.test/${p}`;
  const e = [
    entry(0, u("json-utf8"), { type: "application/json", body: utf8(JSON.stringify({ greeting: "Grüße aus Köln 😀" })) }),
    entry(1, u("plain-latin1"), { type: "text/plain; charset=ISO-8859-1", body: latin1("Grüße aus München") }),
    entry(2, u("html-meta"), { type: "text/html", body: cp1252('<!doctype html><html><head><meta charset="windows-1252"><title>t</title></head><body><p>Preis: 5 € – Grüße</p></body></html>') }),
    entry(3, u("xml-8859-15"), { type: "application/xml", body: iso885915('<?xml version="1.0" encoding="ISO-8859-15"?>\n<preis>100 €</preis>') }),
    entry(4, u("utf16le-bom"), { type: "text/plain", body: utf16le("Grüße in UTF-16 😀") }),
    entry(5, u("utf8-bom"), { type: "text/plain", body: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), utf8("Grüße mit BOM")]) }),
    entry(6, u("form-utf8"), { type: "text/plain", body: utf8("ok"), reqType: "application/x-www-form-urlencoded", reqBody: utf8("name=Gr%C3%BC%C3%9Fe&city=K%C3%B6ln") }),
    entry(7, u("form-1252"), { type: "text/plain", body: utf8("ok"), reqType: "application/x-www-form-urlencoded; charset=windows-1252", reqBody: utf8("name=Gr%FC%DFe&price=5+%80") }),
    entry(8, u("multipart"), {
      type: "multipart/mixed; boundary=B",
      body: Buffer.concat(MULTIPART.split(/(LATIN1_PART|UTF8_PART)/).map((s) => (s === "LATIN1_PART" ? latin1("Grüße latin1") : s === "UTF8_PART" ? utf8("Grüße utf8") : utf8(s)))),
    }),
    entry(9, u("mislabeled"), { type: "text/plain; charset=utf-8", body: latin1("Grüße falsch deklariert") }),
  ];
  return { log: { version: "1.2", creator: { name: "quena-e2e", version: "1" }, entries: e } };
}
