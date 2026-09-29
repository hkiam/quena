// Guarded DOMParser use for captured (possibly hostile) XML.

export const XML_ENTITY_NOTE = "XML with entity declarations is shown as text only.";

/** Entity declarations / an internal DTD subset allow entity-expansion bombs; don't parse those. */
export function hasEntityDecl(text: string): boolean {
  return /<!ENTITY/i.test(text) || /<!DOCTYPE[^>[]*\[/i.test(text);
}

/** Parse XML; never throws. `error` is a user-facing message. */
export function parseXml(text: string): { doc: Document; root: Element } | { error: string } {
  if (hasEntityDecl(text)) return { error: XML_ENTITY_NOTE };
  let doc: Document;
  try {
    doc = new DOMParser().parseFromString(text, "application/xml");
  } catch (e) {
    return { error: `Not well-formed XML: ${String(e)}` };
  }
  const err = doc.getElementsByTagName("parsererror")[0];
  if (err) {
    // WebKit wraps the message in markup; keep it short.
    const msg = (err.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, 500);
    return { error: `Not well-formed XML${msg ? `: ${msg}` : "."}` };
  }
  const root = doc.documentElement;
  if (!root) return { error: "Empty XML document." };
  return { doc, root };
}
