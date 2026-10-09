// SAML messages in a session: SAMLRequest / SAMLResponse in the URL (HTTP-Redirect binding,
// deflated), in a form body (HTTP-POST binding) or in the auto-submitting form of an HTML
// answer. Decoded to XML with the facts that matter for debugging a login.
import { parseQuery } from "./http";

export interface SamlMessage {
  name: "SAMLRequest" | "SAMLResponse";
  value: string;
  binding: "redirect" | "post";
  /** RelayState next to it, if any. */
  relay?: string;
}

const NAMES = ["SAMLRequest", "SAMLResponse"] as const;

/** SAML parameters of a URL (`redirect`) and of a urlencoded form body (`post`). */
export function findSaml(url: string, form?: string): SamlMessage[] {
  const out: SamlMessage[] = [];
  const add = (pairs: [string, string][], binding: SamlMessage["binding"]) => {
    const relay = pairs.find(([k]) => k === "RelayState")?.[1];
    for (const [k, v] of pairs) if ((NAMES as readonly string[]).includes(k) && v) out.push({ name: k as SamlMessage["name"], value: v, binding, relay });
  };
  const i = url.indexOf("?");
  if (i >= 0) add(parseQuery(url.slice(i + 1).split("#")[0]), "redirect");
  if (form) add(parseQuery(form.trim()), "post");
  return out;
}

const attr = (tag: string, name: string) => new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`).exec(tag)?.[1];

/** SAML fields of an HTML form that posts them on (an identity provider's answer). */
export function findSamlInHtml(html: string): SamlMessage[] {
  const out: SamlMessage[] = [];
  const inputs = html.match(/<input\b[^>]*>/gi) ?? [];
  const unescape = (v: string) => v.replace(/&#x?[0-9a-f]+;|&[a-z]+;/gi, (e) => entity(e));
  const raw = inputs.map((t) => (attr(t, "name") === "RelayState" ? attr(t, "value") : undefined)).find((x) => x != null);
  const relay = raw == null ? undefined : unescape(raw);
  for (const t of inputs) {
    const name = attr(t, "name");
    const value = attr(t, "value");
    if (name && value && (NAMES as readonly string[]).includes(name)) out.push({ name: name as SamlMessage["name"], value: unescape(value), binding: "post", relay });
  }
  return out;
}

function entity(e: string): string {
  const named: Record<string, string> = { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'" };
  if (named[e]) return named[e];
  const hex = e.startsWith("&#x") || e.startsWith("&#X");
  const n = parseInt(e.slice(hex ? 3 : 2, -1), hex ? 16 : 10);
  return Number.isFinite(n) ? String.fromCodePoint(n) : e;
}

function base64Bytes(s: string): Uint8Array {
  const b = atob(s.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

/** The XML of a message (Redirect binding: raw deflate inflated). */
export async function decodeSaml(m: SamlMessage): Promise<string> {
  const bytes = base64Bytes(m.value);
  if (m.binding === "post") return new TextDecoder().decode(bytes);
  try {
    const stream = new Blob([bytes as BlobPart]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
    return await new Response(stream).text();
  } catch {
    // Some senders do not deflate.
    return new TextDecoder().decode(bytes);
  }
}

const text = (xml: string, local: string) => new RegExp(`<(?:[\\w-]+:)?${local}\\b[^>]*>([\\s\\S]*?)</(?:[\\w-]+:)?${local}>`).exec(xml)?.[1]?.trim();
const tagOf = (xml: string, local: string) => new RegExp(`<(?:[\\w-]+:)?${local}\\b[^>]*>`).exec(xml)?.[0];

/** What a message says: its type, issuer, destination, status, subject, validity, audience,
 * attributes and whether it is signed or encrypted. */
export function samlFacts(xml: string): [string, string][] {
  const out: [string, string][] = [];
  const root = /<(?:[\w-]+:)?(AuthnRequest|Response|LogoutRequest|LogoutResponse|ArtifactResolve|ArtifactResponse)\b[^>]*>/.exec(xml);
  if (root) {
    out.push(["Type", root[1]]);
    for (const a of ["ID", "IssueInstant", "Destination", "AssertionConsumerServiceURL", "InResponseTo", "ProtocolBinding"]) {
      const v = attr(root[0], a);
      if (v) out.push([a, v]);
    }
  }
  const issuer = text(xml, "Issuer");
  if (issuer) out.push(["Issuer", issuer]);
  const status = tagOf(xml, "StatusCode");
  if (status) out.push(["Status", (attr(status, "Value") ?? "").replace(/^urn:oasis:names:tc:SAML:2\.0:status:/, "")]);
  const msg = text(xml, "StatusMessage");
  if (msg) out.push(["StatusMessage", msg]);
  const nameId = text(xml, "NameID");
  if (nameId) out.push(["NameID", nameId]);
  const cond = tagOf(xml, "Conditions");
  if (cond) {
    const nb = attr(cond, "NotBefore");
    const na = attr(cond, "NotOnOrAfter");
    if (nb || na) out.push(["Valid", `${nb ?? "…"} – ${na ?? "…"}`]);
  }
  const aud = text(xml, "Audience");
  if (aud) out.push(["Audience", aud]);
  for (const m of xml.matchAll(/<(?:[\w-]+:)?Attribute\b([^>]*)>([\s\S]*?)<\/(?:[\w-]+:)?Attribute>/g)) {
    const name = attr(m[1], "FriendlyName") ?? attr(m[1], "Name");
    const values = [...m[2].matchAll(/<(?:[\w-]+:)?AttributeValue\b[^>]*>([\s\S]*?)<\/(?:[\w-]+:)?AttributeValue>/g)].map((v) => v[1].trim());
    if (name) out.push([`Attribute ${name}`, values.join(", ")]);
  }
  out.push(["Signed", /<(?:[\w-]+:)?Signature\b/.test(xml) ? "yes" : "no"]);
  if (/<(?:[\w-]+:)?EncryptedAssertion\b/.test(xml)) out.push(["Assertion", "encrypted"]);
  return out;
}
