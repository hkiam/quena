import { describe, expect, it } from "vitest";
import { decodeSaml, findSaml, findSamlInHtml, samlFacts } from "./saml";

const RESPONSE = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" InResponseTo="_q1" Destination="https://sp.example.com/acs" IssueInstant="2026-10-01T10:00:00Z">
<saml:Issuer>https://idp.example.com</saml:Issuer>
<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
<saml:Assertion><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>
<saml:Subject><saml:NameID>jo@example.com</saml:NameID></saml:Subject>
<saml:Conditions NotBefore="2026-10-01T09:59:00Z" NotOnOrAfter="2026-10-01T10:05:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction></saml:Conditions>
<saml:AttributeStatement><saml:Attribute Name="groups"><saml:AttributeValue>dev</saml:AttributeValue><saml:AttributeValue>ops</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
</saml:Assertion></samlp:Response>`;

describe("SAML", () => {
  it("finds messages in URLs, form bodies and HTML forms", () => {
    const m = findSaml("https://idp.example.com/sso?SAMLRequest=abc%2B&RelayState=xyz");
    expect(m).toEqual([{ name: "SAMLRequest", value: "abc+", binding: "redirect", relay: "xyz" }]);
    expect(findSaml("https://sp/acs", "SAMLResponse=PHg%2B&RelayState=r")[0]).toMatchObject({ binding: "post", value: "PHg+", relay: "r" });
    const html = `<form method="post"><input type="hidden" name="SAMLResponse" value="PHg+PC94Pg=="/><input type="hidden" name="RelayState" value="a&amp;b"/></form>`;
    expect(findSamlInHtml(html)).toEqual([{ name: "SAMLResponse", value: "PHg+PC94Pg==", binding: "post", relay: "a&b" }]);
    expect(findSaml("https://x/?q=1")).toEqual([]);
  });
  it("decodes the POST binding and reads the facts", async () => {
    const value = btoa(RESPONSE);
    const xml = await decodeSaml({ name: "SAMLResponse", value, binding: "post" });
    const f = Object.fromEntries(samlFacts(xml));
    expect(f.Type).toBe("Response");
    expect(f.Issuer).toBe("https://idp.example.com");
    expect(f.Status).toBe("Success");
    expect(f.NameID).toBe("jo@example.com");
    expect(f.Valid).toBe("2026-10-01T09:59:00Z – 2026-10-01T10:05:00Z");
    expect(f.Audience).toBe("https://sp.example.com");
    expect(f["Attribute groups"]).toBe("dev, ops");
    expect(f.Signed).toBe("yes");
    expect(f.InResponseTo).toBe("_q1");
  });
  it("inflates the Redirect binding", async () => {
    const xml = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_q1" Destination="https://idp/sso"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp</saml:Issuer></samlp:AuthnRequest>';
    const deflated = new Uint8Array(await new Response(new Blob([xml]).stream().pipeThrough(new CompressionStream("deflate-raw"))).arrayBuffer());
    const value = btoa(String.fromCharCode(...deflated));
    const out = await decodeSaml({ name: "SAMLRequest", value, binding: "redirect" });
    expect(out).toBe(xml);
    expect(Object.fromEntries(samlFacts(out)).Type).toBe("AuthnRequest");
  });
});
