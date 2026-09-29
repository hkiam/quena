// SOAP inspector (M12): works on XML bodies and on decoder-plugin output
// (e.g. Fast Infoset → XML) – decoder outputs are chained.
import { useEffect, useMemo, useState } from "react";
import type { Detail, Part, Variant } from "../api";
import { loadText } from "../lib/bodytext";
import { parseXml } from "../lib/xml";
import { fmtBytes, headerValue } from "../lib/format";
import { ROW_CAP, XNode } from "./views";

const SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/";
const SOAP12 = "http://www.w3.org/2003/05/soap-envelope";
const WSA = ["http://www.w3.org/2005/08/addressing", "http://schemas.xmlsoap.org/ws/2004/08/addressing"];
const LIMIT = 8 << 20;

export function soapCandidate(detail: Detail, part: Part): boolean {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const ct = (info.contentType ?? "").toLowerCase();
  if (!info.len) return false;
  if (ct.includes("soap") || ct.includes("fastinfoset")) return true;
  if (part === "request" && headerValue(detail.request.headers, "soapaction")) return true;
  return ct.includes("text/xml") || ct.includes("application/xml");
}

function sourceVariant(detail: Detail, part: Part): Variant {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const fi = info.plugins.find((p) => p.output === "xml");
  if (fi) return fi.variant;
  return info.variants.includes("decoded") ? "decoded" : "raw";
}

function child(el: Element, ns: string, local: string): Element | null {
  for (const c of Array.from(el.children)) if (c.namespaceURI === ns && c.localName === local) return c;
  return null;
}

function text(el: Element | null): string {
  return el?.textContent?.trim() ?? "";
}

export function SoapView({ detail, part }: { detail: Detail; part: Part }) {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const variant = sourceVariant(detail, part);
  const [xml, setXml] = useState<string | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    setXml(null);
    setLoadErr(null);
    if (info.len > LIMIT && !variant.startsWith("plugin:")) return;
    loadText(detail.summary.id, part, info, LIMIT, variant).then(
      (t) => alive && setXml(t),
      (e) => alive && setLoadErr(`Could not load the body: ${String(e)}`),
    );
    return () => {
      alive = false;
    };
  }, [detail.summary.id, part, variant, info.len]);

  const parsed = useMemo(() => {
    if (xml == null) return null;
    const res = parseXml(xml);
    if ("error" in res) return { error: res.error };
    const env = res.root;
    const ns = env.namespaceURI ?? "";
    if (env.localName !== "Envelope" || (ns !== SOAP11 && ns !== SOAP12)) return { error: `Not a SOAP envelope (root element {${ns}}${env.localName}).` };
    const header = child(env, ns, "Header");
    const body = child(env, ns, "Body");
    const blocks = header ? Array.from(header.children) : [];
    const payload = body?.firstElementChild ?? null;
    let fault: { code: string; reason: string; detail: Element | null } | null = null;
    if (payload && payload.namespaceURI === ns && payload.localName === "Fault") {
      if (ns === SOAP11) {
        fault = { code: text(payload.querySelector("faultcode")), reason: text(payload.querySelector("faultstring")), detail: payload.querySelector("detail") };
      } else {
        const code = child(payload, ns, "Code");
        const reason = child(payload, ns, "Reason");
        fault = { code: text(code && child(code, ns, "Value")), reason: text(reason && child(reason, ns, "Text")), detail: child(payload, ns, "Detail") };
      }
    }
    const wsa = (local: string) => blocks.find((b) => WSA.includes(b.namespaceURI ?? "") && b.localName === local);
    return { ns, header, body, blocks, payload, fault, wsa };
  }, [xml]);

  if (info.len > LIMIT && !variant.startsWith("plugin:")) return <div className="placeholder">Body is {fmtBytes(info.len)} – too large for the SOAP view. Use TextView/SyntaxView.</div>;
  if (loadErr) return <div className="placeholder">{loadErr}</div>;
  if (!parsed) return <div className="placeholder">Loading…</div>;
  if ("error" in parsed) return <div className="placeholder">{parsed.error}</div>;
  const { ns, blocks, payload, fault, wsa } = parsed;
  const ctAction = /action="?([^";]+)"?/i.exec(info.contentType ?? "")?.[1];
  const action = (part === "request" ? headerValue(detail.request.headers, "soapaction")?.replace(/^"|"$/g, "") : undefined) || ctAction || text(wsa("Action") ?? null);
  return (
    <div className="scroll pad soap">
      {fault && (
        <div className="banner error soap-fault">
          <b>SOAP Fault</b> {fault.code && <span className="mono">{fault.code}</span>} – {fault.reason || "(no reason)"}
        </div>
      )}
      <table className="kv">
        <tbody>
          <tr>
            <td>SOAP version</td>
            <td>{ns === SOAP11 ? "1.1" : "1.2"}</td>
          </tr>
          {action && (
            <tr>
              <td>Action</td>
              <td className="mono">{action}</td>
            </tr>
          )}
          {payload && (
            <tr>
              <td>Operation</td>
              <td className="mono">
                {payload.localName} <span className="muted">{payload.namespaceURI ? `{${payload.namespaceURI}}` : ""}</span>
              </td>
            </tr>
          )}
          {(["MessageID", "RelatesTo", "To", "ReplyTo"] as const).map((k) => {
            const el = wsa(k);
            return el ? (
              <tr key={k}>
                <td>WS-Addressing {k}</td>
                <td className="mono">{text(el)}</td>
              </tr>
            ) : null;
          })}
          <tr>
            <td>Source</td>
            <td>{variant.startsWith("plugin:") ? `decoded by ${info.plugins.find((p) => p.variant === variant)?.tab}` : variant}</td>
          </tr>
        </tbody>
      </table>
      {blocks.length > 0 && (
        <>
          <h4>Header blocks ({blocks.length}{blocks.length > ROW_CAP ? `, first ${ROW_CAP} shown` : ""})</h4>
          <table className="kv">
            <thead>
              <tr>
                <th>Name</th>
                <th>Namespace</th>
                <th>mustUnderstand</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              {blocks.slice(0, ROW_CAP).map((b, i) => (
                <tr key={i}>
                  <td className="mono">{b.localName}</td>
                  <td className="mono small">{b.namespaceURI}</td>
                  <td>{b.getAttributeNS(ns, "mustUnderstand") ?? ""}</td>
                  <td className="mono small">{text(b).slice(0, 200)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      <h4>Body</h4>
      {fault?.detail && (
        <div className="mono">
          <XNode n={fault.detail} depth={0} />
        </div>
      )}
      {payload ? (
        <div className="mono">
          <XNode n={payload} depth={0} />
        </div>
      ) : (
        <div className="muted">Empty body</div>
      )}
    </div>
  );
}
