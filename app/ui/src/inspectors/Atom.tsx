// Atom / OData (v2/v3 Atom) inspector: feed, entries, properties, links.
// Works on XML bodies and on decoder-plugin output (e.g. Fast Infoset).
import { useEffect, useMemo, useState } from "react";
import type { Detail, Part, Variant } from "../api";
import { loadText } from "../lib/bodytext";
import { fmtBytes } from "../lib/format";

const ATOM = "http://www.w3.org/2005/Atom";
const ODATA_M = ["http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"];
const ODATA_D = ["http://schemas.microsoft.com/ado/2007/08/dataservices"];
const EDMX = ["http://schemas.microsoft.com/ado/2007/06/edmx", "http://docs.oasis-open.org/odata/ns/edmx"];
const LIMIT = 16 << 20;

export function atomCandidate(detail: Detail, part: Part): boolean {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const ct = (info.contentType ?? "").toLowerCase();
  if (!info.len) return false;
  return ct.includes("atom") || ct.includes("fastinfoset") || ct.includes("xml") || /\$metadata/.test(detail.request.url);
}

function sourceVariant(detail: Detail, part: Part): Variant {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const fi = info.plugins.find((p) => p.output === "xml");
  if (fi) return fi.variant;
  return info.variants.includes("decoded") ? "decoded" : "raw";
}

const kids = (el: Element, ns: string, local: string) => Array.from(el.children).filter((c) => c.namespaceURI === ns && c.localName === local);
const first = (el: Element, ns: string, local: string) => kids(el, ns, local)[0] ?? null;
const txt = (el: Element | null) => el?.textContent?.trim() ?? "";

interface Entry {
  id: string;
  title: string;
  updated: string;
  type: string;
  etag: string;
  edit: string;
  props: { name: string; type: string; value: string; nul: boolean }[];
  links: { rel: string; title: string; href: string; inline: number }[];
}

function readEntry(e: Element): Entry {
  const m = (el: Element, local: string) => Array.from(el.getElementsByTagNameNS("*", local)).find((x) => ODATA_M.includes(x.namespaceURI ?? ""));
  // properties: m:properties in content, or directly in entry (media link entries)
  const content = first(e, ATOM, "content");
  const propsEl = (content && Array.from(content.children).find((c) => c.localName === "properties" && ODATA_M.includes(c.namespaceURI ?? ""))) ?? Array.from(e.children).find((c) => c.localName === "properties" && ODATA_M.includes(c.namespaceURI ?? ""));
  const props = propsEl
    ? Array.from(propsEl.children).map((p) => ({
        name: p.localName,
        type: Array.from(p.attributes).find((a) => a.localName === "type" && ODATA_M.includes(a.namespaceURI ?? ""))?.value ?? "",
        nul: Array.from(p.attributes).some((a) => a.localName === "null" && a.value === "true"),
        value: p.children.length ? p.innerHTML : txt(p),
      }))
    : [];
  const links = kids(e, ATOM, "link").map((l) => ({
    rel: (l.getAttribute("rel") ?? "").replace("http://schemas.microsoft.com/ado/2007/08/dataservices/related/", "→ "),
    title: l.getAttribute("title") ?? "",
    href: l.getAttribute("href") ?? "",
    inline: m(l, "inline") ? m(l, "inline")!.getElementsByTagNameNS(ATOM, "entry").length : 0,
  }));
  return {
    id: txt(first(e, ATOM, "id")),
    title: txt(first(e, ATOM, "title")),
    updated: txt(first(e, ATOM, "updated")),
    type: first(e, ATOM, "category")?.getAttribute("term") ?? "",
    etag: Array.from(e.attributes).find((a) => a.localName === "etag")?.value ?? "",
    edit: kids(e, ATOM, "link").find((l) => l.getAttribute("rel") === "edit")?.getAttribute("href") ?? "",
    props,
    links,
  };
}

export function AtomView({ detail, part }: { detail: Detail; part: Part }) {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const variant = sourceVariant(detail, part);
  const [xml, setXml] = useState<string | null>(null);
  const [sel, setSel] = useState(0);
  useEffect(() => {
    let alive = true;
    setXml(null);
    if (info.len > LIMIT && !variant.startsWith("plugin:")) return;
    loadText(detail.summary.id, part, info, LIMIT, variant).then((t) => alive && setXml(t));
    return () => {
      alive = false;
    };
  }, [detail.summary.id, part, variant, info.len]);

  const parsed = useMemo(() => {
    if (xml == null) return null;
    const doc = new DOMParser().parseFromString(xml, "application/xml");
    if (doc.querySelector("parsererror")) return { error: "The body is not well-formed XML." };
    const root = doc.documentElement;
    if (EDMX.includes(root.namespaceURI ?? "")) {
      const types = Array.from(root.getElementsByTagNameNS("*", "EntityType")).map((t) => ({
        name: t.getAttribute("Name") ?? "",
        keys: Array.from(t.getElementsByTagNameNS("*", "PropertyRef")).map((k) => k.getAttribute("Name")),
        props: Array.from(t.children)
          .filter((c) => c.localName === "Property")
          .map((p) => `${p.getAttribute("Name")}: ${p.getAttribute("Type")}${p.getAttribute("Nullable") === "false" ? "!" : ""}`),
        nav: Array.from(t.children)
          .filter((c) => c.localName === "NavigationProperty")
          .map((p) => p.getAttribute("Name")),
      }));
      const sets = Array.from(root.getElementsByTagNameNS("*", "EntitySet")).map((s) => `${s.getAttribute("Name")} → ${s.getAttribute("EntityType")}`);
      return { kind: "edmx" as const, types, sets, version: root.getAttribute("Version") ?? "" };
    }
    if (root.namespaceURI !== ATOM || (root.localName !== "feed" && root.localName !== "entry")) {
      return { error: `Not an Atom document (root element {${root.namespaceURI}}${root.localName}).` };
    }
    const odata = ODATA_D.concat(ODATA_M).some((n) => xml.includes(n));
    if (root.localName === "entry") return { kind: "feed" as const, odata, feed: null, entries: [readEntry(root)] };
    const count = Array.from(root.children).find((c) => c.localName === "count" && ODATA_M.includes(c.namespaceURI ?? ""));
    return {
      kind: "feed" as const,
      odata,
      feed: {
        id: txt(first(root, ATOM, "id")),
        title: txt(first(root, ATOM, "title")),
        updated: txt(first(root, ATOM, "updated")),
        count: txt(count ?? null),
        next: kids(root, ATOM, "link").find((l) => l.getAttribute("rel") === "next")?.getAttribute("href") ?? "",
        base: root.getAttribute("xml:base") ?? root.getAttributeNS("http://www.w3.org/XML/1998/namespace", "base") ?? "",
      },
      entries: kids(root, ATOM, "entry").map(readEntry),
    };
  }, [xml]);

  if (info.len > LIMIT && !variant.startsWith("plugin:")) return <div className="placeholder">Body is {fmtBytes(info.len)} – too large for the Atom view.</div>;
  if (!parsed) return <div className="placeholder">Loading…</div>;
  if ("error" in parsed) return <div className="placeholder">{parsed.error}</div>;
  const src = variant.startsWith("plugin:") ? `decoded by ${info.plugins.find((p) => p.variant === variant)?.tab}` : variant;

  if (parsed.kind === "edmx") {
    return (
      <div className="scroll pad">
        <div className="muted small">OData service metadata (EDMX {parsed.version}) · {src}</div>
        <h4>Entity sets</h4>
        <ul className="notes">{parsed.sets.map((s) => <li key={s} className="mono">{s}</li>)}</ul>
        <h4>Entity types</h4>
        <table className="kv">
          <thead><tr><th>Type</th><th>Key</th><th>Properties</th><th>Navigation</th></tr></thead>
          <tbody>
            {parsed.types.map((t) => (
              <tr key={t.name}>
                <td className="mono">{t.name}</td>
                <td className="mono">{t.keys.join(", ")}</td>
                <td className="mono small">{t.props.join(" · ")}</td>
                <td className="mono small">{t.nav.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  const { feed, entries, odata } = parsed;
  const cols = Array.from(new Set(entries.flatMap((e) => e.props.map((p) => p.name))));
  const e = entries[Math.min(sel, entries.length - 1)];
  return (
    <div className="scroll pad atom">
      <div className="muted small">
        {odata ? "OData Atom" : "Atom"} {feed ? "feed" : "entry"} · {entries.length} entr{entries.length === 1 ? "y" : "ies"} · {src}
      </div>
      {feed && (
        <table className="kv">
          <tbody>
            <tr><td>Title</td><td>{feed.title}</td></tr>
            <tr><td>Id</td><td className="mono">{feed.id}</td></tr>
            <tr><td>Updated</td><td>{feed.updated}</td></tr>
            {feed.count && <tr><td>$inlinecount</td><td>{feed.count}</td></tr>}
            {feed.next && <tr><td>Next page</td><td className="mono">{feed.next}</td></tr>}
            {feed.base && <tr><td>xml:base</td><td className="mono">{feed.base}</td></tr>}
          </tbody>
        </table>
      )}
      {cols.length > 0 && (
        <>
          <h4>Entries</h4>
          <div className="atom-grid">
            <table className="kv">
              <thead><tr><th>#</th>{cols.map((c) => <th key={c}>{c}</th>)}</tr></thead>
              <tbody>
                {entries.map((en, i) => (
                  <tr key={i} className={i === sel ? "sel" : ""} onClick={() => setSel(i)}>
                    <td>{i + 1}</td>
                    {cols.map((c) => {
                      const p = en.props.find((x) => x.name === c);
                      return <td key={c} className={p?.nul ? "muted" : ""}>{p ? (p.nul ? "null" : p.value) : ""}</td>;
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      {e && (
        <>
          <h4>Entry {sel + 1}{e.type ? ` · ${e.type}` : ""}</h4>
          <table className="kv">
            <tbody>
              {e.id && <tr><td>Id</td><td className="mono">{e.id}</td></tr>}
              {e.edit && <tr><td>Edit link</td><td className="mono">{e.edit}</td></tr>}
              {e.etag && <tr><td>ETag</td><td className="mono">{e.etag}</td></tr>}
              {e.updated && <tr><td>Updated</td><td>{e.updated}</td></tr>}
            </tbody>
          </table>
          <table className="kv">
            <thead><tr><th>Property</th><th>Edm type</th><th>Value</th></tr></thead>
            <tbody>
              {e.props.map((p) => (
                <tr key={p.name}>
                  <td className="mono">{p.name}</td>
                  <td className="mono small">{p.type || "Edm.String"}</td>
                  <td className={p.nul ? "muted" : ""}>{p.nul ? "null" : p.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {e.links.length > 0 && (
            <table className="kv">
              <thead><tr><th>Link</th><th>Title</th><th>href</th><th>Inline</th></tr></thead>
              <tbody>
                {e.links.map((l, i) => (
                  <tr key={i}>
                    <td className="mono small">{l.rel}</td>
                    <td>{l.title}</td>
                    <td className="mono small">{l.href}</td>
                    <td>{l.inline ? `${l.inline} entr${l.inline === 1 ? "y" : "ies"} expanded` : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}
