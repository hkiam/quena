// Atom / OData (v2/v3 Atom) inspector: feed, entries, properties, links.
// Works on XML bodies and on decoder-plugin output (e.g. Fast Infoset).
import { useEffect, useMemo, useState } from "react";
import type { Detail, Part, Variant } from "../api";
import { loadText } from "../lib/bodytext";
import { useCharsetOverride } from "./CharsetPicker";
import { parseXml } from "../lib/xml";
import { fmtBytes, fmtInt } from "../lib/format";
import { MoreRows } from "./views";
import { plural, t } from "../i18n";

const ATOM = "http://www.w3.org/2005/Atom";
const ODATA_M = ["http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"];
const ODATA_D = ["http://schemas.microsoft.com/ado/2007/08/dataservices"];
const EDMX = ["http://schemas.microsoft.com/ado/2007/06/edmx", "http://docs.oasis-open.org/odata/ns/edmx"];
const LIMIT = 16 << 20;
/** Rendered rows / columns before "more" (feeds can hold 100k entries × many properties). */
const ROWS = 500;
const COLS = 60;

export function atomCandidate(detail: Detail, part: Part): boolean {
  const info = part === "request" ? detail.requestBody : detail.responseBody;
  const ct = (info.contentType ?? "").toLowerCase();
  if (!info.len) return false;
  if (info.shape !== undefined && info.isText) return info.shape === "atom" || info.shape === "edmx";
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
  const [override] = useCharsetOverride(detail.summary.id, part);
  const [xml, setXml] = useState<string | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [sel, setSel] = useState(0);
  const [rows, setRows] = useState(ROWS);
  const [propRows, setPropRows] = useState(ROWS);
  useEffect(() => {
    let alive = true;
    setXml(null);
    setLoadErr(null);
    setSel(0);
    setRows(ROWS);
    if (info.len > LIMIT && !variant.startsWith("plugin:")) return;
    loadText(detail.summary.id, part, info, LIMIT, variant, override).then(
      (s) => alive && setXml(s),
      (e) => alive && setLoadErr(t("Could not load the body: {error}", { error: String(e) })),
    );
    return () => {
      alive = false;
    };
  }, [detail.summary.id, part, variant, info.len, override]);

  const parsed = useMemo(() => {
    if (xml == null) return null;
    const res = parseXml(xml);
    if ("error" in res) return { error: res.error };
    const root = res.root;
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
      return { error: t("Not an Atom document (root element {element}).", { element: `{${root.namespaceURI}}${root.localName}` }) };
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

  if (info.len > LIMIT && !variant.startsWith("plugin:")) return <div className="placeholder">{t("Body is {size} – too large for the Atom view.", { size: fmtBytes(info.len) })}</div>;
  if (loadErr) return <div className="placeholder">{loadErr}</div>;
  if (!parsed) return <div className="placeholder">{t("Loading…")}</div>;
  if ("error" in parsed) return <div className="placeholder">{parsed.error}</div>;
  const src = variant.startsWith("plugin:") ? t("decoded by {plugin}", { plugin: info.plugins.find((p) => p.variant === variant)?.tab ?? "" }) : variant === "decoded" ? t("decoded") : t("raw");

  if (parsed.kind === "edmx") {
    return (
      <div className="scroll pad">
        <div className="muted small">{t("OData service metadata (EDMX {version})", { version: parsed.version })} · {src}</div>
        <h4>{t("Entity sets")}</h4>
        <ul className="notes">{parsed.sets.slice(0, rows).map((s, i) => <li key={i} className="mono">{s}</li>)}</ul>
        <MoreRows shown={rows} total={parsed.sets.length} onMore={setRows} step={ROWS} />
        <h4>{t("Entity types")}</h4>
        <table className="kv">
          <thead><tr><th>{t("Type")}</th><th>{t("Key")}</th><th>{t("Properties")}</th><th>{t("Navigation")}</th></tr></thead>
          <tbody>
            {parsed.types.slice(0, rows).map((t, i) => (
              <tr key={i}>
                <td className="mono">{t.name}</td>
                <td className="mono">{t.keys.join(", ")}</td>
                <td className="mono small">{t.props.join(" · ")}</td>
                <td className="mono small">{t.nav.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <MoreRows shown={rows} total={parsed.types.length} onMore={setRows} step={ROWS} />
      </div>
    );
  }
  const { feed, entries, odata } = parsed;
  const allCols = Array.from(new Set(entries.flatMap((e) => e.props.map((p) => p.name))));
  const cols = allCols.slice(0, COLS);
  const e = entries[Math.min(sel, entries.length - 1)];
  return (
    <div className="scroll pad atom">
      <div className="muted small">
        {odata ? "OData Atom" : "Atom"} {feed ? t("feed") : t("entry")} · {plural(entries.length, "{n} entry", "{n} entries")} · {src}
      </div>
      {feed && (
        <table className="kv">
          <tbody>
            <tr><td>{t("Title")}</td><td>{feed.title}</td></tr>
            <tr><td>Id</td><td className="mono">{feed.id}</td></tr>
            <tr><td>{t("Updated")}</td><td>{feed.updated}</td></tr>
            {feed.count && <tr><td>$inlinecount</td><td>{feed.count}</td></tr>}
            {feed.next && <tr><td>{t("Next page")}</td><td className="mono">{feed.next}</td></tr>}
            {feed.base && <tr><td>xml:base</td><td className="mono">{feed.base}</td></tr>}
          </tbody>
        </table>
      )}
      {cols.length > 0 && (
        <>
          <h4>{t("Entries")}</h4>
          {allCols.length > cols.length && <div className="muted small">{t("Showing the first {cols} of {total} properties as columns; select an entry to see all.", { cols: COLS, total: fmtInt(allCols.length) })}</div>}
          <div className="atom-grid">
            <table className="kv">
              <thead><tr><th>#</th>{cols.map((c) => <th key={c}>{c}</th>)}</tr></thead>
              <tbody>
                {entries.slice(0, rows).map((en, i) => {
                  const byName = new Map(en.props.map((x) => [x.name, x]));
                  return (
                    <tr key={i} className={i === sel ? "sel" : ""} onClick={() => { setSel(i); setPropRows(ROWS); }}>
                      <td>{i + 1}</td>
                      {cols.map((c) => {
                        const p = byName.get(c);
                        return <td key={c} className={p?.nul ? "muted" : ""}>{p ? (p.nul ? "null" : p.value) : ""}</td>;
                      })}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <MoreRows shown={rows} total={entries.length} onMore={setRows} step={ROWS} />
        </>
      )}
      {e && (
        <>
          <h4>{t("Entry {n}", { n: sel + 1 })}{e.type ? ` · ${e.type}` : ""}</h4>
          <table className="kv">
            <tbody>
              {e.id && <tr><td>Id</td><td className="mono">{e.id}</td></tr>}
              {e.edit && <tr><td>{t("Edit link")}</td><td className="mono">{e.edit}</td></tr>}
              {e.etag && <tr><td>ETag</td><td className="mono">{e.etag}</td></tr>}
              {e.updated && <tr><td>{t("Updated")}</td><td>{e.updated}</td></tr>}
            </tbody>
          </table>
          <table className="kv">
            <thead><tr><th>{t("Property")}</th><th>{t("Edm type")}</th><th>{t("Value")}</th></tr></thead>
            <tbody>
              {e.props.slice(0, propRows).map((p, i) => (
                <tr key={i}>
                  <td className="mono">{p.name}</td>
                  <td className="mono small">{p.type || "Edm.String"}</td>
                  <td className={p.nul ? "muted" : ""}>{p.nul ? "null" : p.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <MoreRows shown={propRows} total={e.props.length} onMore={setPropRows} step={ROWS} />
          {e.links.length > 0 && (
            <table className="kv">
              <thead><tr><th>{t("Link")}</th><th>{t("Title")}</th><th>href</th><th>{t("Inline")}</th></tr></thead>
              <tbody>
                {e.links.slice(0, ROWS).map((l, i) => (
                  <tr key={i}>
                    <td className="mono small">{l.rel}</td>
                    <td>{l.title}</td>
                    <td className="mono small">{l.href}</td>
                    <td>{l.inline ? plural(l.inline, "{n} entry expanded", "{n} entries expanded") : ""}</td>
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
