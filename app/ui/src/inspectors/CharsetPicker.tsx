// The charset a text view decodes with: the detected one (and where it came from), with a
// menu to override it for this body. Overrides last until another session is selected.
import type { Charset, SessionId } from "../api";
import { CHARSETS, sameCharset } from "../lib/bodytext";
import { set, useStore } from "../store";
import { t } from "../i18n";

/** The user's charset for one body of a session (`key`: "request", "response:part2" …). */
export function useCharsetOverride(id: SessionId, key: string): [string | null, (charset: string | null) => void] {
  const value = useStore((s) => (s.charsetOverrides.id === id ? s.charsetOverrides.map[key] ?? null : null));
  const change = (charset: string | null) =>
    set((s) => {
      const map = s.charsetOverrides.id === id ? { ...s.charsetOverrides.map } : {};
      if (charset) map[key] = charset;
      else delete map[key];
      return { charsetOverrides: { id, map } };
    });
  return [value, change];
}

const SOURCE_LABELS: Record<string, string> = {
  bom: t("BOM"),
  header: t("header"),
  document: t("document"),
  default: t("default"),
};

function tooltip(c: Charset | null | undefined): string {
  const lines = [t("Character encoding used to show this body. Choose another one if characters look wrong.")];
  if (c?.header) lines.push(t("Content-Type: charset={charset}", { charset: c.header }));
  if (c?.document) lines.push(t("Declared in the document: {charset}", { charset: c.document }));
  if (c?.source === "bom") lines.push(t("The body starts with a byte order mark."));
  if (c?.source === "default") lines.push(t("Nothing declared: the default for this type of content."));
  return lines.join("\n");
}

export function CharsetPicker({ detected, value, onChange }: { detected: Charset | null | undefined; value: string | null; onChange: (charset: string | null) => void }) {
  const name = value ?? detected?.name ?? "UTF-8";
  const source = value ? t("chosen") : SOURCE_LABELS[detected?.source ?? "default"] ?? detected?.source ?? "";
  const options = CHARSETS.some((c) => sameCharset(c, name)) ? CHARSETS : [...CHARSETS, name];
  return (
    <span className="cs-pick" title={tooltip(detected)}>
      <span className="cs-label">
        {name} · {source}
      </span>
      <select
        className="cs-select"
        aria-label={t("Character encoding")}
        value={value ? options.find((c) => sameCharset(c, value)) ?? value : ""}
        onChange={(e) => onChange(e.target.value || null)}
      >
        <option value="">{t("Auto")}</option>
        {options.map((c) => (
          <option key={c} value={c}>
            {c}
          </option>
        ))}
      </select>
    </span>
  );
}
