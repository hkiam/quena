// Text Tools: quick encoders/decoders.
import { useMemo, useState } from "react";
import { b64decode, percentDecodeText, percentEncodeBytes } from "../lib/http";
import { CHARSETS, decodeBytes, encodeText } from "../lib/bodytext";
import { t } from "../i18n";

const OPS = [
  "To Base64",
  "From Base64",
  "URLEncode",
  "URLDecode",
  "HTML Encode",
  "HTML Decode",
  "To Hex",
  "From Hex",
  "JS String Escape",
  "JS String Unescape",
  "Decode JWT",
  "Unix time → Date",
  "UTF-8 bytes",
] as const;

type Op = (typeof OPS)[number];

// The ops are matched in run(); only their labels are translated.
const OP_LABELS: Record<Op, string> = {
  "To Base64": t("To Base64"),
  "From Base64": t("From Base64"),
  "URLEncode": t("URLEncode"),
  "URLDecode": t("URLDecode"),
  "HTML Encode": t("HTML Encode"),
  "HTML Decode": t("HTML Decode"),
  "To Hex": t("To Hex"),
  "From Hex": t("From Hex"),
  "JS String Escape": t("JS String Escape"),
  "JS String Unescape": t("JS String Unescape"),
  "Decode JWT": t("Decode JWT"),
  "Unix time → Date": t("Unix time → Date"),
  "UTF-8 bytes": t("UTF-8 bytes"),
};

/** Byte conversions (Base64, URL encoding, hex) use this charset for the text. */
function run(op: Op, s: string, charset: string): string {
  const enc = new TextEncoder();
  const bytes = () => {
    const b = encodeText(s, charset);
    if (!b) throw new Error(t("The text cannot be encoded in {charset} here.", { charset }));
    return b;
  };
  try {
    switch (op) {
      case "To Base64": {
        let bin = "";
        bytes().forEach((b) => (bin += String.fromCharCode(b)));
        return btoa(bin);
      }
      case "From Base64":
        return b64decode(s.trim(), charset);
      case "URLEncode":
        return percentEncodeBytes(bytes());
      case "URLDecode":
        return percentDecodeText(s, charset);
      case "HTML Encode":
        return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
      case "HTML Decode": {
        const ta = document.createElement("textarea");
        ta.innerHTML = s;
        return ta.value;
      }
      case "To Hex":
        return [...bytes()].map((b) => b.toString(16).padStart(2, "0")).join(" ");
      case "From Hex": {
        const hex = s.replace(/0x/gi, "").replace(/[^0-9a-f]/gi, "").match(/../g) ?? [];
        return decodeBytes(Uint8Array.from(hex.map((h) => parseInt(h, 16))), charset);
      }
      case "JS String Escape":
        return JSON.stringify(s).slice(1, -1);
      case "JS String Unescape":
        return JSON.parse(`"${s.replace(/"/g, '\\"')}"`);
      case "Decode JWT": {
        const [h, p] = s.trim().split(".");
        return `${JSON.stringify(JSON.parse(b64decode(h)), null, 2)}\n\n${JSON.stringify(JSON.parse(b64decode(p)), null, 2)}`;
      }
      case "Unix time → Date": {
        const n = Number(s.trim());
        const ms = n > 1e15 ? n / 1000 : n > 1e12 ? n : n * 1000;
        return `${new Date(ms).toISOString()}\n${new Date(ms).toString()}`;
      }
      case "UTF-8 bytes":
        return [...enc.encode(s)].join(", ");
    }
  } catch (e) {
    return t("Error: {error}", { error: String(e) });
  }
}

/** The decoding that most likely fits `s` (for *Decode…* in context menus). */
export function guessDecode(s: string): Op {
  const v = s.trim();
  if (/^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(v)) return "Decode JWT";
  if (/^\d{10}(\d{3})?$/.test(v)) return "Unix time → Date";
  if (/%[0-9A-Fa-f]{2}/.test(v) || (/\+/.test(v) && /=/.test(v) && /&/.test(v))) return "URLDecode";
  if (/&(#\d+|#x[0-9a-f]+|[a-z]+);/i.test(v)) return "HTML Decode";
  if (/\\(u[0-9a-f]{4}|x[0-9a-f]{2}|[nrt"'\\])/i.test(v)) return "JS String Unescape";
  if (v.length >= 8 && v.length % 2 === 0 && /^[0-9a-f]+$/i.test(v) && /[a-f]/i.test(v) && /\d/.test(v)) return "From Hex";
  return "From Base64";
}

export function TextWizard({ initial }: { initial?: string }) {
  const [input, setInput] = useState(initial ?? "");
  const [op, setOp] = useState<Op>(initial ? guessDecode(initial) : "From Base64");
  const [charset, setCharset] = useState("UTF-8");
  const out = useMemo(() => run(op, input, charset), [op, input, charset]);
  return (
    <div className="textwizard">
      <textarea className="mono" rows={8} value={input} onChange={(e) => setInput(e.target.value)} placeholder={t("Input")} autoFocus />
      <div className="tw-ops">
        {OPS.map((o) => (
          <label key={o} className="f-check">
            <input type="radio" checked={op === o} onChange={() => setOp(o)} /> {OP_LABELS[o]}
          </label>
        ))}
      </div>
      <label className="f-check tw-charset" title={t("Charset of the text for Base64, URL encoding and hex")}>
        {t("Charset")}{" "}
        <select value={charset} onChange={(e) => setCharset(e.target.value)}>
          {CHARSETS.map((c) => (
            <option key={c}>{c}</option>
          ))}
        </select>
      </label>
      <textarea className="mono" rows={8} value={out} readOnly placeholder={t("Output")} />
    </div>
  );
}
