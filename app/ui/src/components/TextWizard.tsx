// Text Tools: quick encoders/decoders.
import { useMemo, useState } from "react";
import { b64decode } from "../lib/http";

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

function run(op: Op, s: string): string {
  const enc = new TextEncoder();
  try {
    switch (op) {
      case "To Base64": {
        let bin = "";
        enc.encode(s).forEach((b) => (bin += String.fromCharCode(b)));
        return btoa(bin);
      }
      case "From Base64":
        return b64decode(s.trim());
      case "URLEncode":
        return encodeURIComponent(s);
      case "URLDecode":
        return decodeURIComponent(s.replace(/\+/g, " "));
      case "HTML Encode":
        return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
      case "HTML Decode": {
        const t = document.createElement("textarea");
        t.innerHTML = s;
        return t.value;
      }
      case "To Hex":
        return [...enc.encode(s)].map((b) => b.toString(16).padStart(2, "0")).join(" ");
      case "From Hex": {
        const bytes = s.replace(/0x/gi, "").replace(/[^0-9a-f]/gi, "").match(/../g) ?? [];
        return new TextDecoder().decode(Uint8Array.from(bytes.map((h) => parseInt(h, 16))));
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
    return `Error: ${e}`;
  }
}

export function TextWizard({ initial }: { initial?: string }) {
  const [input, setInput] = useState(initial ?? "");
  const [op, setOp] = useState<Op>("From Base64");
  const out = useMemo(() => run(op, input), [op, input]);
  return (
    <div className="textwizard">
      <textarea className="mono" rows={8} value={input} onChange={(e) => setInput(e.target.value)} placeholder="Input" autoFocus />
      <div className="tw-ops">
        {OPS.map((o) => (
          <label key={o} className="f-check">
            <input type="radio" checked={op === o} onChange={() => setOp(o)} /> {o}
          </label>
        ))}
      </div>
      <textarea className="mono" rows={8} value={out} readOnly placeholder="Output" />
    </div>
  );
}
