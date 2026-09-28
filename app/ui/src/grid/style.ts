// Fiddler Classic row colouring and icons.
import { Flags, type SessionSummary } from "../api";

export interface Palette {
  bg: string;
  bgAlt: string;
  fg: string;
  muted: string;
  red: string;
  blue: string;
  green: string;
  purple: string;
  gray: string;
  selBg: string;
  selFg: string;
  selInactiveBg: string;
  focus: string;
  grid: string;
  marks: Record<string, string>;
  markFg: Record<string, string>;
}

export function readPalette(el: HTMLElement): Palette {
  const cs = getComputedStyle(el);
  const v = (n: string) => cs.getPropertyValue(n).trim();
  return {
    bg: v("--grid-bg"),
    bgAlt: v("--grid-bg-alt"),
    fg: v("--fg"),
    muted: v("--muted"),
    red: v("--row-red"),
    blue: v("--row-blue"),
    green: v("--row-green"),
    purple: v("--row-purple"),
    gray: v("--row-gray"),
    selBg: v("--sel-bg"),
    selFg: v("--sel-fg"),
    selInactiveBg: v("--sel-inactive-bg"),
    focus: v("--focus"),
    grid: v("--grid-line"),
    marks: {
      red: v("--mark-red"),
      blue: v("--mark-blue"),
      gold: v("--mark-gold"),
      green: v("--mark-green"),
      orange: v("--mark-orange"),
      purple: v("--mark-purple"),
    },
    markFg: {
      red: v("--markfg-red"),
      blue: v("--markfg-blue"),
      gold: v("--markfg-gold"),
      green: v("--markfg-green"),
      orange: v("--markfg-orange"),
      purple: v("--markfg-purple"),
    },
  };
}

export interface RowStyle {
  fg: string;
  bold: boolean;
  bg: string | null;
  italic: boolean;
}

export function rowStyle(r: SessionSummary, p: Palette): RowStyle {
  const ct = r.contentType.toLowerCase();
  let fg = p.fg;
  let bold = false;
  let italic = false;
  if (r.state === "breakpointRequest" || r.state === "breakpointResponse") {
    return { fg: p.red, bold: true, bg: p.marks.red, italic: false };
  }
  if (r.kind === "tunnel") fg = p.gray;
  else if (r.state === "aborted") fg = p.red;
  else if (r.status >= 400) fg = p.red;
  else if (r.status === 304) fg = p.gray;
  else if (ct.includes("html")) fg = p.blue;
  else if (ct.includes("javascript") || ct.includes("ecmascript")) fg = p.green;
  else if (ct.includes("css")) fg = p.purple;
  else if (ct.startsWith("image/")) fg = p.gray;
  if (r.state !== "done" && r.state !== "aborted") italic = true;
  let bg: string | null = null;
  if (r.color) {
    bg = p.marks[r.color];
    fg = p.markFg[r.color] || fg;
    bold = true;
  }
  return { fg, bold, bg, italic };
}

export interface Icon {
  glyph: string;
  color: string;
}

export function rowIcon(r: SessionSummary, p: Palette): Icon {
  const ct = r.contentType.toLowerCase();
  switch (r.state) {
    case "breakpointRequest":
      return { glyph: "⏸", color: p.red };
    case "breakpointResponse":
      return { glyph: "⏸", color: p.red };
    case "requestHeaders":
    case "sendingRequest":
      return { glyph: "↑", color: p.blue };
    case "awaitingResponse":
      return { glyph: "⋯", color: p.blue };
    case "receivingResponse":
      return { glyph: "↓", color: p.green };
    case "aborted":
      return { glyph: "✕", color: p.red };
  }
  if (r.kind === "tunnel") return { glyph: "🔒︎", color: p.gray };
  if (r.kind === "webSocket") return { glyph: "⇅", color: p.purple };
  if (r.flags & Flags.AUTO_RESPONDED) return { glyph: "⚡", color: p.purple };
  if (r.status >= 400) return { glyph: "⚠", color: p.red };
  if (r.status === 304) return { glyph: "↻", color: p.gray };
  if (r.status >= 300 && r.status < 400) return { glyph: "↪", color: p.muted };
  if (ct.includes("html")) return { glyph: "◧", color: p.blue };
  if (ct.includes("json")) return { glyph: "{}", color: p.fg };
  if (ct.includes("xml") || ct.includes("soap")) return { glyph: "‹›", color: p.purple };
  if (ct.includes("javascript")) return { glyph: "ʃ", color: p.green };
  if (ct.includes("css")) return { glyph: "#", color: p.purple };
  if (ct.startsWith("image/")) return { glyph: "▣", color: p.gray };
  if (ct.startsWith("font/") || ct.includes("woff")) return { glyph: "A", color: p.gray };
  if (r.status === 0) return { glyph: "·", color: p.muted };
  return { glyph: "◇", color: p.muted };
}
