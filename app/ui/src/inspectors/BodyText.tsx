// Chooses the right text viewer for a body: CodeMirror for small/medium
// bodies, the virtualised LargeTextView for big or still-growing ones.
import { useEffect, useState } from "react";
import { api, fetchBody, type BodyInfo, type Part, type SessionId, type Variant } from "../api";
import { CodeView, langFor } from "./CodeView";
import { LargeTextView } from "./LargeTextView";
import { decodeText } from "../lib/bodytext";
import { fmtBytes } from "../lib/format";

/** Bodies up to this size (after decoding) go into CodeMirror. */
export const CODEMIRROR_LIMIT = 8 << 20;

export function BodyText({
  id,
  part,
  info,
  variant,
  highlight,
  wrap,
}: {
  id: SessionId;
  part: Part;
  info: BodyInfo;
  variant: Variant;
  highlight: boolean;
  wrap: boolean;
}) {
  const [state, setState] = useState<{ mode: "loading" | "small" | "large"; text?: string; note?: string }>({ mode: "loading" });

  useEffect(() => {
    let alive = true;
    const ctl = new AbortController();
    let timer: number | undefined;
    setState({ mode: "loading" });
    const decide = async () => {
      try {
        const v = await api.bodyOpen(id, part, variant);
        if (!alive) return;
        if (v.len > CODEMIRROR_LIMIT || (!v.complete && v.len > 256 * 1024) || (!info.complete && part === "response")) {
          setState({ mode: "large" });
          return;
        }
        if (!v.complete) {
          timer = window.setTimeout(decide, 100);
          return;
        }
        const r = await fetchBody(id, part, variant, 0, v.len, ctl.signal);
        if (!alive) return;
        setState({ mode: "small", text: decodeText(r.data), note: v.error ?? undefined });
      } catch (e) {
        if (alive && !(e instanceof DOMException)) setState({ mode: "small", text: "", note: String(e) });
      }
    };
    decide();
    return () => {
      alive = false;
      ctl.abort();
      window.clearTimeout(timer);
    };
  }, [id, part, variant, info.complete, info.len]);

  if (state.mode === "loading") return <div className="placeholder">Loading {fmtBytes(info.len)}…</div>;
  if (state.mode === "large") return <LargeTextView id={id} part={part} variant={variant} wrap={wrap} />;
  return (
    <div className="bodytext">
      {state.note && <div className="banner error">{state.note}</div>}
      <CodeView text={state.text ?? ""} lang={highlight ? langFor(info.contentType) : "text"} wrap={wrap} highlight={highlight} />
    </div>
  );
}
