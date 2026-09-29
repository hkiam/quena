// CodeMirror 6 wrapper for small and medium bodies (read-only unless editable).
// The editor (~250 KB) loads on first use, so it is not part of the startup bundle.
import { lazy, Suspense } from "react";

export type Lang = "json" | "xml" | "html" | "js" | "css" | "text";

export function langFor(contentType: string | null | undefined): Lang {
  const ct = (contentType ?? "").toLowerCase();
  if (ct.includes("json")) return "json";
  if (ct.includes("html")) return "html";
  if (ct.includes("xml") || ct.includes("soap")) return "xml";
  if (ct.includes("javascript") || ct.includes("ecmascript")) return "js";
  if (ct.includes("css")) return "css";
  return "text";
}

const Impl = lazy(() => import("./CodeViewImpl").then((m) => ({ default: m.CodeView })));

export function CodeView(props: { text: string; lang?: Lang; wrap?: boolean; editable?: boolean; highlight?: boolean; onChange?: (t: string) => void }) {
  return (
    <Suspense fallback={<div className="codeview" />}>
      <Impl {...props} />
    </Suspense>
  );
}
