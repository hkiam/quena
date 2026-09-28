// Global shortcuts that are not native menu accelerators (those arrive as
// menu events). Grid-specific keys are handled in actions.gridKey.
import { actions } from "./actions";
import { get, set } from "./store";

export function installGlobalKeys(): () => void {
  const onKey = (e: KeyboardEvent) => {
    const t = e.target as HTMLElement;
    const typing = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable || t.closest(".cm-editor"));
    if (e.key === "Escape" && get().dialog) {
      set({ dialog: null });
      e.preventDefault();
      return;
    }
    if (typing) return;
    // Alt+Q focuses QuickExec (Fiddler).
    if (e.altKey && (e.key === "q" || e.key === "Q" || e.code === "KeyQ")) {
      document.querySelector<HTMLInputElement>(".quickexec input")?.focus();
      e.preventDefault();
    }
    // Ctrl+I focuses inspectors.
    if (e.ctrlKey && (e.key === "i" || e.key === "I")) {
      actions.showTab("inspectors");
      e.preventDefault();
    }
  };
  window.addEventListener("keydown", onKey);
  return () => window.removeEventListener("keydown", onKey);
}
