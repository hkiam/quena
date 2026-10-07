// Before an archive or capture is imported: capturing stops, and the sessions already in the
// list go or stay (asked, or as Settings → General says), so the import is not mixed with
// live traffic by accident.
import { actions } from "../actions";
import { patchSettings } from "../settingsActions";
import { get, say, set } from "../store";
import { t } from "../i18n";

export type ImportChoice = "remove" | "keep";

/** Ask what happens to the sessions in the list; `null`: the import is cancelled. */
function ask(total: number, what: string): Promise<{ choice: ImportChoice; remember: boolean } | null> {
  return new Promise((resolve) => set({ dialog: { kind: "import-existing", total, what, resolve } }));
}

/** Prepare the list for importing `what` (a file name, or a count of files). False: cancelled. */
export async function prepareImport(what: string): Promise<boolean> {
  const total = get().listTotal;
  let choice: ImportChoice = "keep";
  if (total > 0) {
    const pref = get().settings?.importExisting ?? "ask";
    if (pref === "ask") {
      const answer = await ask(total, what);
      if (!answer) return false;
      choice = answer.choice;
      if (answer.remember) await patchSettings((s) => (s.importExisting = answer.choice));
    } else {
      choice = pref;
    }
  }
  if (get().status?.engine.capturing) {
    await actions.toggleCapture();
    if (get().status?.engine.capturing) {
      say(t("Capturing could not be stopped; the import was not started"), "error");
      return false;
    }
  }
  if (choice === "remove" && get().listTotal > 0) await actions.clearSessions();
  return true;
}
