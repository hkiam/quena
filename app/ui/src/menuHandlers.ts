// Native menu → actions.
import { api, type MarkColor } from "./api";
import { actions } from "./actions";
import { get, say, set } from "./store";
import { patchSettings } from "./settingsActions";

export async function handleMenu(id: string) {
  if (id.startsWith("edit.mark-")) return actions.mark(id.slice(10) as MarkColor);
  switch (id) {
    case "file.capture":
      return actions.toggleCapture();
    case "file.recover":
      return set({ dialog: { kind: "recover" } });
    case "edit.copy-url":
      return actions.copySessions("url");
    case "edit.copy-summary":
      return actions.copySessions("summary");
    case "edit.copy-headers":
      return actions.copySessions("headers");
    case "edit.copy-full":
      return actions.copySessions("full");
    case "edit.copy-curl":
      return actions.copySessions("curl");
    case "edit.remove-selected":
      return actions.removeSelected();
    case "edit.remove-unselected":
      return actions.removeUnselected();
    case "edit.remove-all":
      return actions.removeAll();
    case "edit.unmark":
      return actions.mark(null);
    case "edit.comment":
      return actions.comment();
    case "edit.find":
      return set({ dialog: { kind: "find" } });
    case "rules.hide-connects":
    case "rules.hide-images":
    case "rules.hide-304": {
      const f = { ...(await api.getFilters()), enabled: true };
      if (id === "rules.hide-connects") f.hideConnects = !f.hideConnects;
      if (id === "rules.hide-images") f.hideImages = !f.hideImages;
      if (id === "rules.hide-304") f.hideNotModified = !f.hideNotModified;
      await api.setFilters(f);
      set({ filters: f });
      return say("Filter updated");
    }
    case "rules.bp-before":
      return import("./breakpoints").then((m) => m.setAuto("before"));
    case "rules.bp-after":
      return import("./breakpoints").then((m) => m.setAuto("after"));
    case "rules.bp-off":
      return import("./breakpoints").then((m) => m.setAuto("off"));
    case "rules.auto-auth": {
      const st = get().settings;
      if (st) {
        const next = { ...st, auth: { ...st.auth, enabled: !st.auth.enabled } };
        set({ settings: next });
        await api.settingsSet(next);
        say(next.auth.enabled ? "Automatic Authentication enabled" : "Automatic Authentication disabled");
      }
      return;
    }
    case "rules.customize":
      return set({ dialog: { kind: "rules" } });
    case "tools.options":
      return set({ dialog: { kind: "options" } });
    case "tools.https":
      return set({ dialog: { kind: "https" } });
    case "tools.connect-device":
      return set({ dialog: { kind: "connect-device" } });
    case "tools.textwizard":
      return set({ dialog: { kind: "textwizard" } });
    case "tools.composer":
    case "view.composer":
      return actions.showTab("composer");
    case "tools.plugins":
      return set({ dialog: { kind: "plugins" } });
    case "view.statistics":
      return actions.showTab("statistics");
    case "view.inspectors":
      return actions.showTab("inspectors");
    case "view.autoresponder":
      return actions.showTab("autoresponder");
    case "view.filters":
      return actions.showTab("filters");
    case "view.log":
      return actions.showTab("log");
    case "view.timeline":
      return actions.showTab("timeline");
    case "view.stacked":
      set((s) => ({ layout: { ...s.layout, stacked: true } }));
      return actions.saveLayout();
    case "view.wide":
      set((s) => ({ layout: { ...s.layout, stacked: false } }));
      return actions.saveLayout();
    case "view.minimize-to-quickexec":
      document.querySelector<HTMLInputElement>(".quickexec input")?.focus();
      return;
    case "view.jobs":
      return set({ dialog: { kind: "jobs" } });
    case "dev.mock-1k":
      return api.mockStart(5000, 1000);
    case "dev.mock-100k":
      return api.mockStart(50000, 100_000);
    case "dev.mock-500k":
      return api.mockStart(100000, 500_000);
    case "dev.mock-stream":
      return api.mockStart(5000, 0);
    case "dev.mock-stop":
      return api.mockStop();
    case "dev.mock-big":
      return api.mockBig(1);
    case "dev.mock-huge":
      return api.mockBig(10);
    case "dev.overlay":
      return set({ overlay: !get().overlay });
    case "dev.reload":
      return location.reload();
    case "help.quickexec":
      return set({ dialog: { kind: "help", topic: "quickexec" } });
    case "help.shortcuts":
      return set({ dialog: { kind: "help", topic: "shortcuts" } });
    case "toolbar.decode":
      return patchSettings((s) => (s.decode = !s.decode));
    default: {
      const { handleFileMenu } = await import("./fileActions");
      if (await handleFileMenu(id)) return;
      say(`'${id}' is not available yet`, "error");
    }
  }
}
