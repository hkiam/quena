// Native menu → actions.
import { api, type GroupBy, type MarkColor } from "./api";
import { actions } from "./actions";
import { get, say, set } from "./store";
import { patchSettings } from "./settingsActions";
import { t } from "./i18n";

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
    case "edit.copy-fetch":
      return actions.copySessions("fetch");
    case "edit.copy-powershell":
      return actions.copySessions("powershell");
    case "edit.copy-python":
      return actions.copySessions("python");
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
      return say(t("Filter updated"));
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
        say(next.auth.enabled ? t("Automatic Authentication enabled") : t("Automatic Authentication disabled"));
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
    case "tools.reverse-proxy":
      return set({ dialog: { kind: "reverse-proxy" } });
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
    case "view.structure":
      return actions.showNavigator(true, "structure");
    case "view.groups":
      return actions.showNavigator(true, "groups");
    case "view.navigator":
      return actions.showNavigator(!get().layout.navOpen);
    case "view.diagnostics":
      return actions.showTab("diagnostics");
    case "view.group-none":
    case "view.group-connection":
    case "view.group-host":
    case "view.group-process":
    case "view.group-trace":
    case "view.group-session":
    case "view.group-custom":
    case "view.group-via":
      return actions.setGroup(id.slice("view.group-".length) as GroupBy);
    case "view.groups-collapse":
      return actions.collapseGroups(true);
    case "view.groups-expand":
      return actions.collapseGroups(false);
    case "view.stacked":
      set((s) => ({ layout: { ...s.layout, stacked: true } }));
      return actions.saveLayout();
    case "view.wide":
      set((s) => ({ layout: { ...s.layout, stacked: false } }));
      return actions.saveLayout();
    case "view.minimize-to-quickexec":
      document.querySelector<HTMLInputElement>(".cmdfield input")?.focus();
      return;
    case "view.jobs":
      return set({ dialog: { kind: "jobs" } });
    case "view.reset-columns":
      return actions.resetColumns();
    case "view.palette":
      return set({ dialog: get().dialog?.kind === "palette" ? null : { kind: "palette" } });
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
    case "help.coming-from":
      return set({ dialog: { kind: "text", title: t("Coming from Fiddler Classic"), text: comingFrom() } });
    case "help.shortcuts":
      return set({ dialog: { kind: "help", topic: "shortcuts" } });
    case "toolbar.decode":
      return patchSettings((s) => (s.decode = !s.decode));
    default: {
      const { handleFileMenu } = await import("./fileActions");
      if (await handleFileMenu(id)) return;
      say(t("'{name}' is not available yet", { name: id }), "error");
    }
  }
}

/** Name mapping for people switching over (descriptive use; see docs/coming-from-fiddler.md). */
const comingFrom = () =>
  t(
    "Quena is an independent project, not affiliated with Progress Software.\nYour files, the filter/command syntax and shortcuts carry over; some features have other names.\n\nFiles\n  .saz session archives     File → Import / Export Sessions → SAZ Archive…\n  .farx AutoResponder rules Mock Rules tab → Import… / Export…\n\nNames\n  QuickExec                 Command field in the toolbar (Alt+Q), palette Cmd/Ctrl+K\n  AutoResponder             Mock Rules\n  Inspectors                Inspect\n  TextView / SyntaxView     Plain Text / Body\n  WebForms / HexView        Form Data / Hex\n  ImageView / WebView       Image / Preview\n  Transformer               Encoding\n  TextWizard                Text Tools (Ctrl/Cmd+E)\n  FiddlerScript             Capture → Rules Script…, JavaScript (Ctrl/Cmd+R)\n  Rules menu                Capture menu; Hide … items under View → Hide in List\n  Reissue …                 Replay …\n  Any Process               Process Filter\n  Hide CONNECTs             View → Hide in List → Tunnels (CONNECT)\n  Result / Body columns     Status / Size columns\n  Reverse proxy (script)    Capture → Reverse Proxy…\n\nLayout\n  Prefer a dense list with the request above the response?\n  Settings → General → Layout: Classic.",
  );
