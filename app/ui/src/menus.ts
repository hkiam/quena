import { actions } from "./actions";
import type { MenuItem } from "./components/ContextMenu";
import { get } from "./store";
import { modKey } from "./lib/format";
import { t } from "./i18n";

export function sessionMenu(): MenuItem[] {
  const n = get().selection.size;
  const one = n === 1;
  const scriptMenus = get().scriptMenus;
  const scriptItems: MenuItem[] =
    scriptMenus.length > 0
      ? [
          {
            label: t("Scripts"),
            submenu: scriptMenus.map((label, i) => ({ label, action: () => actions.runScriptMenu(i) })),
          },
          { separator: true },
        ]
      : [];
  return [
    ...scriptItems,
    {
      label: t("Mock Rules"),
      submenu: [
        { label: t("Add Rule"), action: () => import("./panels/autoresponderActions").then((m) => m.addRulesFromSelection()) },
        { label: t("Add Rule (Exact URL)"), action: () => import("./panels/autoresponderActions").then((m) => m.addRulesFromSelection(true)) },
      ],
    },
    {
      label: t("Copy"),
      submenu: [
        { label: t("Just Url"), shortcut: `${modKey}U`, action: () => actions.copySessions("url") },
        { label: t("Summary"), shortcut: `${modKey}C`, action: () => actions.copySessions("summary") },
        { label: t("Headers only"), action: () => actions.copySessions("headers") },
        { label: t("Full Session"), action: () => actions.copySessions("full") },
        { label: t("As cURL"), action: () => actions.copySessions("curl") },
        { label: t("As fetch (JavaScript)"), action: () => actions.copySessions("fetch") },
        { label: t("As PowerShell"), action: () => actions.copySessions("powershell") },
        { label: t("As Python requests"), action: () => actions.copySessions("python") },
      ],
    },
    {
      label: t("Save"),
      submenu: [
        { label: t("Selected Sessions…"), action: () => actions.menu("file.save-selected") },
        { label: t("Request Body…"), disabled: !one, action: () => actions.menu("file.save-request-body") },
        { label: t("Response Body…"), disabled: !one, action: () => actions.menu("file.save-response-body") },
      ],
    },
    {
      label: t("Remove"),
      submenu: [
        { label: t("Selected Sessions"), shortcut: "Del", action: () => actions.removeSelected() },
        { label: t("Unselected Sessions"), shortcut: "Shift+Del", action: () => actions.removeUnselected() },
        { label: t("All Sessions"), shortcut: "Ctrl+X", action: () => actions.removeAll() },
      ],
    },
    {
      label: t("Filter Now"),
      submenu: [
        { label: t("Hide this Host"), action: () => import("./panels/filterActions").then((m) => m.filterNow("hideHost")) },
        { label: t("Show only this Host"), action: () => import("./panels/filterActions").then((m) => m.filterNow("onlyHost")) },
        { label: t("Hide this URL"), action: () => import("./panels/filterActions").then((m) => m.filterNow("hideUrl")) },
        { label: t("Hide this Process"), action: () => import("./panels/filterActions").then((m) => m.filterNow("hideProcess")) },
        { label: t("Show only this Process"), action: () => import("./panels/filterActions").then((m) => m.filterNow("onlyProcess")) },
      ],
    },
    { separator: true },
    { label: t("Comment…"), shortcut: "M", action: () => actions.comment() },
    {
      label: t("Mark"),
      submenu: [
        { label: t("Red"), shortcut: `${modKey}1`, action: () => actions.mark("red") },
        { label: t("Blue"), shortcut: `${modKey}2`, action: () => actions.mark("blue") },
        { label: t("Gold"), shortcut: `${modKey}3`, action: () => actions.mark("gold") },
        { label: t("Green"), shortcut: `${modKey}4`, action: () => actions.mark("green") },
        { label: t("Orange"), shortcut: `${modKey}5`, action: () => actions.mark("orange") },
        { label: t("Purple"), shortcut: `${modKey}6`, action: () => actions.mark("purple") },
        { separator: true },
        { label: t("Unmark"), shortcut: `${modKey}0`, action: () => actions.mark(null) },
      ],
    },
    {
      label: t("Replay"),
      submenu: [
        { label: t("Replay Requests"), shortcut: "R", action: () => import("./replay").then((m) => m.replaySelected({})) },
        { label: t("Replay Unconditionally"), shortcut: "U", action: () => import("./replay").then((m) => m.replaySelected({ unconditional: true })) },
        { label: t("Replay Sequentially…"), shortcut: "Shift+R", action: () => import("./replay").then((m) => m.replaySelected({ repeat: true })) },
        { label: t("Replay and Edit"), action: () => import("./replay").then((m) => m.replaySelected({ breakpoint: true })) },
        { label: t("Replay from Composer"), disabled: !one, action: () => import("./replay").then((m) => m.toComposer()) },
      ],
    },
    {
      label: t("Select"),
      submenu: [
        { label: t("Same Host"), action: () => import("./panels/filterActions").then((m) => m.selectSimilar("host")) },
        { label: t("Same Process"), action: () => import("./panels/filterActions").then((m) => m.selectSimilar("process")) },
        { label: t("Duplicate Requests"), action: () => import("./panels/filterActions").then((m) => m.selectSimilar("url")) },
      ],
    },
    { separator: true },
    { label: t("Compare"), disabled: n !== 2, action: () => import("./panels/compare").then((m) => m.compareSelected()) },
    { label: t("Properties…"), disabled: !one, action: () => import("./panels/properties").then((m) => m.showProperties()) },
  ];
}
