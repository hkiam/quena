import { actions } from "./actions";
import type { MenuItem } from "./components/ContextMenu";
import { get } from "./store";
import { modKey } from "./lib/format";

export function sessionMenu(): MenuItem[] {
  const n = get().selection.size;
  const one = n === 1;
  const scriptMenus = get().scriptMenus;
  const scriptItems: MenuItem[] =
    scriptMenus.length > 0
      ? [
          {
            label: "Scripts",
            submenu: scriptMenus.map((label, i) => ({ label, action: () => actions.runScriptMenu(i) })),
          },
          { separator: true },
        ]
      : [];
  return [
    ...scriptItems,
    {
      label: "Mock Rules",
      submenu: [
        { label: "Add Rule", action: () => import("./panels/autoresponderActions").then((m) => m.addRulesFromSelection()) },
        { label: "Add Rule (Exact URL)", action: () => import("./panels/autoresponderActions").then((m) => m.addRulesFromSelection(true)) },
      ],
    },
    {
      label: "Copy",
      submenu: [
        { label: "Just Url", shortcut: `${modKey}U`, action: () => actions.copySessions("url") },
        { label: "Summary", shortcut: `${modKey}C`, action: () => actions.copySessions("summary") },
        { label: "Headers only", action: () => actions.copySessions("headers") },
        { label: "Full Session", action: () => actions.copySessions("full") },
        { label: "As cURL", action: () => actions.copySessions("curl") },
        { label: "As fetch (JavaScript)", action: () => actions.copySessions("fetch") },
        { label: "As PowerShell", action: () => actions.copySessions("powershell") },
        { label: "As Python requests", action: () => actions.copySessions("python") },
      ],
    },
    {
      label: "Save",
      submenu: [
        { label: "Selected Sessions…", action: () => actions.menu("file.save-selected") },
        { label: "Request Body…", disabled: !one, action: () => actions.menu("file.save-request-body") },
        { label: "Response Body…", disabled: !one, action: () => actions.menu("file.save-response-body") },
      ],
    },
    {
      label: "Remove",
      submenu: [
        { label: "Selected Sessions", shortcut: "Del", action: () => actions.removeSelected() },
        { label: "Unselected Sessions", shortcut: "Shift+Del", action: () => actions.removeUnselected() },
        { label: "All Sessions", shortcut: "Ctrl+X", action: () => actions.removeAll() },
      ],
    },
    {
      label: "Filter Now",
      submenu: [
        { label: "Hide this Host", action: () => import("./panels/filterActions").then((m) => m.filterNow("hideHost")) },
        { label: "Show only this Host", action: () => import("./panels/filterActions").then((m) => m.filterNow("onlyHost")) },
        { label: "Hide this URL", action: () => import("./panels/filterActions").then((m) => m.filterNow("hideUrl")) },
        { label: "Hide this Process", action: () => import("./panels/filterActions").then((m) => m.filterNow("hideProcess")) },
        { label: "Show only this Process", action: () => import("./panels/filterActions").then((m) => m.filterNow("onlyProcess")) },
      ],
    },
    { separator: true },
    { label: "Comment…", shortcut: "M", action: () => actions.comment() },
    {
      label: "Mark",
      submenu: [
        { label: "Red", shortcut: `${modKey}1`, action: () => actions.mark("red") },
        { label: "Blue", shortcut: `${modKey}2`, action: () => actions.mark("blue") },
        { label: "Gold", shortcut: `${modKey}3`, action: () => actions.mark("gold") },
        { label: "Green", shortcut: `${modKey}4`, action: () => actions.mark("green") },
        { label: "Orange", shortcut: `${modKey}5`, action: () => actions.mark("orange") },
        { label: "Purple", shortcut: `${modKey}6`, action: () => actions.mark("purple") },
        { separator: true },
        { label: "Unmark", shortcut: `${modKey}0`, action: () => actions.mark(null) },
      ],
    },
    {
      label: "Replay",
      submenu: [
        { label: "Replay Requests", shortcut: "R", action: () => import("./replay").then((m) => m.replaySelected({})) },
        { label: "Replay Unconditionally", shortcut: "U", action: () => import("./replay").then((m) => m.replaySelected({ unconditional: true })) },
        { label: "Replay Sequentially…", shortcut: "Shift+R", action: () => import("./replay").then((m) => m.replaySelected({ repeat: true })) },
        { label: "Replay and Edit", action: () => import("./replay").then((m) => m.replaySelected({ breakpoint: true })) },
        { label: "Replay from Composer", disabled: !one, action: () => import("./replay").then((m) => m.toComposer()) },
      ],
    },
    {
      label: "Select",
      submenu: [
        { label: "Same Host", action: () => import("./panels/filterActions").then((m) => m.selectSimilar("host")) },
        { label: "Same Process", action: () => import("./panels/filterActions").then((m) => m.selectSimilar("process")) },
        { label: "Duplicate Requests", action: () => import("./panels/filterActions").then((m) => m.selectSimilar("url")) },
      ],
    },
    { separator: true },
    { label: "Compare", disabled: n !== 2, action: () => import("./panels/compare").then((m) => m.compareSelected()) },
    { label: "Properties…", disabled: !one, action: () => import("./panels/properties").then((m) => m.showProperties()) },
  ];
}
