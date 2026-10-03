// End-to-end tests: start the real Quena app (tauri-driver + WebKitWebDriver on Linux) with an
// isolated data directory and a HAR file, and drive the UI like a user would.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { Driver } from "./webdriver.mjs";
import { AUDIT, checkPluginsDialog } from "./audit.mjs";
import path from "node:path";

const app = process.env.QUENA_APP;
const har = path.resolve(import.meta.dirname, "fixtures/two-sessions.har");
const d = new Driver();
// The visible view tabs of an inspector pane (not the hidden copy used for measuring).
const VIEW_SEGS = ".view-tabs > .segmented:not(.view-tabs-measure) .seg";

before(async () => {
  assert.ok(app, "QUENA_APP must point to the built quena binary");
  await d.start(app, [har]);
});
after(() => d.quit());

test("starts and lists the sessions of the HAR passed on the command line", async () => {
  await d.waitFor(".statusbar", { text: "4 sessions", timeout: 20000 });
  await d.waitFor(".capture-switch");
});

test("selecting a session shows its URL, headers and pretty JSON body", async () => {
  const canvas = await d.waitFor(".grid-canvas");
  await d.clickAt(canvas, 80, 12); // first row
  await d.waitFor(".insp-url", { text: "https://api.example.com/v1/items?page=2" });
  // Request headers table (wire order) …
  await d.waitFor(".hv-table", { text: "quena-e2e" });
  // … and the response body, loaded lazily with the editor.
  const panes = await d.findAll(".insp-pane"); // request, response
  for (const b of await d.findIn(panes[1], VIEW_SEGS)) if ((await d.text(b)) === "Body") await d.click(b);
  await d.waitFor(".cm-content", { text: '"items"' });
});

test("the header filter narrows the table", async () => {
  const filter = await d.waitFor(".hv-filter");
  await d.type(filter, "user-agent");
  await d.waitFor(".hv-table", { text: (t) => t.includes("quena-e2e") && !t.includes("application/json") });
});

test("Ctrl+F opens Find Sessions, Escape closes it", async () => {
  await d.keys(["Control", "f"]);
  await d.waitFor(".modal-title", { text: "Find Sessions" });
  await d.keys(["Escape"]);
  const end = Date.now() + 3000;
  while ((await d.findAll(".modal-title")).length && Date.now() < end) await new Promise((r) => setTimeout(r, 100));
  assert.equal((await d.findAll(".modal-title")).length, 0, "dialog still open");
});

test("settings open with readable tabs", async () => {
  await d.click(await d.waitFor('button[title="Settings"]'));
  await d.waitFor(".modal-title", { text: "Options" });
  const tabs = [];
  for (const t of await d.findAll(".tabs-row .insp-tab")) tabs.push(await d.text(t));
  assert.ok(tabs.length >= 4, `tabs: ${tabs}`);
  assert.equal(new Set(tabs).size, tabs.length, `duplicate tabs: ${tabs}`);
  // Titles must not run into each other (regression: missing spacing).
  const rects = [];
  for (const t of await d.findAll(".tabs-row .insp-tab")) rects.push(await d.rect(t));
  for (let i = 1; i < rects.length; i++) assert.ok(rects[i].x >= rects[i - 1].x + rects[i - 1].width, "tabs overlap");
  await d.keys(["Escape"]);
});

test("the plugins dialog keeps its columns readable", async () => {
  await checkPluginsDialog(d, assert);
  await d.cmd("POST", d.s("/window/rect"), { width: 1920, height: 1080 });
});

test("live traffic through the proxy appears in the list", async () => {
  const status = await d.text(await d.waitFor(".sb-capture", { text: "Proxy 127.0.0.1:" }));
  const port = Number(status.match(/127\.0\.0\.1:(\d+)/)[1]);
  // A tiny local server, requested through Quena.
  const http = await import("node:http");
  const server = http.createServer((_, res) => res.end("hello from e2e")).listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const target = `http://127.0.0.1:${server.address().port}/live-check`;
  const body = await new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: target, headers: { Host: `127.0.0.1:${server.address().port}` } }, (res) => {
      let b = "";
      res.on("data", (c) => (b += c));
      res.on("end", () => resolve(b));
    });
    req.on("error", reject);
    req.end();
  });
  server.close();
  assert.equal(body, "hello from e2e");
  await d.waitFor(".statusbar", { text: "5 sessions" });
});

test("command field: =403 selects the forbidden request", async () => {
  const field = await d.waitFor(".cmdfield input");
  await d.type(field, "=403\uE007");
  await d.waitFor(".insp-url", { text: "/v1/items/7" });
});

test("capture switch toggles off and on", async () => {
  const sw = await d.waitFor(".capture-switch", { text: "Capturing" });
  await d.click(sw);
  await d.waitFor(".capture-switch", { text: "Paused" });
  await d.click(await d.waitFor(".capture-switch"));
  await d.waitFor(".capture-switch", { text: "Capturing" });
});

const ROW = 24; // session list row height (Quena layout)
const selectRow = async (n) => d.clickAt(await d.waitFor(".grid-canvas"), 80, 12 + ROW * (n - 1));
const activeView = async (pane) => {
  const panes = await d.findAll(".insp-pane");
  for (const b of await d.findIn(panes[pane], `${VIEW_SEGS}.active`)) return d.text(b);
  return null;
};
const chooseView = async (pane, label) => {
  const panes = await d.findAll(".insp-pane");
  for (const b of await d.findIn(panes[pane], VIEW_SEGS)) if ((await d.text(b)) === label) return d.click(b);
  throw new Error(`view ${label} not shown directly in pane ${pane}`);
};

test("views: as many as fit are shown directly, More only holds the rest", async () => {
  // The flat strip (all views in one row), still available as an option.
  await d.exec(`window.__quena.setLayout({ stacked: true, leftWidth: 0.4, inspectorTabs: "flat" })`);
  for (const [width, height] of [[1920, 1080], [1100, 700]]) {
    await d.cmd("POST", d.s("/window/rect"), { width, height });
    await selectRow(1);
    await new Promise((r) => setTimeout(r, 400));
    const res = await d.exec(`
      const pane = document.querySelectorAll('.insp-pane')[1];
      const wrap = pane.querySelector('.view-tabs').getBoundingClientRect();
      const segs = [...pane.querySelectorAll('.view-tabs > .segmented:not(.view-tabs-measure) .seg')].map((e) => e.getBoundingClientRect());
      const more = pane.querySelector('.view-tabs > .seg-more');
      const all = pane.querySelectorAll('.view-tabs-measure .seg:not(.seg-more)').length;
      const overlap = segs.some((r, i) => i && r.left < segs[i - 1].right - 0.5);
      const outside = segs.some((r) => r.right > wrap.right + 0.5 || r.left < wrap.left - 0.5) || (more && more.getBoundingClientRect().right > wrap.right + 0.5);
      return { shown: segs.length, all, more: !!more, overlap, outside, width: Math.round(wrap.width) };`);
    assert.ok(!res.overlap && !res.outside, `tabs overlap or overflow at ${width}px: ${JSON.stringify(res)}`);
    assert.equal(res.more, res.shown < res.all, `More must appear exactly when views are hidden: ${JSON.stringify(res)}`);
    if (width === 1920) assert.ok(res.shown >= 10, `a wide pane should show most views directly: ${JSON.stringify(res)}`);
  }
  await d.exec(`window.__quena.setLayout({ stacked: false, leftWidth: 0.5 })`);
  await d.cmd("POST", d.s("/window/rect"), { width: 1920, height: 1080 });
});

test("views: sensible default per content, and the choice is remembered per kind of content", async () => {
  await d.exec(`window.__quena.setLayout({ viewByType: {}, rememberViews: true, stacked: true, inspectorTabs: "flat" })`);
  await selectRow(3); // SOAP
  await d.waitFor(".insp-url", { text: "GetOrder" });
  assert.equal(await activeView(1), "SOAP", "SOAP responses open in the SOAP view");
  await selectRow(1); // JSON
  await d.waitFor(".insp-url", { text: "v1/items" });
  assert.equal(await activeView(1), "Body", "JSON responses open formatted");
  // Choose XML for SOAP: every SOAP message now opens as XML, JSON keeps Body.
  await selectRow(3);
  await d.waitFor(".insp-url", { text: "GetOrder" });
  await chooseView(1, "XML");
  await selectRow(4);
  await d.waitFor(".insp-url", { text: "GetCustomer" });
  assert.equal(await activeView(1), "XML", "choice not remembered for SOAP");
  await selectRow(1);
  await d.waitFor(".insp-url", { text: "v1/items" });
  assert.equal(await activeView(1), "Body", "JSON must not follow the SOAP choice");
  // Request and response are remembered separately.
  await selectRow(4);
  await d.waitFor(".insp-url", { text: "GetCustomer" });
  assert.equal(await activeView(0), "SOAP", "the request side keeps its own default");
  // Turned off: the last view chosen applies everywhere (classic behaviour).
  await d.exec(`window.__quena.setLayout({ rememberViews: false })`);
  await chooseView(1, "Raw");
  await selectRow(1);
  await d.waitFor(".insp-url", { text: "v1/items" });
  assert.equal(await activeView(1), "Raw");
  await d.exec(`window.__quena.setLayout({ rememberViews: true, viewByType: {}, stacked: false, inspectorTabs: "grouped" })`);
});

test("grouped views: sections first, then the views that fit the body", async () => {
  await d.exec(`window.__quena.setLayout({ viewByType: {}, subViews: {}, rememberViews: true, stacked: true, inspectorTabs: "grouped" })`);
  const rows = (pane) =>
    d.exec(
      `const p = document.querySelectorAll('.insp-pane')[arguments[0]];
       const segs = (sel) => [...p.querySelectorAll(sel + ' > .segmented:not(.view-tabs-measure) .seg')];
       const label = (e) => e.firstChild ? e.firstChild.textContent : e.textContent;
       return { sections: segs('.view-sections').map(label), section: segs('.view-sections').filter((e) => e.classList.contains('active')).map(label)[0] ?? null,
                views: segs('.view-sub').map(label), view: segs('.view-sub').filter((e) => e.classList.contains('active')).map(label)[0] ?? null,
                other: !!p.querySelector('.view-sub > .seg-more') };`,
      [pane],
    );
  const pick = async (pane, sel, label) => {
    const panes = await d.findAll(".insp-pane");
    for (const b of await d.findIn(panes[pane], `${sel} > .segmented:not(.view-tabs-measure) .seg`)) if ((await d.text(b)).startsWith(label)) return d.click(b);
    throw new Error(`${label} not shown in pane ${pane}`);
  };
  await selectRow(1); // JSON
  await d.waitFor(".insp-url", { text: "v1/items" });
  let r = await rows(1);
  assert.deepEqual(r.sections, ["Headers", "Body", "Cookies", "Auth", "Raw"], JSON.stringify(r));
  assert.equal(r.section, "Body", JSON.stringify(r));
  assert.equal(r.view, "Formatted", JSON.stringify(r));
  assert.ok(r.views.includes("Tree") && !r.views.includes("SOAP") && !r.views.includes("Image") && r.other, `only fitting views directly: ${JSON.stringify(r)}`);
  // SOAP opens in the SOAP view; choosing the tree is remembered for SOAP only.
  await selectRow(3);
  await d.waitFor(".insp-url", { text: "GetOrder" });
  r = await rows(1);
  assert.equal(r.view, "SOAP", JSON.stringify(r));
  assert.ok(!r.views.includes("Image"), JSON.stringify(r));
  await pick(1, ".view-sub", "Tree");
  await selectRow(4);
  await d.waitFor(".insp-url", { text: "GetCustomer" });
  assert.equal((await rows(1)).view, "Tree");
  await selectRow(1);
  await d.waitFor(".insp-url", { text: "v1/items" });
  assert.equal((await rows(1)).view, "Formatted");
  // Headers, then Body again: back to the view chosen for the body.
  await pick(1, ".view-sections", "Headers");
  assert.equal((await rows(1)).section, "Headers");
  await d.waitFor(".hv-table");
  await pick(1, ".view-sections", "Body");
  r = await rows(1);
  assert.equal(r.section, "Body");
  assert.equal(r.view, "Formatted");
  // The request of a GET has no body: Body is there, but faint.
  const faint = await d.exec(`return [...document.querySelectorAll('.insp-pane')[0].querySelectorAll('.view-sections > .segmented:not(.view-tabs-measure) .seg')].map((e) => e.classList.contains('dim'));`);
  assert.equal(faint[1], true, `empty request body shown faint: ${faint}`);
  // Switching to the flat strip keeps the view.
  await d.exec(`window.__quena.setLayout({ inspectorTabs: "flat" })`);
  assert.equal(await activeView(1), "Body");
  await d.exec(`window.__quena.setLayout({ inspectorTabs: "grouped", viewByType: {}, subViews: {}, stacked: false })`);
});

test("right-click: Quena's menus, never the browser's", async () => {
  const menu = () => d.exec(`return [...document.querySelectorAll('.ctx-menu .ctx-label')].map((e) => e.textContent);`);
  const close = async () => {
    await d.keys(["Escape"]);
    await new Promise((r) => setTimeout(r, 100));
  };
  const rightClick = async (el, x, y) => {
    const r = await d.rect(el);
    await d.clickAt(el, x ?? r.width / 2, y ?? r.height / 2, 2);
    await new Promise((r) => setTimeout(r, 200));
  };
  await d.exec(`window.__quena.setLayout({ inspectorTabs: "grouped", stacked: true, viewByType: {}, subViews: {} })`);
  // A session: the session menu.
  await rightClick(await d.waitFor(".grid-canvas"), 80, 12);
  let items = await menu();
  assert.ok(items.includes("Copy") && items.includes("Replay"), `session menu: ${items}`);
  await close();
  // Below the last session: the list's menu.
  const canvas = await d.waitFor(".grid-canvas");
  await rightClick(canvas, 80, (await d.rect(canvas)).height - 10);
  items = await menu();
  assert.ok(items.includes("Open archive") && items.includes("Select all"), `list menu: ${items}`);
  await close();
  // A text field: the Edit menu.
  await selectRow(1);
  await d.waitFor(".insp-url", { text: "v1/items" });
  await rightClick(await d.waitFor(".hv-filter"));
  items = await menu();
  assert.ok(["Cut", "Copy", "Paste", "Select All"].every((x) => items.includes(x)), `edit menu: ${items}`);
  await close();
  // A header row (a shown one: the other pane may keep its table hidden): copy its value.
  const row = await d.exec(`return [...document.querySelectorAll('.hv-table tr')].find((r) => r.offsetHeight > 0 && r.offsetWidth > 0)`);
  await rightClick(row["element-6066-11e4-a52e-4f735466cecf"]);
  items = await menu();
  assert.ok(items.includes("Copy Value") && items.includes("Copy All Headers"), `header menu: ${items}`);
  await close();
  // The JSON tree: copy the JSONPath, change the value in later responses.
  const panes = await d.findAll(".insp-pane");
  for (const b of await d.findIn(panes[1], ".view-sub > .segmented:not(.view-tabs-measure) .seg")) if ((await d.text(b)) === "Tree") await d.click(b);
  const key = await d.waitFor(".j-children .j-key");
  await rightClick(key);
  items = await menu();
  assert.ok(items.includes("Copy JSONPath") && items.some((x) => x.startsWith("Change Value")), `JSON menu: ${items}`);
  await close();
  // The toolbar: no menu at all (and not the browser's, which would block the driver).
  await rightClick(await d.waitFor(".capture-switch"));
  assert.deepEqual(await menu(), []);
  await d.exec(`window.__quena.setLayout({ stacked: false, viewByType: {}, subViews: {} })`);
});

test("layout fills the window at small and large sizes, side by side and stacked", async () => {
  const problems = [];
  for (const patch of [{ stacked: false, leftWidth: 0.5 }, { stacked: true, leftWidth: 0.5 }, { stacked: false, leftWidth: 0.72 }]) {
    await d.exec(`window.__quena.setLayout(${JSON.stringify(patch)})`);
    for (const [width, height] of [[900, 560], [1920, 1080]]) {
      await d.cmd("POST", d.s("/window/rect"), { width, height });
      await new Promise((r) => setTimeout(r, 400));
      for (const g of await d.exec(AUDIT)) problems.push({ ...patch, width, height, ...g });
    }
  }
  await d.exec(`window.__quena.setLayout({ stacked: false, leftWidth: 0.5 })`);
  assert.deepEqual(problems, [], "unused space in the layout");
});

test("navigator: structure and groups narrow the session list", async () => {
  const count = async () => Number((await d.text(await d.waitFor(".statusbar"))).match(/(\d+) sessions/)[1]);
  const all = await count();
  // Structure: hosts and paths as a tree; a click shows only that host, a second click all.
  await d.exec(`window.__quena.menu("view.structure")`);
  const host = await d.waitFor(".navigator .st-row", { text: "soap.example.com" });
  await d.click(host);
  await d.waitFor(".scope-bar", { text: (t) => t.includes("soap.example.com") && t.includes("2 sessions") });
  await d.click(await d.findIn(host, ".st-chev").then((c) => c[0]));
  const shop = await d.waitFor(".st-row", { text: (t) => t.startsWith("shop/") });
  await d.click(await d.findIn(shop, ".st-chev").then((c) => c[0]));
  await d.waitFor(".st-row", { text: "GetCustomer" });
  await d.click(await d.waitFor(".navigator .st-row", { text: "soap.example.com" }));
  await d.waitFor(".scope-bar", { text: (t) => t === "" });
  // Groups by host: the list shows one host; the bar above it brings all back.
  await d.click(await d.waitFor(".nav-head .seg", { text: "Groups" }));
  await d.exec(`window.__quena.menu("view.group-host")`);
  const api = await d.waitFor(".nav-row", { text: (t) => t.startsWith("api.example.com") });
  await d.click(api);
  await d.waitFor(".scope-bar", { text: (t) => t.includes("api.example.com") && t.includes("2 sessions") });
  assert.ok((await d.findAll(".nav-row")).length >= 3, "all groups stay listed: All + the hosts");
  await d.click(await d.waitFor(".scope-bar .icon-btn"));
  await d.waitFor(".scope-bar", { text: (t) => t === "" });
  assert.equal(await count(), all);
  // Hiding the navigator ends any narrowing; the list grouping stays as chosen.
  await d.click(api);
  await d.exec(`window.__quena.menu("view.navigator")`);
  await d.waitFor(".scope-bar", { text: (t) => t === "" });
  assert.equal((await d.findAll(".navigator")).length, 0);
  await d.exec(`window.__quena.menu("view.group-none")`);
  await d.exec(`window.__quena.menu("view.inspectors")`);
});

test("timeline: a waterfall of the selected sessions", async () => {
  await selectRow(1);
  await d.keys(["Control", "a"]);
  await d.exec(`window.__quena.menu("view.timeline")`);
  await d.waitFor(".tl-row", { text: "GetOrder" });
  const bars = await d.findAll(".tl-track .tl-seg, .tl-track .tl-bar");
  assert.ok(bars.length >= 4, `bars: ${bars.length}`);
  const geo = () =>
    d.exec(`const s = document.querySelector('.tl-scroll'), tb = document.querySelector('.tl-table'), g = document.querySelector('.tl-hrow .tl-c-graph'), u = document.querySelector('.tl-hrow .tl-c-url');
      return { client: s.clientWidth, scroll: s.scrollWidth, table: tb.getBoundingClientRect().width, graph: g.getBoundingClientRect().width, url: u.getBoundingClientRect().width, ticks: document.querySelectorAll('.tl-tick').length };`);
  // A time axis, and at zoom 1 everything fits the width.
  const g1 = await geo();
  assert.ok(g1.ticks >= 2, `axis ticks: ${JSON.stringify(g1)}`);
  assert.ok(g1.scroll <= g1.client + 1, `no horizontal overflow at zoom 1: ${JSON.stringify(g1)}`);
  // Zoom in: the graph gets wider and the view scrolls horizontally; Fit resets.
  const button = async (label) => {
    for (const b of await d.findAll(".tl-zoom button")) if ((await d.exec("return arguments[0].getAttribute('aria-label') || arguments[0].textContent", [{ "element-6066-11e4-a52e-4f735466cecf": b }])).includes(label)) return b;
    throw new Error(`no zoom button ${label}`);
  };
  await d.click(await button("Zoom in"));
  await d.click(await button("Zoom in"));
  await new Promise((r) => setTimeout(r, 200));
  const g2 = await geo();
  assert.ok(g2.graph > g1.graph * 2, `zoomed graph wider: ${JSON.stringify([g1, g2])}`);
  assert.ok(g2.scroll > g2.client, `horizontal scrollbar when zoomed: ${JSON.stringify(g2)}`);
  await d.click(await button("Fit"));
  await new Promise((r) => setTimeout(r, 200));
  assert.ok(Math.abs((await geo()).graph - g1.graph) < 2, "Fit restores the width");
  // Resize the URL column by dragging its header edge.
  const handle = (await d.findAll(".tl-hrow .tl-c-url .tl-resize"))[0];
  await d.cmd("POST", d.s("/actions"), {
    actions: [
      {
        type: "pointer",
        id: "mouse",
        parameters: { pointerType: "mouse" },
        actions: [
          { type: "pointerMove", origin: { "element-6066-11e4-a52e-4f735466cecf": handle }, x: 0, y: 0 },
          { type: "pointerDown", button: 0 },
          { type: "pointerMove", origin: "pointer", x: 80, y: 0, duration: 100 },
          { type: "pointerUp", button: 0 },
        ],
      },
    ],
  });
  await d.cmd("DELETE", d.s("/actions"));
  await new Promise((r) => setTimeout(r, 200));
  const g3 = await geo();
  // On failure: what lies on the handle (something covering it swallows the drag).
  const onHandle = () =>
    d.exec(`const h = arguments[0].getBoundingClientRect(), e = document.elementFromPoint(h.left + h.width / 2, h.top + h.height / 2);
      return { handle: [h.left, h.top, h.width, h.height].map(Math.round), top: e ? e.tagName + "." + e.className : null, win: [innerWidth, innerHeight] };`, [{ "element-6066-11e4-a52e-4f735466cecf": handle }]);
  assert.ok(g3.url > g1.url + 50, `URL column wider after dragging its edge: ${JSON.stringify([g1.url, g3.url, await onHandle()])}`);
  // Every bar lies completely inside the graph — also the one that ends last.
  const outside = await d.exec(`return [...document.querySelectorAll('.tl-row')].flatMap((row) => {
      const cell = row.querySelector('.tl-c-graph').getBoundingClientRect();
      return [...row.querySelectorAll('.tl-seg, .tl-bar')].map((b) => b.getBoundingClientRect()).filter((b) => b.right > cell.right + 0.5 || b.left < cell.left - 0.5).map((b) => [Math.round(b.left), Math.round(b.right), Math.round(cell.right)]);
    });`);
  assert.deepEqual(outside, [], "bars cut off at the edge of the graph");
  await d.exec(`window.__quena.menu("view.inspectors")`);
});

test("views still fit after coming back from another tab", async () => {
  // Regression: while Inspect is hidden, tab widths measure 0; they must be measured again.
  // Each row of views (flat; grouped: the sections and the views below them) stays inside
  // its own strip.
  const fit = () =>
    d.exec(`
    return [...document.querySelectorAll('.insp-pane .view-tabs')].map((bar) => {
      const wrap = bar.getBoundingClientRect();
      const segs = [...bar.querySelectorAll(':scope > .segmented:not(.view-tabs-measure) .seg')].map((e) => e.getBoundingClientRect());
      return { bar: bar.className, outside: segs.some((r) => r.left < wrap.left - 0.5 || r.right > wrap.right + 0.5), shown: segs.length };
    });`);
  for (const inspectorTabs of ["flat", "grouped"]) {
    await d.exec(`window.__quena.setLayout({ inspectorTabs: ${JSON.stringify(inspectorTabs)} })`);
    await selectRow(1);
    for (const tab of ["view.timeline", "view.statistics", "view.inspectors"]) {
      await d.exec(`window.__quena.menu(${JSON.stringify(tab)})`);
      await new Promise((r) => setTimeout(r, 300));
    }
    await selectRow(2);
    await new Promise((r) => setTimeout(r, 400));
    const res = await fit();
    assert.ok(res.length >= 2 && res.every((p) => !p.outside && p.shown > 0), `${inspectorTabs}: view tabs overflow after a tab switch: ${JSON.stringify(res)}`);
  }
});

test("an archive dropped onto the window is loaded", async () => {
  const fs = await import("node:fs");
  const text = fs.readFileSync(har, "utf8");
  await d.exec(`
    const dt = new DataTransfer();
    dt.items.add(new File([arguments[0]], "dropped.har", { type: "application/json" }));
    for (const type of ["dragenter", "dragover", "drop"]) window.dispatchEvent(new DragEvent(type, { dataTransfer: dt, bubbles: true, cancelable: true }));`, [text]);
  await d.waitFor(".statusbar", { text: "9 sessions", timeout: 15000 }).catch(async (e) => {
    const trace = await d.exec("return JSON.stringify(window.__quenaDrop || null)").catch(() => "?");
    throw new Error(`${e.message}; drop trace: ${trace}`);
  });
  assert.ok(!(await d.exec(`return document.body.classList.contains("file-drop")`)), "drop overlay still shown");
});

test("Delete / Backspace remove the selected sessions after a confirmation", async () => {
  const count = async () => {
    const t = await d.text(await d.waitFor(".statusbar"));
    return t.match(/(\d+) sessions/)?.[1];
  };
  const dialogGone = async () => {
    const end = Date.now() + 3000;
    while ((await d.findAll(".modal-title")).length && Date.now() < end) await new Promise((r) => setTimeout(r, 100));
    assert.equal((await d.findAll(".modal-title")).length, 0, "confirmation still open");
  };
  const before = Number(await count());
  // Cancel: nothing is removed.
  await selectRow(1);
  await d.keys(["Delete"]);
  await d.waitFor(".modal-title", { text: "Remove 1 session?" });
  await d.keys(["Escape"]);
  await dialogGone();
  assert.equal(Number(await count()), before);
  // Confirm with Enter: the row disappears from the list, the status bar agrees ("n of m"
  // would mean the list still shows removed rows).
  await selectRow(1);
  await d.keys(["Delete"]);
  await d.waitFor(".modal-title", { text: "Remove 1 session?" });
  await d.keys(["Enter"]);
  await dialogGone();
  await d.waitFor(".statusbar", { text: (t) => t.includes(`${before - 1} sessions`) && !/\d+ of \d+ sessions/.test(t) });
  // The Mac delete key (Backspace) with several sessions selected (Ctrl+A), then cancel.
  await selectRow(1);
  await d.keys(["Control", "a"]);
  await d.keys(["Backspace"]);
  await d.waitFor(".modal-title", { text: `Remove ${before - 1} sessions?` });
  await d.keys(["Escape"]);
  await dialogGone();
  assert.equal(Number(await count()), before - 1, "cancelled: nothing removed");
});

test("timeline: sessions a day apart, the last bar visible, readable axis", async () => {
  // Two archives recorded a day apart: one session from each.
  const fs = await import("node:fs");
  const os = await import("node:os");
  const day = JSON.parse(fs.readFileSync(har, "utf8"));
  for (const e of day.log.entries) e.startedDateTime = new Date(Date.parse(e.startedDateTime) + 86_400_000).toISOString();
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "quena-tl-")), "next-day.har");
  fs.writeFileSync(file, JSON.stringify(day));
  const before = Number((await d.text(await d.waitFor(".statusbar"))).match(/(\d+) sessions/)[1]);
  await d.exec("return window.__quena.load(arguments[0]).then(() => true)", [file]);
  await d.waitFor(".statusbar", { text: `${before + day.log.entries.length} sessions` });
  // From the first session (old day) to the last one (next day): click, then Shift+End.
  await selectRow(1);
  await d.cmd("POST", d.s("/actions"), {
    actions: [{ type: "key", id: "kbd", actions: [{ type: "keyDown", value: "\uE008" }, { type: "keyDown", value: "\uE010" }, { type: "keyUp", value: "\uE010" }, { type: "keyUp", value: "\uE008" }] }],
  });
  await d.cmd("DELETE", d.s("/actions"));
  await d.exec(`window.__quena.menu("view.timeline")`);
  await d.waitFor(".tl-row", { timeout: 5000 });
  const state = () =>
    d.exec(`
    const rows = [...document.querySelectorAll('.tl-row')];
    const cut = rows.flatMap((row) => {
      const cell = row.querySelector('.tl-c-graph').getBoundingClientRect();
      const bars = [...row.querySelectorAll('.tl-seg, .tl-bar')].map((b) => b.getBoundingClientRect());
      return bars.some((b) => b.right > cell.right + 0.5 || b.left < cell.left - 0.5 || b.width < 0.5) ? [row.textContent.slice(0, 40)] : [];
    });
    return { rows: rows.length, cut, breaks: document.querySelectorAll('.tl-hrow .tl-break').length, starts: document.querySelectorAll('.tl-tick.first').length,
      ticks: [...document.querySelectorAll('.tl-tick')].map((t) => t.textContent), toggle: !!document.querySelector('.tl-compress input') };`);
  // The idle day is cut to a break; both blocks start with their clock time; no bar is cut off.
  let res = await state();
  assert.ok(res.rows >= 2 && res.toggle, JSON.stringify(res));
  // (The selection also holds the live session of an earlier test, recorded now: then there
  // are three blocks.)
  assert.ok(res.breaks >= 1, `the idle day is cut: ${JSON.stringify(res)}`);
  // Blocks start with their clock time (labels of very narrow blocks that would overlap are
  // left out until zoomed in).
  assert.ok(res.starts >= 2 && res.starts <= res.breaks + 1, `blocks labelled with their time: ${JSON.stringify(res)}`);
  assert.deepEqual(res.cut, [], `bars outside the graph: ${JSON.stringify(res)}`);
  // Without collapsing: the real scale, in hours, and still every bar inside the graph.
  await d.click((await d.findAll(".tl-compress input"))[0]);
  await new Promise((r) => setTimeout(r, 200));
  res = await state();
  assert.equal(res.breaks, 0);
  assert.deepEqual(res.cut, [], `bars outside the graph: ${JSON.stringify(res)}`);
  assert.ok(!res.ticks.some((t) => /\d{4,}[.,]\d s/.test(t)), `axis labels must use h/d, not thousands of seconds: ${res.ticks}`);
  // Hours or days, depending on how long ago the fixture was recorded (the live session is from now).
  assert.ok(res.ticks.some((t) => / h| d/.test(t)), `hours or days on the axis: ${res.ticks}`);
  await d.click((await d.findAll(".tl-compress input"))[0]);
  await d.exec(`window.__quena.menu("view.inspectors")`);
});

test("no view crashed", async () => {
  assert.equal((await d.findAll(".view-error")).length, 0, "an inspector shows 'This view failed'");
  assert.equal((await d.findAll(".app-crash")).length, 0, "the app shows its crash screen");
});
