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
  await d.exec(`window.__quena.setLayout({ stacked: true, leftWidth: 0.4 })`);
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
  await d.exec(`window.__quena.setLayout({ viewByType: {}, rememberViews: true, stacked: true })`);
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
  await d.exec(`window.__quena.setLayout({ rememberViews: true, viewByType: {}, stacked: false })`);
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

test("structure: hosts and paths as a tree, a click selects the sessions below", async () => {
  await d.exec(`window.__quena.menu("view.structure")`);
  const host = await d.waitFor(".st-row", { text: "soap.example.com" });
  await d.click(host);
  await d.waitFor(".insp-url", { text: "soap.example.com/shop/" });
  await d.click(await d.findIn(host, ".st-chev").then((c) => c[0]));
  const shop = await d.waitFor(".st-row", { text: (t) => t.startsWith("shop/") });
  await d.click(await d.findIn(shop, ".st-chev").then((c) => c[0]));
  await d.waitFor(".st-row", { text: "GetCustomer" });
});

test("timeline: a waterfall of the selected sessions", async () => {
  await selectRow(1);
  await d.keys(["Control", "a"]);
  await d.exec(`window.__quena.menu("view.timeline")`);
  await d.waitFor(".tl-row", { text: "GetOrder" });
  const bars = await d.findAll(".tl-track .tl-seg, .tl-track .tl-bar");
  assert.ok(bars.length >= 4, `bars: ${bars.length}`);
  await d.exec(`window.__quena.menu("view.inspectors")`);
});

test("views still fit after coming back from another tab", async () => {
  // Regression: while Inspect is hidden, tab widths measure 0; they must be measured again.
  await selectRow(1);
  for (const tab of ["view.structure", "view.statistics", "view.inspectors"]) {
    await d.exec(`window.__quena.menu(${JSON.stringify(tab)})`);
    await new Promise((r) => setTimeout(r, 300));
  }
  await selectRow(2);
  await new Promise((r) => setTimeout(r, 400));
  const res = await d.exec(`
    return [...document.querySelectorAll('.insp-pane')].map((pane) => {
      const wrap = pane.querySelector('.view-tabs').getBoundingClientRect();
      const segs = [...pane.querySelectorAll('.view-tabs > .segmented:not(.view-tabs-measure) .seg')].map((e) => e.getBoundingClientRect());
      return { outside: segs.some((r) => r.left < wrap.left - 0.5 || r.right > wrap.right + 0.5), shown: segs.length };
    });`);
  assert.ok(res.every((p) => !p.outside && p.shown > 0), `view tabs overflow after a tab switch: ${JSON.stringify(res)}`);
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

test("no view crashed", async () => {
  assert.equal((await d.findAll(".view-error")).length, 0, "an inspector shows 'This view failed'");
  assert.equal((await d.findAll(".app-crash")).length, 0, "the app shows its crash screen");
});
