// End-to-end tests: start the real Quena app (tauri-driver + WebKitWebDriver on Linux) with an
// isolated data directory and a HAR file, and drive the UI like a user would.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { Driver } from "./webdriver.mjs";
import path from "node:path";

const app = process.env.QUENA_APP;
const har = path.resolve(import.meta.dirname, "fixtures/two-sessions.har");
const d = new Driver();

before(async () => {
  assert.ok(app, "QUENA_APP must point to the built quena binary");
  await d.start(app, [har]);
});
after(() => d.quit());

test("starts and lists the sessions of the HAR passed on the command line", async () => {
  await d.waitFor(".statusbar", { text: "2 sessions", timeout: 20000 });
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
  for (const b of await d.findIn(panes[1], ".segmented .seg")) if ((await d.text(b)) === "Body") await d.click(b);
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
  await d.waitFor(".statusbar", { text: "3 sessions" });
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

test("no view crashed", async () => {
  assert.equal((await d.findAll(".view-error")).length, 0, "an inspector shows 'This view failed'");
  assert.equal((await d.findAll(".app-crash")).length, 0, "the app shows its crash screen");
});
