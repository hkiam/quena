// Rewrite rules end to end: a rule made in the editor (with a preview on a captured
// session) changes live responses, and applied to a captured session it adds a changed copy.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { Driver } from "./webdriver.mjs";

const d = new Driver();
let server;
let port;

function viaProxy(proxyPort, path) {
  return new Promise((resolve, reject) => {
    http
      .get({ host: "127.0.0.1", port: proxyPort, path: `http://127.0.0.1:${port}${path}`, headers: { Host: `127.0.0.1:${port}` } }, (res) => {
        let b = "";
        res.on("data", (c) => (b += c));
        res.on("end", () => resolve(b));
      })
      .on("error", reject);
  });
}

async function fill(el, text) {
  await d.cmd("POST", d.s(`/element/${el}/clear`), {});
  await d.type(el, text);
}

before(async () => {
  server = http.createServer((req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ price: 10, path: req.url }));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
  await d.start(process.env.QUENA_APP);
  await d.waitFor(".statusbar", { timeout: 30000 });
});
after(async () => {
  await d.quit();
  server.close();
});

test("Rewrite rule: editor with preview, live change, applied to a captured session", async () => {
  await d.ensureCapturing();
  const status = await d.text(await d.waitFor(".sb-capture", { text: "Proxy 127.0.0.1:" }));
  const proxyPort = Number(status.match(/127\.0\.0\.1:(\d+)/)[1]);
  assert.match(await viaProxy(proxyPort, "/item"), /"price":10/);
  await d.waitFor(".statusbar", { text: "1 session", timeout: 15000 });
  await d.exec("return window.__quena.selectRow(0)");

  // New rule from the Mock Rules tab.
  await d.exec(`window.__quena.menu("view.autoresponder")`);
  await d.click(await d.waitFor(".ar-rewrite-empty button", { text: "New rewrite rule" }));
  await d.waitFor(".modal-title", { text: "New Rewrite Rule" });
  const rows = await d.findAll(".rw-editor .f-row input");
  await fill(rows[0], "price as text");
  await fill(rows[2], `prefix:http://127.0.0.1:${port}/`);
  await fill(await d.waitFor(".rw-op .rw-path"), "$.price");
  await fill(await d.waitFor(".rw-op .rw-value"), '"free"');
  await d.click(await d.waitFor(".rw-editor .rp-buttons button", { text: "Preview on #" }));
  await d.waitFor(".rw-preview", { text: "free", timeout: 10000 });
  await d.click(await d.waitFor(".rw-editor .rp-buttons .primary", { text: "Add" }));
  await d.waitFor(".ar-table", { text: "price as text", timeout: 10000 });

  // Live traffic is changed.
  assert.match(await viaProxy(proxyPort, "/item"), /"price":\s*"free"/);

  // Applied to the first (unchanged) session: a changed copy appears.
  await d.exec(`window.__quena.dialog({ kind: "rewrite-apply", ids: [1] })`);
  await d.click(await d.waitFor(".rw-apply button", { text: "All rules that are on" }));
  await d.waitFor(".statusbar", { text: "changed copies added", timeout: 10000 });
  await d.waitFor(".statusbar", { text: "3 sessions", timeout: 10000 });
});
