// Reverse proxy end to end: an entry made in Capture → Reverse Proxy… listens while
// capturing, forwards to its target and records the exchange.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { Driver } from "./webdriver.mjs";

const d = new Driver();
let target;

/** A port that is free right now. */
function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

function get(port, path) {
  return new Promise((resolve, reject) => {
    http
      .get({ host: "127.0.0.1", port, path }, (res) => {
        let b = "";
        res.on("data", (c) => (b += c));
        res.on("end", () => resolve({ status: res.statusCode, body: b }));
      })
      .on("error", reject);
  });
}

before(async () => {
  target = http.createServer((req, res) => res.end(`hello ${req.url} host=${req.headers.host}`));
  await new Promise((r) => target.listen(0, "127.0.0.1", r));
  await d.start(process.env.QUENA_APP);
  await d.waitFor(".statusbar", { timeout: 30000 });
});
after(async () => {
  await d.quit();
  target.close();
});

test("Capture → Reverse Proxy…: add an entry, it forwards and records", async () => {
  const port = await freePort();
  const targetPort = target.address().port;
  await d.exec(`window.__quena.menu("tools.reverse-proxy")`);
  await d.waitFor(".modal-title", { text: "Reverse Proxy" });
  await d.click(await d.waitFor(".reverse-proxy button", { text: "Add entry…" }));
  await d.waitFor(".rp-editor input");
  const inputs = await d.findAll(".rp-editor input");
  // Name, local port, target.
  await d.cmd("POST", d.s(`/element/${inputs[0]}/clear`), {});
  await d.type(inputs[0], "api");
  await d.cmd("POST", d.s(`/element/${inputs[1]}/clear`), {});
  await d.type(inputs[1], String(port));
  await d.type(inputs[2], `http://127.0.0.1:${targetPort}/base`);
  await d.clickEnabled(".rp-buttons .primary", { text: "Add" });
  await d.waitFor(".rp-list", { text: "api", timeout: 15000 });

  await d.ensureCapturing();
  await d.waitFor(".rp-tag.rp-on", { text: "listening", timeout: 15000 });
  const res = await get(port, "/x?y=1");
  assert.equal(res.status, 200);
  assert.equal(res.body, `hello /base/x?y=1 host=127.0.0.1:${targetPort}`);
  // The status bar names the running entry; the session is in the list.
  await d.waitFor(".statusbar", { text: "1 reverse proxy" });
  await d.waitFor(".statusbar", { text: "1 session", timeout: 15000 });
});
