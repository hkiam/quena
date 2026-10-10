// Mocks from sessions end to end: a recorded session becomes a Mock Rule through the
// "Mocks from Sessions" dialog, and the proxy then answers a matching request from the
// package's response file (also with another cache-buster value).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { Driver } from "./webdriver.mjs";

const d = new Driver();
const har = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "quena-mocks-")), "mocks.har");
const RECORDED = '{"items":[42],"source":"recording"}';

function mocksHar() {
  return {
    log: {
      version: "1.2",
      creator: { name: "quena-e2e", version: "1" },
      entries: [
        {
          startedDateTime: "2026-09-30T10:00:00.000Z",
          time: 20,
          request: {
            method: "GET",
            url: "http://mock-e2e.invalid/api/items?page=2&_=1700000000",
            httpVersion: "HTTP/1.1",
            cookies: [],
            headers: [{ name: "Accept", value: "application/json" }],
            queryString: [],
            headersSize: -1,
            bodySize: 0,
          },
          response: {
            status: 200,
            statusText: "OK",
            httpVersion: "HTTP/1.1",
            cookies: [],
            headers: [
              { name: "Content-Type", value: "application/json" },
              { name: "X-Recorded", value: "yes" },
            ],
            content: { size: RECORDED.length, mimeType: "application/json", text: RECORDED },
            redirectURL: "",
            headersSize: -1,
            bodySize: RECORDED.length,
          },
          cache: {},
          timings: { send: 1, wait: 18, receive: 1 },
        },
      ],
    },
  };
}

before(async () => {
  fs.writeFileSync(har, JSON.stringify(mocksHar()));
  await d.start(process.env.QUENA_APP, [har]);
  await d.waitFor(".statusbar", { text: "1 session", timeout: 30000 });
});
after(async () => {
  await d.quit();
  fs.rmSync(path.dirname(har), { recursive: true, force: true });
});

/** GET `url` through Quena's proxy → { status, headers, body }. */
function viaProxy(port, url) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: url, headers: { Host: new URL(url).host } }, (res) => {
      let b = "";
      res.on("data", (c) => (b += c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on("error", reject);
    req.end();
  });
}

test("Mocks from Sessions → Create Mock Rules now answers through the proxy", async () => {
  await d.exec(`window.__quena.menu("file.export-mocks")`);
  await d.waitFor(".modal-title", { text: "Mocks from Sessions" });
  // File → Export Sessions → Mocks… starts with the package; switch to Mock Rules.
  assert.equal(await d.exec(`return document.querySelector('.mocks-dialog input[name="mock-target"][value="package"]').checked`), true);
  await d.click(await d.waitFor('.mocks-dialog input[name="mock-target"][value="apply"]'));
  // Live preview: one mapping from one session.
  await d.waitFor(".mocks-counts", { text: "1 mapping", timeout: 15000 });
  await d.clickEnabled(".mocks-actions .primary", { text: "Create rules" });
  // The dialog closes, the Mock Rules tab shows the package and its rule.
  await d.waitFor(".ar-package", { text: "1 rule", timeout: 20000 });
  await d.waitFor(".ar-table", { text: "items" });

  await d.ensureCapturing();
  const status = await d.text(await d.waitFor(".sb-capture", { text: "Proxy 127.0.0.1:" }));
  const port = Number(status.match(/127\.0\.0\.1:(\d+)/)[1]);
  const res = await viaProxy(port, "http://mock-e2e.invalid/api/items?page=2&_=1800000000");
  assert.equal(res.status, 200);
  assert.equal(res.body, RECORDED);
  assert.equal(res.headers["x-recorded"], "yes");
  // Another page is not mocked (the host does not exist, so no recorded body).
  const other = await viaProxy(port, "http://mock-e2e.invalid/api/items?page=3");
  assert.notEqual(other.body, RECORDED);
});
