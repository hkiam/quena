// Sanitized export end to end: File → Export Sessions → Sanitized for Sharing with the
// "GDPR strict" preset writes a HAR without the planted marker values, the redaction log
// opens, and "Open Sanitized File" loads the sessions again. The native save dialog is
// bypassed through window.__quenaSanitizePath.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Driver } from "./webdriver.mjs";

const d = new Driver();
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "quena-sanitize-"));
const har = path.join(dir, "capture.har");
const out = path.join(dir, "sanitized.har");
const MARKERS = ["SECRET-E2E-COOKIE", "SECRET-E2E-PW", "e2e.person@example.com", "203.0.113.7", "+49 30 1234567"];

function captureHar() {
  const entry = (url, reqHeaders, post, respText) => ({
    startedDateTime: "2026-09-30T10:00:00.000Z",
    time: 20,
    request: {
      method: post ? "POST" : "GET",
      url,
      httpVersion: "HTTP/1.1",
      cookies: [],
      headers: reqHeaders,
      queryString: [],
      headersSize: -1,
      bodySize: post ? post.length : 0,
      ...(post ? { postData: { mimeType: "application/json", text: post } } : {}),
    },
    response: {
      status: 200,
      statusText: "OK",
      httpVersion: "HTTP/1.1",
      cookies: [],
      headers: [{ name: "Content-Type", value: "application/json" }],
      content: { size: respText.length, mimeType: "application/json", text: respText },
      redirectURL: "",
      headersSize: -1,
      bodySize: respText.length,
    },
    cache: {},
    timings: { send: 1, wait: 10, receive: 1 },
  });
  return {
    log: {
      version: "1.2",
      creator: { name: "quena-e2e", version: "1" },
      entries: [
        entry("https://shop.example.test/api/login", [{ name: "Cookie", value: "sid=SECRET-E2E-COOKIE; lang=de" }], '{"user":"e2e.person@example.com","password":"SECRET-E2E-PW"}', '{"ok":true}'),
        entry(
          "https://shop.example.test/api/me",
          [{ name: "X-Forwarded-For", value: "203.0.113.7" }],
          null,
          '{"email":"e2e.person@example.com","phone":"+49 30 1234567","items":[1,2]}',
        ),
      ],
    },
  };
}

before(async () => {
  fs.writeFileSync(har, JSON.stringify(captureHar()));
  await d.start(process.env.QUENA_APP, [har]);
  await d.waitFor(".statusbar", { text: "2 sessions", timeout: 30000 });
});
after(async () => {
  await d.quit();
  fs.rmSync(dir, { recursive: true, force: true });
});

const click = async (el) => {
  for (let i = 0; ; i++) {
    try {
      return await d.click(el);
    } catch (e) {
      if (i >= 20 || !/intercepted|not interactable/.test(String(e))) throw e;
      await new Promise((r) => setTimeout(r, 150));
    }
  }
};

const button = async (scope, label) => {
  for (const b of await d.findAll(`${scope} button`)) if ((await d.text(b)).trim() === label) return b;
  throw new Error(`no button ${label}`);
};

test("the GDPR preset writes a HAR without the marker values", async () => {
  await d.exec("window.__quenaSanitizePath = arguments[0]", [out]);
  await d.exec(`window.__quena.menu("file.export-sanitized")`);
  await d.waitFor(".sanitize-dialog", { text: "Credentials" });
  await click(await d.waitFor('.sanitize-dialog input[value="gdpr"]'));
  await click(await d.waitFor('.sanitize-dialog input[value="har"]'));
  await click(await button(".sanitize-dialog", "Export…"));
  const result = await d.waitFor(".sanitize-result", { text: "values replaced", timeout: 30000 });
  const text = await d.text(result);
  assert.ok(text.includes("Cookie values") && text.includes("E-mail addresses"), text);
  const written = fs.readFileSync(out, "utf8");
  for (const m of MARKERS) assert.ok(!written.includes(m), `${m} in the export`);
  assert.ok(written.includes("sid=<cookie-1>"), "cookie name kept, value replaced");
  assert.equal(JSON.parse(written).log._quenaRedaction.preset, "gdpr");
});

test("the sanitized file opens again", async () => {
  await click(await button(".sanitize-result", "Open Sanitized File"));
  await d.waitFor(".statusbar", { text: "4 sessions", timeout: 30000 });
});

test("the session menu exports only the one session it was opened on", async () => {
  const one = path.join(dir, "one.har");
  await d.exec("window.__quenaSanitizePath = arguments[0]", [one]);
  await d.exec("return window.__quena.selectRow(0).then(() => true)");
  await d.exec(`window.__quena.menu("file.export-sanitized-selection")`);
  await d.waitFor(".sanitize-dialog", { text: "Selected session (1)" });
  assert.equal(await d.exec(`return document.querySelector('.sanitize-dialog input[name="sanitize-scope"][value="selected"]').checked`), true);
  await click(await d.waitFor('.sanitize-dialog input[value="har"]'));
  await click(await button(".sanitize-dialog", "Export…"));
  await d.waitFor(".sanitize-result", { timeout: 30000 });
  const entries = JSON.parse(fs.readFileSync(one, "utf8")).log.entries;
  assert.equal(entries.length, 1, "only the selected session");
});
