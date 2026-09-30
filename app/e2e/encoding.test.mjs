// Character encodings end to end: bodies in many charsets (header, BOM, XML declaration,
// HTML meta, defaults, a wrong declaration) show the right characters, the text views name
// the charset and where it came from, and choosing another charset fixes a wrong one.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Driver } from "./webdriver.mjs";
import { CASES, encodingHar } from "./fixtures/encoding-har.mjs";

const d = new Driver();
const har = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "quena-enc-")), "encoding.har");

before(async () => {
  fs.writeFileSync(har, JSON.stringify(encodingHar()));
  await d.start(process.env.QUENA_APP, [har]);
  await d.waitFor(".statusbar", { text: `${CASES.length} sessions`, timeout: 30000 });
  // Fixed views instead of the remembered ones.
  await d.exec(`window.__quena.setLayout({ rememberViews: false, stacked: false, requestTab: "headers", responseTab: "textview" })`);
});
after(async () => {
  await d.quit();
  fs.rmSync(path.dirname(har), { recursive: true, force: true });
});

const row = (p) => CASES.findIndex((c) => c.path === p);

async function select(p, tabs = {}) {
  await d.exec(`window.__quena.setLayout(${JSON.stringify({ requestTab: tabs.request ?? "headers", responseTab: tabs.response ?? "textview" })})`);
  await d.exec(`return window.__quena.selectRow(${row(p)}).then(() => true)`);
  await d.waitFor(".insp-url", { text: `/${p}` });
}

/** Text of `css` inside the request (0) or response (1) pane, once `pred` holds. */
async function paneText(pane, css, pred, timeout = 10000) {
  const end = Date.now() + timeout;
  let last = "";
  for (;;) {
    const panes = await d.findAll(".insp-pane");
    for (const el of panes[pane] ? await d.findIn(panes[pane], css) : []) {
      last = await d.text(el).catch(() => "");
      if (pred(last)) return last;
    }
    if (Date.now() > end) throw new Error(`timeout waiting for ${css} in pane ${pane} (last: ${JSON.stringify(last).slice(0, 300)})`);
    await new Promise((r) => setTimeout(r, 150));
  }
}

async function chooseCharset(pane, value) {
  const ok = await d.exec(
    `const p = document.querySelectorAll('.insp-pane')[arguments[0]];
     const s = p && p.querySelector('.cs-select');
     if (!s) return false;
     Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(s, arguments[1]);
     s.dispatchEvent(new Event('change', { bubbles: true }));
     return true;`,
    [pane, value],
  );
  assert.ok(ok, "charset menu");
}

for (const c of CASES.filter((c) => c.text)) {
  test(`${c.path}: the text shows the right characters and names its charset`, async () => {
    await select(c.path);
    const text = await paneText(1, ".cm-content", (t) => t.includes(c.text));
    assert.ok(!text.includes("﻿"), "the byte order mark is not part of the text");
    if (!c.text.includes("�")) assert.ok(!text.includes("�"), `replacement characters in ${JSON.stringify(text)}`);
    await paneText(1, ".cs-label", (t) => t.includes(c.charset));
  });
}

test("the Raw view decodes the body in its charset too", async () => {
  await select("utf16le-bom", { response: "raw" });
  await paneText(1, ".raw-body .cm-content", (t) => t.includes("Grüße in UTF-16 😀"));
  await select("plain-latin1", { response: "raw" });
  await paneText(1, ".raw-body .cm-content", (t) => t.includes("Grüße aus München"));
});

test("a body declared UTF-8 that is Latin-1: U+FFFD, fixed by choosing windows-1252", async () => {
  const c = CASES.find((x) => x.path === "mislabeled");
  await select("mislabeled");
  await paneText(1, ".cm-content", (t) => t.includes(c.text));
  await chooseCharset(1, "windows-1252");
  await paneText(1, ".cm-content", (t) => t.includes(c.fixed) && !t.includes("�"));
  await paneText(1, ".cs-label", (t) => t.includes("windows-1252 · chosen"));
  // The choice belongs to this session: gone after selecting another one.
  await select("plain-latin1");
  await paneText(1, ".cs-label", (t) => t.includes("windows-1252 · header"));
  await select("mislabeled");
  await paneText(1, ".cs-label", (t) => t.includes("UTF-8 · header"));
  await paneText(1, ".cm-content", (t) => t.includes(c.text));
});

test("an override to UTF-16 reads the bytes as UTF-16", async () => {
  await select("plain-latin1");
  await chooseCharset(1, "UTF-16LE");
  await paneText(1, ".cs-label", (t) => t.includes("UTF-16LE · chosen"));
  await paneText(1, ".cm-content", (t) => !t.includes("Grüße") && t.length > 0);
  await chooseCharset(1, "");
  await paneText(1, ".cm-content", (t) => t.includes("Grüße aus München"));
});

for (const c of CASES.filter((c) => c.form)) {
  test(`${c.path}: form fields are percent-decoded in the form's charset`, async () => {
    await select(c.path, { request: "webforms" });
    await paneText(0, "table.kv", (t) => c.form.every(([k, v]) => t.includes(k) && t.includes(v)));
    await paneText(0, ".cs-label", (t) => t.includes(c.charset));
  });
}

test("multipart parts are decoded in their own charset", async () => {
  await select("multipart", { response: "multipart" });
  await paneText(1, ".mp-detail .cm-content", (t) => t.includes("Grüße latin1"));
  await paneText(1, ".mp-detail .cs-label", (t) => t.includes("windows-1252 · header"));
  const panes = await d.findAll(".insp-pane");
  const parts = await d.findIn(panes[1], ".mp-part");
  assert.equal(parts.length, 2);
  await d.click(parts[1]);
  await paneText(1, ".mp-detail .cm-content", (t) => t.includes("Grüße utf8"));
  await paneText(1, ".mp-detail .cs-label", (t) => t.includes("UTF-8 · header"));
});

test("Find Sessions finds text in every charset", async () => {
  await d.keys(["Control", "f"]);
  await d.waitFor(".modal-title", { text: "Find Sessions" });
  const input = await d.waitFor(".modal input");
  await d.type(input, "Grüße");
  await d.keys(["Enter"]);
  // JSON, Latin-1, HTML (windows-1252), UTF-16, UTF-8 with BOM, multipart; not the mislabeled one.
  await d.waitFor(".statusbar", { text: "6 selected", timeout: 20000 });
});
