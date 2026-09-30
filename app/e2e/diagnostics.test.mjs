// Diagnostics end to end: a generated capture with planted problems is analysed by the real
// webdiag plugin, the findings show up, and a finding selects its sessions in the list.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Driver } from "./webdriver.mjs";
import { AUDIT } from "./audit.mjs";
import { diagnosticsHar } from "./fixtures/diagnostics-har.mjs";

const d = new Driver();
const har = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "quena-diag-")), "diagnostics.har");

before(async () => {
  fs.writeFileSync(har, JSON.stringify(diagnosticsHar()));
  await d.start(process.env.QUENA_APP, [har]);
  await d.waitFor(".statusbar", { text: "68 sessions", timeout: 30000 });
});
after(async () => {
  await d.quit();
  fs.rmSync(path.dirname(har), { recursive: true, force: true });
});

// Clicks can hit a layout that is still settling (lazy panel, report rendering): retry.
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

const button = async (label) => {
  for (const b of await d.findAll(".diag button")) if ((await d.text(b)).trim().startsWith(label)) return b;
  return null;
};

test("the analysis finds the planted problems", async () => {
  await d.exec(`window.__quena.menu("view.diagnostics")`);
  const end = Date.now() + 10000;
  let run;
  while (!(run = await button("Run")) && Date.now() < end) await new Promise((r) => setTimeout(r, 200));
  assert.ok(run, "Run button");
  await click(run);
  await d.waitFor(".diag-f-row", { text: "N+1", timeout: 30000 });
  const titles = [];
  for (const r of await d.findAll(".diag-f-row")) titles.push(await d.text(r));
  const all = titles.join("\n");
  for (const want of ["N+1", "Authentication loop", "Polling", "redirect chain", "Retries", "SameSite=None", "Uncompressed", "Large OData query"])
    assert.ok(all.toLowerCase().includes(want.toLowerCase()), `missing finding "${want}" in:\n${all}`);
  // Background polling is one operation, not one per poll.
  const ops = [];
  for (const o of await d.findAll(".diag-op-row")) ops.push(await d.text(o));
  assert.ok(ops.some((o) => o.includes("Background")), `operations: ${ops}`);
  assert.ok(ops.length <= 6, `too many operations: ${ops.length}`);
});

test("a finding selects its sessions", async () => {
  for (const r of await d.findAll(".diag-f-row")) if ((await d.text(r)).includes("N+1")) await click(r);
  const end = Date.now() + 5000;
  let sel;
  while (!(sel = await button("Select 30 sessions")) && Date.now() < end) await new Promise((r) => setTimeout(r, 200));
  assert.ok(sel, "Select 30 sessions button");
  await click(sel);
  await d.waitFor(".statusbar", { text: "30 selected" });
});

test("the scope can be narrowed to a target host", async () => {
  await click(await button("Host"));
  const item = await d.waitFor(".diag-pick-pop .f-check", { text: "legacy.test" });
  await click(await d.findIn(item, "input").then((i) => i[0]));
  await d.keys(["Escape"]);
  await d.exec(`document.body.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }))`);
  await click(await button("Run"));
  await d.waitFor(".diag-head", { text: "Host: legacy.test", timeout: 30000 });
  const titles = [];
  for (const r of await d.findAll(".diag-f-row")) titles.push(await d.text(r));
  assert.ok(titles.some((x) => /Authentication loop/i.test(x)), titles.join("\n"));
  assert.ok(!titles.some((x) => x.includes("N+1")), "app.test findings must be gone: " + titles.join("\n"));
});

test("the report fits the pane at small and large sizes", async () => {
  const problems = [];
  for (const [width, height] of [[900, 560], [1920, 1080]]) {
    await d.cmd("POST", d.s("/window/rect"), { width, height });
    await new Promise((r) => setTimeout(r, 400));
    for (const g of await d.exec(AUDIT)) problems.push({ width, ...g });
    const over = await d.exec(`const p = document.querySelector('.diag'); return p ? p.scrollWidth - p.clientWidth : -1;`);
    if (over > 1) problems.push({ width, el: ".diag horizontal overflow", w: over });
  }
  await d.cmd("POST", d.s("/window/rect"), { width: 1920, height: 1080 });
  assert.deepEqual(problems, []);
  assert.equal((await d.findAll(".app-crash")).length, 0);
});
