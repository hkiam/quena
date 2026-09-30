// The German UI (longer texts): translated, and the layout still fits at small and large sizes.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { Driver } from "./webdriver.mjs";
import { AUDIT, checkPluginsDialog } from "./audit.mjs";
import path from "node:path";

const har = path.resolve(import.meta.dirname, "fixtures/two-sessions.har");
const d = new Driver();
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

before(async () => {
  await d.start(process.env.QUENA_APP, [har]);
  await d.waitFor(".grid-canvas", { timeout: 20000 });
});
after(() => d.quit());

test("the UI is German", async () => {
  assert.equal(await d.exec("return document.documentElement.lang"), "de");
  await d.waitFor(".rp-tab", { text: "Inspektor" });
  await d.waitFor(".rp-tab", { text: "Zeitachse" });
});

// Elements of a bar that stick out of the bar or the window, or overlap their neighbour.
const OVERFLOW = `
const out = [];
for (const sel of ['.toolbar', '.statusbar', '.rp-tabs']) for (const bar of document.querySelectorAll(sel)) {
  const b = bar.getBoundingClientRect();
  const right = Math.min(b.right, bar.parentElement.getBoundingClientRect().right, innerWidth);
  const kids = [...bar.children].filter((k) => k.getBoundingClientRect().width > 0);
  kids.forEach((k, i) => {
    const r = k.getBoundingClientRect();
    if (r.right > right + 1 || r.left < b.left - 1) out.push(sel + ': ' + (k.textContent || k.className).trim().slice(0, 40) + ' outside');
    const prev = kids[i - 1]?.getBoundingClientRect();
    if (prev && Math.abs(prev.top - r.top) < 4 && r.left < prev.right - 1) out.push(sel + ': ' + (k.textContent || k.className).trim().slice(0, 40) + ' overlaps');
  });
}
return out;`;

test("toolbar, status bar and tabs fit, and the layout fills the window", async () => {
  const problems = [];
  for (const stacked of [false, true]) {
    await d.exec(`window.__quena.setLayout({ stacked: ${stacked}, leftWidth: 0.5 })`);
    for (const [width, height] of [[900, 560], [1280, 800], [1920, 1080]]) {
      await d.cmd("POST", d.s("/window/rect"), { width, height });
      await d.clickAt(await d.waitFor(".grid-canvas"), 80, 12);
      await pause(400);
      for (const g of await d.exec(AUDIT)) problems.push({ stacked, width, ...g });
      for (const o of await d.exec(OVERFLOW)) problems.push({ stacked, width, o });
    }
  }
  await d.exec(`window.__quena.setLayout({ stacked: false, leftWidth: 0.5 })`);
  await d.cmd("POST", d.s("/window/rect"), { width: 1920, height: 1080 });
  assert.deepEqual(problems, []);
});

test("settings tabs are readable", async () => {
  await d.exec(`window.__quena.menu("tools.options")`);
  await d.waitFor(".modal-title", { text: "Optionen" });
  const rects = [];
  for (const t of await d.findAll(".tabs-row .insp-tab")) rects.push(await d.rect(t));
  assert.ok(rects.length >= 4);
  for (let i = 1; i < rects.length; i++) assert.ok(rects[i].x >= rects[i - 1].x + rects[i - 1].width, "tabs overlap");
  await d.keys(["Escape"]);
});

test("the plugins dialog keeps its columns readable", async () => {
  await checkPluginsDialog(d, assert);
  await d.cmd("POST", d.s("/window/rect"), { width: 1920, height: 1080 });
});

test("every panel opens without crashing", async () => {
  for (const id of ["view.composer", "view.statistics", "view.filters", "view.log", "view.timeline", "view.structure", "view.inspectors"]) {
    await d.exec(`window.__quena.menu(${JSON.stringify(id)})`);
    await pause(250);
  }
  assert.equal((await d.findAll(".view-error")).length, 0);
  assert.equal((await d.findAll(".app-crash")).length, 0);
});
