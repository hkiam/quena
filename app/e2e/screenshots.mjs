// Screenshots for the README and the manual, taken from the real app with a generated
// capture (no personal data): `QUENA_SHOTS=1 app/e2e/run.sh <quena binary>` (Linux container,
// see run.sh) writes docs/screenshots/diagnostics*.png.
import { test, before, after } from "node:test";
import fs from "node:fs";
import path from "node:path";
import { Driver } from "./webdriver.mjs";
import { diagnosticsHar } from "./fixtures/diagnostics-har.mjs";

const d = new Driver();
const out = path.resolve(import.meta.dirname, "../../docs/screenshots");
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

// Realistic example domains instead of .test.
const capture = JSON.stringify(diagnosticsHar()).replaceAll("app.test", "shop.example.com").replaceAll("legacy.test", "erp.example.com");

async function shot(name) {
  await pause(700);
  fs.writeFileSync(path.join(out, name), Buffer.from(await d.cmd("GET", d.s("/screenshot")), "base64"));
  console.log("wrote", name);
}
async function clickText(css, text) {
  for (const e of await d.findAll(css)) if ((await d.text(e)).includes(text)) return d.click(e);
  throw new Error(`no ${css} with ${text}`);
}
async function button(label) {
  const end = Date.now() + 10000;
  for (;;) {
    for (const b of await d.findAll(".diag button")) if ((await d.text(b)).trim().startsWith(label)) return b;
    if (Date.now() > end) throw new Error(`no button ${label}`);
    await pause(200);
  }
}

before(async () => {
  // Dropped onto the window like a user would (the status bar then names only the file).
  await d.start(process.env.QUENA_APP, []);
  await d.waitFor(".grid-canvas", { timeout: 30000 });
  await d.exec(
    `const dt = new DataTransfer();
    dt.items.add(new File([arguments[0]], "shop-checkout.har", { type: "application/json" }));
    for (const type of ["dragenter", "dragover", "drop"]) window.dispatchEvent(new DragEvent(type, { dataTransfer: dt, bubbles: true, cancelable: true }));`,
    [capture],
  );
  await d.waitFor(".statusbar", { text: "68 sessions", timeout: 30000 });
  await d.cmd("POST", d.s("/window/rect"), { width: 1600, height: 1000 });
  // The default arrangement (run.sh sets request beside response for the tests).
  await d.exec(`window.__quena.setLayout({ leftWidth: 0.36, stacked: true, theme: "light" })`);
});
after(async () => {
  await d.quit();
});

test("diagnostics screenshots", async () => {
  await d.exec(`window.__quena.menu("view.diagnostics")`);
  await pause(800);
  await d.click(await button("Run"));
  await d.waitFor(".diag-f-row", { text: "N+1", timeout: 30000 });
  // 1. The report with the N+1 finding open and its sessions selected in the list.
  await clickText(".diag-f-row", "N+1");
  await d.click(await button("Select 30 sessions"));
  await shot("diagnostics.png");
  // 2. The latency estimate per network profile.
  await clickText(".diag-f-row", "Latency-sensitive");
  await d.exec(`document.querySelector('.diag-side')?.scrollTo(0, 0)`);
  await shot("diagnostics-latency.png");
  // 3. Dark theme, authentication loop.
  await d.exec(`window.__quena.setLayout({ theme: "dark" })`);
  await clickText(".diag-f-row", "Authentication loop");
  await shot("diagnostics-dark.png");
  await d.exec(`window.__quena.setLayout({ theme: "light" })`);
});

test("dark theme screenshot", async () => {
  // Inspect a JSON response in the dark theme.
  await d.exec(`window.__quena.setLayout({ theme: "dark", leftWidth: 0.44 })`);
  await d.exec(`window.__quena.menu("view.inspectors")`);
  await pause(800);
  try {
    await d.clickAt(await d.waitFor(".grid-canvas"), 80, 12 + 24 * 4);
  } catch (e) {
    console.log("grid click:", String(e).slice(0, 120), await d.exec(`const c=document.querySelector('.grid-canvas').getBoundingClientRect(); return [c.x,c.y,c.width,c.height, innerWidth, innerHeight]`));
    throw e;
  }
  await d.waitFor(".insp-url", { text: "odata/Documents" });
  const panes = await d.findAll(".insp-pane");
  // JSON opens formatted (Body) by default; make sure of it without a pointer click.
  for (const b of await d.findIn(panes[1], ".view-tabs > .segmented:not(.view-tabs-measure) .seg")) if ((await d.text(b)) === "Body") await d.exec("arguments[0].click()", [{ "element-6066-11e4-a52e-4f735466cecf": b }]);
  await d.waitFor(".cm-content", { text: "items" });
  await shot("overview-dark.png");
  await d.exec(`window.__quena.setLayout({ theme: "light", leftWidth: 0.36 })`);
});
