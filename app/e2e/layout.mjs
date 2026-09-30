// Layout audit: open the real app at several window sizes and layouts, visit every right-pane
// tab, and report containers whose content leaves unused space (plus screenshots).
//   QUENA_APP=... node layout.mjs <out-dir>   (tauri-driver must be running)
import { Driver } from "./webdriver.mjs";
import { AUDIT } from "./audit.mjs";
import fs from "node:fs";
import path from "node:path";

const out = process.argv[2] ?? "/tmp/layout";
fs.mkdirSync(out, { recursive: true });
const d = new Driver();
await d.start(process.env.QUENA_APP, [path.resolve(import.meta.dirname, "fixtures/two-sessions.har")]);
await d.waitFor(".statusbar", { text: "sessions", timeout: 20000 });

async function shot(file) {
  const b64 = await d.cmd("GET", d.s("/screenshot"));
  fs.writeFileSync(path.join(out, file), Buffer.from(b64, "base64"));
}
async function tab(label) {
  for (const t of await d.findAll(".rp-tab")) if ((await d.text(t)).includes(label)) return d.click(t);
}

const report = [];
const sizes = [[900, 560], [1280, 800], [1920, 1080], [2560, 1440]];
// Select the first session so the inspectors have content.
await d.clickAt(await d.waitFor(".grid-canvas"), 80, 12);
await d.waitFor(".insp-url", { text: "api.example.com" });
// Response pane on Body, so the text/editor views are measured too.
const panes = await d.findAll(".insp-pane");
for (const b of await d.findIn(panes[1], ".view-tabs > .segmented:not(.view-tabs-measure) .seg")) if ((await d.text(b)) === "Body") await d.click(b);
await d.waitFor(".cm-content", { text: "items" });
const scenarios = [
  { name: "side", patch: { stacked: false, leftWidth: 0.5 } },
  { name: "stacked", patch: { stacked: true, leftWidth: 0.5 } },
  // Splitter dragged far right: a narrow right pane.
  { name: "narrowpane", patch: { stacked: false, leftWidth: 0.72 } },
];
for (const sc of scenarios) {
  const stacked = sc.name;
  await d.exec(`window.__quena.setLayout(${JSON.stringify(sc.patch)})`);
  for (const [w, h] of sizes) {
    await d.cmd("POST", d.s("/window/rect"), { width: w, height: h }).catch((e) => report.push({ size: `${w}x${h}`, error: String(e) }));
    await new Promise((r) => setTimeout(r, 400));
    for (const t of ["Inspect", "Composer", "Mock Rules", "Filters", "Timeline", "Statistics", "Log"]) {
      await tab(t);
      await new Promise((r) => setTimeout(r, 250));
      const gaps = await d.exec(AUDIT);
      const view = await d.exec("return [innerWidth, innerHeight]");
      if (gaps.length) report.push({ layout: stacked, size: `${w}x${h}`, viewport: view.join("x"), tab: t, gaps });
      if (t === "Inspect" || w === 1920) await shot(`${stacked}-${w}x${h}-${t.replace(" ", "")}.png`);
    }
    await tab("Inspect");
  }
}
fs.writeFileSync(path.join(out, "report.json"), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));
await d.quit();
