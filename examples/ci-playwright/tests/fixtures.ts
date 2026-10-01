// Every test records its traffic to captures/<test>.har, the input of `quena-cli diagnose`.
import { test as base } from "@playwright/test";

export const test = base.extend({
  context: async ({ browser, baseURL }, use, testInfo) => {
    const name = testInfo.titlePath.slice(1).join("-").replace(/[^a-z0-9]+/gi, "-").toLowerCase();
    const context = await browser.newContext({
      baseURL,
      // "omit": the diagnostics need timings, sizes and headers, not the bodies. Use "embed"
      // to have the character encoding of textual bodies checked as well.
      recordHar: { path: `captures/${name}.har`, content: "omit" },
    });
    await use(context);
    await context.close(); // writes the HAR
  },
});
export { expect } from "@playwright/test";
