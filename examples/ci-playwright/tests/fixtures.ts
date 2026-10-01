// Every test records its traffic to its own captures/<project>-<file>-<title>-<id>.har, the
// input of `quena-cli diagnose`. Only the context options change; Playwright's own `context`
// fixture creates and closes the context (closing writes the HAR).
import { test as base } from "@playwright/test";

const slug = (parts: string[]) =>
  parts
    .join("-")
    .replace(/[^a-z0-9]+/gi, "-")
    .replace(/^-|-$/g, "")
    .toLowerCase()
    .slice(0, 100);

export const test = base.extend({
  contextOptions: async ({ contextOptions }, use, testInfo) => {
    // Project, spec file and title make the name readable; the test id keeps it unique (two
    // titles that differ only in punctuation). A retry overwrites the file of the failed try.
    const name = `${slug([testInfo.project.name, ...testInfo.titlePath])}-${testInfo.testId}`;
    await use({
      ...contextOptions,
      // "omit": the diagnostics need timings, sizes and headers, not the bodies. Use "embed"
      // to have the character encoding of textual bodies checked as well.
      recordHar: { path: `captures/${name}.har`, content: "omit" },
    });
  },
});
export { expect } from "@playwright/test";
