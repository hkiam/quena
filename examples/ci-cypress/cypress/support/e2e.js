// Every test records its traffic to its own captures/<spec>-<test title>.har (Chromium-based
// browsers only); `quena-cli diagnose captures/*.har` analyses them together.
require("@neuralegion/cypress-har-generator/commands");

const slug = (parts) =>
  parts
    .join("-")
    .replace(/[^a-z0-9]+/gi, "-")
    .replace(/^-|-$/g, "")
    .toLowerCase()
    .slice(0, 120);

beforeEach(() => cy.recordHar());
afterEach(() => {
  // The spec name keeps tests with the same title in different specs apart; a retry
  // overwrites the file of the failed attempt.
  const name = slug([Cypress.spec.name, ...Cypress.currentTest.titlePath]);
  cy.saveHar({ outDir: "captures", fileName: `${name}.har` });
});
