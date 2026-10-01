// Every spec records its traffic to captures/<spec>.har (Chromium-based browsers only).
require("@neuralegion/cypress-har-generator/commands");

beforeEach(() => cy.recordHar());
afterEach(() => cy.saveHar({ outDir: "captures", fileName: `${Cypress.spec.name}.har` }));
