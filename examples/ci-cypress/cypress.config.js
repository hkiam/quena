const { defineConfig } = require("cypress");
const { install } = require("@neuralegion/cypress-har-generator");

module.exports = defineConfig({
  e2e: {
    baseUrl: process.env.BASE_URL ?? "https://example.cypress.io",
    setupNodeEvents(on) {
      install(on);
    },
  },
});
