import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests",
  use: { baseURL: process.env.BASE_URL ?? "https://demo.playwright.dev" },
});
