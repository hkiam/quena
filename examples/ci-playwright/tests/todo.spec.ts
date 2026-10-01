import { expect, test } from "./fixtures";

test("add a todo", async ({ page }) => {
  await page.goto("/todomvc/");
  await page.getByPlaceholder("What needs to be done?").fill("Check the network with Quena");
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("todo-title")).toHaveText(["Check the network with Quena"]);
});
