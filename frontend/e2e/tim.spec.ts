import { expect, type Page, test } from "@playwright/test";

const USER = process.env.TIM_E2E_USER ?? "admin";
const PASSWORD = process.env.TIM_E2E_PASSWORD ?? "ChangeMe!2026";

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Username").fill(USER);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
}

test.describe("analyst workflow (demo data)", () => {
  test.beforeEach(async ({ page }) => login(page));

  test("dashboard shows statistics, clusters and screenshots", async ({ page }) => {
    await expect(page.getByText("Investigations today")).toBeVisible();
    await expect(page.getByText("Threat clusters").first()).toBeVisible();
    await expect(page.getByText("Recent screenshots")).toBeVisible();
    await expect(page.locator("img[alt]").first()).toBeVisible();
  });

  test("rejects invalid IOCs on the investigation form", async ({ page }) => {
    await page.getByRole("link", { name: "Investigations" }).first().click();
    await page.getByRole("textbox", { name: "IOC", exact: true }).fill("not a valid ioc !!");
    await page.getByRole("button", { name: "Investigate" }).click();
    await expect(page.getByText(/invalid domain/i)).toBeVisible();
  });

  test("threat clusters list, detail and graph explorer", async ({ page }) => {
    await page.goto("/clusters");
    await expect(page.getByText("Contoso Bank impersonation cluster")).toBeVisible();
    await page.getByText("Contoso Bank impersonation cluster").click();
    await expect(page.getByRole("tab", { name: /Members/ })).toBeVisible();
    await expect(page.getByText(/result\(s\)/)).toBeVisible();
    await page.getByRole("link", { name: "Open graph" }).click();
    await expect(page.getByRole("heading", { name: "Graph Explorer" })).toBeVisible();
    await expect(page.locator(".react-flow__node").first()).toBeVisible();
    await page.getByPlaceholder("Search & highlight…").fill("contoso");
    await expect(page.getByText(/match\(es\)/)).toBeVisible();
  });

  test("asset search, filter and asset detail", async ({ page }) => {
    await page.getByLabel("Search assets").fill("fabrikam");
    await page.getByLabel("Search assets").press("Enter");
    await expect(page.getByRole("heading", { name: "Assets" })).toBeVisible();
    const firstAsset = page.getByRole("link", { name: /fabrikam/ }).first();
    await expect(firstAsset).toBeVisible();
    await firstAsset.click();
    await expect(page.getByRole("tab", { name: /Relationships/ })).toBeVisible();
    await page.getByRole("tab", { name: /Relationships/ }).click();
    await expect(page.getByText("USES_CERTIFICATE").first()).toBeVisible();
  });

  test("investigation detail shows pipeline, results table and exports", async ({ page }) => {
    await page.goto("/investigations");
    await page.getByRole("link", { name: /contoso-secure\.test/ }).first().click();
    await expect(page.getByText("Pipeline")).toBeVisible();
    await page.getByRole("tab", { name: "Results" }).click();
    await expect(page.getByLabel("Search results")).toBeVisible();
    await page.getByRole("button", { name: "Export" }).first().click();
    await expect(page.getByText("Generate report")).toBeVisible();
    await page.getByRole("button", { name: /JSON/ }).first().click();
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: /Generate JSON/ }).click();
    expect((await download).suggestedFilename()).toMatch(/\.json$/);
  });

  test("providers and settings pages render for admins", async ({ page }) => {
    await page.goto("/providers");
    await expect(page.getByText("Free sources", { exact: true })).toBeVisible();
    await expect(page.getByText("crt.sh", { exact: true })).toBeVisible();
    await page.goto("/settings");
    await page.getByRole("tab", { name: "Scoring model" }).click();
    await expect(page.getByText("Correlation weights")).toBeVisible();
  });
});
