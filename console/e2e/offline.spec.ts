// FR-8.26 local assets: every view loads and works with every request to
// another origin blocked. The browser context aborts any request that is
// not to the Gateway's admin listener and records it; each view, its help
// and its main read action are used; the page's scripts, style sheets,
// fonts and every loaded resource must come from the admin listener, and
// nothing may have tried to leave it.
import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";
import { g, go, signIn } from "./helpers";

const views = [
  "/",
  "/sessions",
  "/servers",
  "/servers/ref",
  "/catalog",
  "/library",
  "/secrets",
  "/egress",
  "/runtime",
  "/remote",
  "/policy",
  "/policy/draft",
  "/policy/filters",
  "/policy/revisions/r1",
  "/audit-profiles",
  "/anomaly-response",
  "/approvals",
  "/audit",
  "/audit/graph",
  "/observations",
  "/analytics",
  "/performance",
  "/data-server",
  "/research",
];

async function settled(page: Page, where: string) {
  await expect(page.locator("main h1"), where).toBeVisible();
  await expect(page.locator("main .loading"), `${where} still loading`).toHaveCount(0, { timeout: 20_000 });
  // Full function: no view shows an error (a route this Gateway does not
  // serve, such as the graph mirror without Neo4j, is a notice, not an error).
  await expect(page.locator("main").getByRole("alert"), `${where} shows an error`).toHaveCount(0);
}

test("every view loads and works from the local installation with outbound requests blocked", async ({ page }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.26" });
  test.setTimeout(300_000);
  const origin = new URL(g.adminURL).origin;
  const blocked: string[] = [];
  await page.context().route(
    (u) => u.origin !== origin && u.protocol !== "data:" && u.protocol !== "blob:",
    (r) => {
      blocked.push(r.request().url());
      return r.abort("internetdisconnected");
    },
  );
  const loaded = new Set<string>();
  page.on("requestfinished", (r) => loaded.add(r.url()));

  await signIn(page, "/");
  for (const v of views) {
    await go(page, v);
    await settled(page, v);
    const help = page.locator("details.help").first();
    if (await help.count()) {
      if (!(await help.evaluate((d) => (d as HTMLDetailsElement).open))) await help.locator("summary").click();
      await expect(help.locator(".help-body")).toBeVisible();
      expect(((await help.locator(".help-body").textContent()) ?? "").trim().length, `${v}: help`).toBeGreaterThan(40);
    }
  }
  // A full page load of a deep link, so the document and every asset it
  // names are fetched again under the block.
  await page.goto(g.adminURL + "/audit");
  await settled(page, "/audit (page load)");

  // Main actions of views that compute something on the Gateway.
  await go(page, "/");
  await page.getByRole("button", { name: "Verify the journal now" }).click();
  await expect(page.getByText("verified", { exact: true }).first()).toBeVisible();
  await go(page, "/policy/filters");
  await page.getByLabel("Result text").fill("Write to jane@example.com about it.");
  await page.getByRole("button", { name: "Run filters" }).click();
  await expect(page.getByRole("table", { name: "Filter runs" })).toBeVisible();
  await go(page, "/audit");
  const dl = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export CSV" }).click();
  const csv = readFileSync(await (await dl).path(), "utf8");
  expect(csv.split("\n")[0]).toContain("event_id");

  // Everything the page uses is local: scripts, style sheets, fonts (the
  // IBM Plex faces are bundled) and every resource the browser loaded.
  const page_ = await page.evaluate(() => ({
    scripts: [...document.scripts].map((s) => s.src).filter(Boolean),
    sheets: [...document.styleSheets].map((s) => s.href).filter((h): h is string => !!h),
    links: [...document.querySelectorAll("link[href]")].map((l) => (l as HTMLLinkElement).href),
    resources: performance.getEntriesByType("resource").map((e) => e.name),
    fonts: [...document.fonts].map((f) => ({ family: f.family, status: f.status })),
  }));
  for (const u of [...page_.scripts, ...page_.sheets, ...page_.links, ...page_.resources, ...loaded]) {
    if (u.startsWith("data:") || u.startsWith("blob:")) continue;
    expect(new URL(u).origin, `${u} is not from the admin listener`).toBe(origin);
  }
  expect(page_.scripts.length).toBeGreaterThan(0);
  expect(page_.sheets.length).toBeGreaterThan(0);
  const plex = page_.fonts.filter((f) => /IBM Plex/.test(f.family));
  expect(plex.length, "the bundled IBM Plex fonts are declared").toBeGreaterThan(0);
  expect(
    plex.some((f) => f.status === "loaded"),
    `no IBM Plex face loaded: ${JSON.stringify(plex)}`,
  ).toBe(true);
  expect(
    page_.resources.some((u) => /\.woff2?($|\?)/.test(u)),
    "a font file was loaded from the admin listener",
  ).toBe(true);
  expect(blocked, "requests to other origins").toEqual([]);
});
