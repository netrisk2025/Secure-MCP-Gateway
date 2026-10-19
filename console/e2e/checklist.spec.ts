// FR-8.31 first-run checklist, from a fresh installation. A dedicated
// Gateway is bootstrapped and started without the bootstrap's Session
// Approver account, and its packaged reference server is suspended, so
// that only "Administrator created" and "First policy revision published"
// are done at the start (bootstrap requires the administrator and imports
// the policy file as the first revision). Each other item is then completed
// in the console or by a harness, and each must turn "done" from Gateway
// state: the checklist has no control a person could tick, and an item's
// state follows the Gateway when the state is taken back (the reference
// server suspended again). Each item links to the view that completes it.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { mcpCall, startDedicated } from "./gateway";
import { go } from "./helpers";

const items = [
  ["Administrator created", "/sessions"],
  ["Session Approver created", "/sessions"],
  ["First server packaged and enabled", "/servers"],
  ["First policy revision published", "/policy"],
  ["First harness connected", "/sessions"],
  ["Approval tested", "/approvals"],
  ["Backup configured", "/data-server"],
] as const;

function row(page: Page, item: string) {
  return page.getByRole("table", { name: "First-run checklist" }).getByRole("row").filter({ hasText: item });
}

async function expectState(page: Page, item: string, state: "done" | "to do") {
  await go(page, "/");
  await expect(row(page, item).getByRole("cell").nth(1), `${item}: ${state}`).toHaveText(state, { timeout: 15_000 });
}

test("the G-01 first-run checklist marks each item done from Gateway state, on a fresh installation", async ({ browser }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.31" });
  test.setTimeout(600_000);
  // No [[approver]] table: the installation starts without a Session Approver.
  const d = await startDedicated("checklist", { edit: (t) => t.replace(/^\[\[approver\]\]\nusername = "approver"\npassword_hash = ".*"\n/m, "") });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  try {
    expect(readFileSync(d.config, "utf8")).not.toContain("[[approver]]");
    const signIn = async () => {
      await page.goto(d.adminURL + "/");
      await page.getByLabel("Password").fill(d.adminPassword);
      await page.getByRole("button", { name: "Sign in" }).click();
      await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
    };
    await signIn();

    // Start state: the server suspended in G-10 (it was enabled by bootstrap).
    await go(page, "/library");
    const revs = page.getByRole("table", { name: "Package revisions" });
    await revs.getByRole("button", { name: /^Suspend smcp-ref-filesystem / }).click();
    await page
      .getByRole("dialog", { name: /^Suspend smcp-ref-filesystem / })
      .getByRole("button", { name: "Suspend", exact: true })
      .click();
    await expect(revs.getByRole("row").filter({ hasText: "verified-disabled" })).toHaveCount(1);

    await go(page, "/");
    const table = page.getByRole("table", { name: "First-run checklist" });
    await expect(table.getByRole("row")).toHaveCount(items.length + 1);
    // Nothing in the checklist can be ticked by hand.
    await expect(table.locator("input, select, textarea, button, [role=checkbox]")).toHaveCount(0);
    for (const [item, to] of items) await expect(row(page, item).getByRole("link"), `${item} links to ${to}`).toHaveAttribute("href", to);
    await expectState(page, "Administrator created", "done");
    await expectState(page, "First policy revision published", "done");
    await expect(row(page, "First policy revision published")).toContainText(/Revision \S+ is active/);
    for (const item of ["Session Approver created", "First server packaged and enabled", "First harness connected", "Approval tested", "Backup configured"])
      await expectState(page, item, "to do");
    await expect(page.getByRole("heading", { name: "First-run checklist: 5 of 7 open" })).toBeVisible();

    // Session Approver: created in G-11 from the item's link.
    await row(page, "Session Approver created").getByRole("link").click();
    await expect(page.getByRole("heading", { level: 1, name: "Sessions and principals" })).toBeVisible();
    const form = page.getByRole("form", { name: "Add a Session Approver" });
    await form.getByLabel("Username").fill("approver");
    await form.getByLabel("Password", { exact: true }).fill(d.sessionApproverPassword);
    await form.getByLabel("Repeat password").fill(d.sessionApproverPassword);
    await form.getByRole("button", { name: "Create Session Approver" }).click();
    await expect(page.getByText("Created Session Approver approver.")).toBeVisible();
    await expectState(page, "Session Approver created", "done");
    await expect(row(page, "Session Approver created")).toContainText("1 Session Approver account configured.");

    // First server packaged and enabled: enabled in G-10; servers launch at start.
    await row(page, "First server packaged and enabled").getByRole("link").click();
    await go(page, "/library");
    await revs.getByRole("button", { name: /^Enable smcp-ref-filesystem / }).click();
    await page
      .getByRole("dialog", { name: /^Enable smcp-ref-filesystem / })
      .getByRole("button", { name: "Enable", exact: true })
      .click();
    await expect(page.getByText(/^Enabled smcp-ref-filesystem .* as ref\./)).toBeVisible();
    await d.restart();
    await signIn();
    await expectState(page, "First server packaged and enabled", "done");
    await expect(row(page, "First server packaged and enabled")).toContainText("1 server enabled from a verified package.");

    // First harness connected: the test MCP client signs in with OAuth.
    let r = await mcpCall(d, "ref_read_file", { path: "hello.txt" }, { expect: d.marker, timeout: "60s" }).done;
    expect(r.code, r.out).toBe(0);
    await expectState(page, "First harness connected", "done");

    // Approval tested: a held call approved in G-13.
    const held = mcpCall(d, "ref_read_file", { path: "hello.txt" }, { scope: "smcp:template:approval-demo", expect: d.marker, timeout: "90s" });
    try {
      await go(page, "/approvals");
      const pending = page.getByRole("table", { name: "Approvals: pending" }).getByRole("link", { name: "ref_read_file" });
      await expect(pending).toBeVisible({ timeout: 60_000 });
      await pending.click();
      await page.getByRole("button", { name: "Approve this call" }).click();
      await expect(page.getByRole("status").filter({ hasText: "Approved." })).toBeVisible();
      r = await held.done;
      expect(r.code, r.out).toBe(0);
    } finally {
      held.kill();
    }
    await expectState(page, "Approval tested", "done");

    // Backup configured: a backup taken in G-08.
    await row(page, "Backup configured").getByRole("link").click();
    await expect(page.getByRole("heading", { level: 1, name: "Data server and memory" })).toBeVisible();
    const take = page.getByRole("form", { name: "Take a backup" });
    await take.getByLabel("Passphrase").fill("checklist backup passphrase");
    await take.getByRole("button", { name: "Take a backup now" }).click();
    await expect(page.getByText(/^Backup written: /)).toBeVisible({ timeout: 60_000 });
    await expectState(page, "Backup configured", "done");
    await expect(page.getByRole("heading", { name: "First-run checklist: complete" })).toBeVisible();
    for (const [item] of items) await expectState(page, item, "done");

    // From Gateway state, not a tick: suspending the server again opens its item.
    await go(page, "/library");
    await revs.getByRole("button", { name: /^Suspend smcp-ref-filesystem / }).click();
    await page
      .getByRole("dialog", { name: /^Suspend smcp-ref-filesystem / })
      .getByRole("button", { name: "Suspend", exact: true })
      .click();
    await expect(revs.getByRole("row").filter({ hasText: "verified-disabled" })).toHaveCount(1);
    await expectState(page, "First server packaged and enabled", "to do");
    await expect(page.getByRole("heading", { name: "First-run checklist: 1 of 7 open" })).toBeVisible();
    expect(readFileSync(join(d.dir, "smcp.toml"), "utf8")).not.toContain("[[approver]]");
  } finally {
    await ctx.close();
    d.stop();
  }
});
