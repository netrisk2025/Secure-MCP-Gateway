// FR-8.23 live updates: with G-01 and G-13 open at the same time, a change
// of health state and a new pending approval, both made outside the
// browser, reach the open views through the server-sent-events channel
// within 2 seconds, without a reload. The health change is an emergency
// stop and resume sent to the control API with the operator token; the
// approval is a held tool call of the test MCP client, timed from the
// approval's created_at.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { expect, test, type APIRequestContext, type Locator } from "@playwright/test";
import { mcpCall } from "./gateway";
import { g, signIn } from "./helpers";

const operatorToken = () => readFileSync(join(dirname(g.config), "state", "keys", "admin.token"), "utf8").trim();

async function control(request: APIRequestContext, path: string, data: object) {
  const r = await request.post(g.adminURL + path, { data, headers: { Authorization: `Bearer ${operatorToken()}` } });
  expect(r.status(), await r.text()).toBe(200);
}

/** Polls the locator until it is visible and returns the time it was first seen. */
async function seenAt(l: Locator, timeout: number): Promise<number> {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (await l.isVisible()) return Date.now();
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`not visible within ${timeout} ms: ${l}`);
}

test("G-01 and G-13 update within 2 seconds of a health change and a new approval, without a reload", async ({ page, browser, request }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.23" });
  await signIn(page, "/");
  await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
  const approvals = await browser.newPage({ ignoreHTTPSErrors: true });
  await approvals.context().addCookies(await page.context().cookies());
  await approvals.goto(g.adminURL + "/approvals");
  await expect(approvals.getByRole("heading", { level: 1, name: "Approvals" })).toBeVisible();
  // Both views hold the live channel open.
  for (const p of [page, approvals]) await expect(p.getByTestId("status-strip")).toContainText("live");
  let reloads = 0;
  for (const p of [page, approvals]) p.on("load", () => reloads++);

  // Health state: emergency stop, then resume.
  const strip = page.getByTestId("status-strip");
  await expect(strip).not.toContainText("emergency stop");
  let t0 = Date.now();
  // The shared Gateway must not stay stopped when an assertion fails.
  const resume = () =>
    request.post(g.adminURL + "/admin/v1/resume", { data: {}, headers: { Authorization: `Bearer ${operatorToken()}` } }).catch(() => undefined);
  try {
    await control(request, "/admin/v1/stop", { reason: "FR-8.23 live update test" });
    let shown = await seenAt(strip.getByText("emergency stop").first(), 2_000);
    console.log(`FR-8.23: emergency stop shown in G-01 ${shown - t0} ms after the request was sent`);
    expect(shown - t0).toBeLessThanOrEqual(2_000);
    await expect(page.getByText("Emergency stop is in effect")).toBeVisible();
    t0 = Date.now();
    await control(request, "/admin/v1/resume", {});
    const end = Date.now() + 2_000;
    while (Date.now() < end && (await strip.textContent())?.includes("emergency stop")) await new Promise((r) => setTimeout(r, 25));
    shown = Date.now();
    console.log(`FR-8.23: resume shown in G-01 ${shown - t0} ms after the request was sent`);
    await expect(strip).not.toContainText("emergency stop", { timeout: 1 });
    expect(shown - t0).toBeLessThanOrEqual(2_000);
  } finally {
    await resume();
  }

  // A new pending approval reaches G-13.
  const call = mcpCall(g, "ref_read_file", { path: "hello.txt" }, { scope: "smcp:template:approval-demo", expect: g.marker, timeout: "90s" });
  try {
    const row = approvals.getByRole("table", { name: "Approvals: pending" }).getByRole("link", { name: "ref_read_file" });
    const seen = await seenAt(row, 60_000);
    const list = await request.get(g.adminURL + "/api/v1/approvals?state=pending", { headers: { Authorization: `Bearer ${operatorToken()}` } });
    const items = ((await list.json()) as { approvals: { id: string; created_at: string; tool?: string }[] }).approvals;
    expect(items.length).toBeGreaterThan(0);
    const created = Math.max(...items.map((a) => Date.parse(a.created_at)));
    console.log(`FR-8.23: pending approval shown in G-13 ${seen - created} ms after it was created`);
    expect(seen - created).toBeLessThanOrEqual(2_000);
    // G-01's session count follows too (the approval's session).
    await expect(page.getByTestId("status-strip")).toContainText(/\d+ sessions?/);
    for (const a of items) {
      const r = await request.post(g.adminURL + `/api/v1/approvals/${a.id}/deny`, {
        data: { comment: "FR-8.23 cleanup" },
        headers: { Authorization: `Bearer ${operatorToken()}` },
      });
      expect([200, 409]).toContain(r.status());
    }
    await call.done;
  } finally {
    call.kill();
  }
  expect(reloads, "a view reloaded instead of updating live").toBe(0);
  await approvals.close();
});
