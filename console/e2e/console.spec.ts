// Acceptance tests of the main console flows against a running Gateway:
// sign-in, emergency stop and resume, approving a held tool call, the
// Approver role, deep links and the "not available in this build" state.
// Requirement claims (annotations) are partial: see docs/console.md.
import { expect, test, type Page } from "@playwright/test";
import { info, mcpCall } from "./gateway";

const g = info();

function claims(...ids: string[]) {
  for (const id of ids) test.info().annotations.push({ type: "requirement-partial", description: id });
}

async function signIn(page: Page, path = "/") {
  await page.goto(g.adminURL + path);
  await page.getByLabel("Password").fill(g.adminPassword);
  await page.getByRole("button", { name: "Sign in" }).click();
}

test("administrator signs in, sees enforcement state and signs out", async ({ page }) => {
  claims("FR-8.3", "FR-8.28", "FR-13.10");
  await page.goto(g.adminURL + "/");
  await page.getByLabel("Password").fill("wrong password value");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("sign-in failed");
  await expect(page.getByRole("alert")).toContainText("signin_failed");

  await page.getByLabel("Password").fill(g.adminPassword);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
  const strip = page.getByTestId("status-strip");
  await expect(strip).toContainText("not enforced");
  await expect(strip).toContainText("policy r1");
  await expect(page.getByRole("navigation", { name: "Views" }).getByRole("link")).toHaveCount(17);
  await expect(page.getByRole("heading", { name: /First-run checklist/ })).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
});

test("emergency stop refuses calls and resume restores them", async ({ page }) => {
  claims("FR-4.14", "FR-8.33");
  // FR-8.3 in full: G-01 shows enforcement state, health causes, policy
  // revision and session count, and its stop and resume actions update
  // the state display within 2 seconds.
  test.info().annotations.push({ type: "requirement", description: "FR-8.3" });
  await signIn(page);
  await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
  const strip = page.getByTestId("status-strip");
  await expect(strip).toContainText(/policy \S+/);
  await expect(strip).toContainText(/\d+ sessions?/);
  await expect(strip).toContainText(/healthy|degraded|fail-closed/);
  await expect(page.getByRole("table", { name: "Health monitor causes" })).toBeVisible();
  await page.getByTestId("emergency-button").click();
  const dialog = page.getByRole("dialog", { name: "Emergency stop" });
  await expect(dialog).toBeVisible();
  // Keyboard only: type the reason and submit with Enter.
  await page.keyboard.type("console acceptance test");
  await page.keyboard.press("Enter");
  await expect(strip).toContainText("emergency stop", { timeout: 2_000 });
  await expect(dialog).toBeHidden();
  await expect(page.getByText("Emergency stop is in effect")).toBeVisible();

  const refused = await mcpCall(g, "ref_read_file", { path: "hello.txt" }, { expect: g.marker, timeout: "30s" }).done;
  expect(refused.code).not.toBe(0);
  expect(refused.out).toMatch(/status 503|EMERGENCY_STOP/);

  await page.getByTestId("emergency-button").click();
  await page.getByRole("dialog", { name: "Resume the Gateway" }).getByRole("button", { name: "Resume the Gateway" }).click();
  await expect(strip).not.toContainText("emergency stop", { timeout: 2_000 });
  const ok = await mcpCall(g, "ref_read_file", { path: "hello.txt" }, { expect: g.marker, timeout: "60s" }).done;
  expect(ok.code, ok.out).toBe(0);

  await page.getByRole("link", { name: "Audit investigation" }).click();
  await page.getByLabel("Reason code").fill("EMERGENCY_STOP");
  await page.getByRole("button", { name: "Apply filter" }).click();
  await expect(page.getByRole("table", { name: "Journal events" })).toContainText("EMERGENCY_STOP");
});

test("an administrator approves a held call in the Approvals view", async ({ page }) => {
  claims("FR-8.23", "FR-3.25");
  // FR-8.21 in full: the pending list shows the remaining validity, and
  // G-13 approves one held call and denies another.
  test.info().annotations.push({ type: "requirement", description: "FR-8.21" });
  await signIn(page, "/approvals");
  await expect(page.getByRole("heading", { level: 1, name: "Approvals" })).toBeVisible();
  const call = mcpCall(g, "ref_read_file", { path: "hello.txt" }, { scope: "smcp:template:approval-demo", expect: g.marker });
  try {
    // The list updates from the live stream; no reload.
    const pending = page.getByRole("table", { name: "Approvals: pending" });
    const row = pending.getByRole("link", { name: "ref_read_file" });
    await expect(row).toBeVisible({ timeout: 60_000 });
    await expect(pending.getByRole("row").filter({ has: page.getByRole("link", { name: "ref_read_file" }) }).getByRole("cell").nth(5)).toHaveText(/^[0-5]:[0-5]\d$/); // Valid for
    await row.click();
    await expect(page.getByRole("heading", { level: 1, name: "Approval" })).toBeVisible();
    await expect(page.getByText("hello.txt")).toBeVisible();
    await expect(page.getByText("demo-approve")).toBeVisible();
    await page.getByLabel(/Comment/).fill("expected read of the marker file");
    await page.getByRole("button", { name: "Approve this call" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Approved." })).toBeVisible();
    // The held call continues at once and uses the approval.
    await expect(page.getByRole("definition").filter({ hasText: /^(approved|consumed)$/ })).toBeVisible();
    await expect(page.getByRole("definition").filter({ hasText: "admin:admin" })).toBeVisible();
    const r = await call.done;
    expect(r.code, r.out).toBe(0);
  } finally {
    call.kill();
  }
  await page.getByRole("link", { name: "Approvals", exact: true }).first().click();
  await page.getByRole("link", { name: "consumed", exact: true }).click();
  await expect(page.getByRole("table", { name: "Approvals: consumed" })).toContainText("ref_read_file");

  // Deny a second held call from G-13; the harness gets the denial.
  await page.getByRole("link", { name: "pending", exact: true }).click();
  const denied = mcpCall(g, "ref_read_file", { path: "hello.txt" }, { scope: "smcp:template:approval-demo", expect: g.marker });
  try {
    const row = page.getByRole("table", { name: "Approvals: pending" }).getByRole("link", { name: "ref_read_file" });
    await expect(row).toBeVisible({ timeout: 60_000 });
    await row.click();
    await page.getByRole("button", { name: "Deny this call" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Denied." })).toBeVisible();
    const r = await denied.done;
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/denied|31001|APPROVAL_DENIED/i);
  } finally {
    denied.kill();
  }
});

test("an approver sees only the Approvals view and can deny a call", async ({ page }) => {
  claims("FR-8.2", "FR-8.21", "FR-8.28");
  await page.goto(g.adminURL + "/");
  await page.getByLabel("Approver (tool-call approvals)").check();
  await page.getByLabel("Username").fill(g.approverUser);
  await page.getByLabel("Password").fill(g.approverPassword);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Approvals" })).toBeVisible();
  // Approvals and, as every role may read health (Appendix C), Gateway control.
  await expect(page.getByRole("navigation", { name: "Views" }).getByRole("link")).toHaveCount(2);
  await expect(page.getByTestId("emergency-button")).toHaveCount(0);

  const call = mcpCall(g, "ref_read_file", { path: "hello.txt" }, { scope: "smcp:template:approval-demo", expect: g.marker });
  try {
    const row = page.getByRole("table", { name: "Approvals: pending" }).getByRole("link", { name: "ref_read_file" });
    await expect(row).toBeVisible({ timeout: 60_000 });
    await row.click();
    await page.getByRole("button", { name: "Deny this call" }).click();
    const r = await call.done;
    expect(r.code).not.toBe(0);
    expect(r.out).toMatch(/denied|31001|APPROVAL_DENIED/i);
  } finally {
    call.kill();
  }
  await page.goto(g.adminURL + "/");
  await expect(page.getByRole("heading", { level: 1, name: "Approvals" })).toBeVisible();
});

test("deep links open after sign-in; missing routes say not available", async ({ page }) => {
  claims("FR-8.28", "FR-8.29");
  await signIn(page, "/servers/ref");
  await expect(page.getByRole("heading", { level: 1, name: "Server ref" })).toBeVisible();
  await expect(page.getByRole("table", { name: "Tools of ref" })).toContainText("ref_read_file");
  // Sortable headers.
  const header = page.getByRole("columnheader", { name: /Tool/ }).first();
  await header.getByRole("button").click();
  await expect(header).toHaveAttribute("aria-sort", "descending");

  // A route this build does not serve shows "Not available in this build".
  await page.route("**/api/v1/observations/status", (r) =>
    r.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ error: { code: "route_not_found", message: "not served" } }) }),
  );
  await page.getByRole("link", { name: "Audit profile tuning" }).click();
  await expect(page.getByText("Not available in this build").first()).toBeVisible();
  await page.unroute("**/api/v1/observations/status");
  await page.getByRole("link", { name: "Sessions and principals" }).click();
  await expect(page.getByRole("table", { name: "Principals" })).toContainText("claude-code-local");
});

test("the console page carries a strict content security policy", async ({ request }) => {
  claims("FR-8.26", "SR-6.17-1");
  const res = await request.get(g.adminURL + "/approvals/some-id");
  expect(res.status()).toBe(200);
  const csp = res.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("script-src 'self'");
  expect(csp).not.toContain("unsafe-inline");
  expect(csp).toContain("frame-ancestors 'none'");
  const api = await request.get(g.adminURL + "/api/v1/sessions");
  expect(api.status()).toBe(401);
});
