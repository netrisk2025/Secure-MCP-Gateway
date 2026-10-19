// Shared steps of the acceptance tests.
import { expect, test, type Cookie, type Page } from "@playwright/test";
import { info } from "./gateway";

export const g = info();

/** Records requirement claims as annotations (partial unless stated). */
export function claims(...ids: string[]) {
  for (const id of ids) test.info().annotations.push({ type: "requirement-partial", description: id });
}

export type Account = "administrator" | "approver" | "session_approver" | "operator" | "policy_author" | "auditor" | "researcher";

const cached = new Map<Account, Cookie[]>();

/**
 * Signs in and opens path. The first sign-in of each account goes through
 * the sign-in page; later ones reuse its session cookie (HttpOnly, so it is
 * copied through the browser context, not the page), which keeps the suite
 * under the per-source sign-in rate limit of the control API.
 */
export async function signIn(page: Page, path = "/", as: Account = "administrator") {
  const saved = cached.get(as);
  if (saved) {
    await page.context().addCookies(saved);
    await page.goto(g.adminURL + path);
    const strip = page.getByTestId("status-strip");
    const form = page.getByRole("button", { name: "Sign in" });
    await expect(strip.or(form)).toBeVisible();
    if (await strip.isVisible()) return;
    cached.delete(as);
  }
  await uiSignIn(page, path, as);
  const c = (await page.context().cookies(g.adminURL)).filter((x) => x.name === "__Host-smcp-session");
  if (c.length) cached.set(as, c);
}

/** Forgets a cached session (after a test signed it out). */
export function forget(as: Account) {
  cached.delete(as);
}

async function uiSignIn(page: Page, path: string, as: Account) {
  await page.goto(g.adminURL + path);
  if (as === "approver") {
    await page.getByLabel("Approver (tool-call approvals)").check();
    await page.getByLabel("Username").fill(g.approverUser);
    await page.getByLabel("Password").fill(g.approverPassword);
  } else if (as === "session_approver") {
    await page.getByLabel("Session Approver (client registrations)").check();
    await page.getByLabel("Username").fill("approver");
    await page.getByLabel("Password").fill(g.sessionApproverPassword);
  } else if (as !== "administrator") {
    await page.getByLabel("Operator, Policy Author, Auditor or Researcher").check();
    await page.getByLabel("Username").fill(g.roleUsers[as]!);
    await page.getByLabel("Password").fill(g.rolePassword);
  } else {
    await page.getByLabel("Password").fill(g.adminPassword);
  }
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByTestId("status-strip")).toBeVisible();
}

/** Moves to a console path without a page load (keeps the sign-in). */
export async function go(page: Page, path: string) {
  await page.evaluate((to) => {
    history.pushState(null, "", to);
    dispatchEvent(new PopStateEvent("popstate"));
  }, path);
}

export const nav = (page: Page) => page.getByRole("navigation", { name: "Views" });

/** Answers a control API route with a fixed JSON body. */
export async function mock(page: Page, glob: string, body: unknown, status = 200) {
  await page.route(glob, (r) => r.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) }));
}
