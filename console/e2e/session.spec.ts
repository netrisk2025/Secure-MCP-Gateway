// The console's browser session in a real browser (SR-2.6-1, SR-8.9-1): the
// cookie the browser stores, that page script sees no credential, that a
// mutation without the CSRF token or with a stale revision is refused, that
// the console recovers from a stale revision, and that sign-out ends the
// session at once. The Go tests in internal/adminapi verify each property;
// these claims are partial.
import { expect, test } from "@playwright/test";
import { claims, forget, g, signIn } from "./helpers";

test("the browser session is an HttpOnly, Secure, SameSite=Strict cookie and survives a reload", async ({ page }) => {
  claims("SR-2.6-1");
  await signIn(page, "/");
  const cookies = await page.context().cookies(g.adminURL);
  const c = cookies.find((x) => x.name === "__Host-smcp-session");
  expect(c, JSON.stringify(cookies)).toBeTruthy();
  expect(c!.httpOnly).toBe(true);
  expect(c!.secure).toBe(true);
  expect(c!.sameSite).toBe("Strict");
  expect(c!.path).toBe("/");
  // Nothing the page script can read holds a credential.
  const visible = await page.evaluate(() => ({ cookie: document.cookie, session: JSON.stringify(sessionStorage), local: JSON.stringify(localStorage) }));
  expect(visible.cookie).not.toContain("smcp-session");
  expect(visible.session + visible.local).not.toMatch(/token/i);
  await page.reload();
  await expect(page.getByTestId("status-strip")).toBeVisible();
});

test("mutations without the CSRF token or with a stale revision are refused", async ({ page }) => {
  claims("SR-8.9-1");
  await signIn(page, "/");
  await expect(page.getByTestId("status-strip")).toBeVisible();
  const results = await page.evaluate(async () => {
    const health = await fetch("/admin/v1/health", { credentials: "same-origin" });
    const tag = health.headers.get("ETag") ?? "";
    const session = (await (await fetch("/api/v1/console/session", { credentials: "same-origin" })).json()) as { csrf_token: string };
    const verify = (h: Record<string, string>) =>
      fetch("/api/v1/audit/verify", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", ...h }, body: "{}" }).then((r) => r.status);
    return {
      tag,
      noToken: await verify({ "If-Match": tag }),
      wrongToken: await verify({ "If-Match": tag, "X-CSRF-Token": "wrong" }),
      noIfMatch: await verify({ "X-CSRF-Token": session.csrf_token }),
      stale: await verify({ "X-CSRF-Token": session.csrf_token, "If-Match": '"stale-0"' }),
      ok: await verify({ "X-CSRF-Token": session.csrf_token, "If-Match": tag }),
      replay: await verify({ "X-CSRF-Token": session.csrf_token, "If-Match": tag }),
    };
  });
  expect(results.tag).not.toBe("");
  expect(results.noToken).toBe(403);
  expect(results.wrongToken).toBe(403);
  expect(results.noIfMatch).toBe(428);
  expect(results.stale).toBe(412);
  expect(results.ok).toBe(200);
  expect(results.replay).toBe(412);
});

test("the console reports a stale revision and the retry succeeds", async ({ page, request }) => {
  claims("SR-8.9-1", "FR-8.29");
  await signIn(page, "/audit");
  await expect(page.getByRole("heading", { level: 1, name: "Audit investigation" })).toBeVisible();
  // Another client (a bearer token, as smcpctl uses) changes Gateway state.
  const login = await request.post(g.adminURL + "/admin/v1/login", { data: { username: "admin", password: g.adminPassword }, headers: { Origin: g.adminURL } });
  const { token } = (await login.json()) as { token: string };
  const r = await request.post(g.adminURL + "/api/v1/audit/verify", { data: {}, headers: { Authorization: `Bearer ${token}`, Origin: g.adminURL } });
  expect(r.status()).toBe(200);
  await page.getByRole("button", { name: /Verify the journal/ }).click();
  await expect(page.getByText(/changed since/)).toBeVisible();
  await page.getByRole("button", { name: /Verify the journal/ }).click();
  await expect(page.getByText(/changed since/)).toHaveCount(0);
});

test("revisions are per object: a change to another object does not force a re-read", async ({ page, request }) => {
  claims("SR-8.9-1");
  await signIn(page, "/audit");
  await expect(page.getByRole("heading", { level: 1, name: "Audit investigation" })).toBeVisible();
  await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
  // Another client changes an unrelated object (a principal) after the view was read.
  const login = await request.post(g.adminURL + "/admin/v1/login", { data: { username: "admin", password: g.adminPassword }, headers: { Origin: g.adminURL } });
  const { token } = (await login.json()) as { token: string };
  const auth = { Authorization: `Bearer ${token}`, Origin: g.adminURL };
  const principals = (await (await request.get(g.adminURL + "/api/v1/principals", { headers: auth })).json()) as { principals: { id: string; status?: string }[] };
  const p = principals.principals.find((x) => x.status !== "suspended") ?? principals.principals[0]!;
  const r = await request.post(g.adminURL + `/api/v1/principals/${p.id}/enable`, { data: { reason: "per-object revision test" }, headers: auth });
  expect(r.headers()["x-smcp-object"]).toBe(`principals/{${p.id}}`);
  // The audit verification (another object) goes through without a re-read.
  const answer = page.waitForResponse((x) => x.url().endsWith("/api/v1/audit/verify") && x.request().method() === "POST");
  await page.getByRole("button", { name: /Verify the journal/ }).click();
  expect((await answer).status()).toBe(200);
  await expect(page.getByRole("definition").filter({ hasText: /^verified$/ })).toBeVisible();
  await expect(page.getByText(/changed since/)).toHaveCount(0);
});

test("sign-out ends the session at once", async ({ page }) => {
  claims("SR-2.6-1");
  await signIn(page, "/");
  const saved = await page.context().cookies(g.adminURL);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  forget("administrator");
  // The old cookie, put back, no longer opens the console.
  await page.context().addCookies(saved.filter((c) => c.name === "__Host-smcp-session"));
  await page.goto(g.adminURL + "/");
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  const status = await page.evaluate(() => fetch("/admin/v1/health", { credentials: "same-origin" }).then((r) => r.status));
  expect(status).toBe(401);
});
