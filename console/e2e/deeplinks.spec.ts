// FR-8.28 navigation and deep links. Each Appendix C role signs in and the
// persistent navigation must list exactly the views that role may open:
// the views one of whose control API routes the role may use, by the
// x-smcp-roles of the Gateway's OpenAPI document. Then the URL of an
// approval, a session, a server revision, a decision and a policy revision
// is opened in a new browser session (no cookie): each shows the sign-in
// form and, after sign-in, the record itself.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { expect, test, type APIRequestContext, type Browser } from "@playwright/test";
import { mcpCall } from "./gateway";
import { g, nav, signIn, type Account } from "./helpers";

// The views of the console registry (console/src/views/registry.tsx): the
// link text of each and the control API routes it reads.
const registry: { title: string; routes: string[] }[] = [
  { title: "Gateway control", routes: ["GET /admin/v1/health"] },
  { title: "Sessions and principals", routes: ["GET /api/v1/sessions"] },
  { title: "Servers and library", routes: ["GET /api/v1/servers", "GET /api/v1/packages"] },
  { title: "Secrets", routes: ["GET /api/v1/secrets"] },
  { title: "Egress", routes: ["GET /api/v1/egress"] },
  { title: "Runtime", routes: ["GET /api/v1/runtime"] },
  { title: "Remote access", routes: ["GET /api/v1/remote", "GET /api/v1/clients"] },
  { title: "Policy studio", routes: ["GET /api/v1/policy", "POST /api/v1/filters/scan"] },
  { title: "Audit profile tuning", routes: ["GET /api/v1/observations/status"] },
  { title: "Anomaly response", routes: ["GET /api/v1/observations/status"] },
  { title: "Approvals", routes: ["GET /api/v1/approvals"] },
  { title: "Audit investigation", routes: ["GET /api/v1/audit/events"] },
  { title: "Observation workbench", routes: ["GET /api/v1/observations/parameters"] },
  { title: "Behavior analytics", routes: ["GET /api/v1/baselines", "GET /api/v1/anomalies"] },
  { title: "Performance", routes: ["GET /api/v1/observations/metrics"] },
  { title: "Data server and memory", routes: ["GET /api/v1/graph/status", "GET /api/v1/backup", "GET /api/v1/observations/status"] },
  { title: "Research campaigns", routes: ["GET /api/v1/research/campaigns", "GET /api/v1/research/exports"] },
];

const roles: Account[] = ["administrator", "operator", "policy_author", "auditor", "researcher", "approver", "session_approver"];

const operatorToken = () => readFileSync(join(dirname(g.config), "state", "keys", "admin.token"), "utf8").trim();

async function getJSON<T>(request: APIRequestContext, path: string): Promise<T> {
  const r = await request.get(g.adminURL + path, { headers: { Authorization: `Bearer ${operatorToken()}` } });
  expect(r.status(), `${path}: ${await r.text()}`).toBe(200);
  return (await r.json()) as T;
}

/** Opens url in a new browser session, signs in as the Administrator, and returns the page. */
async function openFresh(browser: Browser, url: string) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  const res = await page.goto(g.adminURL + url);
  expect(res?.status(), `${url}: ${await res?.text()}`).toBe(200);
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Password").fill(g.adminPassword);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByTestId("status-strip")).toBeVisible();
  expect(new URL(page.url()).pathname).toBe(url.split("?")[0]);
  return { page, close: () => ctx.close() };
}

test("the navigation lists exactly the permitted views of each role, and record URLs open after sign-in", async ({ browser, request }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.28" });
  test.setTimeout(300_000);
  const doc = await getJSON<{ paths: Record<string, Record<string, { "x-smcp-roles"?: string[] }>> }>(request, "/api/v1/openapi.json");
  const rolesOf = (route: string): string[] | undefined => {
    const [method, path] = route.split(" ");
    return doc.paths[path!]?.[method!.toLowerCase()]?.["x-smcp-roles"];
  };
  for (const role of roles) {
    const permitted = registry
      .filter((v) => role === "administrator" || v.routes.some((r) => (rolesOf(r) ?? []).includes(role)))
      .map((v) => v.title)
      .sort();
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await ctx.newPage();
    await signIn(page, "/", role);
    await expect(nav(page).getByRole("link").first()).toBeVisible();
    const listed = (await nav(page).getByRole("link").allTextContents()).map((t) => t.replace(/^G-\d\d\s*/, "").trim()).sort();
    expect(listed, `navigation of ${role}`).toEqual(permitted);
    // The navigation is persistent: it stays on a detail page.
    await page.goto(g.adminURL + "/policy/revisions/r1");
    await expect(nav(page).getByRole("link")).toHaveCount(permitted.length);
    await ctx.close();
  }

  // Records to link to.
  await mcpCall(g, "ref_echo", { text: "deep link" }, { expect: "deep link", timeout: "60s" }).done;
  const sessions = await getJSON<{ sessions: { id: string }[] }>(request, "/api/v1/sessions");
  expect(sessions.sessions.length).toBeGreaterThan(0);
  const sessionID = sessions.sessions[0]!.id;
  const decisions = await getJSON<{ events: { decision_id?: string }[] }>(request, "/api/v1/audit/events?class=decision&limit=20");
  const decisionID = decisions.events.find((e) => e.decision_id)?.decision_id;
  expect(decisionID, "a decision in the journal").toBeTruthy();
  const pkgs = await getJSON<{ revisions: { server_id: string; revision: string }[] }>(request, "/api/v1/packages");
  const pkg = pkgs.revisions[0]!;
  const revs = await getJSON<{ active: string }>(request, "/api/v1/policy/revisions");

  const links: [string, string, RegExp][] = [
    ["session", `/sessions/${sessionID}`, /^Session/],
    ["server revision", `/library/${encodeURIComponent(pkg.server_id)}/${encodeURIComponent(pkg.revision)}`, new RegExp(`^Package ${pkg.server_id}$`)],
    ["decision", `/audit/decisions/${decisionID}`, /^Decision$/],
    [
      "policy revision",
      `/policy/revisions/${encodeURIComponent(revs.active)}`,
      new RegExp(`^Policy revision ${revs.active.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`),
    ],
  ];
  // An approval exists only while its call is held.
  const call = mcpCall(g, "ref_read_file", { path: "hello.txt" }, { scope: "smcp:template:approval-demo", expect: g.marker, timeout: "90s" });
  try {
    let approvalID = "";
    for (let i = 0; i < 300 && !approvalID; i++) {
      const p = await getJSON<{ approvals: { id: string }[] }>(request, "/api/v1/approvals?state=pending");
      approvalID = p.approvals[0]?.id ?? "";
      if (!approvalID) await new Promise((r) => setTimeout(r, 200));
    }
    expect(approvalID, "a pending approval").toBeTruthy();
    links.unshift(["approval", `/approvals/${approvalID}`, /^Approval$/]);
    for (const [what, url, title] of links) {
      const { page, close } = await openFresh(browser, url);
      await expect(page.getByRole("heading", { level: 1 }), `${what} ${url}`).toHaveText(title);
      await expect(page.locator("main .loading")).toHaveCount(0, { timeout: 20_000 });
      await expect(page.locator("main").getByRole("alert"), `${what} ${url} shows an error`).toHaveCount(0);
      if (what === "session") await expect(page.locator("main")).toContainText(sessionID);
      if (what === "decision") await expect(page.locator("main")).toContainText(decisionID!);
      if (what === "approval") await expect(page.locator("main")).toContainText("hello.txt");
      await close();
    }
    const r = await request.post(g.adminURL + `/api/v1/approvals/${approvalID}/deny`, {
      data: { comment: "FR-8.28 cleanup" },
      headers: { Authorization: `Bearer ${operatorToken()}` },
    });
    expect(r.status()).toBe(200);
    await call.done;
  } finally {
    call.kill();
  }
});
