// FR-8.22 G-14 audit investigation on a Gateway with the graph mirror (a
// dedicated Gateway on the Neo4j database of SMCP_NEO4J_URL; the CI console
// job runs Neo4j Community Edition in a service container). The SRS
// demonstration: start from a withheld event and navigate to its decisive
// rule and server revision. On the way the test opens the event's
// decision, its rule revisions, route, server revision, baseline snapshot
// and the other phases of the call, and the event's path rendered as a
// bounded graph from the mirror (no fixture). The mirror is rebuilt from
// the journal in G-08 with the keyboard first (an accepted rebuild,
// FR-8.33).
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { mcpCall, neo4j, startDedicated } from "./gateway";
import { claims, go } from "./helpers";

const SECRET = "e2e-large-result-marker";

async function axe(page: Page, state: string) {
  const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  expect(
    r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html.slice(0, 160) + " " + (n.failureSummary ?? "")).join(" | ")}`),
    `axe at ${state}`,
  ).toEqual([]);
}

test("G-14 from a withheld event to its decision, decisive rule, route, server revision, baseline snapshot, phases and the bounded graph", async ({
  browser,
  browserName,
}) => {
  test.skip(!neo4j, "needs a Neo4j database: set SMCP_NEO4J_URL (and SMCP_NEO4J_USER, SMCP_NEO4J_PASSWORD)");
  test.setTimeout(600_000);
  claims("FR-8.33", "FR-8.32", "FR-8.16");
  // A result above the CP-08 result bound is withheld (E-11, RESULT_TOO_LARGE).
  const d = await startDedicated(`decision-${browserName}`, { graph: true, edit: (t) => t + "\n[limits]\nresult_bytes = 4096\n" });
  writeFileSync(join(d.dir, "sandbox", "large.txt"), `${SECRET}\n` + "x".repeat(16_384) + "\n");
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  const signIn = async () => {
    await page.goto(d.adminURL + "/");
    await page.getByLabel("Password").fill(d.adminPassword);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
  };
  try {
    await signIn();
    // A promoted baseline snapshot, in force for decisions after a restart.
    let r = await mcpCall(d, "ref_read_file", { path: "hello.txt" }, { expect: d.marker, timeout: "60s" }).done;
    expect(r.code, r.out).toBe(0);
    await go(page, "/analytics");
    await page.getByRole("button", { name: "Build a snapshot now" }).click();
    await expect(page.getByText(/Built snapshot/)).toBeVisible();
    await page.getByRole("table", { name: "Baseline snapshots" }).getByRole("button", { name: "Promote" }).first().click();
    await expect(page.getByText(/is promoted/).first()).toBeVisible();
    await d.restart();
    await signIn();

    // G-08: rebuild the mirror from this instance's journal (the database
    // is shared by the runs), with the keyboard.
    await go(page, "/data-server");
    const rebuild = page.getByRole("button", { name: "Rebuild from the journal" });
    await rebuild.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByText("A rebuild is queued.")).toBeVisible();
    await axe(page, "G-08 rebuild queued");

    // A permitted call and a call whose result is withheld (a file larger
    // than the result bound).
    r = await mcpCall(d, "ref_echo", { text: "decision path" }, { expect: "decision path", timeout: "60s" }).done;
    expect(r.code, r.out).toBe(0);
    r = await mcpCall(d, "ref_read_file", { path: "large.txt" }, { timeout: "60s" }).done;
    expect(r.out).not.toContain(SECRET);

    // G-14: the withheld event.
    await go(page, "/audit");
    await page.getByLabel("Text").fill("withheld");
    await page.getByRole("button", { name: "Apply filter" }).click();
    const events = page.getByRole("table", { name: "Journal events" });
    const withheld = events.getByRole("row").filter({ hasText: "withheld" }).first();
    await expect(withheld).toBeVisible();
    await withheld.getByRole("link").first().click();
    await expect(page.getByRole("heading", { level: 1, name: "Evidence event" })).toBeVisible();
    await expect(
      page
        .getByRole("definition")
        .filter({ hasText: /^withheld$/ })
        .first(),
    ).toBeVisible();
    const eventURL = page.url();

    // The path as a bounded graph from the mirror (it catches up within seconds).
    const graph = page.getByRole("group", { name: /Investigation path: \d of 8 related nodes/ });
    await expect(async () => {
      await page.reload();
      await expect(graph).toBeVisible({ timeout: 3_000 });
      await expect(graph.getByRole("link", { name: /^Decision / })).toBeVisible({ timeout: 1_000 });
    }).toPass({ timeout: 90_000 });
    for (const label of ["Session", "Invocation", "AuditEvent", "Decision", "PolicyRevision", "ServerRevision"])
      await expect(graph.getByRole("link", { name: new RegExp(`^${label} `) }), label).toBeVisible();
    await expect(page.getByText(/^Phases of the call:/)).toBeVisible();
    await axe(page, "G-14 withheld event with its graph");

    // To the decision.
    await page
      .getByRole("definition")
      .getByRole("link")
      .filter({ hasText: /^[0-9a-f-]{36}$/ })
      .first()
      .click();
    await expect(page.getByRole("heading", { level: 1, name: "Decision" })).toBeVisible();
    const record = page.locator("section").filter({ has: page.getByRole("heading", { name: "Decision record" }) });
    await expect(record.getByRole("definition").filter({ hasText: /^permit$/ })).toBeVisible();
    // Its rule revisions: the decisive one with the rule as published.
    const rules = page.getByRole("table", { name: "Rule revisions of the decision" });
    const decisive = rules.getByRole("row").filter({ hasText: "decisive" });
    await expect(decisive).toHaveCount(1);
    await expect(decisive).toContainText(/r1\/\S+\/\S+/);
    await expect(decisive).toContainText(/"id":/);
    // Related phases of the call.
    const phases = page.getByRole("table", { name: "Events of the decided call" });
    await expect(phases).toContainText("withheld");
    await expect(phases).toContainText("requested");
    // The bounded graph again, from the decision.
    await expect(page.getByRole("group", { name: /Investigation path: \d of 8 related nodes/ })).toBeVisible();
    await axe(page, "G-14 decision");
    const decisionURL = page.url();

    // The baseline snapshot the decision used.
    const snap = record.locator(".kv-row").filter({ hasText: "Baseline snapshot" }).getByRole("link");
    await expect(snap).toBeVisible();
    await snap.click();
    await expect(page.getByRole("heading", { level: 1 })).toContainText(/snapshot/i);
    await page.goto(decisionURL);

    // The decisive rule's policy revision.
    await record.locator(".kv-row").filter({ hasText: "Policy revision" }).getByRole("link").click();
    await expect(page.getByRole("heading", { level: 1, name: /^Policy revision / })).toBeVisible();
    await page.goto(decisionURL);

    // The route and the server revision.
    const serverRev = (await record.locator(".kv-row").filter({ hasText: "Server revision" }).getByRole("definition").textContent())!.trim();
    expect(serverRev.length).toBeGreaterThan(0);
    await record.locator(".kv-row").filter({ hasText: "Server revision" }).getByRole("link").click();
    await expect(page.getByRole("heading", { level: 1, name: "Server ref" })).toBeVisible();
    await expect(page.getByRole("definition").filter({ hasText: serverRev }).first()).toBeVisible();
    await page.goto(decisionURL);
    await record.locator(".kv-row").filter({ hasText: "Route (server alias)" }).getByRole("link").click();
    await expect(page.getByRole("heading", { level: 1, name: "Server ref" })).toBeVisible();

    // From the graph: a node opens its record.
    await page.goto(eventURL);
    await graph.getByRole("link", { name: /^PolicyRevision / }).focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("heading", { level: 1, name: /^Policy revision / })).toBeVisible();
    test.info().annotations.push({ type: "requirement", description: "FR-8.22" });
  } finally {
    await ctx.close();
    d.stop();
  }
});
