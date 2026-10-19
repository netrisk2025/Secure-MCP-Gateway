// FR-8.24, scripted: the G-04 task of the first-time-user demonstration
// (create and publish a scoped Observation Policy of at least 10
// parameters), performed the way the view's help describes it, with the
// steps counted and the time measured. It is a script, not a person: the
// SRS Demonstration with three first-time users is a separate record
// (docs/verification/FR-8.24.md). The test shows that the task can be done
// in the view with the help it offers and how many actions it takes.
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";
import { work } from "./gateway";
import { claims, nav, signIn } from "./helpers";

const parameters = [
  "tool_name",
  "request_bytes",
  "response_bytes",
  "argument_count",
  "decision_outcome",
  "server_execution_time",
  "is_error",
  "calls_in_session",
  "inter_call_interval",
  "end_to_end_latency",
];

test("G-04 first-time task, scripted: a scoped Observation Policy of 10 parameters, timed", async ({ page, browserName }) => {
  claims("FR-8.24", "FR-8.6");
  test.setTimeout(600_000);
  await signIn(page, "/");
  const steps: string[] = [];
  const t0 = Date.now();
  await nav(page).getByRole("link", { name: "Observation workbench" }).click();
  steps.push("open G-04 from the view list");
  await expect(page.getByRole("heading", { level: 1, name: "Observation workbench" })).toBeVisible();
  await page.getByText("Help for this view").click();
  steps.push("open the view's help");
  await expect(page.locator("details.help .help-body")).toContainText("publish it as the Observation Policy");

  const search = page.getByLabel(/Search parameters/);
  for (const p of parameters) {
    await search.fill(p);
    steps.push(`search for ${p}`);
    const box = page.getByRole("checkbox", { name: `Capture ${p}`, exact: true });
    await expect(box).toBeVisible();
    if (!(await box.isChecked())) {
      await box.check();
      steps.push(`select ${p}`);
    }
  }
  await search.fill("");
  steps.push("clear the search");

  const policyId = `first-time-${browserName}`;
  await page.getByLabel("Observation Policy ID").fill(policyId);
  steps.push("name the policy");
  const tools = page.getByRole("group", { name: "Tools" });
  await tools.getByRole("checkbox", { name: "ref/read_file", exact: true }).check();
  steps.push("scope it to the tool ref/read_file");
  const form = page.getByRole("form", { name: "Publish the Observation Policy" });
  await form.getByRole("button", { name: "Publish the Observation Policy" }).click();
  steps.push("publish");
  await expect(page.getByText(/Published Observation Policy revision \d+/)).toBeVisible();
  const seconds = (Date.now() - t0) / 1000;

  const revs = await page.evaluate(() => fetch("/api/v1/observations/objects/observation_policy").then((r) => r.json()));
  const body = (revs.revisions ?? revs)[0].body as { policy_id: string; parameters: string[]; scope?: Record<string, string[]> };
  expect(body.policy_id).toBe(policyId);
  for (const p of parameters) expect(body.parameters).toContain(p);
  expect(body.parameters.length).toBeGreaterThanOrEqual(10);
  expect(body.scope?.tools).toEqual(["ref/read_file"]);
  expect(seconds).toBeLessThan(600);
  const result = { browser: browserName, seconds, steps: steps.length, parameters: body.parameters.length, scope: body.scope, policy_id: body.policy_id };
  writeFileSync(join(work, `firsttime-${browserName}.json`), JSON.stringify({ ...result, step_list: steps }, null, 2));
  console.log(`G-04 first-time task (${browserName}, scripted): ${seconds.toFixed(1)} s, ${steps.length} steps, ${body.parameters.length} parameters, scope ${JSON.stringify(body.scope)}`);
});
