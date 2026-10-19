// One acceptance test per console view (FR-8.34) against the running
// Gateway of global-setup: each exercises the view's primary actions
// through the real control API. Where the element behind a view needs
// state this test Gateway cannot produce (the graph mirror without Neo4j,
// scored anomalies without a promoted baseline, remote registrations
// without a tunnel), the route is answered with a fixture and the test
// says so. Claims are annotations (see docs/console.md).
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { bin, mcpCall, startDedicated, work } from "./gateway";
import { claims, g, go, mock, nav, signIn } from "./helpers";

test.describe.configure({ mode: "serial" });

test("G-01 gateway control: health, monitor causes, verification and checklist", async ({ page }) => {
  claims("FR-8.3", "FR-8.31", "FR-7.12");
  await signIn(page, "/");
  await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
  await expect(page.getByRole("table", { name: "Health monitor causes" })).toContainText("unconfined");
  await page.getByRole("button", { name: "Verify the journal now" }).click();
  await expect(page.getByText("verified", { exact: true }).first()).toBeVisible();
  const checklist = page.getByRole("table", { name: "First-run checklist" });
  await expect(checklist).toContainText("Administrator created");
  await expect(checklist).toContainText("Backup configured");
});

// FR-8.4's demonstration (a full claim): a Session Allow template is
// authored with the structured editor, validated, diffed, simulated and
// published entirely in G-02, and the policy rolls back; then the Secret
// Use Policy, the other object type G-02 edits (Framework Profiles are
// edited with the templates), is edited structurally, validated, diffed,
// published twice and rolled back.
test("G-02 policy studio: draft, validate, diff, simulate, publish and roll back", async ({ page }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.4" });
  claims("FR-3.4", "FR-3.9");
  // A call in the journal for the simulation to replay (earlier tests made
  // others; a refused call is recorded as well).
  await mcpCall(g, "ref_echo", { text: "policy" }, { expect: "policy", timeout: "60s" }).done;
  await signIn(page, "/policy");
  await expect(page.getByRole("table", { name: "Policy revisions" })).toContainText("r1");
  await page.getByRole("link", { name: "Draft", exact: true }).click();
  // The draft takes the next free revision ID (r2 on a fresh Gateway).
  const revInput = page.getByLabel("Revision ID of the draft");
  await expect(revInput).toHaveValue(/^r\d+/);
  const rev = `e2e-${Date.now()}`;
  await revInput.fill(rev);
  // Structured editor: add a template with one rule.
  await page.getByLabel("New template name").fill("echo-only");
  await page.getByRole("button", { name: "Add", exact: true }).first().click();
  await page.getByRole("button", { name: "Add a rule to echo-only" }).click();
  const rule = page.getByRole("group", { name: "Rule rule-1" });
  await rule.getByLabel("Tools (space separated)").fill("echo");
  await rule.getByLabel("Rule ID").fill("echo-rule");
  // Offer it to the dev profile.
  await page.getByRole("group", { name: "Templates sessions of this profile may use" }).getByLabel("echo-only").check();
  await page.getByRole("button", { name: "Validate" }).click();
  await expect(page.getByText(new RegExp(`Valid: revision ${rev}`))).toBeVisible();
  await page.getByRole("button", { name: "Diff against the active revision" }).click();
  await expect(page.getByRole("table", { name: "Policy changes" })).toContainText("template_added");
  await page.getByRole("button", { name: "Simulate" }).click();
  await expect(page.getByText(/replayed from the/)).toBeVisible();
  await page.getByRole("button", { name: "Publish" }).click();
  await expect(page.getByRole("heading", { level: 1, name: `Policy revision ${rev}` })).toBeVisible();
  await expect(page.getByText("active", { exact: true }).first()).toBeVisible();
  // Effective permissions of the new template.
  await page.getByLabel("Template").selectOption("echo-only");
  await expect(page.getByRole("table", { name: "Effective permissions of echo-only" })).toContainText("ref/echo");
  // Roll back to r1.
  await go(page, "/policy/revisions/r1");
  await page.getByRole("button", { name: "Roll back to this revision" }).click();
  await page.getByRole("dialog", { name: "Roll back to r1" }).getByRole("button", { name: "Roll back" }).click();
  await expect(page.getByRole("table", { name: "Policy revisions" })).toContainText(/r1-rb\d+/);
  await expect(page.getByTestId("status-strip")).toContainText(/policy r1-rb\d+/);

  // Secret Use Policy. A secret to bind, created in G-12.
  await go(page, "/secrets");
  await page.getByText("Create a secret").click();
  await page.getByLabel("Name").fill("sup-token");
  await page.getByLabel(/^Value/).fill("sup-token-value-0123456789");
  await page.getByRole("button", { name: "Create secret" }).click();
  await expect(page.getByText("Created sup-token as version 1.")).toBeVisible();
  await go(page, "/policy");
  await page.getByRole("link", { name: "Secret Use Policy" }).click();
  await expect(page.getByRole("heading", { name: "Active Secret Use Policy" })).toBeVisible();
  await expect(page.getByText(/^Revision u0, 0 bindings/)).toBeVisible();
  await expect(page.getByLabel("Revision ID of the draft")).toHaveValue("u0-2");
  // A slot: the validation refuses it until it names the file variable S3 needs.
  await page.getByRole("button", { name: "Add a slot" }).click();
  const slot = page.getByRole("group", { name: "Slot ref/slot-1" });
  await slot.getByLabel("Slot name").fill("api_key");
  const slotNamed = page.getByRole("group", { name: "Slot ref/api_key" });
  await expect(slotNamed.getByRole("group", { name: "Delivery modes the slot supports" }).getByLabel("S3")).toBeChecked();
  await page.getByRole("button", { name: "Validate" }).click();
  await expect(page.getByRole("alert")).toContainText("S2 and S3 need file_env");
  await slotNamed.getByLabel("File variable (S2, S3)").fill("API_KEY_FILE");
  await page.getByRole("button", { name: "Validate" }).click();
  await expect(page.getByText("Valid: revision u0-2, 0 bindings.")).toBeVisible();
  await page.getByRole("button", { name: "Diff against the active document" }).click();
  const changes = page.getByRole("table", { name: "Secret Use Policy changes" });
  await expect(changes.getByRole("row").filter({ hasText: "ref/api_key" })).toContainText("added");
  const publishSup = page.getByRole("form", { name: "Publish the Secret Use Policy" });
  await publishSup.getByLabel(/Reason for this revision/).fill("declare the API key slot");
  await publishSup.getByRole("button", { name: "Publish the Secret Use Policy" }).click();
  await expect(page.getByText("Published Secret Use Policy revision u0-2 (0 bindings). It is active.")).toBeVisible();
  await expect(page.getByText(/^Revision u0-2, 0 bindings/)).toBeVisible();
  // A binding of the secret to the slot, in the next revision.
  await expect(page.getByLabel("Revision ID of the draft")).toHaveValue("u0-3");
  await page.getByRole("button", { name: "Add a binding" }).click();
  const binding = page.getByRole("group", { name: "Binding binding-1" });
  await binding.getByLabel("Secret").selectOption("sup-token");
  await binding.getByLabel("Slot").selectOption("api_key");
  await expect(binding.getByLabel("Mode")).toHaveValue("S3");
  await binding.getByLabel("Purpose").fill("console acceptance test");
  await page.getByRole("button", { name: "Diff against the active document" }).click();
  await expect(changes.getByRole("row").filter({ hasText: "binding-1" })).toContainText("added");
  await publishSup.getByLabel(/Reason for this revision/).fill("bind the token");
  await publishSup.getByRole("button", { name: "Publish the Secret Use Policy" }).click();
  await expect(page.getByText("Published Secret Use Policy revision u0-3 (1 binding). It is active.")).toBeVisible();
  const sup = await page.evaluate(() => fetch("/api/v1/secret-use-policy").then((r) => r.json()));
  expect(sup.active).toMatchObject({ revision: "u0-3", bindings: 1 });
  expect(sup.document.policies).toEqual([{ id: "binding-1", secret: "sup-token", server: "ref", slot: "api_key", mode: "S3", tools: ["*"], purpose: "console acceptance test" }]);
  // Roll back to u0-2: the binding is gone again.
  await page.getByRole("table", { name: "Secret Use Policy revisions" }).getByRole("button", { name: "Roll back to u0-2" }).click();
  await expect(page.getByText("Rolled back: Secret Use Policy revision u0-2 is active.")).toBeVisible();
  await expect(page.getByText(/^Revision u0-2, 0 bindings/)).toBeVisible();
});

test("G-02 filter workbench: a redaction profile on synthetic text", async ({ page }) => {
  claims("FR-8.27");
  await signIn(page, "/policy/filters");
  await expect(page.getByRole("table", { name: "Rule sets" })).toContainText("pii");
  const filters = page.getByRole("group", { name: "Filters to run" });
  for (const id of ["size-limit", "output-schema", "content-type-gate", "secret-fingerprint", "unicode-control", "injection-marker", "delimit-untrusted"]) await filters.getByLabel(id).uncheck();
  await page.getByLabel("Result text").fill("Write to jane@example.com about it.");
  await page.getByRole("button", { name: "Run filters" }).click();
  await expect(page.getByRole("definition").filter({ hasText: "redact" })).toBeVisible();
  const runs = page.getByRole("table", { name: "Filter runs" });
  await expect(runs).toContainText("pii-detect");
  await expect(page.getByText("Transformed output")).toBeVisible();
  await expect(page.locator("figure.json pre").last()).not.toContainText("jane@example.com");
});

// FR-8.5's verification: edit an Audit Profile, the floor is not editable
// and the profile publishes (a full claim).
test("G-03 audit profile tuning: the floor is read-only and the profile publishes", async ({ page }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.5" });
  await signIn(page, "/audit-profiles");
  const floor = page.getByRole("table", { name: "Mandatory audit floor" });
  await expect(floor).toContainText("auth_failure");
  await expect(floor.locator("input, select, textarea")).toHaveCount(0);
  await page.getByLabel(/Observation retention/).fill("720h");
  await expect(page.getByText('retention = "720h"')).toBeVisible();
  const form = page.getByRole("form", { name: "Publish the Audit Profile" });
  await form.getByLabel(/Reason for this revision/).fill("acceptance test");
  await form.getByRole("button", { name: "Publish the Audit Profile" }).click();
  // The running Gateway applies the profile at once (no restart).
  await expect(page.getByText(/Published Audit Profile revision \d+\. It applies at once/)).toBeVisible();
  await expect(page.getByText(/Revision \d+ is not in force/)).toHaveCount(0);
});

test("G-04 observation workbench: grouped catalog search, presets, cost and preview", async ({ page }) => {
  claims("FR-8.6", "FR-8.7", "FR-8.8", "FR-8.11", "FR-8.12");
  // FR-8.9 and FR-8.10 are demonstrated in full here: the scope is built
  // from lists without free text, and each sampling, escalation, context,
  // feature and band control is set, published and read back.
  test.info().annotations.push({ type: "requirement", description: "FR-8.9" }, { type: "requirement", description: "FR-8.10" });
  await signIn(page, "/observations");
  await page.getByLabel(/Search parameters/).fill("latency");
  await expect(page.getByRole("checkbox", { name: "Capture end_to_end_latency" })).toBeVisible();
  await expect(page.getByText(/^(dispatch|release|response-inspection|request-received|decision|periodic)/).first()).toBeVisible();
  await page.getByLabel(/Search parameters/).fill("");
  await page.getByRole("button", { name: "Performance profiling" }).click();
  await expect(page.getByText(/Applied preset Performance profiling/)).toBeVisible();
  await page.getByLabel("Save the selection as a preset").fill("my preset");
  await page.getByRole("button", { name: "Save preset" }).click();
  await expect(page.getByRole("button", { name: "my preset (saved)" })).toBeVisible();
  await expect(page.getByText("Bytes per captured record (estimate)")).toBeVisible();
  await page.getByRole("button", { name: "Show the configuration for this selection" }).click();
  await expect(page.getByText(/parameters = \[/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Live record preview" })).toBeVisible();
  // Sampling and baseline controls (FR-8.10), published after the cost preview.
  await page.getByLabel("Normal-band sampling rate (0 to 1)").fill("0.25");
  await page.getByLabel("critical band from |z|").fill("5");
  await page.getByRole("checkbox", { name: "server", exact: true }).check();
  // Scope of one principal and two tools, chosen from lists (FR-8.9).
  const principals = page.getByRole("group", { name: "Principals" }).getByRole("checkbox");
  await expect(principals.first()).toBeVisible();
  const principal = (await principals.first().locator("xpath=..").innerText()).trim();
  await principals.first().check();
  const tools = page.getByRole("group", { name: "Tools" });
  await tools.getByRole("checkbox", { name: "ref/echo", exact: true }).check();
  await tools.getByRole("checkbox", { name: "ref/read_file", exact: true }).check();
  await expect(page.getByRole("group", { name: "Principals" }).getByRole("textbox")).toHaveCount(0);
  // Per-band escalation parameters and per-feature statistics options (FR-8.10).
  await page.locator("summary", { hasText: "Escalation parameters per band" }).click();
  const escRow = page.getByRole("table", { name: "Escalation parameters per band" }).getByRole("row").nth(1);
  const escParam = (await escRow.getByRole("cell").first().innerText()).trim();
  await escRow.getByRole("checkbox", { name: `${escParam} abnormal` }).check();
  await page.locator("summary", { hasText: "Baselined features and statistics" }).click();
  await page.getByLabel("request_bytes transform").selectOption("none");
  await page.getByRole("checkbox", { name: "request_bytes robust statistics" }).check();
  await page.getByLabel("request_bytes sigma floor").fill("0.5");
  const form = page.getByRole("form", { name: "Publish the Observation Policy" });
  await form.getByRole("button", { name: "Publish the Observation Policy" }).click();
  await expect(page.getByText(/Published Observation Policy revision \d+/)).toBeVisible();
  // The stored Observation Policy carries every control as set.
  const revs = await page.evaluate(() => fetch("/api/v1/observations/objects/observation_policy").then((r) => r.json()));
  const body = (revs.revisions ?? revs)[0].body;
  expect(body.sampling_rate).toBe(0.25);
  expect(body.bands).toEqual([2, 3, 5]);
  expect(body.contexts).toContain("server");
  expect(body.scope).toEqual({ principals: [principal], tools: ["ref/echo", "ref/read_file"] });
  expect(body.escalation).toEqual({ abnormal: [escParam] });
  expect(body.features.find((f: { parameter: string }) => f.parameter === "request_bytes")).toMatchObject({ transform: "none", robust: true, sigma_floor: 0.5 });
});

// FR-8.6's demonstration (a full claim): a search for "latency" shows the
// matching catalog parameters under their capture-point group, and every
// result row shows its description, unit, sensitivity class and cost
// indicator. The catalog has one latency parameter, so a second search
// ("bytes") shows results spread over several groups.
test("G-04 catalog search: grouped results with description, unit, sensitivity and cost", async ({ page }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.6" });
  await signIn(page, "/observations");
  const catalog = await page.evaluate(() => fetch("/api/v1/observations/parameters").then((r) => r.json()));
  type P = { id: string; name: string; description: string; unit: string; sensitivity: string; cost_class?: string; capture_point: string };
  const params = catalog.parameters as P[];
  const tables = page.getByRole("table", { name: /^Parameters captured at / });
  const search = async (term: string) => {
    await page.getByLabel(/Search parameters/).fill(term);
    const want = params.filter((p) => [p.id, p.name, p.description, p.unit, p.capture_point].some((s) => s.toLowerCase().includes(term)));
    const groups = new Set(want.map((p) => p.capture_point));
    await expect(tables).toHaveCount(groups.size);
    let seen = 0;
    for (let i = 0; i < groups.size; i++) {
      const t = tables.nth(i);
      const group = (await t.locator("caption").innerText()).replace(/^Parameters captured at /, "").trim();
      expect(groups.has(group), group).toBe(true);
      const headers = (await t.locator("thead th").allInnerTexts()).map((s) => s.trim());
      const col = (h: string) => headers.findIndex((x) => x.startsWith(h));
      for (const h of ["ID", "Name", "Description", "Unit", "Sensitivity", "Cost class"]) expect(col(h), h).toBeGreaterThanOrEqual(0);
      const rows = t.locator("tbody tr");
      const rc = await rows.count();
      for (let j = 0; j < rc; j++) {
        const cells = (await rows.nth(j).locator("td").allInnerTexts()).map((s) => s.trim());
        const p = params.find((x) => x.name === cells[col("Name")])!;
        expect(p, cells[col("Name")]).toBeTruthy();
        expect(p.capture_point).toBe(group);
        expect(cells[col("Description")]).toBe(p.description);
        expect(cells[col("Unit")]).toBe(p.unit);
        expect(cells[col("Sensitivity")]).toContain(p.sensitivity);
        expect(cells[col("Cost class")]).toContain(p.cost_class!);
        seen++;
      }
    }
    expect(seen).toBe(want.length);
    return groups.size;
  };
  expect(await search("latency")).toBeGreaterThanOrEqual(1);
  await expect(page.getByRole("checkbox", { name: "Capture end_to_end_latency" })).toBeVisible();
  expect(await search("bytes")).toBeGreaterThan(1);
});

// FR-8.7's verification (a full claim): a test catalog version with one
// added parameter, served to the same console build in place of the
// release catalog, shows the parameter with its controls and attributes in
// its own group; selecting it puts it in the configuration.
test("G-04 controls come from the catalog: a parameter added to a test catalog version appears without a console rebuild", async ({ page }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.7" });
  const added = {
    id: "P-990",
    name: "e2e_added_metric",
    description: "Parameter added by the test catalog version",
    unit: "ms",
    data_type: "number",
    sensitivity: "S1",
    capture_point: "test-capture-point",
    baselinable: true,
    selected: false,
    escalation: false,
    cost_class: "C1",
  };
  await page.route("**/api/v1/observations/parameters", async (route) => {
    const res = await route.fetch();
    const body = await res.json();
    body.catalog_version = "e2e-test-catalog";
    body.parameters.push(added);
    await route.fulfill({ response: res, json: body });
  });
  await signIn(page, "/observations");
  await expect(page.getByRole("heading", { name: /Parameter Catalog e2e-test-catalog: \d+ of \d+ selected/ })).toBeVisible();
  await page.getByLabel(/Search parameters/).fill("e2e_added");
  const t = page.getByRole("table", { name: "Parameters captured at test-capture-point" });
  await expect(t).toBeVisible();
  const row = t.getByRole("row").filter({ hasText: "e2e_added_metric" });
  for (const v of ["P-990", "Parameter added by the test catalog version", "ms", "S1", "C1"]) await expect(row).toContainText(v);
  await row.getByRole("checkbox", { name: "Capture e2e_added_metric" }).check();
  await expect(page.getByRole("heading", { name: /test-capture-point \(1 of 1 selected\)/ }).or(page.getByText("test-capture-point (1 of 1 selected)"))).toBeVisible();
  await page.getByRole("button", { name: "Show the configuration for this selection" }).click();
  await expect(page.getByText(/parameters = \[.*"e2e_added_metric"/)).toBeVisible();
});

// FR-8.8's demonstration (a full claim): each of the five presets is
// applied, one is modified and saved as a new preset, and the saved preset
// is still offered after the page is loaded again.
test("G-04 presets: apply each, modify one and save it as a new preset", async ({ page }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.8" });
  await signIn(page, "/observations");
  const heading = page.getByRole("heading", { name: /^Parameter Catalog .*: \d+ of \d+ selected$/ });
  const selectedCount = async () => Number(/: (\d+) of/.exec(await heading.innerText())![1]);
  const counts: Record<string, number> = {};
  for (const name of ["Minimal security floor", "Security standard", "Behavior characterization", "Performance profiling", "Research — full capture"]) {
    await page.getByRole("button", { name, exact: true }).click();
    const note = page.getByText(new RegExp(`^Applied preset ${name}: (\\d+) parameters\\.$`));
    await expect(note).toBeVisible();
    counts[name] = Number(/: (\d+) parameters/.exec(await note.innerText())![1]);
    expect(counts[name]).toBeGreaterThan(0);
    expect(await selectedCount()).toBe(counts[name]);
  }
  // The presets select different sets.
  expect(new Set(Object.values(counts)).size).toBeGreaterThan(1);
  // Modify Security standard: drop request_bytes, then save it.
  await page.getByRole("button", { name: "Security standard", exact: true }).click();
  await page.getByLabel(/Search parameters/).fill("request_bytes");
  const box = page.getByRole("checkbox", { name: "Capture request_bytes" });
  await expect(box).toBeChecked();
  await box.uncheck();
  await page.getByLabel(/Search parameters/).fill("");
  expect(await selectedCount()).toBe(counts["Security standard"]! - 1);
  await page.getByLabel("Save the selection as a preset").fill("e2e edited standard");
  await page.getByRole("button", { name: "Save preset" }).click();
  await expect(page.getByText("Saved the selection as preset e2e edited standard in this browser.")).toBeVisible();
  // Saved presets outlive the page.
  await page.reload();
  await page.getByRole("button", { name: "Research — full capture", exact: true }).click();
  await page.getByRole("button", { name: "e2e edited standard (saved)" }).click();
  await expect(page.getByText(`Applied preset e2e edited standard: ${counts["Security standard"]! - 1} parameters.`)).toBeVisible();
  await page.getByLabel(/Search parameters/).fill("request_bytes");
  await expect(page.getByRole("checkbox", { name: "Capture request_bytes" })).not.toBeChecked();
});

// FR-8.11's demonstration (a full claim, statement as narrowed with the
// FR-3.7 deferral): the cost preview refreshes with each edit of the
// draft, and the publish action stays disabled while the draft has no
// cost preview (no parameter selected).
test("G-04 cost preview: it refreshes with each edit and publish waits for it", async ({ page }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.11" });
  await signIn(page, "/observations");
  const preview = page.locator("section").filter({ has: page.getByRole("heading", { name: "Cost preview" }) });
  const value = async (term: string) => (await preview.getByRole("term").filter({ hasText: term }).locator("xpath=following-sibling::dd[1]").innerText()).trim();
  const publish = page.getByRole("button", { name: "Publish the Observation Policy" });
  await page.getByRole("button", { name: "Clear the selection" }).click();
  expect(await value("Selected parameters")).toBe("0");
  expect(await value("Bytes per captured record (estimate)")).toBe("0 B");
  await expect(publish).toBeDisabled();
  const steps: string[] = [];
  for (const name of ["request_bytes", "tool_name", "argument_entropy"]) {
    await page.getByLabel(/Search parameters/).fill(name);
    await page.getByRole("checkbox", { name: `Capture ${name}` }).check();
    const bytesNow = await value("Bytes per captured record (estimate)");
    expect(steps).not.toContain(bytesNow);
    steps.push(bytesNow);
    expect(await value("Selected parameters")).toBe(String(steps.length));
    await expect(publish).toBeEnabled();
  }
  expect(await value("Sampling rate in force")).toMatch(/^[\d.]+$/);
  expect(await value("Store growth at that volume")).toMatch(/B$/);
  // An S2 parameter changes the sensitivity line of the preview.
  await page.getByLabel(/Search parameters/).fill("path_prefixes");
  await page.getByRole("checkbox", { name: "Capture path_prefixes" }).check();
  await expect(preview.getByText("included: raw values need a separate grant")).toBeVisible();
  await page.getByRole("button", { name: "Clear the selection" }).click();
  await expect(publish).toBeDisabled();
});

/**
 * Publishes, from G-04, an Observation Policy that records every call with
 * every per-call parameter of the catalog except S3 ones (the Research —
 * full capture preset, sampling rate 1, no scope), so that a test does not
 * depend on the policy an earlier test left in force.
 */
async function recordEveryCall(page: Page) {
  await go(page, "/observations");
  await page.getByRole("button", { name: "Research — full capture", exact: true }).click();
  await page.getByLabel("Normal-band sampling rate (0 to 1)").fill("1");
  for (const grp of ["Principals", "Tools"]) {
    const group = page.getByRole("group", { name: grp });
    await expect(group.getByRole("checkbox").first()).toBeVisible(); // the lists have loaded
    for (const box of await group.getByRole("checkbox", { checked: true }).all()) await box.uncheck();
  }
  await page.getByRole("form", { name: "Publish the Observation Policy" }).getByRole("button", { name: "Publish the Observation Policy" }).click();
  await expect(page.getByText(/Published Observation Policy revision \d+/)).toBeVisible();
  const pol = await page.evaluate(() => fetch("/api/v1/observations/objects/observation_policy").then((r) => r.json()));
  const body = (pol.revisions ?? pol)[0].body;
  expect(body).toMatchObject({ sampling_rate: 1 });
  expect(body.scope).toBeUndefined();
  expect(body.parameters).toContain("gateway_overhead");
}

// FR-8.12's demonstration (a full claim): the preview shows up to 20
// recent records the draft would have produced, within the draft's scope
// and limited to its parameters, with S2 values masked.
test("G-04 live record preview: masked records within the draft's scope", async ({ page }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.12" });
  await signIn(page, "/observations");
  await recordEveryCall(page);
  // Two calls in the scope used below and one outside it (the per-principal
  // burst limit of CP-11 allows ten calls at once).
  for (const [tool, args, want] of [
    ["ref_read_file", { path: "hello.txt" }, g.marker],
    ["ref_echo", { text: "preview" }, "preview"],
    ["ref_read_file", { path: "hello.txt" }, g.marker],
  ] as const) {
    {
      const r = await mcpCall(g, tool, args, { expect: want, timeout: "60s" }).done;
      expect(r.code, r.out).toBe(0);
    }
  }
  const preview = page.getByRole("table", { name: "Recent records with the selected parameters" });
  // The stored records the draft's scope admits. Records reach the store
  // shortly after the calls and the preview reads them when the page loads,
  // so load the page until the preview shows every stored record of the
  // scope (at most 20) and the store also holds records outside it.
  type Rec = Record<string, unknown>;
  await expect(async () => {
    await page.reload();
    // Research — full capture includes end_user_claim (S2).
    await page.getByRole("button", { name: "Research — full capture", exact: true }).click();
    await page.getByRole("group", { name: "Tools" }).getByRole("checkbox", { name: "ref/read_file", exact: true }).check();
    const d = await page.evaluate(() => fetch("/api/v1/observations?limit=200").then((r) => r.json()));
    const rows = (d.rows ?? []) as Rec[];
    const inScope = rows.filter((r) => `${r.server_id}/${r.tool_name}` === "ref/read_file").length;
    expect(inScope).toBeGreaterThan(0);
    expect(rows.length).toBeGreaterThan(inScope); // a record outside the scope is left out
    await expect(preview).toBeVisible({ timeout: 10_000 });
    expect(await preview.locator("tbody tr").count()).toBe(Math.min(20, inScope));
  }).toPass({ timeout: 60_000 });
  const headers = (await preview.locator("thead th").allInnerTexts()).map((s) => s.trim());
  const selected = Number(/: (\d+) of/.exec(await page.getByRole("heading", { name: /^Parameter Catalog .*selected$/ }).innerText())![1]);
  expect(headers.length).toBe(1 + selected); // the time and every parameter of the draft
  expect(headers.join("|")).toContain("end_user_claim");
  await expect(preview.locator("tbody tr").first()).toContainText("masked (S2)");
});

test("G-05 behavior analytics: snapshot, promotion, distributions and anomaly drill-down", async ({ page }) => {
  claims("FR-8.13");
  await signIn(page, "/analytics");
  await page.getByRole("button", { name: "Build a snapshot now" }).click();
  await expect(page.getByText(/Built snapshot/)).toBeVisible();
  await page.getByRole("table", { name: "Baseline snapshots" }).getByRole("button", { name: "Promote" }).first().click();
  await expect(page.getByText(/is promoted/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Feature distributions" })).toBeVisible();
  // Scored anomalies need a characterized baseline; a fixture stands in.
  const now = Date.now();
  await mock(page, "**/api/v1/anomalies?**", {
    count: 2,
    rows: [
      { ts: new Date(now - 60_000).toISOString(), correlation_id: "corr-elevated", snapshot_id: "s", context: "principal=cc|tool=read_file", combined: 2.4, contributing_feature: "request_bytes", band: "elevated", actions: '["alert"]', mode: "async" },
      { ts: new Date(now - 30_000).toISOString(), correlation_id: "corr-critical", snapshot_id: "s", context: "principal=cc|tool=read_file", combined: 6.2, contributing_feature: "request_bytes", band: "critical", actions: '["alert","capture_escalation"]', mode: "async" },
    ],
  });
  await page.reload();
  await expect(page.getByRole("group", { name: /z-score timeline/ })).toBeVisible();
  const table = page.getByRole("table", { name: "Abnormal events" });
  await expect(table).toContainText("critical");
  // Keyboard: focus the critical dot and open it with Enter.
  await page.getByRole("button", { name: /^critical 6.20/ }).focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/audit\?correlation_id=corr-critical/);
});

// FR-8.13's demonstration (a full claim), on a dedicated Gateway whose
// baseline characterizes a context after five calls: calls train the
// baseline, a snapshot is built and promoted from G-05, the context's
// feature distribution is inspected, a call far outside it is scored and
// opened from the abnormal-event list and the z-score timeline, a second
// snapshot is built and its drift against the promoted one is shown, and
// it is promoted and then rolled back to the first.
test("G-05 behavior analytics on a dedicated Gateway: inspect a context, open a scored abnormal event, diff, promote and roll back snapshots", async ({ browser, browserName }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.13" });
  test.setTimeout(600_000);
  const d = await startDedicated(`g05-${browserName}`);
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  try {
    appendFileSync(
      d.config,
      [
        "",
        "[limits]",
        "principal_call_burst = 0",
        "sessions_per_principal = 64",
        "",
        "[observation]",
        "sampling_rate = 1.0",
        'flush_interval = "1s"',
        "",
        "[observation.baseline]",
        "n_min = 5",
        "",
      ].join("\n"),
    );
    await d.restart();
    const call = async (text: string, repeat = 1) => {
      const r = await mcpCall(d, "ref_echo", { text }, { expect: text, repeat, timeout: "120s" }).done;
      expect(r.code, r.out).toBe(0);
    };
    await call("steady", 12);
    const page = await context.newPage();
    await page.goto(d.adminURL + "/analytics");
    await page.getByLabel("Password").fill(d.adminPassword);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Behavior analytics" })).toBeVisible();
    const kv = (term: string) => page.getByRole("term").filter({ hasText: term }).locator("xpath=following-sibling::dd[1]");
    // The calls are learned once their records are stored.
    await expect(async () => {
      await page.reload();
      await expect(kv("Records learned")).toHaveText(/^(1[2-9]|[2-9]\d|\d{3,})$/, { timeout: 2_000 });
    }).toPass({ timeout: 60_000 });
    // First snapshot: build and promote.
    const snapshots = page.getByRole("table", { name: "Baseline snapshots" });
    await page.getByRole("button", { name: "Build a snapshot now" }).click();
    await expect(page.getByText(/^Built snapshot \w{8} from \d+ records/)).toBeVisible();
    await snapshots.getByRole("button", { name: "Promote" }).click();
    await expect(page.getByText(/^Snapshot \w{8} is promoted/)).toBeVisible();
    await expect(kv("Contexts / characterized")).toHaveText(/^\d+ \/ [1-9]\d*$/);
    const first = (await snapshots.getByRole("row").filter({ hasText: "promoted" }).getByRole("link").innerText()).trim();
    // Inspect the context: the request size of the echo calls per context.
    // The baseline learns from the collector's stream; the distributions are
    // read from the Observation Store, whose low-priority writer stores each
    // batch later, so the view is reloaded until the stored records show.
    const perContext = page.getByRole("table", { name: "request_bytes per context" });
    await expect(async () => {
      await page.reload();
      await page.getByRole("combobox", { name: "Feature", exact: true }).selectOption("request_bytes");
      await expect(perContext.getByRole("row").filter({ hasText: "echo" }).first()).toBeVisible({ timeout: 2_000 });
    }).toPass({ timeout: 60_000 });
    // A call far outside the learned request size is scored abnormal.
    await call("x".repeat(6000));
    const events = page.getByRole("table", { name: "Abnormal events" });
    await expect(async () => {
      await page.reload();
      await expect(events.getByRole("row").filter({ hasText: /abnormal|critical/ }).first()).toBeVisible({ timeout: 2_000 });
    }).toPass({ timeout: 60_000 });
    const row = events.getByRole("row").filter({ hasText: /abnormal|critical/ }).first();
    await expect(row).toContainText("request_bytes");
    await expect(page.getByRole("group", { name: /z-score timeline/ })).toBeVisible();
    await expect(page.getByRole("button", { name: /^(abnormal|critical) \d/ }).first()).toBeVisible();
    // Drill down to the call in the journal.
    await row.getByRole("link").click();
    await expect(page).toHaveURL(/\/audit\?correlation_id=/);
    await expect(page.getByRole("heading", { level: 1, name: "Audit investigation" })).toBeVisible();
    const corr = new URL(page.url()).searchParams.get("correlation_id")!;
    await expect(page.getByText(corr).first()).toBeVisible();
    // Second snapshot: its drift against the promoted one is shown.
    await page.goto(d.adminURL + "/analytics");
    const stored = () => page.evaluate(() => fetch("/api/v1/observations?limit=1000").then((r) => r.json()).then((d) => (d.rows ?? []).length as number));
    const before = await stored();
    await call("steady", 6);
    await expect.poll(stored, { timeout: 60_000 }).toBeGreaterThanOrEqual(before + 6);
    await page.getByRole("button", { name: "Build a snapshot now" }).click();
    await expect(page.getByText(/^Built snapshot \w{8} from \d+ records/)).toBeVisible();
    await expect(page.getByRole("heading", { name: "Drift of the last build" })).toBeVisible();
    await expect(page.getByRole("table", { name: "Drift per context and feature" })).toContainText("request_bytes");
    // Promote the second snapshot, then roll back to the first.
    await snapshots.getByRole("button", { name: "Promote" }).click();
    await expect(page.getByText(/^Snapshot \w{8} is promoted/)).toBeVisible();
    // The table reloads after the promotion.
    await expect(snapshots.getByRole("row").filter({ hasText: "promoted" }).getByRole("link")).not.toHaveText(first);
    await snapshots.getByRole("row").filter({ hasText: first }).getByRole("button", { name: "Roll back to this snapshot" }).click();
    await expect(page.getByText(/^Snapshot \w{8} is promoted/)).toBeVisible();
    await expect(snapshots.getByRole("row").filter({ hasText: "promoted" }).getByRole("link")).toHaveText(first);
    await expect(page.getByRole("table", { name: "Promotion history" }).getByRole("row")).toHaveCount(4); // header and three promotions
  } finally {
    await context.close();
    d.stop();
  }
});

test("G-06 anomaly response: only restrict-only actions per band", async ({ page }) => {
  // FR-8.14 in full: each band and the uncharacterized state is set from
  // the restrict-only lists only, published, and read back.
  test.info().annotations.push({ type: "requirement", description: "FR-8.14" });
  await signIn(page, "/anomaly-response");
  await expect(page.getByRole("table", { name: "Current response per band" })).toContainText("uncharacterized");
  const options = await page.getByLabel("critical action").locator("option").allTextContents();
  expect(options).toEqual(["Record and alert", "Alert and escalate capture", "Escalate and require approval", "Require approval and withhold the result"]);
  const un = await page.getByLabel("uncharacterized action").locator("option").allTextContents();
  expect(un).toEqual(["Record only", "Escalate capture", "Escalate and require approval"]);
  await page.getByLabel("elevated action").selectOption("alert");
  await page.getByLabel("abnormal action").selectOption("escalate");
  await page.getByLabel("critical action").selectOption("approve");
  await page.getByLabel("uncharacterized action").selectOption("escalate");
  await expect(page.getByText(/escalate_capture_band = "abnormal"/)).toBeVisible();
  await expect(page.getByText(/require_approval_band = "critical"/)).toBeVisible();
  await expect(page.getByText(/uncharacterized_action = "escalate"/)).toBeVisible();
  await page.getByLabel("critical action").selectOption("withhold");
  await expect(page.getByText(/withhold_band = "critical"/)).toBeVisible();
  await expect(page.getByText(/scoring = "sync"/)).toBeVisible();
  await page.getByRole("form", { name: "Publish the Anomaly Response Policy" }).getByRole("button", { name: "Publish the Anomaly Response Policy" }).click();
  await expect(page.getByText(/Published Anomaly Response Policy revision \d+/)).toBeVisible();
  const revs = await page.evaluate(() => fetch("/api/v1/observations/objects/anomaly_response").then((r) => r.json()));
  expect((revs.revisions ?? revs)[0].body).toEqual({
    scoring: "sync",
    escalate_capture_band: "abnormal",
    uncharacterized: "escalate",
    require_approval_band: "critical",
    withhold_band: "critical",
  });
});

// FR-8.15's demonstration (a full claim): the costs of two policy
// revisions are compared in G-07. Calls were made under r1 by earlier tests
// and are made here under the revision the G-02 rollback activated; the
// view shows throughput, p50, p95 and p99 overhead for both, and the
// revision filter narrows the overhead, stage, rule and filter tables to
// one revision at a time.
test("G-07 performance: compare two policy revisions' overhead, stage, rule and filter time", async ({ page }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.15" });
  const calls = async () => {
    const r = await mcpCall(g, "ref_echo", { text: "perf" }, { expect: "perf", timeout: "60s" }).done;
    expect(r.code, r.out).toBe(0);
  };
  // Calls under the active revision, then under a second one: a rollback
  // to r1 publishes r1's content under a new revision ID.
  await signIn(page, "/observations");
  await recordEveryCall(page);
  await calls();
  await go(page, "/policy/revisions/r1");
  await page.getByRole("button", { name: "Roll back to this revision" }).click();
  await page.getByRole("dialog", { name: "Roll back to r1" }).getByRole("button", { name: "Roll back" }).click();
  await expect(page.getByRole("table", { name: "Policy revisions" })).toBeVisible();
  await calls();
  await go(page, "/performance");
  const overhead = page.getByRole("table", { name: "Gateway overhead per policy revision" });
  const revCells = async () => (await overhead.locator("tbody tr td:first-child").allInnerTexts()).map((s) => s.trim()).filter(Boolean);
  // Observation records reach the store shortly after the calls, and the
  // meta-metrics (throughput) are sampled every 10 seconds.
  await expect(async () => {
    await page.reload();
    await expect(overhead.or(page.getByText(/^No stored call in this range/))).toBeVisible({ timeout: 10_000 });
    expect((await revCells()).length).toBeGreaterThanOrEqual(2);
    await expect(page.getByRole("img", { name: /Calls assembled per second/ }).or(page.getByText("Calls assembled per second")).first()).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 60_000 });
  const revs = (await revCells()).slice(0, 2);
  for (const row of await overhead.locator("tbody tr").all()) {
    const cells = (await row.locator("td").allInnerTexts()).map((s) => s.trim());
    for (const q of cells.slice(2, 5)) expect(q, `p50/p95/p99 of ${cells[0]}`).toMatch(/^[\d.]+[kM]?$/);
  }
  const stage = page.getByRole("table", { name: "Time per stage, policy revision and observation policy" });
  const rules = page.getByRole("table", { name: "Time per decisive rule" });
  const filters = page.getByRole("table", { name: "Time per filter" });
  const revColumn = async (t: typeof stage, col: number) => (await t.locator(`tbody tr td:nth-child(${col})`).allInnerTexts()).map((s) => s.trim());
  for (const rev of revs) {
    await page.getByRole("combobox", { name: "Policy revision" }).selectOption(rev);
    await expect(overhead.locator("tbody tr")).toHaveCount(1);
    expect(await revCells()).toEqual([rev]);
    // Each table lists rows of the selected revision only, and has some.
    for (const [t, col, what] of [
      [stage, 2, "stages"],
      [rules, 3, "rules"],
      [filters, 3, "filters"],
    ] as const) {
      await expect.poll(async () => [...new Set(await revColumn(t, col))], { message: `${what} under ${rev}` }).toEqual([rev]);
    }
  }
});

test("G-08 data server: graph state, store sizes, backup and keys", async ({ page }) => {
  claims("FR-8.16", "FR-17.6");
  await signIn(page, "/data-server");
  await expect(page.getByText("The graph mirror is disabled")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Observation Store" })).toBeVisible();
  // Degradation stage and storage quota levels.
  await expect(page.getByRole("term").filter({ hasText: "Degradation stage" }).locator("xpath=following-sibling::dd[1]")).toContainText("normal");
  const quotas = page.getByRole("table", { name: "Storage quotas" });
  await expect(quotas.getByRole("row").filter({ hasText: "journal" })).toContainText(/\d+\.\d%/);
  // Change the Observation Store memory budget; it is published and shown as pending until the next start.
  await page.getByLabel(/Observation Store memory budget \(MiB\)/).fill("384");
  await page.getByRole("form", { name: "Publish the memory budget" }).getByRole("button", { name: "Publish the memory budget" }).click();
  await expect(page.getByText(/Published memory budget revision \d+/)).toBeVisible();
  await expect(page.getByRole("definition").filter({ hasText: /^384 MiB$/ })).toBeVisible();
  await page.getByLabel("Passphrase").fill("console e2e backup passphrase");
  await page.getByRole("button", { name: "Take a backup now" }).click();
  await expect(page.getByText(/Backup written/)).toBeVisible({ timeout: 60_000 });
  await expect(page.getByRole("table", { name: "Backups" })).toContainText("ok");
  await expect(page.getByRole("term").filter({ hasText: "Listener certificate" })).toBeVisible();
});

// FR-8.17's demonstration (a full claim): one campaign through its whole
// lifecycle in G-09. It is created, submitted, approved and becomes
// active; its record count is monitored while calls are made (its scope
// is empty, so it captures every call); it is stopped (completed),
// exported with its data dictionary (exported) and expired.
test("G-09 research campaigns: create, submit, approve, monitor, stop, export with dictionary and expire", async ({ page }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.17" });
  claims("FR-8.9");
  await signIn(page, "/research");
  await page.getByRole("link", { name: "New campaign" }).click();
  await page.getByLabel("Name", { exact: true }).fill("console acceptance study");
  await page.getByLabel("Start (RFC 3339)").fill(new Date(Date.now() - 60_000).toISOString().replace(/\.\d{3}Z$/, "Z"));
  await page.getByRole("button", { name: "Create draft campaign" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Campaign console acceptance study" })).toBeVisible();
  await expect(page.getByRole("definition").filter({ hasText: /^draft$/ })).toBeVisible();
  await page.getByRole("button", { name: "Submit for approval" }).click();
  await expect(page.getByText("The campaign is now submitted.")).toBeVisible();
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText(/The campaign is now (approved|active)\./)).toBeVisible();
  // The campaign becomes active once its start time has passed.
  await expect(async () => {
    await page.reload();
    await expect(page.getByRole("definition").filter({ hasText: /^active$/ })).toBeVisible({ timeout: 2_000 });
  }).toPass({ timeout: 60_000 });
  // Monitor: calls raise the record count.
  const records = page.getByRole("definition").filter({ hasText: / records, / });
  await expect(records).toContainText(/^0 records/);
  for (let i = 0; i < 2; i++) {
    const r = await mcpCall(g, "ref_echo", { text: `campaign ${i}` }, { expect: `campaign ${i}`, timeout: "60s" }).done;
    expect(r.code, r.out).toBe(0);
  }
  await expect(async () => {
    await page.reload();
    await expect(records).toContainText(/^[1-9]\d* records/, { timeout: 2_000 });
  }).toPass({ timeout: 60_000 });
  // Stop: the campaign is completed.
  await page.getByLabel("Reason (optional, recorded)").fill("enough data");
  await page.getByRole("button", { name: "Stop now" }).click();
  await expect(page.getByText("The campaign is now completed.")).toBeVisible();
  // Export with the data dictionary.
  await page.getByRole("button", { name: "Export", exact: true }).click();
  await expect(page.getByRole("table", { name: "Export files" })).toContainText("dictionary.json");
  const dict = page.getByRole("table", { name: "Data dictionary" });
  await expect(dict).toBeVisible();
  await expect(dict).toContainText("tool_name");
  await page.reload();
  await expect(page.getByRole("definition").filter({ hasText: /^exported$/ })).toBeVisible();
  // Expire ends the lifecycle.
  await page.getByRole("button", { name: "Expire" }).click();
  await expect(page.getByText("The campaign is now expired.")).toBeVisible();
  const history = page.getByRole("table", { name: "Campaign history" });
  for (const step of ["draft to submitted", "submitted to approved", "approved to active", "active to completed", "completed to exported", "exported to expired"]) {
    await expect(history).toContainText(step);
  }
  await go(page, "/research");
  await expect(page.getByRole("table", { name: "Dataset exports" })).toContainText("csv");
});

// FR-8.19's verification: create a principal, issue a credential and
// terminate one of its sessions from G-11 (a full claim). The session is
// opened by the test MCP client signing in through OAuth with the new
// credential; suspension and resumption are exercised on the way.
test("G-11 sessions and principals: create a principal, issue a credential, suspend, resume and terminate its session", async ({ page }) => {
  test.info().annotations.push({ type: "requirement", description: "FR-8.19" });
  claims("FR-2.8", "FR-2.18");
  await signIn(page, "/sessions");
  await expect(page.getByRole("table", { name: "Principals" })).toContainText("claude-code-local");
  const id = `e2e-agent-${Date.now() % 1_000_000}`;
  const add = page.getByRole("form", { name: "Add a principal" });
  await add.getByLabel("Principal ID").fill(id);
  await add.getByLabel("Framework", { exact: true }).selectOption("other");
  await add.getByLabel("Display name").fill("Acceptance test agent");
  await add.getByRole("button", { name: "Create principal" }).click();
  await expect(page.getByText(`Created principal ${id}.`)).toBeVisible();
  await expect(page.getByRole("table", { name: "Principals" })).toContainText(id);

  const issue = page.getByRole("form", { name: "Issue a credential" });
  await issue.getByLabel("Principal").selectOption(id);
  await issue.getByRole("button", { name: "Issue credential" }).click();
  const issued = issue.getByRole("status");
  await expect(issued).toContainText("Issued client");
  const clientID = ((await issued.locator(".mono").first().textContent()) ?? "").trim();
  expect(clientID).toMatch(/^smcp-client-/);
  await expect(page.getByRole("table", { name: "Credentials" })).toContainText(clientID);

  // A harness signs in with the new credential and makes one call.
  const r = await mcpCall(g, "ref_read_file", { path: "hello.txt" }, { expect: g.marker, clientID }).done;
  expect(r.code, r.out).toBe(0);
  const row = page.getByRole("table", { name: "Sessions" }).getByRole("row").filter({ hasText: clientID });
  await expect(row).toBeVisible({ timeout: 30_000 });
  await row.getByRole("link").click();
  await expect(page.getByRole("heading", { level: 1, name: "Session" })).toBeVisible();

  await page.getByRole("button", { name: "Suspend session" }).click();
  await page.getByRole("dialog", { name: "Suspend this session" }).getByRole("button", { name: "Suspend session" }).click();
  await expect(page.getByText("Suspended.")).toBeVisible();
  await expect(page.getByRole("definition").filter({ hasText: /^suspended$/ })).toBeVisible();
  await page.getByRole("button", { name: "Resume session" }).click();
  await page.getByRole("dialog", { name: "Resume this session" }).getByRole("button", { name: "Resume session" }).click();
  await expect(page.getByRole("definition").filter({ hasText: /^active$/ })).toBeVisible();
  await page.getByRole("button", { name: "Terminate session" }).click();
  const term = page.getByRole("dialog", { name: "Terminate this session" });
  await term.getByLabel(/Reason/).fill("acceptance test");
  await term.getByRole("button", { name: "Terminate session" }).click();
  await expect(page.getByRole("definition").filter({ hasText: /^terminated$/ })).toBeVisible();

  // Suspend and enable the principal, then revoke the credential.
  await go(page, "/sessions");
  await page.getByRole("button", { name: `Suspend ${id}` }).click();
  await page.getByRole("dialog", { name: `Suspend principal ${id}` }).getByRole("button", { name: "Suspend principal" }).click();
  await expect(page.getByText(`Suspended principal ${id}.`)).toBeVisible();
  await page.getByRole("button", { name: `Enable ${id}` }).click();
  await page.getByRole("dialog", { name: `Enable principal ${id}` }).getByRole("button", { name: "Enable principal" }).click();
  await expect(page.getByText(`Enabled principal ${id}.`)).toBeVisible();
  await page.getByRole("button", { name: `Revoke ${clientID}` }).click();
  await page.getByRole("dialog", { name: `Revoke credential ${clientID}` }).getByRole("button", { name: "Revoke credential" }).click();
  await expect(page.getByText(`Revoked credential ${clientID}.`)).toBeVisible();
  await expect(page.getByRole("table", { name: "Credentials" }).getByRole("row").filter({ hasText: clientID })).toContainText("revoked");
});

test("G-11 remote access: enable, disable and decide a client registration", async ({ page }) => {
  claims("FR-16.5", "FR-16.11");
  await signIn(page, "/remote");
  await page.getByLabel(/Public URL/).fill("https://gateway.example.ts.net");
  await page.getByRole("button", { name: "Enable remote access" }).click();
  await expect(page.getByText("enabled: reachable from outside this machine")).toBeVisible();
  await page.getByRole("button", { name: "Disable", exact: true }).click();
  await expect(page.getByRole("definition").filter({ hasText: /^disabled$/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Client registrations" })).toBeVisible();
  // A pending registration needs a client on the tunnel; a fixture stands in
  // for the list, and the approval request goes to the fixture as well.
  const pending = { client_id: "smcp-dcr-e2e", client_name: "Example agent", status: "pending", registration: "dynamic", redirect_uris: ["https://agent.example/cb"], registered_at: new Date().toISOString(), source_address: "203.0.113.7" };
  await mock(page, "**/api/v1/clients", { clients: [pending] });
  let approved: unknown = null;
  await page.route("**/api/v1/clients/smcp-dcr-e2e/approve", async (r) => {
    approved = r.request().postDataJSON();
    await r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ...pending, status: "approved", principal: "claude-code-local" }) });
  });
  await page.reload();
  await page.getByRole("table", { name: "Client registrations" }).getByRole("button", { name: "Approve" }).click();
  const dialog = page.getByRole("dialog", { name: "Approve Example agent" });
  await dialog.getByRole("combobox", { name: "Principal" }).selectOption("claude-code-local");
  await dialog.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText("Example agent is approved and bound to claude-code-local.")).toBeVisible();
  expect(approved).toEqual({ principal: "claude-code-local" });
});

test("G-12 secrets: write-only create, rotate, impact and revoke", async ({ page }) => {
  claims("FR-6.2");
  // FR-8.20 in full: create, rotate (with the reference-impact preview)
  // and revoke from G-12; neither value appears on any page or in any
  // control API response the console receives.
  test.info().annotations.push({ type: "requirement", description: "FR-8.20" });
  const value = "e2e-secret-value-1234567890";
  const rotated = "e2e-rotated-value-0987654321";
  const leaks: string[] = [];
  page.on("response", async (r) => {
    if (!r.url().includes("/api/v1/")) return;
    const body = await r.text().catch(() => "");
    if (body.includes(value) || body.includes(rotated)) leaks.push(r.url());
  });
  const shown = async () => {
    const text = await page.locator("body").innerText();
    expect(text).not.toContain(value);
    expect(text).not.toContain(rotated);
  };
  await signIn(page, "/secrets");
  await expect(page.getByRole("heading", { name: "Vault" })).toBeVisible();
  await page.getByText("Create a secret").click();
  await page.getByLabel("Name").fill("e2e-token");
  await page.getByLabel("Type").selectOption("token");
  await page.getByLabel(/^Value/).fill(value);
  await page.getByRole("button", { name: "Create secret" }).click();
  await expect(page.getByText("Created e2e-token as version 1.")).toBeVisible();
  await expect(page.getByLabel(/^Value/)).toHaveValue("");
  await shown();
  await page.getByRole("table", { name: "Secrets" }).getByRole("link", { name: "e2e-token" }).click();
  await expect(page.getByRole("table", { name: "References to e2e-token" }).or(page.getByText(/Nothing references this secret/))).toBeVisible();
  await shown();
  await page.getByRole("button", { name: "Rotate" }).click();
  await page.getByLabel("New value (write-only)").fill(rotated);
  await page.getByRole("dialog", { name: "Rotate e2e-token" }).getByRole("button", { name: "Rotate" }).click();
  await expect(page.getByText("Rotated to version 2.")).toBeVisible();
  const text = await page.locator("body").innerText();
  expect(text).not.toContain(value);
  expect(text).not.toContain(rotated);
  await page.getByRole("button", { name: "Revoke" }).click();
  await page.getByRole("dialog", { name: "Revoke e2e-token" }).getByRole("button", { name: "Revoke e2e-token" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Secrets" })).toBeVisible();
  await expect(page.getByRole("table", { name: "Secrets" }).or(page.getByText(/No secret is stored/))).not.toContainText("e2e-token");
  await shown();
  expect(leaks).toEqual([]);
});

test("G-13 approvals: a deep link to one approval opens after sign-in", async ({ page, browser }) => {
  claims("FR-8.21", "FR-8.28");
  await signIn(page, "/approvals");
  const call = mcpCall(g, "ref_read_file", { path: "hello.txt" }, { scope: "smcp:template:approval-demo", expect: g.marker, timeout: "60s" });
  try {
    const row = page.getByRole("table", { name: "Approvals: pending" }).getByRole("link", { name: "ref_read_file" });
    await expect(row).toBeVisible({ timeout: 60_000 });
    const href = await row.getAttribute("href");
    expect(href).toMatch(/^\/approvals\/[0-9a-f-]+$/);
    const other = await browser.newPage({ ignoreHTTPSErrors: true });
    await signIn(other, href!, "approver");
    await expect(other.getByRole("heading", { level: 1, name: "Approval" })).toBeVisible();
    await other.getByRole("button", { name: "Deny this call" }).click();
    await expect(other.getByRole("definition").filter({ hasText: /^denied$/ })).toBeVisible();
    await other.close();
    const r = await call.done;
    expect(r.code).not.toBe(0);
  } finally {
    call.kill();
  }
});

test("G-14 audit investigation: event, call phases and the investigation graph", async ({ page }) => {
  claims("FR-8.22");
  await signIn(page, "/audit");
  await page.getByLabel("Class").fill("call");
  await page.getByRole("button", { name: "Apply filter" }).click();
  const table = page.getByRole("table", { name: "Journal events" });
  await expect(table).toContainText("call");
  await table.getByRole("link").first().click();
  await expect(page.getByRole("heading", { level: 1, name: "Evidence event" })).toBeVisible();
  const id = page.url().split("/").pop()!;
  // Without Neo4j the mirror is disabled; the view says so.
  await expect(page.getByText("Not enabled on this Gateway.")).toBeVisible();
  // With the mirror, the path renders as a bounded graph: fixture.
  await mock(page, `**/api/v1/graph/events/${id}/path`, {
    event: { id, class: "call", phase: "delivered" },
    decision: { id: "d1", outcome: "permit", revisionId: "r1", decisiveRules: "ro-ref" },
    invocation: { id: "c1", phase: "delivered", outcome: "ok" },
    session: { id: "s1", state: "active" },
    principal: { id: "claude-code-local" },
    serverRevision: { id: "smcp-ref-filesystem@0.0.0" },
    toolRevision: { id: "live/echo", name: "echo" },
    policyRevision: { id: "r1" },
    phases: [{ id: "p1", phase: "requested" }, { id, phase: "delivered" }],
  });
  await page.reload();
  const graph = page.getByRole("group", { name: /Investigation path: 8 of 8/ });
  await expect(graph).toBeVisible();
  await expect(page.getByText("Decisive rules: ro-ref")).toBeVisible();
  await graph.getByRole("link", { name: /^PolicyRevision r1/ }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: "Policy revision r1" })).toBeVisible();
  // Neighborhood explorer, bounded by the limit: fixture.
  await mock(page, "**/api/v1/graph/neighborhood?**", {
    node: { id: "s1", labels: ["Session"], properties: {} },
    neighbors: [
      { id: "claude-code-local", labels: ["Principal"] },
      { id: "c1", labels: ["Invocation"] },
    ],
    edges: [
      { type: "OF_PRINCIPAL", from: "s1", to: "claude-code-local" },
      { type: "IN_SESSION", from: "c1", to: "s1" },
    ],
    degree: 41,
    truncated: true,
  });
  await go(page, "/audit/graph?label=Session&id=s1&limit=25");
  await expect(page.getByRole("group", { name: /2 of 41 relationships shown \(truncated/ })).toBeVisible();
  await expect(page.getByRole("table", { name: "Relationships" })).toContainText("OF_PRINCIPAL");
});

test("Egress: broker, grants and the connection log", async ({ page }) => {
  claims("FR-6.20");
  await signIn(page, "/egress");
  await expect(page.getByRole("heading", { name: "Broker" })).toBeVisible();
  await expect(page.getByText(/No server has an egress grant/)).toBeVisible();
  await page.getByLabel("Decision").selectOption("denied");
  await page.getByRole("button", { name: "Apply filter" }).click();
  await expect(page.getByText(/No egress operation matches/)).toBeVisible();
});

test("Runtime: launcher, prerequisites and instances", async ({ page }) => {
  claims("FR-5.20");
  await signIn(page, "/runtime");
  await expect(page.getByText("none: servers run as your user")).toBeVisible();
  await expect(page.getByRole("table", { name: "Prerequisite checks" })).toBeVisible();
  await expect(page.getByText(/No sandboxed instance exists/)).toBeVisible();
});

test("views show loading, empty and error states with the reason code and retry", async ({ page }) => {
  claims("FR-8.29");
  await signIn(page, "/");
  // Error state: the control API message and reason code, with Retry.
  await mock(page, "**/api/v1/egress/grants", { error: { code: "egress_broken", message: "grant table unreadable" } }, 500);
  await go(page, "/egress");
  const alert = page.getByRole("alert").filter({ hasText: "grant table unreadable" });
  await expect(alert).toContainText("egress_broken");
  await page.unroute("**/api/v1/egress/grants");
  await alert.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByText(/No server has an egress grant/)).toBeVisible();
  // Loading state within 200 ms of navigation, shown while a slow route answers.
  await page.route("**/api/v1/runtime/instances", async (r) => {
    await new Promise((ok) => setTimeout(ok, 1500));
    await r.continue();
  });
  const t0 = Date.now();
  await go(page, "/runtime");
  await expect(page.getByText("Loading server instances")).toBeVisible();
  expect(Date.now() - t0).toBeLessThan(1000);
  await expect(page.getByText(/No sandboxed instance exists/)).toBeVisible();
});

test("each role sees only its views and actions", async ({ page }) => {
  claims("FR-8.2", "FR-8.28");
  const expectViews = async (names: string[], absent: string[]) => {
    for (const n of names) await expect(nav(page).getByRole("link", { name: n })).toBeVisible();
    for (const n of absent) await expect(nav(page).getByRole("link", { name: n })).toHaveCount(0);
  };
  await signIn(page, "/", "operator");
  await expectViews(["Gateway control", "Sessions and principals", "Runtime", "Data server and memory"], ["Research campaigns"]);
  await expect(page.getByTestId("emergency-button")).toBeVisible();
  await go(page, "/policy");
  await expect(page.getByRole("link", { name: "Draft", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Sign out" }).click();

  await signIn(page, "/", "policy_author");
  await expectViews(["Policy studio", "Behavior analytics", "Research campaigns"], ["Secrets", "Runtime"]);
  await expect(page.getByTestId("emergency-button")).toHaveCount(0);
  await go(page, "/policy");
  await expect(page.getByRole("link", { name: "Draft", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();

  await signIn(page, "/", "auditor");
  await expectViews(["Audit investigation", "Secrets", "Policy studio", "Research campaigns"], ["Approvals", "Remote access"]);
  await go(page, "/secrets");
  await expect(page.getByText("Create a secret")).toHaveCount(0);
  await page.getByRole("button", { name: "Sign out" }).click();

  await signIn(page, "/", "researcher");
  await expectViews(["Research campaigns", "Observation workbench", "Behavior analytics"], ["Audit investigation", "Policy studio", "Secrets"]);
  await page.getByRole("button", { name: "Sign out" }).click();

  await signIn(page, "/", "session_approver");
  await expect(page.getByRole("heading", { level: 1, name: "Remote access" })).toBeVisible();
  await expectViews(["Remote access", "Gateway control"], ["Sessions and principals", "Approvals", "Audit investigation"]);
  await expect(page.getByRole("button", { name: "Enable remote access" })).toHaveCount(0);
});

test("the OpenAPI document describes every route with its roles", async ({ request }) => {
  claims("FR-8.1");
  const post = () => request.post(g.adminURL + "/admin/v1/login", { data: { username: "admin", password: g.adminPassword }, headers: { Origin: g.adminURL } });
  let login = await post();
  if (login.status() === 429) {
    // The suite signs in many times; wait out the per-source sign-in limit once.
    await new Promise((r) => setTimeout(r, (Number(login.headers()["retry-after"]) || 5) * 1000 + 250));
    login = await post();
  }
  expect(login.status(), await login.text()).toBe(200);
  const { token } = (await login.json()) as { token: string };
  const res = await request.get(g.adminURL + "/api/v1/openapi.json", { headers: { Authorization: `Bearer ${token}` } });
  expect(res.status()).toBe(200);
  const doc = (await res.json()) as { openapi: string; paths: Record<string, Record<string, { "x-smcp-roles"?: string[] }>> };
  expect(doc.openapi).toBe("3.1.0");
  expect(doc.paths["/api/v1/policy/revisions"]?.post?.["x-smcp-roles"]).toEqual(["administrator", "policy_author"]);
  expect(doc.paths["/api/v1/filters/scan"]?.post).toBeTruthy();
});

// Last: suspending the reference server stops it until smcpd restarts.
// FR-7.10 and FR-8.18: a second, separately signed revision of the
// reference server. Its key is enrolled from G-10 only after the fingerprint
// is shown and confirmed; the revision is installed with smcpctl and
// retired from G-10.
test("G-10 servers and library: enroll an anchor after its fingerprint, then retire a second revision", async ({ page }) => {
  claims("FR-8.18", "FR-7.10", "FR-5.7");
  const ctl = join(bin, "smcpctl");
  const prefix = join(work, `rev2-${Date.now()}`);
  const keyID = execFileSync(ctl, ["package", "keygen", "--out", prefix, "--unencrypted"], { encoding: "utf8" }).match(/^key (\S+)/m)![1]!;
  const refserver = join(bin, "smcp-refserver");
  const sha = createHash("sha256").update(readFileSync(refserver)).digest("hex");
  const rev = "99.0.0-e2e";
  const recipe = {
    recipe_version: 1,
    server: { id: "smcp-ref-filesystem", alias: "ref", publisher: "Secure MCP Gateway project", description: "Second revision of the reference server for the G-10 retire test.", revision: rev },
    artifact: { type: "binary", reference: refserver, version: rev, sha256: sha },
    launch: { runtime: "native", argv: ["smcp-refserver", "--root", "{root}"] },
    risk_class: "low",
    instance_scope: ["shared"],
    tools: { default: { side_effect: "read", source_trust: "trusted" }, expect: ["echo", "time_now", "list_files", "read_file"] },
    capabilities: { filesystem: [{ slot: "root", mode: "ro", argv_placeholder: "{root}" }], egress: [] },
    licenses: ["Apache-2.0"],
    operator_note: "Acceptance test package.",
    source: { kind: "archive", uri: "file://" + refserver, sha256: sha },
  };
  const recipeFile = prefix + "-recipe.json";
  writeFileSync(recipeFile, JSON.stringify(recipe));
  const pkg = prefix + "-pkg";
  execFileSync(ctl, ["package", "build", "--recipe", recipeFile, "--out", pkg]);
  execFileSync(ctl, ["package", "sign", pkg, "--key", prefix + ".key"]);

  await signIn(page, "/library");
  const anchors = page.getByRole("table", { name: "Trust anchors" });
  await page.getByText("Enroll a trust anchor").click();
  const form = page.getByRole("form", { name: "Enroll a trust anchor" });
  await form.getByLabel("Anchor name").fill("e2e-rev2");
  await form.getByLabel("Minisign public key (the .pub file)").fill(readFileSync(prefix + ".pub", "utf8"));
  await form.getByLabel("moderate").uncheck();
  await form.getByLabel("Expires (date, default one year)").fill("2027-10-16");
  await form.getByRole("button", { name: "Show fingerprint" }).click();
  // The fingerprint step: nothing is enrolled until the key ID is confirmed.
  const fp = form.getByRole("status", { name: "Key fingerprint" });
  await expect(fp).toContainText(keyID);
  await expect(fp).toContainText(/[0-9a-f]{64}/);
  await expect(fp).toContainText("low");
  await expect(form.getByRole("button", { name: "Enroll anchor" })).toBeDisabled();
  await expect(anchors).not.toContainText("e2e-rev2");
  await form.getByLabel("The key ID matches the publisher's").check();
  await form.getByRole("button", { name: "Enroll anchor" }).click();
  const row = anchors.getByRole("row").filter({ hasText: "e2e-rev2" });
  await expect(row).toContainText(keyID);
  await expect(row).toContainText("low");
  await expect(row).not.toContainText("moderate");
  await expect(row).toContainText("2027");

  // smcpctl installs the second revision through the running Gateway.
  execFileSync(ctl, ["package", "install", pkg, "--config", g.config]);
  await page.reload();
  const revs = page.getByRole("table", { name: "Package revisions" });
  const second = revs.getByRole("row").filter({ hasText: rev });
  await expect(second).toContainText("verified-disabled", { timeout: 20_000 });
  await expect(second).toContainText("e2e-rev2");
  await second.getByRole("button", { name: `Retire smcp-ref-filesystem ${rev}` }).click();
  const dialog = page.getByRole("dialog", { name: `Retire smcp-ref-filesystem ${rev}` });
  await dialog.getByLabel("Reason (optional, recorded)").fill("superseded test revision");
  await dialog.getByRole("button", { name: "Retire" }).click();
  await expect(page.getByText(`Retired smcp-ref-filesystem ${rev}. This cannot be undone.`)).toBeVisible();
  await expect(second).toContainText("retired");
  await expect(second.getByRole("button")).toHaveCount(0);
  // The enabled first revision is unaffected.
  await expect(revs.getByRole("row").filter({ hasText: "enabled" })).toHaveCount(1);
  // Clean up the anchor so later tests see the bootstrap state.
  await page.getByRole("button", { name: "Remove e2e-rev2" }).click();
  await expect(anchors).not.toContainText("e2e-rev2");
});

test("G-10 servers and library: suspend, enable, trust anchors and receipts", async ({ page }) => {
  claims("FR-8.18", "FR-5.7");
  await signIn(page, "/servers");
  await expect(page.getByRole("table", { name: "Servers" })).toContainText("ref");
  await page.getByRole("link", { name: "Library and trust anchors" }).click();
  const revs = page.getByRole("table", { name: "Package revisions" });
  await expect(revs).toContainText("smcp-ref-filesystem");
  await expect(page.getByRole("table", { name: "Import receipts" })).toContainText("accepted");
  // Enroll and remove a trust anchor.
  const prefix = join(work, `anchor-${Date.now()}`);
  execFileSync(join(bin, "smcpctl"), ["package", "keygen", "--out", prefix, "--unencrypted"]);
  await page.getByText("Enroll a trust anchor").click();
  await page.getByLabel("Anchor name").fill("e2e-anchor");
  await page.getByLabel("Minisign public key (the .pub file)").fill(readFileSync(prefix + ".pub", "utf8"));
  await page.getByRole("button", { name: "Show fingerprint" }).click();
  await page.getByLabel("The key ID matches the publisher's").check();
  await page.getByRole("button", { name: "Enroll anchor" }).click();
  await expect(page.getByRole("table", { name: "Trust anchors" })).toContainText("e2e-anchor");
  await page.getByRole("button", { name: "Remove e2e-anchor" }).click();
  await expect(page.getByRole("table", { name: "Trust anchors" })).not.toContainText("e2e-anchor");
  // Retire is offered; it is final, so it is not used here.
  await expect(revs.getByRole("button", { name: "Retire" })).toBeVisible();
  // Suspend the running server, then enable it again (needs a restart to run).
  await revs.getByRole("button", { name: "Suspend" }).click();
  await page.getByRole("dialog", { name: /Suspend smcp-ref-filesystem/ }).getByRole("button", { name: "Suspend" }).click();
  await expect(page.getByText(/Suspended smcp-ref-filesystem/)).toBeVisible();
  await expect(revs).toContainText("verified-disabled");
  await revs.getByRole("button", { name: "Enable" }).click();
  await page.getByRole("dialog", { name: /Enable smcp-ref-filesystem/ }).getByRole("button", { name: "Enable" }).click();
  await expect(page.getByText(/Enabled smcp-ref-filesystem/)).toBeVisible();
  await expect(revs).toContainText("enabled");
  await revs.getByRole("row").filter({ hasText: "enabled" }).getByRole("link", { name: "smcp-ref-filesystem" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Package smcp-ref-filesystem" })).toBeVisible();
  await expect(page.getByRole("heading", { name: /^Signed manifest/ })).toBeVisible();
});
