// FR-8.33 and FR-8.32 on intermediate states: console actions completed
// with keyboard events only, with axe (WCAG 2.2 A/AA) run on every state the
// flows pass through (sign-in, forms filled, dialogs open, results shown) in
// Chromium, Firefox and WebKit. WebKit moves Tab only between form controls
// by default (the macOS "keyboard navigation" setting); Option+Tab moves
// through every control there, so the WebKit run presses Alt+Tab. Every
// focus stop of the walk must show a focus indicator.
//
// The flows: sign-in; navigation by the view list; G-11 Session Approver
// create and remove (FR-2.23) and principal create, suspend and enable;
// G-01 emergency stop and resume; G-02 draft validate and diff; G-10 trust
// anchor enrollment with the fingerprint confirmation (FR-7.10) and
// removal; Escape closes a dialog and returns focus (no keyboard trap).
import AxeBuilder from "@axe-core/playwright";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { expect, test, type Locator, type Page } from "@playwright/test";
import { bin, mcpCall, startDedicated, work } from "./gateway";
import { claims, forget, g, mock, signIn } from "./helpers";

test.describe.configure({ mode: "serial" });

let tabKey = "Tab";
let states = 0;

async function axe(page: Page, state: string) {
  const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(r.violations.map((v) => `${state}: ${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
  states++;
}

/**
 * Presses Tab, or Shift+Tab when the target comes before the focused element
 * in document order, until target has focus; every stop must show a focus
 * indicator.
 */
async function tabTo(page: Page, target: Locator, max = 400) {
  await expect(target).toBeVisible();
  const handle = await target.elementHandle();
  const trail: string[] = [];
  for (let i = 0; i < max; i++) {
    const st = await page.evaluate((t) => {
      const el = document.activeElement as HTMLElement | null;
      if (!el || el === document.body) return { at: false, back: false, ring: true, what: "body" };
      const s = getComputedStyle(el);
      // Headings focused after navigation (tabindex -1) are not Tab stops.
      const ring = el.tabIndex < 0 || (s.outlineStyle !== "none" && parseFloat(s.outlineWidth) >= 1) || s.boxShadow !== "none";
      const back = !!t && el !== t && !!(el.compareDocumentPosition(t) & Node.DOCUMENT_POSITION_PRECEDING);
      return { at: el === t, back, ring, what: `${el.tagName.toLowerCase()} "${(el.getAttribute("aria-label") || el.textContent || "").trim().slice(0, 30)}"` };
    }, handle);
    expect(st.ring, `no focus indicator on ${st.what}`).toBe(true);
    trail.push(st.what);
    if (st.at) return;
    await page.keyboard.press(st.back ? tabKey.replace("Tab", "Shift+Tab") : tabKey);
  }
  throw new Error(`Tab did not reach ${target}; last stops: ${trail.slice(-12).join(" > ")}`);
}

/**
 * Puts the sequential focus starting point at the top of the page, as a
 * person does by reloading or by tabbing in from the address bar: a
 * temporary button before every control is focused, and the next Tab leaves
 * it (it is removed then). The walk itself uses keyboard events only.
 */
async function fromTop(page: Page) {
  await page.evaluate(() => {
    const b = document.createElement("button");
    b.id = "kbd-start";
    b.textContent = "start";
    b.style.outline = "2px solid black";
    b.addEventListener("blur", () => b.remove(), { once: true });
    document.body.prepend(b);
    b.focus();
  });
}

async function navTo(page: Page, name: string, heading: string | RegExp) {
  await fromTop(page);
  await tabTo(page, page.getByRole("navigation", { name: "Views" }).getByRole("link", { name }));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
  await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
}

test("console actions complete with the keyboard alone and every intermediate state passes axe", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-2.23", "FR-7.10");
  test.setTimeout(600_000);
  tabKey = browserName === "webkit" ? "Alt+Tab" : "Tab";
  states = 0;
  await page.emulateMedia({ reducedMotion: "reduce" });

  // Sign in.
  await page.goto(g.adminURL + "/");
  await axe(page, "sign-in");
  await tabTo(page, page.getByLabel("Password"));
  await page.keyboard.type(g.adminPassword);
  await axe(page, "sign-in filled");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
  await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
  await axe(page, "G-01 signed in");

  // G-11: create a Session Approver, then remove it through its dialog.
  await navTo(page, "Sessions and principals", "Sessions and principals");
  const user = `kbd-${browserName}`;
  const form = page.getByRole("form", { name: "Add a Session Approver" });
  await tabTo(page, form.getByLabel("Username"));
  await page.keyboard.type(user);
  await page.keyboard.press("Tab");
  await page.keyboard.type("keyboard-approver-pw");
  await page.keyboard.press("Tab");
  await page.keyboard.type("keyboard-approver-px");
  await expect(form.getByRole("alert")).toContainText("differ");
  await axe(page, "G-11 approver passwords differ");
  await page.keyboard.press("Backspace");
  await page.keyboard.type("w");
  await page.keyboard.press("Enter");
  await expect(page.getByText(`Created Session Approver ${user}.`)).toBeVisible();
  await expect(page.getByRole("table", { name: "Session Approver accounts" })).toContainText(user);
  await axe(page, "G-11 approver created");
  await tabTo(page, page.getByRole("button", { name: `Remove ${user}` }));
  await page.keyboard.press("Enter");
  const rm = page.getByRole("dialog", { name: `Remove Session Approver ${user}` });
  await expect(rm).toBeVisible();
  await axe(page, "G-11 remove dialog");
  // Escape closes the dialog: no keyboard trap.
  await page.keyboard.press("Escape");
  await expect(rm).toBeHidden();
  await tabTo(page, page.getByRole("button", { name: `Remove ${user}` }));
  await page.keyboard.press("Enter");
  await expect(rm).toBeVisible();
  await page.keyboard.type("keyboard test");
  await page.keyboard.press("Enter");
  await expect(page.getByText(`Removed Session Approver ${user}.`)).toBeVisible();
  await expect(page.getByRole("table", { name: "Session Approver accounts" })).not.toContainText(user);
  await axe(page, "G-11 approver removed");

  // G-11: create a principal, suspend it and enable it again.
  const pid = `kbd-agent-${browserName}`;
  const add = page.getByRole("form", { name: "Add a principal" });
  await tabTo(page, add.getByLabel("Principal ID"));
  await page.keyboard.type(pid);
  await page.keyboard.press("Enter");
  await expect(page.getByText(`Created principal ${pid}.`)).toBeVisible();
  await axe(page, "G-11 principal created");
  await tabTo(page, page.getByRole("button", { name: `Suspend ${pid}` }));
  await page.keyboard.press("Enter");
  const sus = page.getByRole("dialog", { name: `Suspend principal ${pid}` });
  await expect(sus).toBeVisible();
  await axe(page, "G-11 suspend dialog");
  await page.keyboard.press("Enter");
  await expect(page.getByText(`Suspended principal ${pid}.`)).toBeVisible();
  await axe(page, "G-11 principal suspended");
  await tabTo(page, page.getByRole("button", { name: `Enable ${pid}` }));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog", { name: `Enable principal ${pid}` })).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page.getByText(`Enabled principal ${pid}.`)).toBeVisible();

  // G-01: emergency stop and resume.
  await navTo(page, "Gateway control", "Gateway control");
  const strip = page.getByTestId("status-strip");
  await fromTop(page);
  await tabTo(page, page.getByTestId("emergency-button"));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog", { name: "Emergency stop" })).toBeVisible();
  await axe(page, "G-01 stop dialog");
  await page.keyboard.type("keyboard acceptance test");
  await page.keyboard.press("Enter");
  await expect(strip).toContainText("emergency stop", { timeout: 2_000 });
  await axe(page, "G-01 stopped");
  await fromTop(page);
  await tabTo(page, page.getByTestId("emergency-button"));
  await page.keyboard.press("Enter");
  const resume = page.getByRole("dialog", { name: "Resume the Gateway" });
  await expect(resume).toBeVisible();
  await axe(page, "G-01 resume dialog");
  await tabTo(page, resume.getByRole("button", { name: "Resume the Gateway" }));
  await page.keyboard.press("Enter");
  await expect(strip).not.toContainText("emergency stop", { timeout: 2_000 });
  await axe(page, "G-01 resumed");

  // G-02: validate a draft and diff it against the active revision.
  await navTo(page, "Policy studio", /Policy studio/);
  await tabTo(page, page.getByRole("link", { name: "Draft", exact: true }));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Session Allow templates" })).toBeVisible();
  await axe(page, "G-02 draft");
  await tabTo(page, page.getByRole("button", { name: "Validate", exact: true }));
  await page.keyboard.press("Enter");
  await expect(page.getByText(/^Valid: revision/)).toBeVisible();
  await page.keyboard.press(tabKey);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: /^Diff against/ })).toBeVisible();
  await axe(page, "G-02 validated and diffed");

  // G-10: enroll a trust anchor after its fingerprint, then remove it.
  await navTo(page, "Servers and library", "Servers and library");
  await tabTo(page, page.getByRole("link", { name: "Library and trust anchors" }));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: "Library and trust anchors" })).toBeVisible();
  const prefix = join(work, `kbd-anchor-${browserName}-${Date.now()}`);
  const keyID = execFileSync(join(bin, "smcpctl"), ["package", "keygen", "--out", prefix, "--unencrypted"], { encoding: "utf8" }).match(/^key (\S+)/m)![1]!;
  const enroll = page.getByText("Enroll a trust anchor");
  await tabTo(page, page.locator("summary", { hasText: "Enroll a trust anchor" }));
  await page.keyboard.press("Enter");
  const ef = page.getByRole("form", { name: "Enroll a trust anchor" });
  await expect(enroll).toBeVisible();
  await tabTo(page, ef.getByLabel("Anchor name"));
  await page.keyboard.type(`kbd-${browserName}`);
  await page.keyboard.press("Tab");
  await page.keyboard.type(readFileSync(prefix + ".pub", "utf8").trim());
  await axe(page, "G-10 enroll form filled");
  await tabTo(page, ef.getByRole("button", { name: "Show fingerprint" }));
  await page.keyboard.press("Enter");
  await expect(ef.getByRole("status", { name: "Key fingerprint" })).toContainText(keyID);
  await axe(page, "G-10 fingerprint shown");
  await tabTo(page, ef.getByLabel("The key ID matches the publisher's"));
  await page.keyboard.press("Space");
  await expect(ef.getByLabel("The key ID matches the publisher's")).toBeChecked();
  await tabTo(page, ef.getByRole("button", { name: "Enroll anchor" }));
  await page.keyboard.press("Enter");
  const anchors = page.getByRole("table", { name: "Trust anchors" });
  await expect(anchors).toContainText(`kbd-${browserName}`);
  await axe(page, "G-10 anchor enrolled");
  await tabTo(page, page.getByRole("button", { name: `Remove kbd-${browserName}` }));
  await page.keyboard.press("Enter");
  await expect(anchors).not.toContainText(`kbd-${browserName}`);
  await axe(page, "G-10 anchor removed");

  // Sign out with the keyboard.
  await fromTop(page);
  await tabTo(page, page.getByRole("button", { name: "Sign out" }));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  await axe(page, "signed out");
  forget("administrator");
  console.log(`keyboard flows (${browserName}): ${states} states passed axe`);
});

// The remaining actions of the acceptance tests, view by view, with
// keyboard events only and axe on every intermediate state. These tests
// reuse the session cookie the helpers cache (the keyboard sign-in is the
// first test's); every action after it is a key press.

/** Focuses a text field by Tab, clears it and types the new value. */
async function typeInto(page: Page, field: Locator, text: string, check = true) {
  await tabTo(page, field);
  await page.keyboard.press("ControlOrMeta+a");
  await page.keyboard.press("Backspace");
  if (text) await page.keyboard.type(text);
  if (check) await expect(field).toHaveValue(text);
}

/** Chooses an option of a focused select by typing its label (type-ahead works on every engine). */
async function choose(page: Page, select: Locator, label: string, value: string) {
  await tabTo(page, select);
  await page.keyboard.type(label);
  await expect(select).toHaveValue(value);
  // A pause ends the type-ahead run, so the next select starts afresh.
  await page.waitForTimeout(1100);
}

/** Presses Space on a checkbox reached by Tab until it has the wanted state. */
async function setCheck(page: Page, box: Locator, on = true) {
  await tabTo(page, box);
  if ((await box.isChecked()) !== on) await page.keyboard.press("Space");
  if (on) await expect(box).toBeChecked();
  else await expect(box).not.toBeChecked();
}

/** Activates a control reached by Tab with Enter. */
async function activate(page: Page, control: Locator) {
  await tabTo(page, control);
  await page.keyboard.press("Enter");
}

async function startIn(page: Page, browserName: string, view: string, heading: string | RegExp) {
  tabKey = browserName === "webkit" ? "Alt+Tab" : "Tab";
  states = 0;
  await page.emulateMedia({ reducedMotion: "reduce" });
  await signIn(page, "/");
  await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
  await navTo(page, view, heading);
}

test("G-04 observation workbench with the keyboard: search, presets, scope, bands, features and publish", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-8.6", "FR-8.8", "FR-8.11");
  test.setTimeout(600_000);
  await startIn(page, browserName, "Observation workbench", "Observation workbench");
  await axe(page, "G-04 loaded");
  await typeInto(page, page.getByLabel(/Search parameters/), "latency");
  await expect(page.getByRole("checkbox", { name: "Capture end_to_end_latency" })).toBeVisible();
  await axe(page, "G-04 searched");
  await setCheck(page, page.getByRole("checkbox", { name: "Capture end_to_end_latency" }));
  await typeInto(page, page.getByLabel(/Search parameters/), "");
  await activate(page, page.getByRole("button", { name: "Performance profiling" }));
  await expect(page.getByText(/Applied preset Performance profiling/)).toBeVisible();
  await axe(page, "G-04 preset applied");
  const preset = `kbd preset ${browserName}`;
  await typeInto(page, page.getByLabel("Save the selection as a preset"), preset);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: `${preset} (saved)` })).toBeVisible();
  await axe(page, "G-04 preset saved");
  await activate(page, page.getByRole("button", { name: "Show the configuration for this selection" }));
  await expect(page.getByText(/parameters = \[/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Live record preview" })).toBeVisible();
  await axe(page, "G-04 configuration and preview shown");
  await typeInto(page, page.getByLabel("Normal-band sampling rate (0 to 1)"), "0.5");
  await typeInto(page, page.getByLabel("critical band from |z|"), "6");
  await setCheck(page, page.getByRole("checkbox", { name: "server", exact: true }));
  const principals = page.getByRole("group", { name: "Principals" }).getByRole("checkbox");
  await setCheck(page, principals.first());
  await setCheck(page, page.getByRole("group", { name: "Tools" }).getByRole("checkbox", { name: "ref/echo", exact: true }));
  await axe(page, "G-04 scope chosen");
  await activate(page, page.locator("summary", { hasText: "Escalation parameters per band" }));
  const escRow = page.getByRole("table", { name: "Escalation parameters per band" }).getByRole("row").nth(1);
  const escParam = (await escRow.getByRole("cell").first().innerText()).trim();
  await setCheck(page, escRow.getByRole("checkbox", { name: `${escParam} abnormal` }));
  await activate(page, page.locator("summary", { hasText: "Baselined features and statistics" }));
  await choose(page, page.getByLabel("request_bytes transform"), "none", "none");
  await setCheck(page, page.getByRole("checkbox", { name: "request_bytes robust statistics" }));
  await typeInto(page, page.getByLabel("request_bytes sigma floor"), "0.75");
  await axe(page, "G-04 bands and features set");
  const form = page.getByRole("form", { name: "Publish the Observation Policy" });
  await activate(page, form.getByRole("button", { name: "Publish the Observation Policy" }));
  await expect(page.getByText(/Published Observation Policy revision \d+/)).toBeVisible();
  await axe(page, "G-04 published");
  const revs = await page.evaluate(() => fetch("/api/v1/observations/objects/observation_policy").then((r) => r.json()));
  const body = (revs.revisions ?? revs)[0].body;
  expect(body.sampling_rate).toBe(0.5);
  expect(body.bands).toEqual([2, 3, 6]);
  expect(body.escalation).toEqual({ abnormal: [escParam] });
  expect(body.features.find((f: { parameter: string }) => f.parameter === "request_bytes")).toMatchObject({ transform: "none", robust: true, sigma_floor: 0.75 });
  console.log(`G-04 keyboard (${browserName}): ${states} states passed axe`);
});

test("G-05 behavior analytics with the keyboard: build, promote and drill down", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-8.13");
  test.setTimeout(300_000);
  await startIn(page, browserName, "Behavior analytics", "Behavior analytics");
  await axe(page, "G-05 loaded");
  await activate(page, page.getByRole("button", { name: "Build a snapshot now" }));
  await expect(page.getByText(/Built snapshot/)).toBeVisible();
  await axe(page, "G-05 snapshot built");
  await activate(page, page.getByRole("table", { name: "Baseline snapshots" }).getByRole("button", { name: "Promote" }).first());
  await expect(page.getByText(/is promoted/)).toBeVisible();
  await axe(page, "G-05 promoted");
  // Scored anomalies need a characterized baseline; a fixture stands in.
  await mock(page, "**/api/v1/anomalies?**", {
    count: 1,
    rows: [{ ts: new Date(Date.now() - 30_000).toISOString(), correlation_id: "corr-kbd", snapshot_id: "s", context: "principal=cc|tool=read_file", combined: 6.2, contributing_feature: "request_bytes", band: "critical", actions: '["alert"]', mode: "async" }],
  });
  await navTo(page, "Gateway control", "Gateway control");
  await navTo(page, "Behavior analytics", "Behavior analytics");
  await expect(page.getByRole("table", { name: "Abnormal events" })).toContainText("critical");
  await axe(page, "G-05 abnormal events");
  await activate(page, page.getByRole("button", { name: /^critical 6.20/ }));
  await expect(page).toHaveURL(/\/audit\?correlation_id=corr-kbd/);
  await axe(page, "G-05 drilled down");
  console.log(`G-05 keyboard (${browserName}): ${states} states passed axe`);
});

test("G-09 research campaigns with the keyboard: create, submit, approve and export", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-8.17");
  test.setTimeout(600_000);
  await startIn(page, browserName, "Research campaigns", "Research campaigns");
  await axe(page, "G-09 loaded");
  await activate(page, page.getByRole("link", { name: "New campaign" }));
  const name = `kbd campaign ${browserName}`;
  await typeInto(page, page.getByLabel("Name", { exact: true }), name);
  await typeInto(page, page.getByLabel("Start (RFC 3339)"), new Date(Date.now() - 60_000).toISOString().replace(/\.\d{3}Z$/, "Z"));
  await axe(page, "G-09 draft filled");
  await activate(page, page.getByRole("button", { name: "Create draft campaign" }));
  await expect(page.getByRole("heading", { level: 1, name: `Campaign ${name}` })).toBeVisible();
  await axe(page, "G-09 draft created");
  await activate(page, page.getByRole("button", { name: "Submit for approval" }));
  await expect(page.getByText("The campaign is now submitted.")).toBeVisible();
  await axe(page, "G-09 submitted");
  await activate(page, page.getByRole("button", { name: "Approve" }));
  await expect(page.getByText(/The campaign is now (approved|active)\./)).toBeVisible();
  await axe(page, "G-09 approved");
  // The campaign becomes active once its start has passed; the list link reopens it.
  await expect(async () => {
    await navTo(page, "Research campaigns", "Research campaigns");
    await activate(page, page.getByRole("link", { name, exact: true }).first());
    await expect(page.getByRole("definition").filter({ hasText: /^active$/ })).toBeVisible({ timeout: 2_000 });
  }).toPass({ timeout: 90_000 });
  await choose(page, page.getByLabel("Format"), "JSON", "jsonl");
  await activate(page, page.getByRole("button", { name: "Export", exact: true }));
  await expect(page.getByRole("table", { name: "Export files" })).toContainText("dictionary.json");
  await expect(page.getByRole("table", { name: "Data dictionary" })).toBeVisible();
  await axe(page, "G-09 exported");
  console.log(`G-09 keyboard (${browserName}): ${states} states passed axe`);
});

test("G-12 secrets with the keyboard: create, rotate and revoke", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-8.20");
  test.setTimeout(300_000);
  await startIn(page, browserName, "Secrets", "Secrets");
  await axe(page, "G-12 loaded");
  const name = `kbd-${browserName}`;
  await activate(page, page.locator("summary", { hasText: "Create a secret" }));
  const form = page.getByRole("form", { name: "Create a secret" });
  await typeInto(page, form.getByLabel("Name"), name);
  await choose(page, form.getByLabel("Type"), "token", "token");
  await tabTo(page, form.getByLabel(/^Value/));
  await page.keyboard.type("kbd-secret-value-1234567890");
  await axe(page, "G-12 create form filled");
  await page.keyboard.press("Enter");
  await expect(page.getByText(`Created ${name} as version 1.`)).toBeVisible();
  await axe(page, "G-12 created");
  await activate(page, page.getByRole("table", { name: "Secrets" }).getByRole("link", { name }));
  await expect(page.getByRole("heading", { level: 1, name: `Secret ${name}` })).toBeVisible();
  await activate(page, page.getByRole("button", { name: "Rotate" }));
  const rot = page.getByRole("dialog", { name: `Rotate ${name}` });
  await expect(rot).toBeVisible();
  await tabTo(page, rot.getByLabel("New value (write-only)"));
  await page.keyboard.type("kbd-rotated-value-0987654321");
  await axe(page, "G-12 rotate dialog filled");
  await page.keyboard.press("Enter");
  await expect(page.getByText("Rotated to version 2.")).toBeVisible();
  await axe(page, "G-12 rotated");
  await activate(page, page.getByRole("button", { name: "Revoke" }));
  const rev = page.getByRole("dialog", { name: `Revoke ${name}` });
  await expect(rev).toBeVisible();
  await axe(page, "G-12 revoke dialog");
  await activate(page, rev.getByRole("button", { name: `Revoke ${name}` }));
  await expect(page.getByRole("heading", { level: 1, name: "Secrets" })).toBeVisible();
  await expect(page.getByRole("table", { name: "Secrets" }).or(page.getByText(/No secret is stored/))).not.toContainText(name);
  await axe(page, "G-12 revoked");
  const text = await page.locator("body").innerText();
  expect(text).not.toContain("kbd-secret-value");
  expect(text).not.toContain("kbd-rotated-value");
  console.log(`G-12 keyboard (${browserName}): ${states} states passed axe`);
});

test("G-13 approvals with the keyboard: approve one held call and deny another", async ({ page, browserName, request }) => {
  claims("FR-8.33", "FR-8.32", "FR-8.21");
  test.setTimeout(300_000);
  await startIn(page, browserName, "Approvals", "Approvals");
  await axe(page, "G-13 loaded");
  // The harness sessions this test opens are terminated at the end, so the
  // rest of the suite stays under the per-principal session limit.
  const login = await request.post(g.adminURL + "/admin/v1/login", { data: { username: "admin", password: g.adminPassword }, headers: { Origin: g.adminURL } });
  const auth = { Authorization: `Bearer ${((await login.json()) as { token: string }).token}`, Origin: g.adminURL };
  const sessionIDs = async () =>
    ((await (await request.get(g.adminURL + "/api/v1/sessions", { headers: auth })).json()) as { sessions: { id: string; state: string }[] }).sessions
      .filter((x) => x.state === "active")
      .map((x) => x.id);
  const before = new Set(await sessionIDs());
  for (const decision of ["approve", "deny"] as const) {
    const call = mcpCall(g, "ref_read_file", { path: "hello.txt" }, { scope: "smcp:template:approval-demo", expect: g.marker, timeout: "90s" });
    try {
      const row = page.getByRole("table", { name: "Approvals: pending" }).getByRole("link", { name: "ref_read_file" });
      await expect(row).toBeVisible({ timeout: 60_000 });
      await axe(page, `G-13 pending (${decision})`);
      await activate(page, row.first());
      await expect(page.getByRole("heading", { level: 1, name: "Approval" })).toBeVisible();
      await tabTo(page, page.getByLabel(/Comment/));
      await page.keyboard.type(`keyboard ${decision}`);
      await axe(page, `G-13 approval open (${decision})`);
      await activate(page, page.getByRole("button", { name: decision === "approve" ? "Approve this call" : "Deny this call" }));
      await expect(page.getByRole("status").filter({ hasText: decision === "approve" ? "Approved." : "Denied." })).toBeVisible();
      await axe(page, `G-13 decided (${decision})`);
      const r = await call.done;
      if (decision === "approve") expect(r.code, r.out).toBe(0);
      else expect(r.code).not.toBe(0);
    } finally {
      call.kill();
    }
    await navTo(page, "Approvals", "Approvals");
  }
  // The state tabs are links.
  await activate(page, page.getByRole("navigation", { name: "Approval states" }).getByRole("link", { name: "consumed", exact: true }));
  await expect(page.getByRole("table", { name: "Approvals: consumed" })).toContainText("ref_read_file");
  await axe(page, "G-13 consumed list");
  for (const id of (await sessionIDs()).filter((x) => !before.has(x))) {
    const t = await request.post(g.adminURL + `/api/v1/sessions/${id}/terminate`, { data: { reason: "keyboard test cleanup" }, headers: auth });
    expect(t.ok(), await t.text()).toBe(true);
  }
  console.log(`G-13 keyboard (${browserName}): ${states} states passed axe`);
});

test("G-01 and a server's tools with the keyboard: verify the journal, reload the policy, show an input schema", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-8.3", "FR-8.18");
  test.setTimeout(300_000);
  await startIn(page, browserName, "Gateway control", "Gateway control");
  await activate(page, page.getByRole("button", { name: "Verify the journal now" }));
  await expect(page.getByRole("definition").filter({ hasText: /^verified$/ })).toBeVisible();
  await axe(page, "G-01 journal verified");
  // Before the G-02 test publishes and rolls back: the policy file's revision is still the active one.
  await activate(page, page.getByRole("button", { name: "Reload policy" }));
  await expect(page.getByRole("status").filter({ hasText: /revision/ })).toBeVisible();
  await axe(page, "G-01 policy reloaded");
  await navTo(page, "Servers and library", "Servers and library");
  await activate(page, page.getByRole("table", { name: "Servers" }).getByRole("link", { name: "ref", exact: true }));
  const tools = page.getByRole("table", { name: "Tools of ref" });
  await expect(tools).toBeVisible();
  await activate(page, tools.getByRole("button", { name: "Show" }).first());
  await expect(page.getByText(/^Input schema of /)).toBeVisible();
  await axe(page, "G-10 input schema shown");
  console.log(`G-01/G-10 keyboard (${browserName}): ${states} states passed axe`);
});

test("G-02 policy studio with the keyboard: structured draft, simulate, publish, permissions and roll back", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-8.4");
  test.setTimeout(600_000);
  // The simulation replays calls in the journal (the G-13 test made some).
  await startIn(page, browserName, "Policy studio", /Policy studio/);
  await axe(page, "G-02 loaded");
  await activate(page, page.getByRole("link", { name: "Draft", exact: true }));
  const rev = `kbd-${browserName}-${Date.now() % 100000}`;
  await typeInto(page, page.getByLabel("Revision ID of the draft"), rev);
  await typeInto(page, page.getByLabel("New template name"), "kbd-echo");
  await page.keyboard.press("Enter");
  await activate(page, page.getByRole("button", { name: "Add a rule to kbd-echo" }));
  const rule = page.getByRole("group", { name: "Rule rule-1" });
  await typeInto(page, rule.getByLabel("Tools (space separated)"), "echo");
  // The group is named after the rule ID, so the check uses the new name.
  await typeInto(page, rule.getByLabel("Rule ID"), "kbd-echo-rule", false);
  await expect(page.getByRole("group", { name: "Rule kbd-echo-rule" }).getByLabel("Rule ID")).toHaveValue("kbd-echo-rule");
  await setCheck(page, page.getByRole("group", { name: "Templates sessions of this profile may use" }).getByLabel("kbd-echo"));
  await axe(page, "G-02 draft edited");
  await activate(page, page.getByRole("button", { name: "Validate", exact: true }));
  await expect(page.getByText(new RegExp(`Valid: revision ${rev}`))).toBeVisible();
  await activate(page, page.getByRole("button", { name: "Diff against the active revision" }));
  await expect(page.getByRole("table", { name: "Policy changes" })).toContainText("template_added");
  await activate(page, page.getByRole("button", { name: "Simulate" }));
  await expect(page.getByText(/replayed from the/)).toBeVisible();
  await axe(page, "G-02 validated, diffed and simulated");
  await activate(page, page.getByRole("button", { name: "Publish", exact: true }));
  await expect(page.getByRole("heading", { level: 1, name: `Policy revision ${rev}` })).toBeVisible();
  await axe(page, "G-02 published");
  await choose(page, page.getByLabel("Template"), "kbd-echo", "kbd-echo");
  await expect(page.getByRole("table", { name: "Effective permissions of kbd-echo" })).toContainText("ref/echo");
  await axe(page, "G-02 effective permissions");
  await navTo(page, "Policy studio", /Policy studio/);
  await activate(page, page.getByRole("table", { name: "Policy revisions" }).getByRole("link", { name: "r1", exact: true }));
  await expect(page.getByRole("heading", { level: 1, name: "Policy revision r1" })).toBeVisible();
  await activate(page, page.getByRole("button", { name: "Roll back to this revision" }));
  const dialog = page.getByRole("dialog", { name: "Roll back to r1" });
  await expect(dialog).toBeVisible();
  await axe(page, "G-02 roll back dialog");
  await activate(page, dialog.getByRole("button", { name: "Roll back" }));
  await expect(page.getByRole("table", { name: "Policy revisions" })).toContainText(/r1-rb\d+/);
  await axe(page, "G-02 rolled back");
  console.log(`G-02 keyboard (${browserName}): ${states} states passed axe`);
});

test("G-02 filter workbench, G-03 and G-06 with the keyboard: run filters and publish both profiles", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-8.27", "FR-8.5", "FR-8.14");
  test.setTimeout(600_000);
  await startIn(page, browserName, "Policy studio", /Policy studio/);
  await activate(page, page.getByRole("link", { name: /Filter workbench/ }));
  await expect(page.getByRole("table", { name: "Rule sets" })).toContainText("pii");
  const filters = page.getByRole("group", { name: "Filters to run" });
  for (const id of ["size-limit", "output-schema", "content-type-gate", "secret-fingerprint", "unicode-control", "injection-marker", "delimit-untrusted"]) await setCheck(page, filters.getByLabel(id), false);
  await typeInto(page, page.getByLabel("Result text"), "Write to jane@example.com about it.");
  await axe(page, "filters set");
  await activate(page, page.getByRole("button", { name: "Run filters" }));
  await expect(page.getByRole("table", { name: "Filter runs" })).toContainText("pii-detect");
  await axe(page, "filters run");

  await navTo(page, "Audit profile tuning", "Audit profile tuning");
  await axe(page, "G-03 loaded");
  await typeInto(page, page.getByLabel(/Observation retention/), "744h");
  const ap = page.getByRole("form", { name: "Publish the Audit Profile" });
  await typeInto(page, ap.getByLabel(/Reason for this revision/), "keyboard test");
  await activate(page, ap.getByRole("button", { name: "Publish the Audit Profile" }));
  await expect(page.getByText(/Published Audit Profile revision \d+\. It applies at once/)).toBeVisible();
  await axe(page, "G-03 published");

  await navTo(page, "Anomaly response", "Anomaly response");
  await axe(page, "G-06 loaded");
  await choose(page, page.getByLabel("elevated action"), "Record and alert", "alert");
  await choose(page, page.getByLabel("abnormal action"), "Alert and escalate", "escalate");
  await choose(page, page.getByLabel("critical action"), "Escalate and require", "approve");
  await expect(page.getByText(/require_approval_band = "critical"/)).toBeVisible();
  await axe(page, "G-06 bands chosen");
  await activate(page, page.getByRole("form", { name: "Publish the Anomaly Response Policy" }).getByRole("button", { name: "Publish the Anomaly Response Policy" }));
  await expect(page.getByText(/Published Anomaly Response Policy revision \d+/)).toBeVisible();
  await axe(page, "G-06 published");
  console.log(`G-02/G-03/G-06 keyboard (${browserName}): ${states} states passed axe`);
});

test("G-07, G-08 and G-14 with the keyboard: revision filter, memory budget, backup and an evidence event", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-8.15", "FR-8.16", "FR-8.22");
  test.setTimeout(600_000);
  await startIn(page, browserName, "Performance", "Performance");
  await axe(page, "G-07 loaded");
  const revSelect = page.getByRole("combobox", { name: "Policy revision" });
  const firstRev = await revSelect.locator("option").nth(1).getAttribute("value");
  if (firstRev) {
    await choose(page, revSelect, firstRev, firstRev);
    await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
    await axe(page, "G-07 one revision");
  }

  await navTo(page, "Data server and memory", "Data server and memory");
  await axe(page, "G-08 loaded");
  await typeInto(page, page.getByLabel(/Observation Store memory budget \(MiB\)/), "320");
  await activate(page, page.getByRole("form", { name: "Publish the memory budget" }).getByRole("button", { name: "Publish the memory budget" }));
  await expect(page.getByText(/Published memory budget revision \d+/)).toBeVisible();
  await axe(page, "G-08 budget published");
  await tabTo(page, page.getByLabel("Passphrase"));
  await page.keyboard.type("keyboard backup passphrase");
  await activate(page, page.getByRole("button", { name: "Take a backup now" }));
  await expect(page.getByText(/Backup written/)).toBeVisible({ timeout: 60_000 });
  await axe(page, "G-08 backup taken");

  await navTo(page, "Audit investigation", "Audit investigation");
  await axe(page, "G-14 loaded");
  await typeInto(page, page.getByLabel("Class"), "call");
  await activate(page, page.getByRole("button", { name: "Apply filter" }));
  const table = page.getByRole("table", { name: "Journal events" });
  await expect(table).toContainText("call");
  await axe(page, "G-14 filtered");
  await activate(page, table.getByRole("link").first());
  await expect(page.getByRole("heading", { level: 1, name: "Evidence event" })).toBeVisible();
  await axe(page, "G-14 event open");
  console.log(`G-07/G-08/G-14 keyboard (${browserName}): ${states} states passed axe`);
});

test("G-11 with the keyboard: credential, session suspend, resume and terminate, revoke, remote access and a registration", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-8.19", "FR-16.5");
  test.setTimeout(600_000);
  await startIn(page, browserName, "Sessions and principals", "Sessions and principals");
  const id = `kbd-g11-${browserName}-${Date.now() % 100000}`;
  const add = page.getByRole("form", { name: "Add a principal" });
  await typeInto(page, add.getByLabel("Principal ID"), id);
  await typeInto(page, add.getByLabel("Display name"), "Keyboard agent");
  await page.keyboard.press("Enter");
  await expect(page.getByText(`Created principal ${id}.`)).toBeVisible();
  const issue = page.getByRole("form", { name: "Issue a credential" });
  await choose(page, issue.getByLabel("Principal"), id, id);
  await activate(page, issue.getByRole("button", { name: "Issue credential" }));
  const issued = issue.getByRole("status");
  await expect(issued).toContainText("Issued client");
  const clientID = ((await issued.locator(".mono").first().textContent()) ?? "").trim();
  expect(clientID).toMatch(/^smcp-client-/);
  await axe(page, "G-11 credential issued");
  const r = await mcpCall(g, "ref_read_file", { path: "hello.txt" }, { expect: g.marker, clientID }).done;
  expect(r.code, r.out).toBe(0);
  const row = page.getByRole("table", { name: "Sessions" }).getByRole("row").filter({ hasText: clientID });
  await expect(row).toBeVisible({ timeout: 30_000 });
  await activate(page, row.getByRole("link").first());
  await expect(page.getByRole("heading", { level: 1, name: "Session" })).toBeVisible();
  await axe(page, "G-11 session open");
  await activate(page, page.getByRole("button", { name: "Suspend session" }));
  const sus = page.getByRole("dialog", { name: "Suspend this session" });
  await expect(sus).toBeVisible();
  await axe(page, "G-11 session suspend dialog");
  await activate(page, sus.getByRole("button", { name: "Suspend session" }));
  await expect(page.getByRole("definition").filter({ hasText: /^suspended$/ })).toBeVisible();
  await activate(page, page.getByRole("button", { name: "Resume session" }));
  await activate(page, page.getByRole("dialog", { name: "Resume this session" }).getByRole("button", { name: "Resume session" }));
  await expect(page.getByRole("definition").filter({ hasText: /^active$/ })).toBeVisible();
  await activate(page, page.getByRole("button", { name: "Terminate session" }));
  const term = page.getByRole("dialog", { name: "Terminate this session" });
  await typeInto(page, term.getByLabel(/Reason/), "keyboard test");
  await axe(page, "G-11 terminate dialog filled");
  await activate(page, term.getByRole("button", { name: "Terminate session" }));
  await expect(page.getByRole("definition").filter({ hasText: /^terminated$/ })).toBeVisible();
  await axe(page, "G-11 session terminated");
  await navTo(page, "Sessions and principals", "Sessions and principals");
  await activate(page, page.getByRole("button", { name: `Revoke ${clientID}` }));
  const rv = page.getByRole("dialog", { name: `Revoke credential ${clientID}` });
  await expect(rv).toBeVisible();
  await activate(page, rv.getByRole("button", { name: "Revoke credential" }));
  await expect(page.getByText(`Revoked credential ${clientID}.`)).toBeVisible();
  await axe(page, "G-11 credential revoked");

  // Remote access: enable and disable.
  await navTo(page, "Remote access", "Remote access");
  await axe(page, "G-11 remote loaded");
  await typeInto(page, page.getByLabel(/Public URL/), "https://gateway.example.ts.net");
  await activate(page, page.getByRole("button", { name: "Enable remote access" }));
  await expect(page.getByText("enabled: reachable from outside this machine")).toBeVisible();
  await axe(page, "G-11 remote enabled");
  await activate(page, page.getByRole("button", { name: "Disable", exact: true }));
  await expect(page.getByRole("definition").filter({ hasText: /^disabled$/ })).toBeVisible();
  // A pending registration needs a client on the tunnel; a fixture stands in.
  const pending = { client_id: "smcp-dcr-kbd", client_name: "Keyboard agent", status: "pending", registration: "dynamic", redirect_uris: ["https://agent.example/cb"], registered_at: new Date().toISOString(), source_address: "203.0.113.7" };
  await mock(page, "**/api/v1/clients", { clients: [pending] });
  let approved: unknown = null;
  await page.route("**/api/v1/clients/smcp-dcr-kbd/approve", async (rt) => {
    approved = rt.request().postDataJSON();
    await rt.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ...pending, status: "approved", principal: "claude-code-local" }) });
  });
  await navTo(page, "Gateway control", "Gateway control");
  await navTo(page, "Remote access", "Remote access");
  await activate(page, page.getByRole("table", { name: "Client registrations" }).getByRole("button", { name: "Approve" }));
  const dialog = page.getByRole("dialog", { name: "Approve Keyboard agent" });
  await expect(dialog).toBeVisible();
  await choose(page, dialog.getByRole("combobox", { name: "Principal" }), "claude-code-local", "claude-code-local");
  await axe(page, "G-11 registration approve dialog");
  await activate(page, dialog.getByRole("button", { name: "Approve" }));
  await expect(page.getByText("Keyboard agent is approved and bound to claude-code-local.")).toBeVisible();
  expect(approved).toEqual({ principal: "claude-code-local" });
  await axe(page, "G-11 registration approved");
  console.log(`G-11 keyboard (${browserName}): ${states} states passed axe`);
});

test("G-10 with the keyboard: retire a second revision, server suspend dialog, package detail; Egress filter", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-8.18");
  test.setTimeout(600_000);
  // A second, signed revision of the reference server for the retire action.
  const ctl = join(bin, "smcpctl");
  const prefix = join(work, `kbd-rev-${browserName}-${Date.now()}`);
  execFileSync(ctl, ["package", "keygen", "--out", prefix, "--unencrypted"]);
  const refserver = join(bin, "smcp-refserver");
  const sha = createHash("sha256").update(readFileSync(refserver)).digest("hex");
  const rev = "98.0.0-kbd";
  const recipe = {
    recipe_version: 1,
    server: { id: "smcp-ref-filesystem", alias: "ref", publisher: "Secure MCP Gateway project", description: "Second revision of the reference server for the keyboard retire test.", revision: rev },
    artifact: { type: "binary", reference: refserver, version: rev, sha256: sha },
    launch: { runtime: "native", argv: ["smcp-refserver", "--root", "{root}"] },
    risk_class: "low",
    instance_scope: ["shared"],
    tools: { default: { side_effect: "read", source_trust: "trusted" }, expect: ["echo", "time_now", "list_files", "read_file"] },
    capabilities: { filesystem: [{ slot: "root", mode: "ro", argv_placeholder: "{root}" }], egress: [] },
    licenses: ["Apache-2.0"],
    operator_note: "Keyboard acceptance test package.",
    source: { kind: "archive", uri: "file://" + refserver, sha256: sha },
  };
  writeFileSync(prefix + "-recipe.json", JSON.stringify(recipe));
  execFileSync(ctl, ["package", "build", "--recipe", prefix + "-recipe.json", "--out", prefix + "-pkg"]);
  execFileSync(ctl, ["package", "sign", prefix + "-pkg", "--key", prefix + ".key"]);

  await startIn(page, browserName, "Servers and library", "Servers and library");
  await activate(page, page.getByRole("link", { name: "Library and trust anchors" }));
  await expect(page.getByRole("heading", { level: 1, name: "Library and trust anchors" })).toBeVisible();
  // Enroll the publisher key with the keyboard, then install through the running Gateway.
  await activate(page, page.locator("summary", { hasText: "Enroll a trust anchor" }));
  const ef = page.getByRole("form", { name: "Enroll a trust anchor" });
  await typeInto(page, ef.getByLabel("Anchor name"), "kbd-rev");
  await page.keyboard.press("Tab");
  await page.keyboard.type(readFileSync(prefix + ".pub", "utf8").trim());
  await activate(page, ef.getByRole("button", { name: "Show fingerprint" }));
  await setCheck(page, ef.getByLabel("The key ID matches the publisher's"));
  await activate(page, ef.getByRole("button", { name: "Enroll anchor" }));
  await expect(page.getByRole("table", { name: "Trust anchors" })).toContainText("kbd-rev");
  execFileSync(ctl, ["package", "install", prefix + "-pkg", "--config", g.config]);
  await navTo(page, "Servers and library", "Servers and library");
  await activate(page, page.getByRole("link", { name: "Library and trust anchors" }));
  const revs = page.getByRole("table", { name: "Package revisions" });
  const second = revs.getByRole("row").filter({ hasText: rev });
  await expect(second).toContainText("verified-disabled", { timeout: 20_000 });
  await axe(page, "G-10 second revision installed");
  await activate(page, second.getByRole("button", { name: `Retire smcp-ref-filesystem ${rev}` }));
  const dialog = page.getByRole("dialog", { name: `Retire smcp-ref-filesystem ${rev}` });
  await typeInto(page, dialog.getByLabel("Reason (optional, recorded)"), "keyboard test revision");
  await axe(page, "G-10 retire dialog filled");
  await activate(page, dialog.getByRole("button", { name: "Retire" }));
  await expect(page.getByText(`Retired smcp-ref-filesystem ${rev}. This cannot be undone.`)).toBeVisible();
  await expect(second).toContainText("retired");
  await axe(page, "G-10 retired");
  // Suspending the running server would stop it for the rest of the suite
  // (enable needs a restart): the dialog opens and Escape cancels it.
  await activate(page, revs.getByRole("button", { name: "Suspend" }));
  const sd = page.getByRole("dialog", { name: /Suspend smcp-ref-filesystem/ });
  await expect(sd).toBeVisible();
  await axe(page, "G-10 suspend dialog");
  await page.keyboard.press("Escape");
  await expect(sd).toBeHidden();
  await expect(revs.getByRole("row").filter({ hasText: "enabled" })).toHaveCount(1);
  await activate(page, page.getByRole("button", { name: "Remove kbd-rev" }));
  await expect(page.getByRole("table", { name: "Trust anchors" })).not.toContainText("kbd-rev");
  await activate(page, revs.getByRole("row").filter({ hasText: "enabled" }).getByRole("link", { name: "smcp-ref-filesystem" }));
  await expect(page.getByRole("heading", { level: 1, name: "Package smcp-ref-filesystem" })).toBeVisible();
  await axe(page, "G-10 package detail");

  await navTo(page, "Egress", "Egress");
  await choose(page, page.getByLabel("Decision"), "denied", "denied");
  await activate(page, page.getByRole("button", { name: "Apply filter" }));
  await expect(page.getByText(/No egress operation matches/)).toBeVisible();
  await axe(page, "Egress filtered");
  console.log(`G-10/Egress keyboard (${browserName}): ${states} states passed axe`);
});

// Actions no other acceptance test performed (FR-8.33): G-08 key rotation
// and graph rebuild, G-14 journal export downloads, Runtime instance kill,
// and, on a dedicated Gateway so that the shared one keeps its server and
// its health, G-10 suspend and enable of the running server and the G-01
// acknowledgment of a latched integrity cause.

function keysStatus(config: string): { listener_certificate: { serial: string }; evidence_public_key: string } {
  return JSON.parse(execFileSync(join(bin, "smcpctl"), ["keys", "status", "--config", config], { encoding: "utf8" })) as { listener_certificate: { serial: string }; evidence_public_key: string };
}

test("G-08 key rotation and graph rebuild, G-14 journal exports, with the keyboard", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-8.16", "FR-8.22");
  test.setTimeout(300_000);
  await startIn(page, browserName, "Data server and memory", "Data server and memory");
  const before = keysStatus(g.config);
  await activate(page, page.getByRole("button", { name: "Rotate the listener certificate" }));
  await expect(page.getByText("Rotated: tls.")).toBeVisible();
  await axe(page, "G-08 listener certificate rotated");
  await fromTop(page);
  await activate(page, page.getByRole("button", { name: "Rotate the evidence key" }));
  await expect(page.getByText("Rotated: evidence.")).toBeVisible();
  await axe(page, "G-08 evidence key rotated");
  const after = keysStatus(g.config);
  expect(after.listener_certificate.serial).not.toBe(before.listener_certificate.serial);
  expect(after.evidence_public_key).not.toBe(before.evidence_public_key);
  // A harness still connects with the same CA after the listener rotation.
  const r = await mcpCall(g, "ref_read_file", { path: "hello.txt" }, { expect: g.marker, timeout: "60s" }).done;
  expect(r.code, r.out).toBe(0);

  // The acceptance Gateway runs without a graph database: the real rebuild
  // request is refused with the API's reason. The accepted case is then
  // shown with the control API's 202 answer mocked. An action that reloads
  // its section can leave focus on the page body (WebKit); each walk then
  // starts from the top, as a person would.
  await fromTop(page);
  await activate(page, page.getByRole("button", { name: "Rebuild from the journal" }));
  const refused = page.getByRole("alert").filter({ hasText: "Could not complete the rebuild." });
  await expect(refused).toContainText("the graph mirror is disabled");
  await expect(refused).toContainText("graph_disabled");
  await axe(page, "G-08 rebuild refused");
  await page.route("**/api/v1/graph/rebuild", (rt) => rt.fulfill({ status: 202, contentType: "application/json", body: JSON.stringify({ status: "queued" }) }));
  await fromTop(page);
  await activate(page, page.getByRole("button", { name: "Rebuild from the journal" }));
  await expect(page.getByText("A rebuild is queued.")).toBeVisible();
  await axe(page, "G-08 rebuild queued (mocked)");
  await page.unroute("**/api/v1/graph/rebuild");

  await navTo(page, "Audit investigation", "Audit investigation");
  for (const [button, ext] of [
    ["Export CSV", "csv"],
    ["Export JSON Lines", "jsonl"],
  ] as const) {
    const dl = page.waitForEvent("download");
    await fromTop(page);
    await activate(page, page.getByRole("button", { name: button }));
    const d = await dl;
    expect(d.suggestedFilename()).toMatch(new RegExp(`\\.${ext}$`));
    const lines = readFileSync(await d.path(), "utf8").trim().split("\n");
    expect(lines.length).toBeGreaterThan(1);
    if (ext === "csv") expect(lines[0]).toContain("event_id");
    else expect(JSON.parse(lines[0]!)).toHaveProperty("event_id");
    await axe(page, `G-14 ${button} downloaded`);
  }
  console.log(`G-08/G-14 keyboard (${browserName}): ${states} states passed axe`);
});

test("Runtime instance kill with the keyboard (instance table mocked: the acceptance Gateway runs no sandboxed instance)", async ({ page, browserName }) => {
  claims("FR-8.33", "FR-8.32");
  test.setTimeout(300_000);
  const id = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
  let state = "running";
  let killed: { reason?: string } | null = null;
  const instance = () => ({
    instance_id: id,
    alias: "ref",
    container: "smcp-ref-0f1e2d3c",
    state,
    removed: false,
    scope: "shared",
    started: "2026-10-17T12:00:00Z",
    ...(state === "killed" ? { ended: "2026-10-17T12:05:00Z", kill_reason: killed?.reason } : {}),
    oom_killed: false,
    deviations: 0,
  });
  await page.route(
    (u) => u.pathname.startsWith("/api/v1/runtime/instances"),
    async (rt) => {
      const p = new URL(rt.request().url()).pathname;
      if (rt.request().method() === "POST" && p === `/api/v1/runtime/instances/${id}/kill`) {
        killed = rt.request().postDataJSON() as { reason?: string };
        state = "killed";
        return rt.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ state }) });
      }
      if (p === `/api/v1/runtime/instances/${id}`) return rt.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ instance: instance(), stderr_tail: "" }) });
      if (p === "/api/v1/runtime/instances") return rt.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ instances: [instance()] }) });
      return rt.continue();
    },
  );
  await startIn(page, browserName, "Runtime", "Runtime");
  await activate(page, page.getByRole("table", { name: "Server instances" }).getByRole("link").first());
  await expect(page.getByRole("heading", { level: 1, name: "Server instance" })).toBeVisible();
  await axe(page, "Runtime instance open");
  await activate(page, page.getByRole("button", { name: "Kill this instance" }));
  const dialog = page.getByRole("dialog", { name: "Kill this instance" });
  await expect(dialog).toBeVisible();
  await typeInto(page, dialog.getByLabel(/Reason/), "keyboard kill test");
  await axe(page, "Runtime kill dialog filled");
  await activate(page, dialog.getByRole("button", { name: "Kill", exact: true }));
  await expect(page.getByText("The instance was killed.")).toBeVisible();
  expect(killed).toEqual({ reason: "keyboard kill test" });
  await expect(page.getByRole("definition").filter({ hasText: /^killed$/ })).toBeVisible();
  await axe(page, "Runtime instance killed");
  console.log(`Runtime keyboard (${browserName}): ${states} states passed axe`);
});

test("G-10 suspend and enable of the running server and G-01 health acknowledgment with the keyboard, on a dedicated Gateway", async ({ browser, browserName }) => {
  claims("FR-8.33", "FR-8.32", "FR-8.18", "FR-8.3");
  test.setTimeout(600_000);
  const d = await startDedicated(`kbd-dedicated-${browserName}`);
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  try {
    const page = await context.newPage();
    tabKey = browserName === "webkit" ? "Alt+Tab" : "Tab";
    states = 0;
    await page.emulateMedia({ reducedMotion: "reduce" });
    const signInKbd = async () => {
      await page.goto(d.adminURL + "/");
      await tabTo(page, page.getByLabel("Password"));
      await page.keyboard.type(d.adminPassword);
      await page.keyboard.press("Enter");
      await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
      await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
    };
    await signInKbd();
    let r = await mcpCall(d, "ref_read_file", { path: "hello.txt" }, { expect: d.marker, timeout: "60s" }).done;
    expect(r.code, r.out).toBe(0);

    // G-10: suspend the running server.
    await navTo(page, "Servers and library", "Servers and library");
    await activate(page, page.getByRole("link", { name: "Library and trust anchors" }));
    const revs = page.getByRole("table", { name: "Package revisions" });
    await expect(revs.getByRole("row").filter({ hasText: "enabled" })).toHaveCount(1);
    await activate(page, revs.getByRole("button", { name: /^Suspend smcp-ref-filesystem / }));
    const sd = page.getByRole("dialog", { name: /^Suspend smcp-ref-filesystem / });
    await typeInto(page, sd.getByLabel("Reason (optional, recorded)"), "keyboard suspend test");
    await axe(page, "G-10 suspend dialog filled");
    await activate(page, sd.getByRole("button", { name: "Suspend", exact: true }));
    await expect(page.getByText(/^Suspended smcp-ref-filesystem .*A running instance was stopped and its tools left the catalog\.$/)).toBeVisible();
    await expect(revs.getByRole("row").filter({ hasText: "verified-disabled" })).toHaveCount(1);
    await axe(page, "G-10 suspended");
    r = await mcpCall(d, "ref_read_file", { path: "hello.txt" }, { expect: d.marker, timeout: "60s" }).done;
    expect(r.code).not.toBe(0);
    expect(r.out).toContain("empty tool catalog");

    // G-10: enable it again; servers are launched at start, so smcpd restarts.
    await fromTop(page);
    await activate(page, revs.getByRole("button", { name: /^Enable smcp-ref-filesystem / }));
    const ed = page.getByRole("dialog", { name: /^Enable smcp-ref-filesystem / });
    await expect(ed).toBeVisible();
    await axe(page, "G-10 enable dialog");
    await activate(page, ed.getByRole("button", { name: "Enable", exact: true }));
    await expect(page.getByText(/^Enabled smcp-ref-filesystem .* as ref\./)).toBeVisible();
    await expect(revs.getByRole("row").filter({ hasText: "enabled" })).toHaveCount(1);
    await axe(page, "G-10 enabled");
    await d.restart();
    r = await mcpCall(d, "ref_read_file", { path: "hello.txt" }, { expect: d.marker, timeout: "60s" }).done;
    expect(r.code, r.out).toBe(0);

    // G-01: an unreadable CA bundle latches trust_anchor_invalid, an
    // integrity cause that needs an acknowledgment (FR-7.13). The check runs
    // every 30 s.
    // Console sessions are held in memory and ended with the restart.
    await signInKbd();
    const caFile = join(d.dir, "state", "tls", "ca.crt");
    const ca = readFileSync(caFile);
    writeFileSync(caFile, "not a certificate\n");
    const ack = page.getByRole("button", { name: "Acknowledge trust_anchor_invalid" });
    try {
      for (let i = 0; i < 18 && !(await ack.isVisible()); i++) {
        await page.waitForTimeout(5_000);
        await page.reload();
        await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
        await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
      }
    } finally {
      writeFileSync(caFile, ca);
    }
    await expect(ack).toBeVisible();
    await axe(page, "G-01 integrity cause latched");
    await fromTop(page);
    await activate(page, ack);
    await expect(ack).toHaveCount(0);
    await expect(page.getByRole("table", { name: "Health monitor causes" }).getByRole("row").filter({ hasText: "trust_anchor_invalid" })).toContainText("admin");
    await axe(page, "G-01 cause acknowledged");
    // With the bundle restored and the acknowledgment given, the latch is
    // released once the cause has been clear for 10 s.
    await expect
      .poll(
        () => {
          try {
            execFileSync(join(bin, "smcpctl"), ["health", "--require-not-fail-closed", "--config", d.config], { stdio: "ignore" });
            return "not fail-closed";
          } catch {
            return "fail-closed";
          }
        },
        { timeout: 90_000, intervals: [2_000] },
      )
      .toBe("not fail-closed");
    console.log(`G-10/G-01 dedicated keyboard (${browserName}): ${states} states passed axe`);
  } finally {
    await context.close();
    d.stop();
  }
});
