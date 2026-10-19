// Decides one held tool call from the Approvals view (G-13) in a real
// browser, as a person would: signs in as the Administrator, waits for the
// pending approval of the named tool to appear in the live list, opens it,
// records a comment and presses "Approve this call" or "Deny this call".
// Used by the FR-3.25 real-harness approval run (scripts/agents
// -approval-acceptance); not a Playwright test file.
//
// Usage: node e2e/approve-held.mjs <console URL> <admin password file> <public tool name> <approve|deny> [comment]
// Prints one JSON line: {"approvalId", "decision", "status", "state"}.
import { readFileSync } from "node:fs";
import { chromium } from "@playwright/test";

const [url, pwFile, tool, decision, comment = "FR-3.25 real-harness approval run"] = process.argv.slice(2);
if (!url || !pwFile || !tool || !["approve", "deny"].includes(decision)) {
  console.error("usage: node e2e/approve-held.mjs <console URL> <admin password file> <public tool name> <approve|deny> [comment]");
  process.exit(2);
}
const password = readFileSync(pwFile, "utf8").trim();
const browser = await chromium.launch();
try {
  const page = await browser.newPage({ ignoreHTTPSErrors: true });
  await page.goto(url + "/approvals");
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByRole("heading", { level: 1, name: "Approvals" }).waitFor();
  // The pending list updates from the live stream; no reload.
  const row = page.getByRole("table", { name: "Approvals: pending" }).getByRole("link", { name: tool });
  await row.first().waitFor({ timeout: 170_000 });
  await row.first().click();
  await page.getByRole("heading", { level: 1, name: "Approval" }).waitFor();
  const approvalId = new URL(page.url()).pathname.split("/").pop();
  await page.getByLabel(/Comment/).fill(comment);
  await page.getByRole("button", { name: decision === "approve" ? "Approve this call" : "Deny this call" }).click();
  const status = page.getByRole("status").filter({ hasText: decision === "approve" ? "Approved." : "Denied." });
  await status.waitFor({ timeout: 20_000 });
  const state = page.getByRole("definition").filter({ hasText: /^(approved|consumed|denied)$/ });
  await state.first().waitFor({ timeout: 20_000 });
  console.log(JSON.stringify({ approvalId, decision, status: (await status.innerText()).trim(), state: (await state.first().innerText()).trim() }));
} finally {
  await browser.close();
}
