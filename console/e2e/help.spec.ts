// FR-8.25 inline help: every view has its help entry, every field of the
// policy document (internal/policy/policy.schema.json) has help in G-02,
// and every form field of the G-02 draft editor is described by its help
// text. Help is part of the embedded console bundle: the test also records
// that no help text is fetched from another origin.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";
import { repoRoot } from "./gateway";
import { claims, g, go, signIn } from "./helpers";

const views = [
  "/",
  "/sessions",
  "/servers",
  "/catalog",
  "/approvals",
  "/audit",
  "/policy",
  "/secrets",
  "/observations",
  "/analytics",
  "/performance",
  "/data-server",
  "/research",
  "/audit-profiles",
  "/anomaly-response",
  "/egress",
  "/runtime",
  "/remote",
  "/library",
];

/** Field paths of the policy schema, "[]" for map values and list items. */
function schemaFields(): string[] {
  const schema = JSON.parse(readFileSync(join(repoRoot, "internal", "policy", "policy.schema.json"), "utf8")) as Record<string, unknown>;
  const out: string[] = [];
  const walk = (n: unknown, path: string) => {
    if (!n || typeof n !== "object") return;
    const o = n as Record<string, unknown>;
    if (o.properties && typeof o.properties === "object") {
      for (const [k, v] of Object.entries(o.properties as Record<string, unknown>)) {
        const p = path ? `${path}.${k}` : k;
        out.push(p);
        walk(v, p);
      }
    }
    for (const k of ["items", "additionalProperties"]) if (o[k] && typeof o[k] === "object") walk(o[k], path + "[]");
  };
  walk(schema, "");
  return out;
}

test("every view, policy field and draft form field has inline help", async ({ page }) => {
  claims("FR-8.25");
  const foreign: string[] = [];
  page.on("request", (r) => {
    if (!r.url().startsWith(g.adminURL) && !r.url().startsWith("data:")) foreign.push(r.url());
  });
  await signIn(page, "/");
  for (const v of views) {
    await go(page, v);
    await expect(page.locator("main h1")).toBeVisible();
    const help = page.locator("details.help");
    await expect(help, `${v} has no help entry`).toHaveCount(1);
    await help.locator("summary").click();
    expect(((await help.locator(".help-body").textContent()) ?? "").trim().length, `${v} help is empty`).toBeGreaterThan(40);
  }

  await go(page, "/policy/draft");
  await expect(page.getByRole("heading", { name: "Session Allow templates" })).toBeVisible();
  // Every schema field is in the field reference with its text.
  const fields = schemaFields();
  expect(fields.length).toBeGreaterThan(30);
  await page.getByText("Help for every policy field").click();
  const ref = page.getByTestId("policy-field-help");
  const listed = await ref.locator("dt").allTextContents();
  expect(listed.map((s) => s.trim()).sort()).toEqual([...fields].sort());
  for (const d of await ref.locator("dd").allTextContents()) expect(d.trim().length).toBeGreaterThan(20);

  // Every control of the template and profile editors and the document
  // section is described by help text.
  const missing = await page.evaluate(() => {
    const out: string[] = [];
    const scope = [...document.querySelectorAll("details.editor[open] .editor-body, main section")].filter((s) => !s.closest("details:not([open])"));
    const seen = new Set<Element>();
    for (const s of scope) {
      for (const el of s.querySelectorAll("input, select, fieldset.checklist")) {
        if (seen.has(el) || el.closest("details:not([open])") || el.closest(".filter-actions")) continue;
        seen.add(el);
        if (el instanceof HTMLInputElement && el.closest("fieldset.checklist")) continue; // described by its fieldset
        const ids = (el.getAttribute("aria-describedby") ?? "").split(/\s+/).filter(Boolean);
        const text = ids.map((id) => document.getElementById(id)?.textContent ?? "").join(" ").trim();
        if (text.length < 20) {
          const label = el.id ? document.querySelector(`label[for="${el.id}"]`)?.textContent : el.closest("label")?.textContent ?? el.querySelector("legend")?.textContent;
          out.push(`${el.tagName.toLowerCase()} "${(label ?? "").trim()}"`);
        }
      }
    }
    return { out, count: seen.size };
  });
  expect(missing.out).toEqual([]);
  expect(missing.count).toBeGreaterThan(15);
  expect(foreign).toEqual([]);
});
