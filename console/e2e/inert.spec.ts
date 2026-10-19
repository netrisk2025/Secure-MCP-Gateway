// SR-3.3-1 and SR-6.17-1: server metadata and evidence are untrusted
// content. Every GET response of the control API (except the sign-in
// session, which carries the route permissions) is rewritten so that each
// string value ends in HTML and script; every view must show that text
// literally and run none of it. A second test checks the 256 KiB page bound
// of G-10's evidence display with a manifest and a provenance statement of
// 1 MiB each.
import { expect, test, type Page } from "@playwright/test";
import { claims, g, go, signIn } from "./helpers";

const HOSTILE = `<img src=x data-xss onerror="window.__smcpXSS=1"><script data-xss>window.__smcpXSS=1</script><a data-xss href="javascript:window.__smcpXSS=1">x</a>`;
const iso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

const paths = [
  "/",
  "/sessions",
  "/servers",
  "/servers/ref",
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
  "/policy/draft",
  "/policy/filters",
  "/policy/secret-use",
  "/audit/graph",
];

function poison(v: unknown): unknown {
  if (typeof v === "string") return v === "" || iso.test(v) ? v : v + HOSTILE;
  if (Array.isArray(v)) return v.map(poison);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, poison(x)]));
  return v;
}

async function poisonResponses(page: Page) {
  await page.route("**/api/v1/**", async (route) => {
    const u = new URL(route.request().url());
    if (route.request().method() !== "GET" || u.pathname.startsWith("/api/v1/console/") || /stream|watch/.test(u.pathname)) return route.continue();
    // Links built from rewritten IDs name the real object without the suffix.
    const clean = route.request().url().split(encodeURIComponent(HOSTILE)).join("");
    const r = await route.fetch({ url: clean });
    const ct = r.headers()["content-type"] ?? "";
    if (!ct.includes("application/json")) return route.fulfill({ response: r });
    let body: unknown;
    try {
      body = await r.json();
    } catch {
      return route.fulfill({ response: r });
    }
    return route.fulfill({ response: r, body: JSON.stringify(poison(body)) });
  });
}

async function inert(page: Page, where: string) {
  const state = await page.evaluate(() => ({
    ran: (window as unknown as { __smcpXSS?: number }).__smcpXSS ?? 0,
    injected: document.querySelectorAll("[data-xss]").length,
    scripts: [...document.scripts].filter((s) => !s.src).length,
    shown: [...document.querySelectorAll("body *")].filter((e) => [...e.childNodes].some((n) => n.nodeType === 3 && (n.textContent ?? "").includes("<script data-xss>"))).length,
  }));
  expect(state.ran, `${where}: hostile script ran`).toBe(0);
  expect(state.injected, `${where}: hostile markup became elements`).toBe(0);
  expect(state.scripts, `${where}: inline script elements`).toBe(0);
  return state.shown;
}

test("hostile strings in server metadata and evidence are shown as inert text in every view", async ({ page }) => {
  claims("SR-3.3-1", "SR-6.17-1");
  // Acceptance scenario AT-07 (with the bound test below), claimed in the
  // profile the Gateway reports (Enforced with SMCP_E2E_PROFILE=enforced).
  test.info().annotations.push({ type: "scenario", description: `AT-07 profile=${g.profile || "standalone"}` });
  test.setTimeout(300_000);
  const dialogs: string[] = [];
  page.on("dialog", (d) => {
    dialogs.push(d.message());
    void d.dismiss();
  });
  await signIn(page, "/");
  await poisonResponses(page);
  const literal: Record<string, number> = {};
  for (const p of paths) {
    await go(page, p);
    await expect(page.locator("main h1")).toBeVisible();
    await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
    literal[p] = await inert(page, p);
  }
  // The package detail of G-10 (manifest, provenance and attestation fields).
  await go(page, "/library");
  await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
  await page.getByRole("table", { name: "Package revisions" }).getByRole("link").first().click();
  await expect(page.getByRole("heading", { name: /^Signed manifest/ })).toBeVisible();
  literal["/library/{id}/{rev}"] = await inert(page, "package detail");
  expect(dialogs).toEqual([]);
  // Server-supplied text reached the page literally in the views that show
  // server metadata and evidence.
  for (const p of ["/servers", "/servers/ref", "/catalog", "/library", "/library/{id}/{rev}", "/audit", "/sessions"]) {
    expect(literal[p], `${p} shows no server text`).toBeGreaterThan(0);
  }
});

test("G-10 bounds evidence text to 256 KiB per page", async ({ page }) => {
  // The whole of SR-3.3-1: G-10 evidence with HTML, script and very large
  // files is rendered inert and bounded.
  test.info().annotations.push({ type: "requirement", description: "SR-3.3-1" });
  test.info().annotations.push({ type: "scenario", description: `AT-07 profile=${g.profile || "standalone"}` });
  const big = (n: number) => (HOSTILE + "é漢").repeat(Math.ceil(n / (HOSTILE.length + 5))).slice(0, n);
  await signIn(page, "/library");
  await page.route("**/api/v1/packages/big-pkg/1.0.0", (r) =>
    r.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        revision: {
          server_id: "big-pkg",
          revision: "1.0.0",
          state: "verified-disabled",
          alias: "big",
          risk_class: "low",
          artifact_type: "binary",
          artifact_sha256: "0".repeat(64),
          manifest_sha256: "1".repeat(64),
          signer_key_id: "7B3357B76507695D",
          anchor: HOSTILE,
          imported_at: "2026-10-17T00:00:00Z",
          expires: "2027-10-17T00:00:00Z",
          state_changed_at: "2026-10-17T00:00:00Z",
          tools: [HOSTILE],
        },
        manifest: { server: { description: big(1024 * 1024) }, licenses: [big(64 * 1024)] },
        provenance: { sbom: big(1024 * 1024) },
      }),
    }),
  );
  await go(page, "/library/big-pkg/1.0.0");
  await expect(page.getByRole("heading", { name: /^Signed manifest/ })).toBeVisible();
  const shown = await page.evaluate(() => [...document.querySelectorAll("figure.json pre")].reduce((n, e) => n + new TextEncoder().encode(e.textContent ?? "").length, 0));
  expect(shown).toBeLessThanOrEqual(256 * 1024);
  expect(shown).toBeGreaterThan(250 * 1024);
  await expect(page.getByText(/Shown: the first 256 KiB of \d+ KiB/)).toBeVisible();
  await inert(page, "large package detail");
});
