// FR-8.29: every view G-01 to G-14 (and the Egress and Runtime views) shows
// a loading state within 200 ms of navigation, an empty state that names the
// action that would populate it, and an error state with the control API's
// message, its reason code and a Retry action. The verification statement:
// run each view against an empty installation (a freshly bootstrapped
// Gateway), a delayed API and a failing API.
import { expect, test, type Browser, type Page, type Route } from "@playwright/test";
import { startDedicated } from "./gateway";
import { go, signIn } from "./helpers";

/** One entry per view of the navigation, by its G number. */
const views: { code: string; path: string; title: RegExp }[] = [
  { code: "G-01", path: "/", title: /^Gateway control$/ },
  { code: "G-02", path: "/policy", title: /^Policy studio$/ },
  { code: "G-03", path: "/audit-profiles", title: /^Audit profile tuning$/ },
  { code: "G-04", path: "/observations", title: /^Observation workbench$/ },
  { code: "G-05", path: "/analytics", title: /^Behavior analytics$/ },
  { code: "G-06", path: "/anomaly-response", title: /^Anomaly response$/ },
  { code: "G-07", path: "/performance", title: /^Performance$/ },
  { code: "G-08", path: "/data-server", title: /^Data server and memory$/ },
  { code: "G-09", path: "/research", title: /^Research campaigns$/ },
  { code: "G-10", path: "/servers", title: /^Servers and library$/ },
  { code: "G-10 library", path: "/library", title: /^Library and trust anchors$/ },
  { code: "G-11", path: "/sessions", title: /^Sessions and principals$/ },
  { code: "G-11 remote", path: "/remote", title: /^Remote access$/ },
  { code: "G-12", path: "/secrets", title: /^Secrets$/ },
  { code: "G-13", path: "/approvals", title: /^Approvals$/ },
  { code: "G-14", path: "/audit", title: /^Audit investigation$/ },
  { code: "Egress", path: "/egress", title: /^Egress$/ },
  { code: "Runtime", path: "/runtime", title: /^Runtime$/ },
];

// Routes the console shell itself needs to stay signed in, and the live
// channels: never delayed or failed.
const shell = (u: URL) => u.pathname.startsWith("/api/v1/console/") || /\/(stream|watch)$/.test(u.pathname) || u.pathname === "/admin/v1/health";
const api = (u: URL) => u.pathname.startsWith("/api/v1/") || u.pathname.startsWith("/admin/v1/");

/** Starts at G-01 with nothing pending, so the next navigation is the one measured. */
async function settle(page: Page) {
  await expect(page.locator("main .loading")).toHaveCount(0, { timeout: 20_000 });
}

test("loading, empty and error states of every view: delayed API, empty installation, failing API", async ({ page, browser }) => {
  test.setTimeout(600_000);
  await test.step("loading state within 200 ms of navigation, with a delayed control API", () => loadingStates(page));
  await test.step("error state with the message, the reason code and Retry, with a failing control API", () => errorStates(page));
  await test.step("empty states name the action that populates them, on a freshly bootstrapped Gateway", () => emptyStates(browser));
  // FR-8.29 in full: the three states of every view in one run.
  test.info().annotations.push({ type: "requirement", description: "FR-8.29" });
});

async function loadingStates(page: Page) {
  await signIn(page, "/");
  await settle(page);
  let delay = false;
  await page.route(
    (u) => api(u) && !shell(u),
    async (r: Route) => {
      if (delay && r.request().method() === "GET") await new Promise((ok) => setTimeout(ok, 1_500));
      await r.continue().catch(() => undefined);
    },
  );
  for (const v of views) {
    // From a neutral page whose data is loaded, without delay.
    delay = false;
    await go(page, v.path === "/" ? "/approvals" : "/");
    await settle(page);
    delay = true;
    // Navigate in the page and time the first loading element in the view.
    const ms = await page.evaluate(async (to) => {
      const main = document.querySelector("main")!;
      const t0 = performance.now();
      const seen = new Promise<number>((ok) => {
        const check = () => (main.querySelector(".loading") ? (ok(performance.now() - t0), true) : false);
        const mo = new MutationObserver(() => {
          if (check()) mo.disconnect();
        });
        mo.observe(main, { childList: true, subtree: true, characterData: true });
        setTimeout(() => ok(Infinity), 2_000);
      });
      history.pushState(null, "", to);
      dispatchEvent(new PopStateEvent("popstate"));
      return seen;
    }, v.path);
    expect(ms, `${v.code} ${v.path}: loading state after ${ms} ms`).toBeLessThan(200);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(v.title);
    await expect(page.locator("main .loading").first()).toBeVisible();
    await expect(page.locator("main .loading").first()).toHaveAttribute("role", "status");
    delay = false;
    await settle(page);
  }
  await page.unrouteAll({ behavior: "ignoreErrors" });
}

async function errorStates(page: Page) {
  await signIn(page, "/");
  await settle(page);
  let fail = false;
  await page.route(
    (u) => api(u) && !shell(u),
    async (r: Route) => {
      if (fail && r.request().method() === "GET") {
        const u = new URL(r.request().url());
        return r.fulfill({
          status: 500,
          contentType: "application/json",
          body: JSON.stringify({ error: { code: "e2e_injected", message: `injected failure of ${u.pathname}` } }),
        });
      }
      await r.continue().catch(() => undefined);
    },
  );
  for (const v of views) {
    fail = false;
    await go(page, v.path === "/" ? "/approvals" : "/");
    await settle(page);
    fail = true;
    await go(page, v.path);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(v.title);
    const alerts = page.locator("main").getByRole("alert");
    await expect(alerts.first(), `${v.code}: error state`).toBeVisible();
    const first = alerts.first();
    await expect(first).toContainText(/injected failure of \/(api|admin)\/v1\//);
    await expect(first).toContainText("HTTP 500");
    await expect(first).toContainText("reason e2e_injected");
    await expect(first.getByRole("button", { name: "Retry" })).toBeVisible();
    // Every error block of the view offers Retry; with the API answering
    // again, Retry replaces each with the data.
    const n = await alerts.count();
    for (let i = 0; i < n; i++) await expect(alerts.nth(i).getByRole("button", { name: "Retry" }), `${v.code}: alert ${i} without Retry`).toBeVisible();
    fail = false;
    for (let i = 0; i < 20 && (await alerts.count()) > 0; i++) {
      await alerts.first().getByRole("button", { name: "Retry" }).click();
      await page.waitForTimeout(100);
    }
    await expect(alerts, `${v.code}: an error stayed after Retry`).toHaveCount(0, { timeout: 10_000 });
    await settle(page);
  }
  await page.unrouteAll({ behavior: "ignoreErrors" });
}

// Words that name what populates an empty list: a step the reader takes
// (create, add, build, take, export, enroll, verify, set, package, sign
// in, select, enter) or the event that fills it (appears when, records
// appear after, measured once).
const action =
  /\b(create|add|build|take|export|enroll|verify|set|package|sign(s)? in|select|enter|use|start|run|appears? (here )?(when|after|as)|appear (here )?(when|after|as)|measured once|is imported)\b/i;

async function emptyStates(browser: Browser) {
  const d = await startDedicated("states-empty", { secrets: true, egress: true });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  try {
    await page.goto(d.adminURL + "/");
    await page.getByLabel("Password").fill(d.adminPassword);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByTestId("status-strip")).toBeVisible();
    const seen: Record<string, string[]> = {};
    for (const v of views) {
      await go(page, v.path);
      await expect(page.getByRole("heading", { level: 1 })).toHaveText(v.title);
      await settle(page);
      const texts = (await page.locator("main .empty").allTextContents()).map((t) => t.trim()).filter(Boolean);
      seen[v.code] = texts;
      for (const t of texts) expect(t, `${v.code}: empty state without an action`).toMatch(action);
      await expect(page.locator("main").getByRole("alert"), `${v.code}: an error on the empty installation`).toHaveCount(0);
    }
    // The lists a fresh installation leaves empty, by view.
    const expected: [string, RegExp][] = [
      ["G-04", /No stored record falls within the draft.s scope\. Records appear after tool calls/],
      ["G-05", /No snapshot is built\. Build one/],
      ["G-07", /Overhead is measured once calls are observed/],
      ["G-08", /No backup has been taken\. Take one/],
      ["G-09", /No campaign exists\. Create one/],
      ["G-09", /No dataset has been exported\. Export one/],
      ["G-11", /No harness is connected\. A session appears here when a harness signs in/],
      ["G-11 remote", /No remote client is registered/],
      ["G-12", /No secret is stored\. Create one/],
      ["G-13", /No call is waiting for approval\. A call appears here when/],
      ["Egress", /No server has an egress grant/],
      ["Runtime", /No sandboxed instance exists/],
    ];
    for (const [code, re] of expected)
      expect(
        seen[code]?.some((t) => re.test(t)),
        `${code}: ${re} in ${JSON.stringify(seen[code])}`,
      ).toBe(true);
    // G-02 and G-10 always hold the bootstrap policy revision, server and
    // package; with their lists empty they say what populates them.
    // G-01 always reports health, and G-03 and G-06 edit the object in
    // force (the defaults on a new installation), so they have no list
    // that can be empty; G-01's journal verification panel is checked
    // above ("Verify it now").
    for (const [route, body] of [
      ["/api/v1/policy/revisions", { revisions: [] }],
      ["/api/v1/servers", { servers: [] }],
      ["/api/v1/packages", { library: "/var/empty", revisions: [], servers: [], trust_anchors: [] }],
    ] as const) {
      await page.route(
        (u) => u.pathname === route,
        (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) }),
      );
    }
    for (const [path, re] of [
      ["/policy", /No revision is published\. The policy file is imported as the first revision when smcpd starts\./],
      ["/servers", /No server is configured\. Add a \[\[server\]\] table/],
      ["/library", /No package is in the library\. Build and sign one/],
    ] as const) {
      await go(page, path);
      await settle(page);
      await expect(page.locator("main .empty").filter({ hasText: re })).toBeVisible();
    }
  } finally {
    await ctx.close();
    d.stop();
  }
}
