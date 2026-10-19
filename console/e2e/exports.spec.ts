// SR-6.17-1 inert rendering: audit and observation content is rendered as
// escaped text, CSV exports prefix cells that begin with =, +, - or @ with
// an apostrophe, and the console loads no remote media. The verification
// statement: display and export fixtures with HTML, script and formula
// payloads and confirm inert output.
//
// Fixtures: on a dedicated Gateway, scripts/evidence-fixture writes journal
// events and observation records whose fields begin with each formula
// character or carry HTML, a script element and a remote image, while
// smcpd is stopped (no call can put such text at the start of an exported
// field). They are displayed in G-14 (the journal, an event) and exported
// from G-14 (CSV and JSON Lines) and from G-09 (a campaign's CSV dataset)
// through the console's own download actions. Then every view is shown
// with every string of the control API's answers carrying the same
// payloads. Requests to any other origin are blocked and recorded: none may
// happen.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { bin, startDedicated } from "./gateway";
import { go } from "./helpers";

const formula = /^[=+\-@]/;

/** RFC 4180 CSV. */
function parseCSV(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") {
      row.push(cell);
      cell = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else cell += c;
  }
  if (cell !== "" || row.length) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

/** Nothing hostile ran or became markup on the page. */
async function inert(page: Page, where: string) {
  const s = await page.evaluate(() => ({
    ran: (window as unknown as { __smcpXSS?: number }).__smcpXSS ?? 0,
    imgs: [...document.images].filter((i) => !i.src.startsWith(location.origin) && !i.src.startsWith("data:")).length,
    inline: [...document.scripts].filter((s) => !s.src).length,
    handlers: [...document.querySelectorAll("[onerror],[onload],[onclick]")].length,
  }));
  expect(s.ran, `${where}: a fixture script ran`).toBe(0);
  expect(s.imgs, `${where}: a remote image element`).toBe(0);
  expect(s.inline, `${where}: an inline script element`).toBe(0);
  expect(s.handlers, `${where}: an inline event handler`).toBe(0);
}

async function downloadText(page: Page, click: () => Promise<void>): Promise<string> {
  const dl = page.waitForEvent("download");
  await click();
  return readFileSync(await (await dl).path(), "utf8");
}

const views = ["/", "/sessions", "/servers", "/servers/ref", "/catalog", "/library", "/approvals", "/audit", "/policy", "/observations", "/analytics", "/performance", "/data-server", "/research", "/audit-profiles", "/anomaly-response", "/remote", "/runtime", "/policy/filters"];

test("audit and observation fixtures are shown as escaped text and exported as CSV with formulas neutralised, with no remote media", async ({ browser, browserName }) => {
  test.info().annotations.push({ type: "requirement", description: "SR-6.17-1" });
  test.setTimeout(600_000);
  const d = await startDedicated(`exports-${browserName}`);
  const marker = `fx${Date.now()}`;
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const origin = new URL(d.adminURL).origin;
  const remote: string[] = [];
  await ctx.route(
    (u) => u.origin !== origin && u.protocol !== "data:" && u.protocol !== "blob:",
    (r) => {
      remote.push(r.request().url());
      return r.abort("blockedbyclient");
    },
  );
  const page = await ctx.newPage();
  const signIn = async () => {
    await page.goto(d.adminURL + "/");
    await page.getByLabel("Password").fill(d.adminPassword);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
  };
  try {
    await signIn();
    // A campaign that captures the two text parameters of the fixture records.
    const tok = readFileSync(join(d.dir, "state", "keys", "admin.token"), "utf8").trim();
    const api = async (path: string, data: object) => {
      const r = await page.request.post(d.adminURL + path, { headers: { Authorization: `Bearer ${tok}` }, data });
      expect(r.status(), `${path}: ${await r.text()}`).toBeLessThan(300);
      return (await r.json()) as { id: string; state: string };
    };
    const cp = await api("/api/v1/research/campaigns", {
      name: "inert export study",
      purpose: "SR-6.17-1",
      parameters: ["tool_name", "framework_type", "request_bytes"],
      start: new Date(Date.now() - 3600_000).toISOString(),
      end: new Date(Date.now() + 86400_000).toISOString(),
      quota_bytes: 1 << 20,
    });
    await api(`/api/v1/research/campaigns/${cp.id}/submit`, {});
    await api(`/api/v1/research/campaigns/${cp.id}/approve`, {});

    // The fixtures, written with smcpd stopped.
    await d.restart(() => {
      execFileSync(join(bin, "evidence-fixture"), ["-config", d.config, "-marker", marker], { stdio: "ignore" });
    });
    await signIn();

    // Display: the journal and each fixture event.
    await go(page, "/audit?class=fixture");
    const table = page.getByRole("table", { name: "Journal events" });
    await expect(table.getByRole("row")).toHaveCount(3);
    await expect(table).toContainText(`+cmd|' /C calc'!A0 ${marker}`);
    await inert(page, "G-14 journal");
    for (let i = 0; i < 2; i++) {
      await go(page, "/audit?class=fixture");
      await table.getByRole("row").nth(i + 1).getByRole("link").first().click();
      await expect(page.getByRole("heading", { level: 1, name: "Evidence event" })).toBeVisible();
      await expect(page.locator("main")).toContainText(`<script>window.__smcpXSS=1</script>${marker}`);
      await expect(page.locator("main")).toContainText(/=HYPERLINK\("https:\/\/evil\.example\//);
      await inert(page, `G-14 fixture event ${i + 1}`);
    }
    await expect(page.locator("main")).toContainText(`<img src="https://evil.example/pixel.png" onerror="window.__smcpXSS=1">${marker}`);

    // G-14 exports.
    await go(page, "/audit?class=fixture");
    const csv = parseCSV(await downloadText(page, () => page.getByRole("button", { name: "Export CSV" }).click()));
    const header = csv[0]!;
    expect(header).toContain("reason_code");
    const fixtureRows = csv.slice(1).filter((r) => r[header.indexOf("class")] === "fixture");
    expect(fixtureRows.length).toBe(2);
    const cells = csv.slice(1).flat();
    expect(cells.filter((c) => formula.test(c)), "CSV cells that begin with a formula character").toEqual([]);
    for (const p of [`=HYPERLINK("https://evil.example/${marker}","open")`, `+cmd|' /C calc'!A0 ${marker}`, `-2+3+cmd|' /C calc'!A0 ${marker}`, `@SUM(1+1)*cmd|' /C calc'!A0 ${marker}`])
      expect(cells, `the neutralised cell '${p}`).toContain("'" + p);
    expect(cells).toContain(`<img src="https://evil.example/pixel.png" onerror="window.__smcpXSS=1">${marker}`);
    const jsonl = await downloadText(page, () => page.getByRole("button", { name: "Export JSON Lines" }).click());
    const events = jsonl
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>)
      .filter((e) => e["class"] === "fixture");
    expect(events.map((e) => e["reason_code"])).toContain(`=HYPERLINK("https://evil.example/${marker}","open")`);

    // G-09: the campaign's CSV dataset with the observation fixtures.
    await go(page, `/research/campaigns/${cp.id}`);
    await expect(page.getByRole("definition").filter({ hasText: /^active$/ })).toBeVisible({ timeout: 60_000 });
    await page.getByLabel("Format").selectOption("csv");
    await page.getByRole("button", { name: "Export", exact: true }).click();
    await expect(page.getByRole("table", { name: "Export files" })).toContainText("dataset.csv");
    const dataset = parseCSV(await downloadText(page, () => page.getByRole("button", { name: "Download dataset.csv" }).click()));
    const dh = dataset[0]!;
    const toolCol = dh.indexOf("tool_name");
    const fwCol = dh.indexOf("framework_type");
    expect(toolCol, `columns ${dh.join(",")}`).toBeGreaterThanOrEqual(0);
    const dcells = dataset.slice(1).flat();
    expect(dcells.filter((c) => formula.test(c)), "dataset cells that begin with a formula character").toEqual([]);
    const tools = dataset.slice(1).map((r) => r[toolCol]);
    for (const p of [`=HYPERLINK("https://evil.example/${marker}","open")`, `+cmd|' /C calc'!A0 ${marker}`, `-2+3+cmd|' /C calc'!A0 ${marker}`, `@SUM(1+1)*cmd|' /C calc'!A0 ${marker}`])
      expect(tools, `the neutralised dataset cell '${p}`).toContain("'" + p);
    expect(tools).toContain(`<script>window.__smcpXSS=1</script>${marker}`);
    expect(dataset.slice(1).map((r) => r[fwCol])).toContain("'" + `=HYPERLINK("https://evil.example/${marker}","open")`);
    await inert(page, "G-09 export");

    // Every view with every string of the API's answers carrying the payloads.
    const hostile = `=HYPERLINK("https://evil.example/x")<img src="https://evil.example/pixel.png" onerror="window.__smcpXSS=1"><script>window.__smcpXSS=1</script>`;
    const iso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;
    const poison = (v: unknown): unknown =>
      typeof v === "string"
        ? v === "" || iso.test(v)
          ? v
          : v + hostile
        : Array.isArray(v)
          ? v.map(poison)
          : v && typeof v === "object"
            ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, poison(x)]))
            : v;
    await page.route("**/api/v1/**", async (route) => {
      const u = new URL(route.request().url());
      if (route.request().method() !== "GET" || u.pathname.startsWith("/api/v1/console/") || /stream|watch/.test(u.pathname)) return route.continue();
      const r = await route.fetch({ url: route.request().url().split(encodeURIComponent(hostile)).join("") });
      if (!(r.headers()["content-type"] ?? "").includes("application/json")) return route.fulfill({ response: r });
      let body: unknown;
      try {
        body = await r.json();
      } catch {
        return route.fulfill({ response: r });
      }
      return route.fulfill({ response: r, body: JSON.stringify(poison(body)) });
    });
    let shown = 0;
    for (const v of views) {
      await go(page, v);
      await expect(page.locator("main h1")).toBeVisible();
      await expect(page.locator("main .loading")).toHaveCount(0, { timeout: 20_000 });
      await inert(page, v);
      shown += await page.evaluate(() => [...document.querySelectorAll("main *")].filter((e) => [...e.childNodes].some((n) => n.nodeType === 3 && (n.textContent ?? "").includes("<script>window.__smcpXSS=1</script>"))).length);
    }
    expect(shown, "payloads shown as text across the views").toBeGreaterThan(20);
    await page.unrouteAll({ behavior: "ignoreErrors" });

    // No remote media: the console's policy allows only its own origin, and
    // nothing tried to leave it.
    const res = await page.request.get(d.adminURL + "/audit");
    const csp = res.headers()["content-security-policy"] ?? "";
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("img-src 'self'");
    expect(csp).not.toMatch(/media-src|https?:/);
    expect(remote, "requests to other origins").toEqual([]);
  } finally {
    await ctx.close();
    d.stop();
  }
});
