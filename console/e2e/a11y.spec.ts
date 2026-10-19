// Automated WCAG 2.2 A/AA checks (axe-core) of every view in light and
// dark color schemes. Automated checks find only part of the failures WCAG
// covers, so this is a partial claim of FR-8.32; keyboard operation is
// exercised in console.spec.ts.
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { info } from "./gateway";

const g = info();
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
  "/research/new",
];

for (const scheme of ["light", "dark"] as const) {
  test(`views have no WCAG 2.2 AA violations found by axe (${scheme})`, async ({ page }) => {
    test.info().annotations.push({ type: "requirement-partial", description: "FR-8.32" });
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    await page.goto(g.adminURL + "/");
    const signin = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
    expect(signin.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
    await page.getByLabel("Password").fill(g.adminPassword);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
    for (const p of paths) {
      await page.evaluate((to) => {
        history.pushState(null, "", to);
        dispatchEvent(new PopStateEvent("popstate"));
      }, p);
      await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
      const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
      expect(r.violations.map((v) => `${p} ${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
    }
  });
}

// Keyboard traversal of every view (FR-8.33, and the focus-order and
// focus-contrast parts of the FR-8.32 manual check, docs/verification/
// FR-8.32.md). From the start of the page, Tab must reach every tabbable
// control of the view in turn (so nothing traps focus), every focused
// control must show an outline or ring whose color has at least 3:1
// contrast against the background behind it (WCAG 1.4.11), and no element
// may carry a positive tabindex (which would break DOM focus order, WCAG
// 2.4.3). WebKit moves Tab only between form controls unless the macOS
// "keyboard navigation" setting is on; Option+Tab moves through every
// control, as that setting does, so the WebKit run presses Alt+Tab.
for (const scheme of ["light", "dark"] as const) {
  test(`every control of each view is reached by Tab with a visible, contrasting focus indicator (${scheme})`, async ({ page, browserName }) => {
    const tab = browserName === "webkit" ? "Alt+Tab" : "Tab";
    test.setTimeout(900_000);
    test.info().annotations.push({ type: "requirement-partial", description: "FR-8.32" }, { type: "requirement-partial", description: "FR-8.33" });
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    await page.goto(g.adminURL + "/");
    await page.getByLabel("Password").fill(g.adminPassword);
    await page.keyboard.press("Enter");
    await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
    const problems: string[] = [];
    let total = 0;
    for (const p of paths) {
      await page.evaluate((to) => {
        history.pushState(null, "", to);
        dispatchEvent(new PopStateEvent("popstate"));
      }, p);
      await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
      // Mark the tabbable controls in DOM order and put a start marker
      // before them.
      const count = await page.evaluate(() => {
        const sel = "a[href], button, input, select, textarea, summary, [tabindex]";
        const els = [...document.querySelectorAll<HTMLElement>(sel)].filter((el) => {
          if (el.matches(":disabled") || el.tabIndex < 0 || el.closest("[inert], [hidden]")) return false;
          if (el instanceof HTMLInputElement && el.type === "hidden") return false;
          if (el.closest("details:not([open])") && el.tagName !== "SUMMARY") return false;
          const s = getComputedStyle(el);
          if (s.visibility === "hidden" || s.display === "none") return false;
          // The skip link is off-screen until focused; keep it.
          return el.classList.contains("skip") || el.getClientRects().length > 0;
        });
        els.forEach((el, i) => (el.dataset.kbd = String(i)));
        const start = document.createElement("button");
        start.id = "kbd-start";
        start.textContent = "start";
        document.body.prepend(start);
        start.focus();
        return els.length;
      });
      total += count;
      const positive = await page.evaluate(() =>
        [...document.querySelectorAll<HTMLElement>("[tabindex]")].filter((e) => e.tabIndex > 0).map((e) => e.outerHTML.slice(0, 80)),
      );
      if (positive.length) problems.push(`${p}: positive tabindex on ${positive.join(", ")}`);
      const seen = new Set<string>();
      for (let i = 0; i < count + 1 && seen.size < count; i++) {
        await page.keyboard.press(tab);
        const f = await page.evaluate(() => {
          const el = document.activeElement as HTMLElement | null;
          if (!el || el === document.body) return null;
          const s = getComputedStyle(el);
          const rgb = (c: string) => (c.match(/[\d.]+/g) ?? []).map(Number);
          const lum = ([r = 0, gg = 0, b = 0]: number[]) => {
            const ch = (v: number) => {
              const x = v / 255;
              return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
            };
            return 0.2126 * ch(r) + 0.7152 * ch(gg) + 0.0722 * ch(b);
          };
          // Background behind the outline: the first opaque ancestor background.
          let bg = "rgb(255, 255, 255)";
          for (let a: HTMLElement | null = el.parentElement; a; a = a.parentElement) {
            const c = getComputedStyle(a).backgroundColor;
            const v = rgb(c);
            if (v.length >= 3 && (v.length < 4 || v[3]! > 0.5)) {
              bg = c;
              break;
            }
          }
          const ring =
            s.outlineStyle !== "none" && parseFloat(s.outlineWidth) >= 1
              ? s.outlineColor
              : s.boxShadow !== "none"
                ? (s.boxShadow.match(/rgba?\([^)]*\)/)?.[0] ?? "")
                : "";
          let ratio = 0;
          if (ring) {
            const [l1, l2] = [lum(rgb(ring)), lum(rgb(bg))].sort((x, y) => y - x) as [number, number];
            ratio = (l1 + 0.05) / (l2 + 0.05);
          }
          const name = (el.getAttribute("aria-label") || el.textContent || el.getAttribute("name") || el.id || "").trim().slice(0, 40);
          return { kbd: el.dataset.kbd ?? "", tag: el.tagName.toLowerCase(), name, ring, ratio };
        });
        if (!f) continue;
        if (f.kbd === "") {
          if (f.tag !== "button" || f.name !== "start") problems.push(`${p}: focus reached an unmarked ${f.tag} "${f.name}"`);
          continue;
        }
        seen.add(f.kbd);
        if (!f.ring) problems.push(`${p}: no focus indicator on ${f.tag} "${f.name}"`);
        else if (f.ratio < 3) problems.push(`${p}: focus indicator contrast ${f.ratio.toFixed(2)}:1 on ${f.tag} "${f.name}"`);
      }
      if (seen.size < count) {
        const missed = await page.evaluate(
          (s) =>
            [...document.querySelectorAll<HTMLElement>("[data-kbd]")]
              .filter((e) => !s.includes(e.dataset.kbd!))
              .map((e) => `${e.tagName.toLowerCase()} "${(e.getAttribute("aria-label") || e.textContent || "").trim().slice(0, 30)}"`),
          [...seen],
        );
        problems.push(`${p}: Tab reached ${seen.size} of ${count} controls; not reached: ${missed.slice(0, 5).join(", ")}`);
      }
      await page.evaluate(() => {
        document.getElementById("kbd-start")?.remove();
        document.querySelectorAll<HTMLElement>("[data-kbd]").forEach((e) => delete e.dataset.kbd);
      });
    }
    console.log(`keyboard traversal (${scheme}): ${paths.length} views, ${total} controls`);
    expect(problems).toEqual([]);
  });
}
