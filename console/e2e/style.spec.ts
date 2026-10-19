// Visual rules of docs/console-style.md checked on every view (FR-8.35),
// in both color schemes: collections are tables whose headers sort, one
// sans family plus one monospaced face at the five sizes of the type
// scale, no gradients, decorative shadows, emoji or exclamation marks, and
// table rows at most 32 px high where the content is one line. The rules
// that need judgment (color is never the only cue, plain labels, no
// component kit) are inspected by hand in docs/verification/inspections.md.
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
  test(`every view follows the console visual rules (${scheme})`, async ({ page }) => {
    test.info().annotations.push({ type: "requirement-partial", description: "FR-8.35" });
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    await page.goto(g.adminURL + "/");
    await page.getByLabel("Password").fill(g.adminPassword);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Gateway control" })).toBeVisible();
    const problems: string[] = [];
    for (const p of paths) {
      await page.evaluate((to) => {
        history.pushState(null, "", to);
        dispatchEvent(new PopStateEvent("popstate"));
      }, p);
      await expect(page.locator(".loading")).toHaveCount(0, { timeout: 20_000 });
      // Open every disclosure so grouped content is checked too.
      await page.evaluate(() => document.querySelectorAll("details").forEach((d) => (d.open = true)));
      const found = await page.evaluate(() => {
        const out: string[] = [];
        const visible = (el: Element) => (el as HTMLElement).getClientRects().length > 0 && getComputedStyle(el).visibility !== "hidden";
        // Lists are tables with sortable headers. A table is a collection
        // when it has a header row and two or more body rows. Exempt: the
        // value tables under charts, which repeat the chart, and tables of
        // a fixed enumeration in a meaningful order rather than a
        // collection of records (the first-run steps in order, the
        // sigma bands in order, the fixed audit floor classes).
        const fixed = new Set(["First-run checklist", "Band thresholds and actions", "Current response per band", "Mandatory audit floor"]);
        for (const t of document.querySelectorAll("main table")) {
          if (!visible(t) || t.closest(".chart")) continue;
          const name = t.getAttribute("aria-label") || t.querySelector("caption")?.textContent || "(unnamed)";
          if (fixed.has(name)) continue;
          if (!t.querySelector("thead th")) out.push(`table "${name}" has no header row`);
          const rows = t.querySelectorAll("tbody tr").length;
          if (rows >= 2 && !t.querySelector("th[aria-sort]")) out.push(`table "${name}" with ${rows} rows has no sortable column`);
          for (const tr of t.querySelectorAll<HTMLTableRowElement>("tbody tr")) {
            const h = tr.getBoundingClientRect().height;
            const oneLine = [...tr.cells].every((c) => c.getClientRects().length <= 1 && c.scrollHeight <= 32 && !/\n/.test(c.innerText.trim()));
            if (oneLine && h > 33) out.push(`table "${name}": one-line row ${h.toFixed(0)} px high`);
          }
        }
        // No gradients and no decorative drop shadows.
        for (const el of document.querySelectorAll<HTMLElement>("main *")) {
          if (!visible(el)) continue;
          const s = getComputedStyle(el);
          if (s.backgroundImage.includes("gradient")) out.push(`gradient on ${el.tagName.toLowerCase()}.${el.className}`);
          // Drop shadows only; an inset bar marks state (a refused row).
          if (s.boxShadow !== "none" && !s.boxShadow.includes("inset") && !el.matches(":focus")) out.push(`drop shadow on ${el.tagName.toLowerCase()}.${el.className}`);
        }
        // Type: one sans family and one monospaced face, five sizes.
        const sizes = new Set([12, 13, 14, 16, 20]);
        const seen = new Set<string>();
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
        for (let n = walker.nextNode(); n; n = walker.nextNode()) {
          const el = n.parentElement;
          if (!el || !n.textContent?.trim() || !visible(el) || el.closest("svg")) continue;
          const s = getComputedStyle(el);
          const fam = s.fontFamily.split(",")[0]!.replace(/["']/g, "").trim();
          const px = Math.round(parseFloat(s.fontSize) * 10) / 10;
          const key = `${fam}|${px}`;
          if (seen.has(key)) continue;
          seen.add(key);
          if (fam !== "IBM Plex Sans" && fam !== "IBM Plex Mono") out.push(`font family ${fam} on ${el.tagName.toLowerCase()} "${n.textContent.trim().slice(0, 30)}"`);
          if (!sizes.has(px)) out.push(`font size ${px} px on ${el.tagName.toLowerCase()} "${n.textContent.trim().slice(0, 30)}"`);
        }
        // Text: no emoji, no exclamation marks outside code and data.
        const text = document.body.innerText;
        const emoji = text.match(/\p{Extended_Pictographic}/gu);
        if (emoji) out.push(`emoji ${[...new Set(emoji)].join(" ")}`);
        const prose = [...document.querySelectorAll<HTMLElement>("main p, main label, main h1, main h2, main h3, main button, main th, main dt, header")]
          .filter((e) => !e.closest("pre, code, .mono, .json"))
          .map((e) => e.innerText);
        for (const t of prose) if (/!(\s|$)/.test(t)) out.push(`exclamation mark in "${t.trim().slice(0, 50)}"`);
        return out;
      });
      for (const f of found) problems.push(`${p}: ${f}`);
    }
    expect([...new Set(problems)]).toEqual([]);
  });
}
