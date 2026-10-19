// Renders the system map (the first Mermaid block of docs/flows/system-map.md)
// to the static SVG download public/system-map.svg, in the site's light
// colors, with SVG text labels (no foreignObject) so it opens in any SVG
// viewer. The file starts with the SHA-256 of the Mermaid source;
// test/system-map.test.ts fails when the SVG is older than the source.
//
//   npm run render-system-map            write public/system-map.svg
//   npm run render-system-map -- --info  also print the drawn size and each stage's box
//
// Uses the same browser as check-diagrams (installed Chrome, else
// Playwright's Chromium, else CHROME_PATH).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright-core";

const SITE = process.cwd();
const REPO = path.resolve(SITE, "..");
const SRC = path.join(REPO, "docs/flows/system-map.md");
const OUT = path.join(SITE, "public/system-map.svg");
const info = process.argv.includes("--info");

const md = fs.readFileSync(SRC, "utf8");
const m = md.match(/```mermaid\n([\s\S]*?)```/);
if (!m) {
  console.error(`${SRC}: no Mermaid block`);
  process.exit(1);
}
const source = m[1];
const digest = crypto.createHash("sha256").update(source).digest("hex");

// Light tokens from the first :root block of globals.css.
const css = fs.readFileSync(path.join(SITE, "src/app/globals.css"), "utf8");
const root = css.slice(css.indexOf(":root {"), css.indexOf("}", css.indexOf(":root {")));
const tok = (n) => root.match(new RegExp(`${n}:\\s*([^;]+);`))?.[1].trim() ?? "";
const vars = {
  background: tok("--paper"),
  mainBkg: tok("--surface"),
  primaryColor: tok("--surface"),
  primaryTextColor: tok("--ink"),
  primaryBorderColor: tok("--ink-2"),
  secondaryColor: tok("--surface-2"),
  tertiaryColor: tok("--paper"),
  lineColor: tok("--ink-2"),
  textColor: tok("--ink"),
  clusterBkg: tok("--surface-2"),
  clusterBorder: tok("--rule-strong"),
  edgeLabelBackground: tok("--paper"),
  titleColor: tok("--ink"),
  nodeTextColor: tok("--ink"),
  fontFamily: '"IBM Plex Mono", ui-monospace, Menlo, Consolas, monospace',
  fontSize: "14px",
};

async function launch() {
  const tries = [];
  if (process.env.CHROME_PATH) tries.push({ executablePath: process.env.CHROME_PATH });
  tries.push({ channel: process.env.CHECK_DIAGRAMS_CHANNEL || "chrome" }, {});
  let last;
  for (const t of tries) {
    try {
      return await chromium.launch(t);
    } catch (e) {
      last = e;
    }
  }
  throw last;
}

const browser = await launch();
try {
  const page = await browser.newPage();
  await page.setContent(`<!doctype html><html><body style="margin:0;background:${vars.background}"><div id="c"></div></body></html>`);
  await page.addScriptTag({ path: path.join(SITE, "node_modules/mermaid/dist/mermaid.min.js") });
  const result = await page.evaluate(
    async ({ source, vars }) => {
      const mermaid = window.mermaid;
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: "strict",
        theme: "base",
        look: "classic",
        themeVariables: vars,
        fontFamily: vars.fontFamily,
        maxTextSize: 200000,
        maxEdges: 1000,
        flowchart: { htmlLabels: false, curve: "basis", useMaxWidth: false, padding: 10, nodeSpacing: 28, rankSpacing: 36, wrappingWidth: 260 },
      });
      const { svg } = await mermaid.render("system-map", source);
      const c = document.getElementById("c");
      c.innerHTML = svg;
      const el = c.querySelector("svg");
      const vb = el.viewBox.baseVal;
      const er = el.getBoundingClientRect();
      const stages = [...el.querySelectorAll("g.cluster")].map((g) => {
        const r = (g.querySelector("rect") ?? g).getBoundingClientRect();
        return { id: g.id, x: Math.round(r.left - er.left), y: Math.round(r.top - er.top), w: Math.round(r.width), h: Math.round(r.height) };
      });
      // Serialize from the DOM so the file is well-formed XML at its natural size.
      el.setAttribute("width", String(Math.ceil(vb.width)));
      el.setAttribute("height", String(Math.ceil(vb.height)));
      el.removeAttribute("style");
      return { svg: new XMLSerializer().serializeToString(el), w: vb.width, h: vb.height, stages };
    },
    { source, vars },
  );
  const svg =
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<!-- Secure MCP Gateway system map. Source: docs/flows/system-map.md, sha256 ${digest}. Regenerate with npm run render-system-map in site/. -->\n` +
    `${result.svg}\n`;
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, svg);
  console.log(`wrote ${path.relative(SITE, OUT)}: ${Math.round(result.w)} x ${Math.round(result.h)} px, ${(svg.length / 1024).toFixed(0)} KiB`);
  if (info) for (const s of result.stages) console.log(`  ${s.id.padEnd(28)} x ${s.x} y ${s.y} w ${s.w} h ${s.h}`);
} finally {
  await browser.close();
}
