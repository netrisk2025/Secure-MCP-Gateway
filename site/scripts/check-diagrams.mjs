// Checks every diagram and chart in the static export in out/ after
// `npm run build`, in a real browser (Chromium through playwright-core):
//
//   at 1280 x 800, on every page with a Mermaid diagram or a chart,
//   - the diagram renders (no Mermaid error);
//   - it is not wider than its box (no horizontal scroll inside the box) and
//     the drawing lies inside the box (nothing cut off left or right);
//   - it is drawn at its full aspect ratio (no fixed height cropping it) and
//     its box does not clip it vertically;
//   - its smallest text is at least MIN_TEXT_PX after scaling;
//   - the page itself does not scroll sideways;
//   at 390 x 844 (a phone), the same checks except the text size.
//
// The system map (/flows/system-map/, SystemMap.tsx) is one chart with its
// own pan and zoom, so measureSystemMap() measures it instead:
//   - overview: the chart is drawn, fitted to the width of its box, inside
//     the box, at its aspect ratio and not clipped; at 1280 px its smallest
//     text is at least MIN_TEXT_PX like any other diagram;
//   - each stage of the stage index, at both widths: selecting it zooms the
//     box to at most the window height, the stage's top left corner is in
//     view, and the stage's smallest text is at least MIN_TEXT_PX. On a phone
//     the overview is a map to zoom into, so the text rule applies to the
//     stage views there.
//
// Exit status 1 lists each problem. Run with `npm run check-diagrams`.
// The browser is the installed Google Chrome (CHECK_DIAGRAMS_CHANNEL,
// default "chrome"), else Playwright's own Chromium if it is installed, else
// CHROME_PATH.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { chromium } from "playwright-core";

const OUT = path.join(process.cwd(), "out");
const MIN_TEXT_PX = Number(process.env.CHECK_DIAGRAMS_MIN_TEXT_PX ?? 11);
const VIEWPORTS = [
  { width: 1280, height: 800, text: true },
  { width: 390, height: 844, text: false },
];

if (!fs.existsSync(path.join(OUT, "index.html"))) {
  console.error("out/index.html is missing; run npm run build first");
  process.exit(1);
}

function walk(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else if (e.name === "index.html") out.push(p);
  }
  return out;
}

// Pages with a diagram placeholder or a chart, as site paths.
const pages = walk(OUT)
  .filter((f) => /data-mermaid=|class="chart-svg"|class="sysmap-box"/.test(fs.readFileSync(f, "utf8")))
  .map((f) => `/${path.relative(OUT, path.dirname(f)).split(path.sep).join("/")}/`.replace(/^\/\/$/, "/"))
  .sort();
if (!pages.length) {
  console.error("no page in out/ has a diagram or a chart; the check would prove nothing");
  process.exit(1);
}

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".txt": "text/plain",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

const server = http.createServer((req, res) => {
  const url = decodeURIComponent((req.url ?? "/").split("?")[0]);
  let file = path.join(OUT, path.normalize(url));
  if (!file.startsWith(OUT)) {
    res.writeHead(403).end();
    return;
  }
  if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, "index.html");
  else if (!fs.existsSync(file) && fs.existsSync(`${file}.html`)) file = `${file}.html`;
  if (!fs.existsSync(file)) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { "content-type": TYPES[path.extname(file)] ?? "application/octet-stream" });
  fs.createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

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

/** Measures every diagram and chart on the page; runs in the browser. */
function measure() {
  const out = [];
  const doc = document.documentElement;
  for (const el of document.querySelectorAll(".mermaid-block, .chart")) {
    const chart = el.classList.contains("chart");
    const box = chart ? (el.querySelector(".chart-scroll") ?? el) : el;
    const svg = chart ? el.querySelector("svg.chart-svg") : el.querySelector(":scope > svg");
    const name = chart
      ? `chart "${el.querySelector(".chart-title")?.textContent?.trim() ?? "?"}"`
      : `${el.closest("figure")?.id ?? "diagram"}`;
    const item = { name, problems: [] };
    out.push(item);
    if (!chart && el.dataset.rendered !== "1") {
      item.problems.push(el.dataset.rendered === "error" ? `Mermaid error: ${el.dataset.error}` : "not rendered");
      continue;
    }
    if (!svg) {
      item.problems.push("no SVG");
      continue;
    }
    const b = box.getBoundingClientRect();
    const r = svg.getBoundingClientRect();
    const vb = svg.viewBox.baseVal;
    if (box.scrollWidth > box.clientWidth + 1) item.problems.push(`wider than its box: ${box.scrollWidth} > ${box.clientWidth} px`);
    if (r.left < b.left - 1 || r.right > b.right + 1)
      item.problems.push(`drawn outside its box: ${Math.round(r.left)}..${Math.round(r.right)} not within ${Math.round(b.left)}..${Math.round(b.right)}`);
    if (box.scrollHeight > box.clientHeight + 1) item.problems.push(`clipped vertically: ${box.scrollHeight} > ${box.clientHeight} px`);
    if (!vb || !vb.width || !vb.height) item.problems.push("no viewBox");
    else {
      const want = (r.width * vb.height) / vb.width;
      if (Math.abs(r.height - want) > 2) item.problems.push(`aspect ratio not kept: ${Math.round(r.height)} px high, ${Math.round(want)} expected`);
    }
    const scale = vb && vb.width ? r.width / vb.width : 1;
    let min = Infinity;
    for (const t of svg.querySelectorAll("text, foreignObject div, foreignObject span, foreignObject p")) {
      if (!t.textContent.trim() || !t.getBoundingClientRect().width) continue;
      min = Math.min(min, parseFloat(getComputedStyle(t).fontSize) * scale);
    }
    item.minText = min === Infinity ? null : Math.round(min * 10) / 10;
    item.width = Math.round(r.width);
    item.natural = vb ? Math.round(vb.width) : null;
  }
  return { pageOverflow: doc.scrollWidth > doc.clientWidth + 1 ? `${doc.scrollWidth} > ${doc.clientWidth}` : null, items: out };
}

/** The system map in its current view; runs in the browser. `stage` is a subgraph ID, or null for the overview. */
function measureSystemMap(stage) {
  const minTextUnder = (root, scale) => {
    let min = Infinity;
    for (const t of root.querySelectorAll("text, foreignObject div, foreignObject span, foreignObject p")) {
      if (!t.textContent.trim() || !t.getBoundingClientRect().width) continue;
      min = Math.min(min, parseFloat(getComputedStyle(t).fontSize) * scale);
    }
    return min === Infinity ? null : Math.round(min * 10) / 10;
  };
  const box = document.querySelector(".sysmap-box");
  const problems = [];
  if (!box) return { problems: ["no .sysmap-box"] };
  if (box.dataset.rendered !== "1") return { problems: [box.dataset.rendered === "error" ? "Mermaid error" : "not rendered"] };
  const svg = box.querySelector(".sysmap-canvas > svg");
  const vb = svg.viewBox.baseVal;
  const b = box.getBoundingClientRect();
  const r = svg.getBoundingClientRect();
  const scale = r.width / vb.width;
  if (!stage) {
    // Zoomed, the box clips the drawing on purpose; in the overview nothing may overflow it.
    if (box.scrollWidth > box.clientWidth + 1) problems.push(`wider than its box: ${box.scrollWidth} > ${box.clientWidth} px`);
    if (box.dataset.zoomed !== "0") problems.push("the overview is zoomed");
    if (r.left < b.left - 1 || r.right > b.right + 1)
      problems.push(`drawn outside its box: ${Math.round(r.left)}..${Math.round(r.right)} not within ${Math.round(b.left)}..${Math.round(b.right)}`);
    if (Math.abs(r.width - box.clientWidth) > 2) problems.push(`not fitted to the box width: ${Math.round(r.width)} of ${box.clientWidth} px`);
    if (r.height > box.clientHeight + 2) problems.push(`clipped vertically: ${Math.round(r.height)} > ${box.clientHeight} px`);
    if (Math.abs(r.height - (r.width * vb.height) / vb.width) > 2) problems.push("aspect ratio not kept");
    return { problems, minText: minTextUnder(svg, scale), width: Math.round(r.width), natural: Math.round(vb.width) };
  }
  if (box.dataset.zoomed !== "1") problems.push("selecting the stage did not zoom");
  if (box.clientHeight > window.innerHeight + 1) problems.push(`zoomed box taller than the window: ${box.clientHeight} > ${window.innerHeight} px`);
  const cluster = svg.querySelector(`g.cluster[id="${stage}"], g.cluster[id$="-${stage}"]`);
  if (!cluster) return { problems: [...problems, "no such subgraph"] };
  const c = (cluster.querySelector("rect") ?? cluster).getBoundingClientRect();
  if (c.left < b.left - 1 || c.left > b.right - 20 || c.top < b.top - 1 || c.top > b.bottom - 20)
    problems.push(
      `the stage's top left corner is not in view: ${Math.round(c.left)},${Math.round(c.top)} in ${Math.round(b.left)},${Math.round(b.top)}..${Math.round(b.right)},${Math.round(b.bottom)}`,
    );
  return { problems, minText: minTextUnder(cluster, scale) };
}

/** Overview, then every stage of the stage index, then back to the overview. */
async function checkSystemMap(page, vp, p, problems) {
  await page.waitForFunction(() => !!document.querySelector(".sysmap-box")?.dataset.rendered, null, { timeout: 30000 }).catch(() => {});
  const o = await page.evaluate(measureSystemMap, null);
  for (const pr of o.problems) problems.push(`${vp.width}px ${p} system map overview: ${pr}`);
  if (vp.text && o.minText != null && o.minText < MIN_TEXT_PX)
    problems.push(`${vp.width}px ${p} system map overview: smallest text ${o.minText}px < ${MIN_TEXT_PX}px (drawn ${o.natural} px wide, shown ${o.width} px)`);
  const stages = await page.locator(".sysmap-stages li").evaluateAll((ls) => ls.map((l) => l.id.replace(/^stage-/, "")));
  if (!stages.length) problems.push(`${vp.width}px ${p} system map: no stage index`);
  const texts = [];
  for (const [i, id] of stages.entries()) {
    await page.locator(".sysmap-stage-zoom").nth(i).click();
    const m = await page.evaluate(measureSystemMap, id);
    for (const pr of m.problems) problems.push(`${vp.width}px ${p} system map stage ${id}: ${pr}`);
    if (m.minText != null && m.minText < MIN_TEXT_PX) problems.push(`${vp.width}px ${p} system map stage ${id}: smallest text ${m.minText}px < ${MIN_TEXT_PX}px`);
    texts.push(`${id} ${m.minText ?? "?"}px`);
  }
  await page.locator(".sysmap-box").press("Escape");
  const back = await page.evaluate(measureSystemMap, null);
  for (const pr of back.problems) problems.push(`${vp.width}px ${p} system map after Escape: ${pr}`);
  console.log(`${vp.width}px ${p}  overview ${o.width ?? "?"}/${o.natural ?? "?"}px ${o.minText ?? "?"}px; stages ${texts.join(", ")}`);
}

const problems = [];
const browser = await launch();
try {
  for (const vp of VIEWPORTS) {
    const ctx = await browser.newContext({ viewport: { width: vp.width, height: vp.height } });
    const page = await ctx.newPage();
    for (const p of pages) {
      await page.goto(base + p, { waitUntil: "load" });
      await page.evaluate(() => document.fonts.ready);
      // Diagrams draw when they come near the viewport: bring each into view and wait for it.
      const n = await page.locator(".mermaid-block").count();
      for (let i = 0; i < n; i++) {
        const block = page.locator(".mermaid-block").nth(i);
        await block.scrollIntoViewIfNeeded();
        await page
          .waitForFunction((el) => !!el.dataset.rendered, await block.elementHandle(), { timeout: 20000 })
          .catch(() => {});
      }
      if (await page.locator(".sysmap-box").count()) await checkSystemMap(page, vp, p, problems);
      const m = await page.evaluate(measure);
      if (m.pageOverflow) problems.push(`${vp.width}px ${p}: the page scrolls sideways (${m.pageOverflow} px)`);
      for (const it of m.items) {
        for (const pr of it.problems) problems.push(`${vp.width}px ${p} ${it.name}: ${pr}`);
        if (vp.text && it.minText !== null && it.minText < MIN_TEXT_PX)
          problems.push(
            `${vp.width}px ${p} ${it.name}: smallest text ${it.minText}px < ${MIN_TEXT_PX}px (drawn ${it.natural} px wide, shown ${it.width} px); lay the diagram out narrower`,
          );
      }
      if (vp.text)
        console.log(
          `${p}  ${m.items.map((it) => `${it.width ?? "?"}/${it.natural ?? "?"}px ${it.minText ?? "?"}px`).join("  ")}`,
        );
    }
    await ctx.close();
  }
} finally {
  await browser.close();
  server.close();
}

if (problems.length) {
  console.error(`\n${problems.length} diagram problem(s):`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(`\n${pages.length} pages: every diagram and chart fits its box at 1280 and 390 px, text at least ${MIN_TEXT_PX}px at 1280 px.`);
