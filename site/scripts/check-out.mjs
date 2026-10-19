// Checks the static export in out/ after `npm run build`:
//   - every Markdown file under docs/ (except docs/flows) has a page under /docs/,
//     and every docs/flows/*.md has a page under /flows/;
//   - every site-internal link and in-page anchor in every page resolves;
//   - the Status page has its sections and tables.
// Exit status 1 lists each problem. Run with `npm run check-out`.
import fs from "node:fs";
import path from "node:path";

const SITE = process.cwd();
const OUT = path.join(SITE, "out");
const REPO = path.resolve(SITE, "..");
const problems = [];

if (!fs.existsSync(path.join(OUT, "index.html"))) {
  console.error("out/index.html is missing; run npm run build first");
  process.exit(1);
}

function walk(dir, pred, base = dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p, pred, base));
    else if (pred(e.name)) out.push(path.relative(base, p).split(path.sep).join("/"));
  }
  return out;
}

const pages = walk(OUT, (n) => n.endsWith(".html"));
const pageSet = new Set(pages);

/** The page file a site path is served from (trailingSlash and cleanUrls in vercel.json). */
function pageFor(p) {
  const clean = p.replace(/^\/+/, "").replace(/\/+$/, "");
  if (clean === "") return "index.html";
  for (const c of [`${clean}/index.html`, `${clean}.html`, clean]) if (pageSet.has(c) || fs.existsSync(path.join(OUT, c))) return c;
  return null;
}

// 1. Document and flow pages.
for (const f of walk(path.join(REPO, "docs"), (n) => n.endsWith(".md"))) {
  const file = `docs/${f}`;
  if (file.startsWith("docs/flows/")) {
    const slug = path.posix.basename(f, ".md").toLowerCase().replace(/[^a-z0-9-]+/g, "-");
    if (!pageFor(`/flows/${slug}/`)) problems.push(`${file}: no page at /flows/${slug}/`);
    continue;
  }
  let slug = f.replace(/\.md$/, "").split("/");
  if (slug[slug.length - 1] === "README") slug.pop();
  slug = slug.map((s) => s.toLowerCase().replace(/[^a-z0-9-]+/g, "-")).join("/");
  if (file === "docs/README.md") slug = "documentation";
  if (!pageFor(`/docs/${slug}/`)) problems.push(`${file}: no page at /docs/${slug}/`);
}

// 2. Internal links and anchors.
const ids = new Map();
function idsOf(page) {
  if (!ids.has(page)) {
    const html = fs.readFileSync(path.join(OUT, page), "utf8");
    ids.set(page, new Set(Array.from(html.matchAll(/\sid="([^"]+)"/g), (m) => m[1])));
  }
  return ids.get(page);
}
let links = 0;
for (const page of pages) {
  if (page.startsWith("_next/") || page === "404.html" || page === "_not-found/index.html") continue;
  const html = fs.readFileSync(path.join(OUT, page), "utf8");
  const here = "/" + page.replace(/index\.html$/, "");
  for (const m of html.matchAll(/<a\s[^>]*?href="([^"]*)"/g)) {
    const href = m[1].replace(/&amp;/g, "&");
    if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith("//")) continue;
    links++;
    const [pathAndQuery, hash] = href.split("#");
    const target = pathAndQuery.split("?")[0];
    const resolved = target === "" ? page : pageFor(target.startsWith("/") ? target : path.posix.join(here, target));
    if (!resolved) {
      problems.push(`${here}: link to ${href} has no page`);
      continue;
    }
    if (hash && resolved.endsWith(".html") && !idsOf(resolved).has(decodeURIComponent(hash))) {
      // Requirement deep links (/requirements/#FR-2.5) are opened by script, not by an id in the HTML.
      if (resolved !== "requirements/index.html") problems.push(`${here}: anchor #${hash} not found in /${resolved}`);
    }
  }
}

// 3. Status page structure.
const status = fs.readFileSync(path.join(OUT, "status/index.html"), "utf8");
for (const id of ["run", "implementation", "element-notes", "verification", "tests", "trends", "agents", "hostile", "console"]) {
  if (!status.includes(`id="${id}"`)) problems.push(`/status/: section #${id} is missing`);
}
const noteRows = (status.match(/<tr id="note-E-\d\d"/g) ?? []).length;
const elementPages = pages.filter((p) => /^elements\/E-\d\d\/index\.html$/.test(p)).length;
if (elementPages === 0 || noteRows !== elementPages) {
  problems.push(`/status/: element notes table has ${noteRows} rows for ${elementPages} element pages`);
}

if (problems.length) {
  console.error(`check-out: ${problems.length} problem(s)`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(`check-out: ${pages.length} pages, ${links} internal links, all resolve`);
