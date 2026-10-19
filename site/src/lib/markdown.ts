import { unified } from "unified";
import remarkParse from "remark-parse";
import remarkGfm from "remark-gfm";
import remarkRehype from "remark-rehype";
import rehypeRaw from "rehype-raw";
import rehypeSlug from "rehype-slug";
import rehypeStringify from "rehype-stringify";
import GithubSlugger from "github-slugger";
import fs from "node:fs";
import path from "node:path";
import { FLOWS_DIR, REPO_ROOT, docByFile, docExists, docHref, flowSlug } from "./content";
import { parseDiagram, withAutonumber, type ParsedDiagram } from "./diagram";
import { REPO_URL } from "./site";

export type TocEntry = { depth: number; text: string; id: string };

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

const STYLE_TEXT: Record<string, string> = {
  solid: "solid",
  dashed: "dashed",
  async: "async",
  flow: "arrow",
  link: "line",
  dotted: "dotted",
  thick: "thick",
};

/** A numbered table of the messages (sequence) or edges (flowchart) in a diagram. */
export function stepTableHtml(d: ParsedDiagram, caption: string): string {
  if (!d.steps.length) return "";
  const hasContext = d.steps.some((s) => s.context);
  const hasStyle = d.steps.some((s) => STYLE_TEXT[s.style]);
  const head =
    `<tr><th scope="col" class="num">${d.kind === "sequence" ? "Step" : "Edge"}</th><th scope="col">From</th><th scope="col">To</th><th scope="col">${d.kind === "sequence" ? "Message" : "Label"}</th>` +
    (hasContext ? `<th scope="col">${d.kind === "sequence" ? "Block" : "Group"}</th>` : "") +
    (hasStyle ? `<th scope="col">Kind</th>` : "") +
    "</tr>";
  const rows = d.steps
    .map(
      (s) =>
        `<tr><td class="num">${s.n}</td><td>${escapeHtml(s.from)}</td><td>${escapeHtml(s.to)}</td><td>${escapeHtml(s.label) || '<span class="nil">none</span>'}</td>` +
        (hasContext ? `<td>${escapeHtml(s.context)}</td>` : "") +
        (hasStyle ? `<td>${escapeHtml(STYLE_TEXT[s.style] ?? s.style)}</td>` : "") +
        "</tr>",
    )
    .join("");
  return `<div class="table-wrap steps"><table><caption>${escapeHtml(caption)}</caption><thead>${head}</thead><tbody>${rows}</tbody></table></div>`;
}

/**
 * Replace ```mermaid fences with a placeholder the client renders.
 * Sequence diagrams get autonumber so their arrows match the step table.
 */
function liftMermaid(md: string, steps: boolean): string {
  let i = 0;
  return md.replace(/```mermaid\n([\s\S]*?)```/g, (_m, body: string) => {
    i++;
    const src = withAutonumber(body);
    const b64 = Buffer.from(src, "utf8").toString("base64");
    const d = parseDiagram(body);
    const what = d.kind === "sequence" ? "sequence diagram" : d.kind === "flowchart" ? "flowchart" : "diagram";
    const label = `Diagram ${i}, ${what}${d.steps.length ? ` with ${d.steps.length} ${d.kind === "sequence" ? "messages" : "edges"}` : ""}`;
    const block =
      `<figure class="diagram" id="diagram-${i}"><div class="mermaid-block" data-mermaid="${b64}" role="img" aria-label="${escapeHtml(label)}. The table that follows lists each step.">` +
      `<pre class="mermaid-fallback">${escapeHtml(body)}</pre></div>` +
      `<figcaption>${escapeHtml(label)}. <button type="button" class="diagram-full" hidden>View full size</button></figcaption></figure>`;
    const table = steps
      ? stepTableHtml(
          d,
          d.kind === "sequence"
            ? `Diagram ${i} messages in order. Numbers match the arrows.`
            : `Diagram ${i} edges in the order they are written in the source.`,
        )
      : "";
    return `\n\n${block}${table}\n\n`;
  });
}

export function toc(md: string, maxDepth = 2): TocEntry[] {
  const slugger = new GithubSlugger();
  const out: TocEntry[] = [];
  let inFence = false;
  for (const line of md.split("\n")) {
    if (line.startsWith("```")) inFence = !inFence;
    if (inFence) continue;
    const m = line.match(/^(#{1,6})\s+(.*)$/);
    if (!m) continue;
    const depth = m[1].length;
    if (depth < 2) continue; // the title is dropped from the rendered page
    const text = m[2].replace(/[*`]/g, "").trim();
    // Slug every rendered heading so ids match rehype-slug, then keep only the depths asked for.
    const id = slugger.slug(text);
    if (depth > maxDepth) continue;
    out.push({ depth, text, id });
  }
  return out;
}

type HastNode = { type: string; tagName?: string; properties?: Record<string, unknown>; children?: HastNode[] };

/**
 * Map a link written relative to a repository file onto the site: a document
 * the site renders goes to its page, anything else to the file on GitHub.
 * Absolute URLs, in-page anchors and site paths are left alone.
 */
export function resolveRepoLink(href: string, fromFile: string): string {
  if (!href || href.startsWith("#") || href.startsWith("/") || /^[a-z][a-z0-9+.-]*:/i.test(href)) return href;
  const hashAt = href.indexOf("#");
  const target = hashAt >= 0 ? href.slice(0, hashAt) : href;
  const hash = hashAt >= 0 ? href.slice(hashAt) : "";
  const repoPath = path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), target)).replace(/\/$/, "");
  if (repoPath.startsWith("..")) return href;
  if (path.posix.dirname(repoPath) === FLOWS_DIR && repoPath.endsWith(".md") && docExists(repoPath)) {
    return `/flows/${flowSlug(repoPath)}/${hash}`;
  }
  if (repoPath === FLOWS_DIR) return `/flows/${hash}`;
  // A directory link goes to its README when the site renders that.
  const doc = docByFile(repoPath) ?? docByFile(`${repoPath}/README.md`);
  if (doc) return `${docHref(doc)}${hash}`;
  const isDir = !path.posix.extname(repoPath) && docExists(repoPath) && !fs.statSync(path.join(REPO_ROOT, repoPath)).isFile();
  return `${REPO_URL}/${isDir ? "tree" : "blob"}/main/${repoPath}${hash}`;
}

/** rehype plugin: rewrite relative links with resolveRepoLink. */
function rehypeRepoLinks(fromFile: string) {
  return () => (tree: HastNode) => {
    const walk = (n: HastNode) => {
      if (n.type === "element" && n.tagName === "a" && typeof n.properties?.href === "string") {
        n.properties.href = resolveRepoLink(n.properties.href, fromFile);
      }
      n.children?.forEach(walk);
    };
    walk(tree);
  };
}

export async function renderMarkdown(
  md: string,
  opts: { dropTitle?: boolean; steps?: boolean; file?: string } = {},
): Promise<string> {
  let src = md;
  if (opts.dropTitle) src = src.replace(/^# .*\n/, "");
  src = liftMermaid(src, opts.steps ?? false);
  const file = await unified()
    .use(remarkParse)
    .use(remarkGfm)
    .use(remarkRehype, { allowDangerousHtml: true })
    .use(rehypeRaw)
    .use(rehypeSlug)
    .use(rehypeRepoLinks(opts.file ?? "README.md"))
    .use(rehypeStringify)
    .process(src);
  return String(file);
}
