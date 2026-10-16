import { unified } from "unified";
import remarkParse from "remark-parse";
import remarkGfm from "remark-gfm";
import remarkRehype from "remark-rehype";
import rehypeRaw from "rehype-raw";
import rehypeSlug from "rehype-slug";
import rehypeStringify from "rehype-stringify";
import GithubSlugger from "github-slugger";

export type TocEntry = { depth: number; text: string; id: string };

/** Replace ```mermaid fences with a placeholder the client renders. */
function liftMermaid(md: string): string {
  return md.replace(/```mermaid\n([\s\S]*?)```/g, (_m, body: string) => {
    const b64 = Buffer.from(body, "utf8").toString("base64");
    return `<div class="mermaid-block" data-mermaid="${b64}"><pre class="mermaid-fallback">${escapeHtml(body)}</pre></div>`;
  });
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
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
    if (depth < 2 || depth > maxDepth) continue;
    const text = m[2].replace(/[*`]/g, "").trim();
    out.push({ depth, text, id: slugger.slug(text) });
  }
  return out;
}

export async function renderMarkdown(md: string, opts: { dropTitle?: boolean } = {}): Promise<string> {
  let src = md;
  if (opts.dropTitle) src = src.replace(/^# .*\n/, "");
  src = liftMermaid(src);
  const file = await unified()
    .use(remarkParse)
    .use(remarkGfm)
    .use(remarkRehype, { allowDangerousHtml: true })
    .use(rehypeRaw)
    .use(rehypeSlug)
    .use(rehypeStringify)
    .process(src);
  return String(file);
}
