import fs from "node:fs";
import path from "node:path";
import GithubSlugger from "github-slugger";
import { REPO_ROOT, flowSlug, readDoc } from "./content";
import { parseDiagram, type ParsedDiagram } from "./diagram";

export type Flow = {
  slug: string;
  title: string;
  /** Repository-relative source file. */
  file: string;
  /** "flow" for docs/flows/*.md, "architecture" for a diagram lifted from ArchitectureV2.md. */
  origin: "flow" | "architecture";
  /** Markdown to render: the whole flow document, or the architecture section around one diagram. */
  markdown: string;
  diagrams: ParsedDiagram[];
};

const FLOW_DIR = "docs/flows";
const MERMAID = /```mermaid\n([\s\S]*?)```/g;

function diagramsIn(md: string): ParsedDiagram[] {
  return Array.from(md.matchAll(MERMAID), (m) => parseDiagram(m[1]));
}

/**
 * docs/flows/*.md, sorted by file name. A missing or empty directory yields no
 * flows. SITE_FLOWS_DIR points at another directory, for testing the renderer.
 */
function flowDocs(): Flow[] {
  const dir = process.env.SITE_FLOWS_DIR?.trim() || path.join(REPO_ROOT, FLOW_DIR);
  let files: string[] = [];
  try {
    files = fs
      .readdirSync(dir)
      .filter((f) => f.endsWith(".md") && f.toLowerCase() !== "readme.md")
      .sort();
  } catch {
    return [];
  }
  return files.map((f) => {
    const md = fs.readFileSync(path.join(dir, f), "utf8");
    const title = (md.match(/^# (.+)$/m)?.[1] ?? f.replace(/\.md$/, "").replace(/[-_]/g, " ")).trim();
    return {
      slug: flowSlug(f),
      title,
      file: `${FLOW_DIR}/${f}`,
      origin: "flow" as const,
      markdown: md,
      diagrams: diagramsIn(md),
    };
  });
}

/**
 * Each section of ArchitectureV2.md that holds Mermaid diagrams, with its
 * heading and text up to the next heading. The diagrams of one section form
 * one entry, so a diagram drawn in parts stays on one page.
 */
function architectureDiagrams(): Flow[] {
  const md = readDoc("ArchitectureV2.md");
  const lines = md.split("\n");
  const out: Flow[] = [];
  const slugger = new GithubSlugger();
  let heading = "";
  let headingLine = 0;
  let inFence = false;
  // The entry of the current section, until the next heading.
  let open: Flow | null = null;
  const close = (upTo: number) => {
    if (!open) return;
    const rest = lines.slice(headingLine + 1, upTo).join("\n").trim();
    if (rest) open.markdown += `\n${rest}\n`;
    open = null;
  };
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.startsWith("```")) {
      if (!inFence && l.startsWith("```mermaid")) {
        // Section text from the heading, or from the previous diagram, to the end of this diagram.
        let end = i + 1;
        while (end < lines.length && !lines[end].startsWith("```")) end++;
        const body = lines.slice(headingLine + 1, end + 1).join("\n");
        if (open) {
          open.markdown += `\n${body}\n`;
          open.diagrams.push(...diagramsIn(body));
        } else {
          const title = heading.replace(/^[\d.]+\s+/, "").replace(/[*`]/g, "");
          open = {
            slug: `architecture-${slugger.slug(title)}`,
            title,
            file: "ArchitectureV2.md",
            origin: "architecture",
            markdown: `# ${title}\n\n${body}\n`,
            diagrams: diagramsIn(body),
          };
          out.push(open);
        }
        headingLine = end;
        i = end;
        continue;
      }
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    const h = l.match(/^#{2,4}\s+(.*)$/);
    if (h) {
      close(i);
      heading = h[1].trim();
      headingLine = i;
    }
  }
  close(lines.length);
  return out;
}

let memo: Flow[] | null = null;

export function loadFlows(): Flow[] {
  if (!memo) memo = [...flowDocs(), ...architectureDiagrams()];
  return memo;
}

export function flowSourceDir(): string {
  return FLOW_DIR;
}
