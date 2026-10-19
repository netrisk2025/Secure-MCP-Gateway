import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

/** Repository root: the site lives in <repo>/site and reads the documents beside it. */
export const REPO_ROOT = path.resolve(process.cwd(), "..");

export function readDoc(relPath: string): string {
  return fs.readFileSync(path.join(REPO_ROOT, relPath), "utf8");
}

export function docExists(relPath: string): boolean {
  return fs.existsSync(path.join(REPO_ROOT, relPath));
}

const mtimes = new Map<string, string>();

/**
 * Date of the last commit that touched a file. A fresh checkout gives every
 * file the same modification time, so git history is the reliable source;
 * the file system date is the fallback when history is unavailable.
 */
export function docMtime(relPath: string): string {
  const hit = mtimes.get(relPath);
  if (hit) return hit;
  let date = "";
  try {
    date = execFileSync("git", ["log", "-1", "--format=%cs", "--", relPath], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
  } catch {
    date = "";
  }
  if (!date) date = fs.statSync(path.join(REPO_ROOT, relPath)).mtime.toISOString().slice(0, 10);
  mtimes.set(relPath, date);
  return date;
}

/** A document the site renders as a long-form page under /docs/. */
export type DocEntry = {
  /** Path under /docs/ without leading or trailing slashes; contains "/" for documents in subdirectories. */
  slug: string;
  /** Repository-relative source file. */
  file: string;
  title: string;
  blurb: string;
  /** Section of the Documents chapter that lists the document. */
  group: string;
};

export function docHref(d: Pick<DocEntry, "slug">): string {
  return `/docs/${d.slug}/`;
}

/** Group of the specification and project documents at the repository root. */
export const ROOT_GROUP = "Specification and project";

/**
 * Documents outside docs/. They are listed by hand; everything under docs/
 * is found by walking the tree at build time.
 */
const ROOT_DOCS: Omit<DocEntry, "group">[] = [
  {
    slug: "architecture-v2",
    file: "ArchitectureV2.md",
    title: "Architecture",
    blurb: "Logical decomposition into subsystems, elements, functions, interfaces and data stores.",
  },
  {
    slug: "implementation-srs",
    file: "Secure_MCP_Gateway_SRS.md",
    title: "Implementation SRS",
    blurb: "Generated coding baseline: every requirement allocated to the architecture.",
  },
  {
    slug: "security-controls",
    file: "MCP_Gateway_Security_SRS.md",
    title: "Security-control SRS V1",
    blurb: "The hierarchical security controls that parent every security requirement.",
  },
  {
    slug: "client-compatibility",
    file: "Client-Compatibility-Brief.md",
    title: "Client compatibility brief",
    blurb: "What Claude Code, Codex and Hermes expect today and where the specification must bend.",
  },
  {
    slug: "problem-space",
    file: "architecture.md",
    title: "Architecture 2.0, problem space",
    blurb: "Threats, Neo4j Community Edition limits, protocol pitfalls, race control and the engineering server catalog.",
  },
  {
    slug: "research-brief",
    file: "Secure-MCP-Gateway-Research-Brief.md",
    title: "Research brief",
    blurb: "The original survey of gateways, policy engines, audit stacks, secrets tools and filters.",
  },
  {
    slug: "readme",
    file: "README.md",
    title: "Repository README",
    blurb: "What the product is, status, scope of v1, profiles, install, quick start and how to verify.",
  },
  {
    slug: "internals",
    file: "internal/README.md",
    title: "Architecture map of the Go packages",
    blurb: "Go packages mapped to architecture elements, the extension points and the residual gaps.",
  },
  {
    slug: "changelog",
    file: "CHANGELOG.md",
    title: "Changelog",
    blurb: "Baseline and implementation history and the revision procedure.",
  },
  {
    slug: "floorplan",
    file: "FloorPlan.md",
    title: "Repository floor plan",
    blurb: "What each path in the repository is for.",
  },
];

const DOCS_DIR = "docs";
/** docs/flows is rendered by the Flows chapter, not as documents. */
export const FLOWS_DIR = "docs/flows";
export const INDEX_FILE = "docs/README.md";

/** Group labels for subdirectories of docs/. A directory not listed takes its README's title. */
const DIR_GROUP: Record<string, string> = {
  api: "Control API",
  clients: "Client quick starts",
  runbooks: "Runbooks",
  operations: "Operations",
  verification: "Verification",
};

/** Slug of a flow document, shared by the Flows chapter and the link rewriter. */
export function flowSlug(fileName: string): string {
  return path.posix
    .basename(fileName)
    .replace(/\.md$/, "")
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-");
}

function walk(rel: string): string[] {
  let names: fs.Dirent[] = [];
  try {
    names = fs.readdirSync(path.join(REPO_ROOT, rel), { withFileTypes: true });
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const n of names) {
    const r = `${rel}/${n.name}`;
    if (n.isDirectory()) {
      if (r !== FLOWS_DIR) out.push(...walk(r));
    } else if (n.isFile() && n.name.endsWith(".md")) out.push(r);
  }
  return out;
}

/** Strip images, link targets, emphasis and HTML from Markdown, keeping code spans. */
function plainText(md: string): string {
  return md
    .replace(/!\[[^\]]*\]\([^)]*\)/g, "")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/<[^>]+>/g, "")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * The first sentence of the prose paragraph before the first section heading
 * of a document body, for the document list. A document without such a
 * paragraph is described by its section headings.
 */
export function firstSentence(md: string): string {
  let inFence = false;
  const para: string[] = [];
  const lines = md.split("\n");
  for (const line of lines) {
    if (line.startsWith("```")) {
      inFence = !inFence;
      if (para.length) break;
      continue;
    }
    if (inFence) continue;
    const t = line.trim();
    if (/^#{2,6}\s/.test(t)) break;
    if (!t) {
      if (para.length) break;
      continue;
    }
    if (/^(#|\||>|[-*+] |\d+\. |<!--|Updated:|Scope:|Reference:)/.test(t)) {
      if (para.length) break;
      continue;
    }
    para.push(t);
  }
  if (!para.length) {
    const heads: string[] = [];
    inFence = false;
    for (const line of lines) {
      if (line.startsWith("```")) inFence = !inFence;
      const h = !inFence && line.match(/^##\s+(.*)$/);
      if (h) heads.push(plainText(h[1]).replace(/\s*\(.*\)$/, ""));
    }
    return heads.length ? `Sections: ${heads.join(", ")}.` : "";
  }
  const text = plainText(para.join(" "));
  // End at the first full stop outside a code span that is followed by a space and a capital.
  let inCode = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "`") inCode = !inCode;
    if (!inCode && c === "." && /^ [A-Z(`]/.test(text.slice(i + 1, i + 3)) && !/\b(e\.g|i\.e|etc|vs)$/.test(text.slice(0, i))) {
      return text.slice(0, i + 1);
    }
  }
  return text;
}

/**
 * Where docs/README.md first links each file: its position and the heading of
 * the linking section. The index decides the order and grouping of the
 * Documents chapter, so listing a document in the index is enough to place it.
 */
export function indexPlacement(indexMd: string): Map<string, { pos: number; heading: string }> {
  const out = new Map<string, { pos: number; heading: string }>();
  let heading = "";
  let pos = 0;
  let inFence = false;
  for (const line of indexMd.split("\n")) {
    if (line.startsWith("```")) inFence = !inFence;
    if (inFence) continue;
    const h = line.match(/^##\s+(.*)$/);
    if (h) {
      heading = h[1].replace(/\s*\(.*\)\s*$/, "").trim();
      continue;
    }
    for (const m of line.matchAll(/\]\(([^)#\s]+)(?:#[^)]*)?\)/g)) {
      if (/^[a-z][a-z0-9+.-]*:/i.test(m[1])) continue;
      let target = path.posix.join(DOCS_DIR, m[1]);
      if (m[1].endsWith("/")) target = path.posix.join(target, "README.md");
      if (!out.has(target)) out.set(target, { pos: pos++, heading });
    }
  }
  return out;
}

/** /docs/ path of a file under docs/: docs/api/policy.md is api/policy, docs/clients/README.md is clients. */
export function docSlug(file: string): string {
  if (file === INDEX_FILE) return "documentation";
  const parts = file
    .slice(DOCS_DIR.length + 1)
    .replace(/\.md$/, "")
    .split("/");
  if (parts[parts.length - 1] === "README") parts.pop();
  return parts.map((p) => p.toLowerCase().replace(/[^a-z0-9-]+/g, "-")).join("/");
}

function titleOf(md: string, file: string): string {
  return (md.match(/^# (.+)$/m)?.[1] ?? path.posix.basename(file, ".md")).replace(/[`*]/g, "").trim();
}

let memo: { docs: DocEntry[]; groups: string[] } | null = null;

function build(): { docs: DocEntry[]; groups: string[] } {
  const place = docExists(INDEX_FILE) ? indexPlacement(readDoc(INDEX_FILE)) : new Map<string, { pos: number; heading: string }>();
  const found = walk(DOCS_DIR).map((file) => {
    const md = readDoc(file);
    const dir = file.split("/").length > 2 ? file.split("/")[1] : "";
    const p = place.get(file);
    let group: string;
    if (file === INDEX_FILE) group = "Start here";
    else if (dir) {
      const readme = `${DOCS_DIR}/${dir}/README.md`;
      group = DIR_GROUP[dir] ?? (docExists(readme) ? titleOf(readDoc(readme), readme) : dir);
    } else group = p?.heading || "Other documents";
    return {
      entry: { slug: docSlug(file), file, title: titleOf(md, file), blurb: firstSentence(md.replace(/^# .*\n/, "")), group },
      pos: file === INDEX_FILE ? -1 : (p?.pos ?? Number.MAX_SAFE_INTEGER),
    };
  });
  found.sort((a, b) => a.pos - b.pos || a.entry.file.localeCompare(b.entry.file));
  // Groups follow the index's section order; groups the index has no section for come after, in reading order.
  const headings = ["Start here", ...[...place.values()].sort((a, b) => a.pos - b.pos).map((p) => p.heading)];
  const groups: string[] = [];
  for (const h of headings) if (!groups.includes(h) && found.some((f) => f.entry.group === h)) groups.push(h);
  for (const f of found) if (!groups.includes(f.entry.group)) groups.push(f.entry.group);
  const docs = groups.flatMap((g) => found.filter((f) => f.entry.group === g).map((f) => f.entry));
  for (const d of ROOT_DOCS) {
    if (docExists(d.file)) docs.push({ ...d, group: ROOT_GROUP });
  }
  if (docs.some((d) => d.group === ROOT_GROUP)) groups.push(ROOT_GROUP);
  const seen = new Map<string, string>();
  for (const d of docs) {
    const prev = seen.get(d.slug);
    if (prev) throw new Error(`Documents ${prev} and ${d.file} both map to /docs/${d.slug}/; rename one.`);
    seen.set(d.slug, d.file);
  }
  return { docs, groups };
}

/** Every document the site renders under /docs/, in reading order. */
export function allDocs(): DocEntry[] {
  if (!memo) memo = build();
  return memo.docs;
}

/** Group names in the order the Documents chapter lists them. */
export function docGroups(): string[] {
  if (!memo) memo = build();
  return memo.groups;
}

/** In-page anchor of a group on the Documents index. */
export function groupAnchor(group: string): string {
  return `g-${group
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")}`;
}

export function docBySlug(slug: string): DocEntry | undefined {
  return allDocs().find((d) => d.slug === slug);
}

export function docByFile(file: string): DocEntry | undefined {
  return allDocs().find((d) => d.file === file);
}
