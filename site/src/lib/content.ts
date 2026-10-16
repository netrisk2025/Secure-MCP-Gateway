import fs from "node:fs";
import path from "node:path";

/** Repository root: the site lives in <repo>/site and reads the documents beside it. */
export const REPO_ROOT = path.resolve(process.cwd(), "..");

export function readDoc(relPath: string): string {
  return fs.readFileSync(path.join(REPO_ROOT, relPath), "utf8");
}

export function docExists(relPath: string): boolean {
  return fs.existsSync(path.join(REPO_ROOT, relPath));
}

export function docMtime(relPath: string): string {
  const st = fs.statSync(path.join(REPO_ROOT, relPath));
  return st.mtime.toISOString().slice(0, 10);
}

/** Documents the site renders as long-form pages. */
export const DOCS: { slug: string; file: string; title: string; blurb: string }[] = [
  {
    slug: "architecture-v2",
    file: "ArchitectureV2.md",
    title: "Architecture",
    blurb: "Logical decomposition into subsystems, elements, functions, interfaces and data stores.",
  },
  {
    slug: "problem-space",
    file: "architecture.md",
    title: "Architecture 2.0, problem space",
    blurb: "Threats, Neo4j Community Edition limits, protocol pitfalls, race control and the engineering server catalog.",
  },
  {
    slug: "security-controls",
    file: "MCP_Gateway_Security_SRS.md",
    title: "Security-control SRS V1",
    blurb: "The 150 hierarchical controls that root every security requirement.",
  },
  {
    slug: "implementation-srs",
    file: "Secure_MCP_Gateway_SRS.md",
    title: "Implementation SRS",
    blurb: "Generated coding baseline: every requirement allocated to the architecture.",
  },
  {
    slug: "client-compatibility",
    file: "Client-Compatibility-Brief.md",
    title: "Client compatibility brief",
    blurb: "What Claude Code, Codex and Hermes expect today and where the specification must bend.",
  },
  {
    slug: "research-brief",
    file: "Secure-MCP-Gateway-Research-Brief.md",
    title: "Research brief, September 2026",
    blurb: "The original survey of gateways, policy engines, audit stacks, secrets tools and filters.",
  },
  {
    slug: "changelog",
    file: "CHANGELOG.md",
    title: "Changelog",
    blurb: "Baseline history and the revision procedure.",
  },
  {
    slug: "floorplan",
    file: "FloorPlan.md",
    title: "Repository floor plan",
    blurb: "What each file in the repository is for.",
  },
];
