import { readDoc } from "./content";
import { parseDiagram, type ParsedDiagram } from "./diagram";
import { resolveRepoLink } from "./markdown";

/**
 * The system map: docs/flows/system-map.md holds one large Mermaid flowchart
 * and a "Stages" table naming its top-level subgraphs. The site gives it its
 * own page with pan and zoom (/flows/system-map/) instead of the generic flow
 * page, and lists the stages beside the chart.
 */

export const SYSTEM_MAP_FILE = "docs/flows/system-map.md";
export const SYSTEM_MAP_SLUG = "system-map";
export const SYSTEM_MAP_HREF = `/flows/${SYSTEM_MAP_SLUG}/`;
/** The static download written by scripts/render-system-map.mjs. */
export const SYSTEM_MAP_SVG = "/system-map.svg";

export type MapStage = {
  no: string;
  title: string;
  /** Subgraph ID in the Mermaid source. */
  id: string;
  summary: string;
  links: { text: string; href: string }[];
};

export type SystemMapDoc = {
  title: string;
  /** Mermaid source of the chart. */
  source: string;
  diagram: ParsedDiagram;
  stages: MapStage[];
  /** Markdown before the chart, without the title. */
  intro: string;
  /** Markdown after the chart, without the Stages section (the page shows the stages itself). */
  rest: string;
};

const LINK = /\[([^\]]+)\]\(([^)]+)\)/g;

function cells(row: string): string[] {
  return row
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((c) => c.trim());
}

/** Parses the Stages table; every stage must name a subgraph that exists in the chart. */
export function parseStages(md: string, source: string, file = SYSTEM_MAP_FILE): MapStage[] {
  const at = md.search(/^## Stages\s*$/m);
  if (at < 0) throw new Error(`${file}: no "## Stages" section`);
  const lines = md.slice(at).split("\n");
  const rows = lines.filter((l) => l.startsWith("|"));
  const head = cells(rows[0] ?? "").map((h) => h.toLowerCase());
  const col = (name: string) => {
    const i = head.indexOf(name);
    if (i < 0) throw new Error(`${file}: the Stages table has no "${name}" column`);
    return i;
  };
  const [cNo, cStage, cId, cWhat, cLinks] = [col("no."), col("stage"), col("subgraph"), col("what it shows"), col("detailed flows")];
  const stages = rows.slice(2).map((r) => {
    const c = cells(r);
    const id = c[cId].replace(/`/g, "");
    if (!new RegExp(`^\\s*subgraph\\s+${id}\\b`, "m").test(source)) throw new Error(`${file}: stage ${c[cNo]} names subgraph ${id}, which the chart does not have`);
    return {
      no: c[cNo],
      title: c[cStage],
      id,
      summary: c[cWhat].replace(/`/g, ""),
      links: Array.from(c[cLinks].matchAll(LINK), (m) => ({ text: m[1], href: resolveRepoLink(m[2], file) })),
    };
  });
  if (!stages.length) throw new Error(`${file}: the Stages table is empty`);
  return stages;
}

export function loadSystemMap(): SystemMapDoc {
  const md = readDoc(SYSTEM_MAP_FILE);
  const fence = md.match(/```mermaid\n([\s\S]*?)```/);
  if (!fence || fence.index === undefined) throw new Error(`${SYSTEM_MAP_FILE}: no Mermaid block`);
  const source = fence[1];
  const title = (md.match(/^# (.+)$/m)?.[1] ?? "System map").trim();
  const intro = md.slice(0, fence.index).replace(/^# .*\n/, "").trim();
  const after = md.slice(fence.index + fence[0].length);
  // Drop the Stages section: from its heading to the next level-2 heading.
  const rest = after.replace(/^## Stages\s*\n[\s\S]*?(?=^## |(?![\s\S]))/m, "").trim();
  return { title, source, diagram: parseDiagram(source), stages: parseStages(after, source), intro, rest };
}
