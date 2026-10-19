import { readDoc } from "./content";

export type Element = {
  id: string;
  name: string;
  trust: "T0" | "T1" | "T2";
  trustNote: string;
  subsystem: string;
  subsystemId: string;
  purpose: string;
  functions: string[];
  interfaces: string[];
  ownedData: string;
  allocationTargets: string;
};

export type Fn = { id: string; name: string; owner: string; phase: string; summary: string };
export type ExtIface = { id: string; name: string; between: string; direction: string; content: string; topics: string };
export type IntIface = { id: string; fromTo: string; purpose: string; content: string };
export type DataStore = { id: string; name: string; host: string; owner: string; contents: string; protection: string };
export type GuiModule = { id: string; name: string; users: string; purpose: string };
export type OpenDecision = { id: string; decision: string; options: string; recommendation: string };
export type Subsystem = { id: string; name: string; elementIds: string[] };

export type Arch = {
  revision: string;
  date: string;
  subsystems: Subsystem[];
  elements: Element[];
  functions: Fn[];
  external: ExtIface[];
  internal: IntIface[];
  stores: DataStore[];
  gui: GuiModule[];
  decisions: OpenDecision[];
  trustLevels: Record<string, string>;
};

function section(md: string, headingRe: RegExp): string {
  const lines = md.split("\n");
  let start = -1;
  let level = 0;
  for (let i = 0; i < lines.length; i++) {
    if (start < 0) {
      if (headingRe.test(lines[i])) {
        start = i + 1;
        level = (lines[i].match(/^#+/) ?? ["#"])[0].length;
      }
    } else {
      const m = lines[i].match(/^(#+)\s/);
      if (m && m[1].length <= level) return lines.slice(start, i).join("\n");
    }
  }
  return start < 0 ? "" : lines.slice(start).join("\n");
}

/**
 * A section the site depends on. A missing heading means the document changed
 * shape; fail the build instead of publishing pages with empty tables.
 */
function required(md: string, headingRe: RegExp, what: string): string {
  const body = section(md, headingRe);
  if (!body.trim()) {
    throw new Error(
      `ArchitectureV2.md: expected section ${headingRe} (${what}) was not found or is empty. ` +
        "Update site/src/lib/parse-arch.ts if the document was restructured.",
    );
  }
  return body;
}

function nonEmpty<T>(rows: T[], what: string): T[] {
  if (rows.length === 0) {
    throw new Error(
      `ArchitectureV2.md: no ${what} rows were parsed. The table format changed; update site/src/lib/parse-arch.ts.`,
    );
  }
  return rows;
}

function strip(s: string): string {
  return s.replace(/\*\*/g, "").replace(/(^|[\s(])\*([^*\n]+?)\*(?=[\s).,;:]|$)/g, "$1$2").trim();
}

function tableRows(text: string, idRe: RegExp): string[][] {
  const rows: string[][] = [];
  for (const line of text.split("\n")) {
    if (!line.startsWith("|")) continue;
    const cells = line
      .slice(1, line.endsWith("|") ? -1 : undefined)
      .split("|")
      .map((c) => c.trim());
    if (cells.length < 2) continue;
    if (idRe.test(strip(cells[0]))) rows.push(cells);
  }
  return rows;
}

let memo: Arch | null = null;

export function loadArch(): Arch {
  if (memo) return memo;
  const md = readDoc("ArchitectureV2.md");
  const revision = (md.match(/\*\*Revision:\*\*\s*(.*)/) ?? ["", ""])[1].trim();
  const date = (md.match(/\*\*Date:\*\*\s*([\d-]+)/) ?? ["", ""])[1].trim();
  if (!revision || !date) throw new Error("ArchitectureV2.md: the **Revision:** or **Date:** line is missing.");

  // Subsystems from the decomposition overview table.
  const subsystems: Subsystem[] = nonEmpty(
    tableRows(required(md, /^## 3\. Decomposition overview/, "decomposition overview"), /^SS-\d+/),
    "subsystem",
  ).map((c) => {
    const head = strip(c[0]);
    const m = head.match(/^(SS-\d+)\s+(.*)$/);
    if (!m) throw new Error(`ArchitectureV2.md: subsystem row "${head}" is not "SS-n Name".`);
    return { id: m[1], name: m[2], elementIds: Array.from(c[1].matchAll(/E-\d\d/g)).map((x) => x[0]) };
  });

  // Elements: #### E-xx Name — Tn [...] followed by bullets.
  const elements: Element[] = [];
  const elemSec = required(md, /^## 4\. Element specifications/, "element specifications");
  let curSS: Subsystem | undefined;
  const lines = elemSec.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const ss = lines[i].match(/^### (SS-\d+)\s+(.*)$/);
    if (ss) {
      curSS = subsystems.find((s) => s.id === ss[1]) ?? { id: ss[1], name: ss[2], elementIds: [] };
      continue;
    }
    const em = lines[i].match(/^#### (E-\d\d) (.*?) — (T\d)(.*)$/);
    if (!em) continue;
    const el: Element = {
      id: em[1],
      name: em[2].trim(),
      trust: em[3] as Element["trust"],
      trustNote: strip(em[4]).replace(/^\(|\)$/g, ""),
      subsystem: curSS?.name ?? "",
      subsystemId: curSS?.id ?? "",
      purpose: "",
      functions: [],
      interfaces: [],
      ownedData: "",
      allocationTargets: "",
    };
    for (let j = i + 1; j < lines.length && !lines[j].startsWith("#"); j++) {
      const b = lines[j].match(/^- \*\*(.*?):\*\*\s*(.*)$/);
      if (!b) continue;
      const key = b[1].toLowerCase();
      const val = b[2].trim();
      if (key === "purpose") el.purpose = strip(val);
      else if (key === "functions") el.functions = Array.from(val.matchAll(/F-\d\d/g)).map((x) => x[0]);
      else if (key === "interfaces") el.interfaces = Array.from(val.matchAll(/[XI]-\d\d/g)).map((x) => x[0]);
      else if (key === "owned data") el.ownedData = strip(val);
      else if (key === "allocation targets") el.allocationTargets = strip(val);
    }
    elements.push(el);
  }
  nonEmpty(elements, "element");
  for (const el of elements) {
    if (!el.subsystemId) throw new Error(`ArchitectureV2.md: ${el.id} is not under an "### SS-n" heading.`);
    if (!el.purpose) throw new Error(`ArchitectureV2.md: ${el.id} has no "- **Purpose:**" bullet.`);
  }

  const functions: Fn[] = nonEmpty(
    tableRows(required(md, /^## 5\. Function catalog/, "function catalog"), /^F-\d\d$/),
    "function",
  ).map((c) => ({
    id: c[0],
    name: c[1],
    owner: c[2],
    phase: c[3],
    summary: c[4] ?? "",
  }));

  const external: ExtIface[] = nonEmpty(
    tableRows(required(md, /^### 6\.1 External interfaces/, "external interfaces"), /^X-\d\d$/),
    "external interface",
  ).map((c) => ({
    id: strip(c[0]),
    name: c[1],
    between: c[2],
    direction: c[3],
    content: c[4],
    topics: c[5] ?? "",
  }));

  const internal: IntIface[] = nonEmpty(
    tableRows(required(md, /^### 6\.2 Internal interfaces/, "internal interfaces"), /^I-\d\d$/),
    "internal interface",
  ).map((c) => ({
    id: c[0],
    fromTo: c[1],
    purpose: c[2],
    content: c[3] ?? "",
  }));

  const stores: DataStore[] = nonEmpty(
    tableRows(required(md, /^## 13\. Data stores/, "data stores"), /^D-\d\d$/),
    "data store",
  ).map((c) => ({
    id: c[0],
    name: c[1],
    host: c[2],
    owner: c[3],
    contents: c[4],
    protection: c[5] ?? "",
  }));

  const gui: GuiModule[] = nonEmpty(
    tableRows(required(md, /^#### E-24 /, "console view modules"), /^G-\d\d$/),
    "console view module",
  ).map((c) => ({
    id: c[0],
    name: c[1],
    users: c[2],
    purpose: c[3] ?? "",
  }));

  const decisions: OpenDecision[] = tableRows(required(md, /^## 19\. Open decisions/, "open decisions"), /^OD-\d+$/).map(
    (c) => ({
      id: c[0],
      decision: c[1],
      options: c[2],
      recommendation: c[3] ?? "",
    }),
  );

  memo = {
    revision,
    date,
    subsystems,
    elements,
    functions,
    external,
    internal,
    stores,
    gui,
    decisions,
    trustLevels: {
      T0: "Trusted computing base. Compromise defeats the security guarantee.",
      T1: "Security-enforcing. Compromise defeats specific controls.",
      T2: "Security-supporting.",
      U: "Untrusted and contained.",
    },
  };
  return memo;
}
