/**
 * Read the messages out of a Mermaid diagram so each diagram can carry a
 * numbered step table. Sequence diagrams yield their messages in source order,
 * which is the order Mermaid's autonumber uses. Flowcharts yield their edges in
 * source order with node labels resolved.
 */

export type DiagramKind = "sequence" | "flowchart" | "other";

export type Step = {
  n: number;
  from: string;
  to: string;
  label: string;
  /** Enclosing block: a loop/alt/opt label in a sequence diagram, a subgraph title in a flowchart. */
  context: string;
  /** The arrow as drawn. Sequence: "solid", "dashed", "async". Flowchart: "flow", "link", "dotted", "thick". */
  style: string;
};

export type ParsedDiagram = { kind: DiagramKind; steps: Step[] };

function clean(label: string): string {
  return label
    .replace(/^["'`]|["'`]$/g, "")
    .replace(/<br\s*\/?>/gi, " ")
    .replace(/&quot;/g, '"')
    .replace(/#quot;/g, '"')
    .replace(/<[^>]+>/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function kindOf(src: string): DiagramKind {
  const first = src
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l && !l.startsWith("%%") && !l.startsWith("---"));
  if (!first) return "other";
  if (/^sequenceDiagram\b/.test(first)) return "sequence";
  if (/^(flowchart|graph)\b/.test(first)) return "flowchart";
  return "other";
}

/* Sequence diagrams ---------------------------------------------------- */

const SEQ_ARROW = /^(.+?)\s*(<<-->>|<<->>|-->>|->>|-->|->|--x|-x|--\)|-\))\s*([+-]?)\s*([^:]+?)\s*:\s*(.*)$/;
const SEQ_BLOCK = /^(loop|alt|else|opt|par|and|critical|option|break|rect|box)\b\s*(.*)$/;

function parseSequence(src: string): Step[] {
  const names = new Map<string, string>();
  const steps: Step[] = [];
  const stack: string[] = [];
  // "autonumber 13" starts the numbering at 13: a diagram drawn in parts
  // keeps one sequence of step numbers across its parts.
  let first = 1;
  for (const raw of src.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("%%")) continue;
    const a = line.match(/^autonumber\s+(\d+)\b/);
    if (a) {
      if (!steps.length) first = Number(a[1]);
      continue;
    }
    const p = line.match(/^(participant|actor)\s+(\S+?)(?:\s+as\s+(.+))?$/);
    if (p) {
      names.set(p[2], clean(p[3] ?? p[2]));
      continue;
    }
    const b = line.match(SEQ_BLOCK);
    if (b) {
      const label = clean(b[2] ?? "");
      if (b[1] === "else" || b[1] === "and" || b[1] === "option") stack[stack.length - 1] = `${b[1]} ${label}`.trim();
      else stack.push(b[1] === "rect" || b[1] === "box" ? "" : `${b[1]} ${label}`.trim());
      continue;
    }
    if (line === "end") {
      stack.pop();
      continue;
    }
    const m = line.match(SEQ_ARROW);
    if (!m) continue;
    const from = m[1].trim();
    const to = m[4].trim();
    const arrow = m[2];
    const style = arrow.endsWith(")") ? "async" : arrow.startsWith("--") || arrow.startsWith("<<--") ? "dashed" : "solid";
    steps.push({
      n: first + steps.length,
      from: names.get(from) ?? clean(from),
      to: names.get(to) ?? clean(to),
      label: clean(m[5]),
      context: stack.filter(Boolean).join(" / "),
      style,
    });
  }
  return steps;
}

/* Flowcharts ----------------------------------------------------------- */

// Node shapes, longest delimiters first. Group 1 id, group 2 open, group 3 label.
const SHAPES: [string, string][] = [
  ["(((", ")))"],
  ["([", "])"],
  ["[[", "]]"],
  ["[(", ")]"],
  ["((", "))"],
  ["{{", "}}"],
  ["[/", "/]"],
  ["[\\", "\\]"],
  ["[/", "\\]"],
  ["[\\", "/]"],
  ["[", "]"],
  ["(", ")"],
  ["{", "}"],
  [">", "]"],
];

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

// A node reference with an optional shape; quoted labels may contain any delimiter.
const NODE_RE = new RegExp(
  "([A-Za-z0-9_]+)\\s*(?:" +
    SHAPES.map(([o, c]) => `${esc(o)}\\s*(?:"([^"]*)"|((?:(?!${esc(c)}).)*?))\\s*${esc(c)}`).join("|") +
    ")",
  "g",
);

// Edge operators, with optional |label| or inline "-- label -->" forms.
const EDGE_RE =
  /\s*(?:(<?-{2,}>|<?-{3,}|<?-\.+->|-\.+-|<?={2,}>|={3,}|--o|--x|o--o|x--x|~~~)(?:\s*\|([^|]*)\|)?|--\s+(.+?)\s+-->|-\.\s+(.+?)\s+\.->|==\s+(.+?)\s+==>)\s*/;

function edgeStyle(op: string): string {
  if (op.includes(".")) return "dotted";
  if (op.includes("=")) return "thick";
  if (op.includes(">")) return "flow";
  return "link";
}

function parseFlowchart(src: string): Step[] {
  const labels = new Map<string, string>();
  const subgraphs = new Map<string, string>();
  const steps: Step[] = [];
  const stack: string[] = [];
  const lines = src.split("\n").slice(1);

  // First pass: labels for every node and subgraph, wherever they are defined.
  for (const raw of lines) {
    const line = raw.trim();
    const sg = line.match(/^subgraph\s+([^\s[]+)\s*(?:\[\s*"?(.*?)"?\s*\])?\s*$/);
    if (sg) {
      subgraphs.set(sg[1], clean(sg[2] || sg[1]));
      continue;
    }
    for (const m of line.matchAll(NODE_RE)) {
      const id = m[1];
      const label = m.slice(2).find((g) => g !== undefined);
      // A node's name in the step table is the first line of its label; later lines are detail.
      if (label !== undefined && !labels.has(id)) labels.set(id, clean(label.split(/<br\s*\/?>/i)[0]) || id);
    }
  }

  const name = (id: string) => labels.get(id) ?? subgraphs.get(id) ?? id;

  for (const raw of lines) {
    const line = raw.trim().replace(/;$/, "");
    if (!line || line.startsWith("%%")) continue;
    const sg = line.match(/^subgraph\s+([^\s[]+)/);
    if (sg) {
      stack.push(subgraphs.get(sg[1]) ?? sg[1]);
      continue;
    }
    if (line === "end") {
      stack.pop();
      continue;
    }
    if (/^(style|classDef|class|click|linkStyle|direction)\b/.test(line)) continue;
    // Reduce node definitions to their ids, then split on edge operators.
    let rest = line.replace(NODE_RE, (_m, id: string) => id).replace(/:::[\w-]+/g, "");
    const groups: string[] = [];
    const ops: { style: string; label: string }[] = [];
    for (;;) {
      const m = rest.match(EDGE_RE);
      if (!m || m.index === undefined) {
        groups.push(rest.trim());
        break;
      }
      groups.push(rest.slice(0, m.index).trim());
      const op = m[1] ?? (m[3] ? "-->" : m[4] ? "-.->" : "==>");
      ops.push({ style: edgeStyle(op), label: clean(m[2] ?? m[3] ?? m[4] ?? m[5] ?? "") });
      rest = rest.slice(m.index + m[0].length);
    }
    if (!ops.length) continue;
    for (let i = 0; i < ops.length; i++) {
      const froms = groups[i].split("&").map((s) => s.trim()).filter(Boolean);
      const tos = groups[i + 1].split("&").map((s) => s.trim()).filter(Boolean);
      for (const f of froms)
        for (const t of tos)
          steps.push({
            n: steps.length + 1,
            from: name(f),
            to: name(t),
            label: ops[i].label,
            context: stack.join(" / "),
            style: ops[i].style,
          });
    }
  }
  return steps;
}

export function parseDiagram(src: string): ParsedDiagram {
  const kind = kindOf(src);
  if (kind === "sequence") return { kind, steps: parseSequence(src) };
  if (kind === "flowchart") return { kind, steps: parseFlowchart(src) };
  return { kind, steps: [] };
}

/**
 * Sequence diagrams are drawn with autonumber so the numbers on the arrows
 * match the step table. Flowcharts have no numbering mechanism; their table
 * follows the order the edges are written.
 */
export function withAutonumber(src: string): string {
  if (kindOf(src) !== "sequence" || /^\s*autonumber\b/m.test(src)) return src;
  return src.replace(/^(\s*sequenceDiagram\b.*)$/m, "$1\n  autonumber");
}
