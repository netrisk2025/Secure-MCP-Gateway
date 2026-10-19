// Bounded graph rendering for audit investigation (G-14, FR-8.22) in
// hand-built SVG. Two forms: the investigation path of one evidence event
// (event, call, decision, rule and policy revision, session, principal,
// tool and server revision) in a fixed layered layout, and the
// neighborhood of any mirrored node in a radial layout capped at the
// route's limit. Every node is a link or a button, reachable by keyboard;
// node properties are shown as text, never interpreted as markup.
import { useId, useState, type ReactNode } from "react";
import { navigate } from "./router";

export interface GNode {
  id: string;
  labels?: string[];
  properties?: Record<string, unknown>;
  [k: string]: unknown;
}

export interface EventPath {
  event: GNode | null;
  decision: GNode | null;
  invocation: GNode | null;
  session: GNode | null;
  principal: GNode | null;
  serverRevision: GNode | null;
  toolRevision: GNode | null;
  policyRevision: GNode | null;
  phases: { id: string; phase?: string }[];
}

export interface Neighborhood {
  node: GNode;
  neighbors: GNode[];
  edges: { type: string; from: string; to: string }[];
  degree: number;
  truncated: boolean;
}

/** Where a node of a label opens in the console. */
export function nodeHref(label: string, id: string): string {
  switch (label) {
    case "AuditEvent":
      return `/audit/events/${encodeURIComponent(id)}`;
    case "Session":
      return `/sessions/${encodeURIComponent(id)}`;
    case "Decision":
      return `/audit/decisions/${encodeURIComponent(id)}`;
    case "Invocation":
      return `/audit?correlation_id=${encodeURIComponent(id)}`;
    case "Principal":
      return `/audit?principal_id=${encodeURIComponent(id)}`;
    case "PolicyRevision":
      return `/policy/revisions/${encodeURIComponent(id)}`;
    case "Approval":
      return `/approvals/${encodeURIComponent(id)}`;
    default:
      return `/audit/graph?label=${encodeURIComponent(label)}&id=${encodeURIComponent(id)}`;
  }
}

const short = (s: string, n = 18) => (s.length > n ? s.slice(0, n - 5) + "…" + s.slice(-4) : s);

function NodeMark({ x, y, label, id, sub, current, onOpen, w = 150 }: { x: number; y: number; label: string; id: string; sub?: string; current?: boolean; onOpen: () => void; w?: number }) {
  const h = 40;
  const shownSub = sub ? short(sub, 12) : "";
  const shownId = short(id, Math.floor((w - 16) / 6.7));
  // The accessible name starts with the visible text (WCAG 2.5.3 label in
  // name), then the full ID and state when the mark shortens them.
  const visible = `${label}${shownSub ? ` ${shownSub}` : ""} ${shownId}`;
  const full = shownId !== id || shownSub !== (sub ?? "") ? `, ${id}${sub ? `, ${sub}` : ""}` : "";
  return (
    <g
      className={current ? "gnode gnode-current" : "gnode"}
      tabIndex={0}
      role="link"
      aria-label={visible + full}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          onOpen();
        }
      }}
    >
      <rect x={x - w / 2} y={y - h / 2} width={w} height={h} rx="2" />
      {/* One text element, so the visible text reads "label state ID" with spaces. */}
      <text x={x - w / 2 + 8} y={y - 5} className="gnode-label">
        {label}
        {sub && <tspan className="gnode-sub"> {shownSub}</tspan>}
        <tspan x={x - w / 2 + 8} dy={16} className="gnode-id">
          {" "}
          {shownId}
        </tspan>
      </text>
    </g>
  );
}

function Edge({ a, b, label }: { a: [number, number]; b: [number, number]; label?: string }) {
  return (
    <g className="gedge">
      <line x1={a[0]} y1={a[1]} x2={b[0]} y2={b[1]} />
      {label &&
        (a[0] === b[0] ? (
          <text x={a[0] + 6} y={(a[1] + b[1]) / 2} dy="0.32em">
            {label}
          </text>
        ) : (
          <text x={(a[0] + b[0]) / 2} y={(a[1] + b[1]) / 2 - 5} textAnchor="middle">
            {label}
          </text>
        ))}
    </g>
  );
}

const prop = (n: GNode | null, k: string): string | undefined => {
  if (!n) return undefined;
  const v = n[k] ?? n.properties?.[k];
  return v === undefined || v === null ? undefined : String(v);
};

/** The investigation path of one event in a layered layout. */
export function EventPathGraph({ path }: { path: EventPath }) {
  const id = useId();
  // Column x, row y of each member; edges follow the mirror's relationships.
  const W = 880;
  const col = [80, 310, 540, 770];
  const row = [40, 110, 180];
  type Slot = { key: keyof EventPath; label: string; x: number; y: number; sub?: string };
  const slots: Slot[] = [
    { key: "principal", label: "Principal", x: col[0]!, y: row[0]! },
    { key: "session", label: "Session", x: col[1]!, y: row[0]!, sub: prop(path.session, "state") },
    { key: "invocation", label: "Invocation", x: col[2]!, y: row[0]!, sub: prop(path.invocation, "outcome") },
    { key: "event", label: "AuditEvent", x: col[3]!, y: row[0]!, sub: prop(path.event, "phase") ?? prop(path.event, "class") },
    { key: "decision", label: "Decision", x: col[2]!, y: row[1]!, sub: prop(path.decision, "outcome") },
    { key: "policyRevision", label: "PolicyRevision", x: col[3]!, y: row[1]! },
    { key: "toolRevision", label: "ToolRevision", x: col[2]!, y: row[2]!, sub: prop(path.toolRevision, "name") },
    { key: "serverRevision", label: "ServerRevision", x: col[3]!, y: row[2]! },
  ];
  const present = slots.filter((s) => path[s.key] && (path[s.key] as GNode).id);
  const at = (k: keyof EventPath) => present.find((s) => s.key === k);
  const edges: [keyof EventPath, keyof EventPath, string][] = [
    ["principal", "session", "OF_PRINCIPAL"],
    ["session", "invocation", "IN_SESSION"],
    ["invocation", "event", "PHASE"],
    ["invocation", "decision", "DECIDED_BY"],
    ["decision", "policyRevision", "UNDER"],
    ["invocation", "toolRevision", "CALLS"],
    ["toolRevision", "serverRevision", "OF_SERVER"],
  ];
  const decisive = prop(path.decision, "decisiveRules") ?? prop(path.decision, "rules");
  return (
    <figure className="graph">
      <figcaption id={id}>Investigation path: {present.length} of 8 related nodes found in the graph mirror. Select a node to open it.</figcaption>
      <div className="graph-scroll">
        <svg width={W} height={220} role="group" aria-labelledby={id}>
          {edges.map(([a, b, l]) => {
            const sa = at(a);
            const sb = at(b);
            return sa && sb ? <Edge key={a + b} a={[sa.x, sa.y]} b={[sb.x, sb.y]} label={l} /> : null;
          })}
          {present.map((s) => {
            const n = path[s.key] as GNode;
            return <NodeMark key={s.key} x={s.x} y={s.y} w={140} label={s.label} id={n.id} sub={s.sub} current={s.key === "event"} onOpen={() => navigate(nodeHref(s.label, n.id))} />;
          })}
        </svg>
      </div>
      {decisive && <p className="small">Decisive rules: <span className="mono">{decisive}</span></p>}
      {path.phases.length > 0 && (
        <p className="small">
          Phases of the call:{" "}
          {path.phases.map((p, i) => (
            <span key={p.id}>
              {i > 0 && " then "}
              <a href={nodeHref("AuditEvent", p.id)} onClick={(e) => { e.preventDefault(); navigate(nodeHref("AuditEvent", p.id)); }} className="mono">
                {p.phase ?? short(p.id)}
              </a>
            </span>
          ))}
        </p>
      )}
    </figure>
  );
}

/** A node and its bounded neighborhood in a radial layout. */
export function NeighborhoodGraph({ data, label, onRecenter }: { data: Neighborhood; label: string; onRecenter: (label: string, id: string) => void }) {
  const id = useId();
  const [hover, setHover] = useState<string | null>(null);
  const n = data.neighbors.length;
  const W = 760;
  const H = n > 24 ? 560 : 440;
  const cx = W / 2;
  const cy = H / 2;
  const R = Math.min(W, H) / 2 - 46;
  const pos = new Map<string, [number, number]>();
  pos.set(data.node.id, [cx, cy]);
  data.neighbors.forEach((nb, i) => {
    const a = (i / Math.max(1, n)) * Math.PI * 2 - Math.PI / 2;
    pos.set(nb.id, [cx + R * Math.cos(a), cy + R * Math.sin(a)]);
  });
  const lab = (g: GNode) => g.labels?.[0] ?? "Node";
  const edgeLabel = (e: { type: string; from: string; to: string }): ReactNode => (hover && (e.from === hover || e.to === hover) ? e.type : undefined) as ReactNode;
  return (
    <figure className="graph">
      <figcaption id={id}>
        {label} <span className="mono">{data.node.id}</span>: {data.edges.length} of {data.degree} relationships shown
        {data.truncated ? " (truncated at the limit; raise it to see more)" : ""}. Select a neighbor to center it.
      </figcaption>
      <div className="graph-scroll">
        <svg width={W} height={H} role="group" aria-labelledby={id}>
          {data.edges.map((e, i) => {
            const a = pos.get(e.from);
            const b = pos.get(e.to);
            return a && b ? <Edge key={i} a={a} b={b} label={edgeLabel(e) as string | undefined} /> : null;
          })}
          {data.neighbors.map((nb) => {
            const [x, y] = pos.get(nb.id)!;
            return (
              <g key={nb.id} onPointerEnter={() => setHover(nb.id)} onPointerLeave={() => setHover(null)} onFocus={() => setHover(nb.id)} onBlur={() => setHover(null)}>
                <NodeMark x={x} y={y} w={n > 24 ? 110 : 140} label={lab(nb)} id={nb.id} onOpen={() => onRecenter(lab(nb), nb.id)} />
              </g>
            );
          })}
          <NodeMark x={cx} y={cy} label={lab(data.node)} id={data.node.id} current onOpen={() => navigate(nodeHref(lab(data.node), data.node.id))} />
        </svg>
      </div>
    </figure>
  );
}
