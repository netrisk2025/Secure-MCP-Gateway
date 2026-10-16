/**
 * One tool call, drawn as a path through the three control points.
 * The traveller animates once on load; reduced motion shows the static drawing.
 */
export default function Hero() {
  const gates = [
    { x: 250, label: "Access time", sub: "policy decides, before any server code runs" },
    { x: 560, label: "Run time", sub: "sandboxed server, brokered egress, runtime monitor" },
    { x: 870, label: "Response time", sub: "inspected and released, or withheld" },
  ];
  return (
    <figure className="hero-figure" aria-labelledby="hero-cap">
      <svg viewBox="0 40 1120 240" role="img" aria-describedby="hero-cap" className="hero-svg">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" />
          </marker>
        </defs>

        {/* harness */}
        <g className="hero-node">
          <rect x="24" y="118" width="120" height="64" rx="6" />
          <text x="84" y="146" textAnchor="middle" className="hero-node-label">
            Agent
          </text>
          <text x="84" y="166" textAnchor="middle" className="hero-node-sub">
            harness
          </text>
        </g>

        {/* server */}
        <g className="hero-node hero-node-untrusted">
          <rect x="976" y="118" width="120" height="64" rx="6" />
          <text x="1036" y="146" textAnchor="middle" className="hero-node-label">
            MCP server
          </text>
          <text x="1036" y="166" textAnchor="middle" className="hero-node-sub">
            signed, sandboxed
          </text>
        </g>

        {/* request path: forward along the top */}
        <path id="hero-req" className="hero-path" d="M 144 138 H 976" markerEnd="url(#arrow)" />
        {/* response path: back along the bottom */}
        <path id="hero-res" className="hero-path hero-path-return" d="M 976 164 H 144" markerEnd="url(#arrow)" />

        {/* gates */}
        {gates.map((g) => (
          <g key={g.label} className="hero-gate">
            <line x1={g.x} y1="92" x2={g.x} y2="208" />
            <circle cx={g.x} cy="138" r="7" />
            <circle cx={g.x} cy="164" r="7" />
            <text x={g.x} y="236" textAnchor="middle" className="hero-gate-label">
              {g.label}
            </text>
            <text x={g.x} y="258" textAnchor="middle" className="hero-gate-sub">
              {g.sub}
            </text>
          </g>
        ))}


      </svg>
      <figcaption id="hero-cap" className="visually-hidden">
        A tool call travels from the agent harness through access-time, run-time and response-time control points to a
        signed, sandboxed MCP server and back.
      </figcaption>
    </figure>
  );
}
