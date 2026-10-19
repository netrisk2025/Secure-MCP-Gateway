import type { ReqStatus } from "@/lib/status";
import { REQ_STATUSES, REQ_STATUS_MEANING, REQ_STATUS_TEXT } from "@/lib/labels";
import { ReqBadge } from "@/components/Sheet";
import { barPath, niceTicks, truncate } from "./scale";

export type VerificationRow = {
  id: string;
  name: string;
  group: string;
  counts: Record<ReqStatus, number>;
  /** Shown in place of a bar, e.g. when the status data has no entry for the element. */
  note?: string;
};

const W = 720;
const LABEL_W = 236;
const TIP_W = 64;
const ROW = 22;
const BAR = 12;
const GROUP_ROW = 26;
const AXIS = 44;
const GAP = 2;

/**
 * Requirement verification per element as horizontal stacked bars, one per
 * element, on a shared count axis so bar lengths compare across elements.
 * Segments run verified, partial, failing, then unverified as the track.
 */
export default function VerificationBars({
  id,
  title,
  desc,
  rows,
}: {
  id: string;
  title: string;
  desc: string;
  rows: VerificationRow[];
}) {
  const max = Math.max(1, ...rows.map((r) => REQ_STATUSES.reduce((a, s) => a + r.counts[s], 0)));
  const ticks = niceTicks(max, 5);
  const end = ticks[ticks.length - 1];
  const x0 = LABEL_W;
  const x1 = W - TIP_W;
  const sx = (v: number) => x0 + ((x1 - x0) * v) / end;

  // Lay out rows with a caption row before each group.
  type Placed = { kind: "group"; y: number; label: string } | { kind: "row"; y: number; row: VerificationRow };
  const placed: Placed[] = [];
  let y = 8;
  let lastGroup = "";
  for (const r of rows) {
    if (r.group !== lastGroup) {
      placed.push({ kind: "group", y, label: r.group });
      y += GROUP_ROW;
      lastGroup = r.group;
    }
    placed.push({ kind: "row", y, row: r });
    y += ROW;
  }
  const plotBottom = y + 4;
  const H = plotBottom + AXIS;

  return (
    <figure className="chart" aria-labelledby={`${id}-t`}>
      <figcaption id={`${id}-t`} className="chart-title">
        {title}
      </figcaption>
      <ul className="legend" aria-label="Legend">
        {REQ_STATUSES.map((s) => (
          <li key={s} title={REQ_STATUS_MEANING[s]}>
            <ReqBadge status={s} />
          </li>
        ))}
      </ul>
      <div className="chart-scroll">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          width={W}
          height={H}
          role="img"
          aria-labelledby={`${id}-svgt ${id}-svgd`}
          className="chart-svg"
        >
          <title id={`${id}-svgt`}>{title}</title>
          <desc id={`${id}-svgd`}>{desc}</desc>
          {ticks.map((t) => (
            <g key={t}>
              <line className="grid" x1={sx(t)} x2={sx(t)} y1={4} y2={plotBottom} />
              <text className="tick" x={sx(t)} y={plotBottom + 18} textAnchor="middle">
                {t}
              </text>
            </g>
          ))}
          <line className="baseline" x1={x0} x2={x0} y1={4} y2={plotBottom} />
          {placed.map((p) => {
            if (p.kind === "group")
              return (
                <text key={`g-${p.label}`} className="group-label" x={0} y={p.y + 16}>
                  {p.label}
                </text>
              );
            const r = p.row;
            const total = REQ_STATUSES.reduce((a, s) => a + r.counts[s], 0);
            const by = p.y + (ROW - BAR) / 2;
            const tip =
              `${r.id} ${r.name}\n` +
              REQ_STATUSES.map((s) => `${REQ_STATUS_TEXT[s]} ${r.counts[s]}`).join("\n") +
              `\ntotal ${total}`;
            let cx = x0;
            const segs = REQ_STATUSES.filter((s) => r.counts[s] > 0);
            return (
              <g key={r.id} data-tip={tip} className="bar-row">
                <rect className="hit" x={0} y={p.y} width={W} height={ROW} />
                <text className="row-id" x={0} y={p.y + 15}>
                  {r.id}
                </text>
                <text className="row-name" x={44} y={p.y + 15}>
                  {truncate(r.name, 28)}
                </text>
                {total === 0 ? (
                  <text className="row-none" x={x0 + 6} y={p.y + 15}>
                    {r.note ?? "no requirements allocated"}
                  </text>
                ) : (
                  segs.map((s, i) => {
                    const segW = ((x1 - x0) * r.counts[s]) / end;
                    const last = i === segs.length - 1;
                    // A 2px surface gap separates touching segments; only the data end is rounded.
                    const drawW = Math.max(1, segW - (last ? 0 : GAP));
                    const d = last ? barPath(cx, by, drawW, BAR, 4) : `M${cx},${by}h${drawW}v${BAR}h${-drawW}Z`;
                    cx += segW;
                    return <path key={s} className={`seg seg-${s}`} d={d} />;
                  })
                )}
                {total > 0 && (
                  <text className="tip-label" x={sx(total) + 6} y={p.y + 15}>
                    {r.counts.verified}/{total}
                  </text>
                )}
              </g>
            );
          })}
          <text className="axis-title" x={x1} y={H - 2} textAnchor="end">
            requirements allocated
          </text>
        </svg>
      </div>
      <p className="chart-key">
        Bar length is the number of requirements allocated to the element; the figure at the end is verified out of
        allocated.
      </p>
      <details className="chart-data">
        <summary>Data table</summary>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Element</th>
                <th scope="col">Name</th>
                {REQ_STATUSES.map((s) => (
                  <th key={s} scope="col" className="num">
                    {REQ_STATUS_TEXT[s]}
                  </th>
                ))}
                <th scope="col" className="num">
                  total
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="id">{r.id}</td>
                  <td>{r.name}</td>
                  {REQ_STATUSES.map((s) => (
                    <td key={s} className="num">
                      {r.counts[s]}
                    </td>
                  ))}
                  <td className="num">{REQ_STATUSES.reduce((a, s) => a + r.counts[s], 0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}
