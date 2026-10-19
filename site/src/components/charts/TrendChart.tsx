import { compact, niceTicks, spreadLabels } from "./scale";

export type TrendSeries = {
  key: string;
  label: string;
  /** CSS class suffix that selects the series color, e.g. "verified" gives .ln-verified. */
  tone: string;
  values: number[];
};

export type TrendPoint = { commit: string; date: string };

const W = 720;
const H = 220;
const M = { top: 14, right: 132, bottom: 34, left: 44 };

/**
 * A line chart over CI runs, oldest to newest, one shared y axis from zero.
 * Points are spaced by run, not by clock time, because runs are irregular.
 */
export default function TrendChart({
  id,
  title,
  desc,
  points,
  series,
  unit = "",
  yMax,
  empty,
}: {
  id: string;
  title: string;
  desc: string;
  points: TrendPoint[];
  series: TrendSeries[];
  unit?: string;
  yMax?: number;
  empty: string;
}) {
  const n = points.length;
  if (n === 0) {
    return (
      <figure className="chart" aria-labelledby={`${id}-t`}>
        <figcaption id={`${id}-t`} className="chart-title">
          {title}
        </figcaption>
        <p className="empty-state">{empty}</p>
      </figure>
    );
  }
  const fmt = (v: number) => `${compact(v)}${unit}`;
  const dataMax = Math.max(1, ...series.flatMap((s) => s.values));
  const ticks = niceTicks(yMax ?? dataMax, 4);
  const top = yMax ?? ticks[ticks.length - 1];
  const px0 = M.left;
  const px1 = W - M.right;
  const py0 = H - M.bottom;
  const py1 = M.top;
  const sx = (i: number) => (n === 1 ? (px0 + px1) / 2 : px0 + ((px1 - px0) * i) / (n - 1));
  const sy = (v: number) => py0 - ((py0 - py1) * v) / top;
  const legend = series.length > 1;

  const ends = series.map((s) => sy(s.values[n - 1] ?? 0));
  // Label centers, spread so labels never overlap; text baseline sits 4px below center.
  const labelYs = spreadLabels(ends, 14, py1, py0);
  const xLabels = n === 1 ? [0] : Array.from(new Set([0, Math.floor((n - 1) / 2), n - 1]));
  const colW = n === 1 ? px1 - px0 : (px1 - px0) / (n - 1);

  return (
    <figure className="chart" aria-labelledby={`${id}-t`}>
      <figcaption id={`${id}-t`} className="chart-title">
        {title}
      </figcaption>
      {legend && (
        <ul className="legend" aria-label="Legend">
          {series.map((s) => (
            <li key={s.key}>
              <svg viewBox="0 0 18 10" width="18" height="10" aria-hidden="true" focusable="false">
                <line className={`ln ln-${s.tone}`} x1="1" x2="17" y1="5" y2="5" />
              </svg>
              {s.label}
            </li>
          ))}
        </ul>
      )}
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
              <line className={t === 0 ? "baseline" : "grid"} x1={px0} x2={px1} y1={sy(t)} y2={sy(t)} />
              <text className="tick" x={px0 - 8} y={sy(t) + 4} textAnchor="end">
                {fmt(t)}
              </text>
            </g>
          ))}
          {xLabels.map((i) => (
            <text
              key={i}
              className="tick"
              x={sx(i)}
              y={py0 + 18}
              textAnchor={n === 1 ? "middle" : i === 0 ? "start" : i === n - 1 ? "end" : "middle"}
            >
              {points[i].date}
            </text>
          ))}
          <text className="axis-title" x={px1} y={H - 2} textAnchor="end">
            CI runs on main, oldest to newest
          </text>
          {series.map((s) => (
            <path
              key={s.key}
              className={`ln ln-${s.tone}`}
              d={s.values.map((v, i) => `${i ? "L" : "M"}${sx(i).toFixed(1)},${sy(v).toFixed(1)}`).join("")}
            />
          ))}
          {/* Hover columns: a crosshair and the values for one run. */}
          {points.map((p, i) => (
            <g
              key={`${p.commit}-${i}`}
              className="col"
              data-tip={`${p.date} ${p.commit}\n${series.map((s) => `${s.label} ${fmt(s.values[i])}`).join("\n")}`}
            >
              <rect
                className="hit"
                x={Math.max(px0 - 6, sx(i) - colW / 2)}
                width={Math.min(colW, px1 + 6 - Math.max(px0 - 6, sx(i) - colW / 2))}
                y={py1}
                height={py0 - py1}
              />
              <line className="xhair" x1={sx(i)} x2={sx(i)} y1={py1} y2={py0} />
              {series.map((s) => (
                <circle key={s.key} className={`pt pt-${s.tone}`} cx={sx(i)} cy={sy(s.values[i])} r="4" />
              ))}
            </g>
          ))}
          {series.map((s, k) => {
            const x = sx(n - 1);
            const y = ends[k];
            const ly = labelYs[k];
            return (
              <g key={s.key}>
                <circle className={`end end-${s.tone}`} cx={x} cy={y} r="4" />
                {Math.abs(ly - y) > 2 && <line className="leader" x1={x + 6} x2={x + 14} y1={y} y2={ly} />}
                <text className="end-label" x={x + 16} y={ly + 4}>
                  {fmt(s.values[n - 1])} {legend ? s.label : ""}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      <details className="chart-data">
        <summary>Data table</summary>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Run</th>
                <th scope="col">Date</th>
                <th scope="col">Commit</th>
                {series.map((s) => (
                  <th key={s.key} scope="col" className="num">
                    {s.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {points.map((p, i) => (
                <tr key={`${p.commit}-${i}`}>
                  <td className="num">{i + 1}</td>
                  <td className="id">{p.date}</td>
                  <td className="id">{p.commit}</td>
                  {series.map((s) => (
                    <td key={s.key} className="num">
                      {fmt(s.values[i])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}
