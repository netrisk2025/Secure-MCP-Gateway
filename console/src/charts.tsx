// Hand-built SVG charts (no chart library). Rules from the data
// visualization method in docs/console-style.md: one y-axis, 2px lines,
// thin bars with a 2px gap, recessive hairline grid, a legend for two or
// more series, a crosshair or per-mark tooltip that also answers keyboard
// focus, and a table view of the same values for every chart.
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { compact } from "./ui";

function useWidth(min = 280): [React.RefObject<HTMLDivElement | null>, number] {
  const ref = useRef<HTMLDivElement>(null);
  const [w, setW] = useState(640);
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((e) => setW(Math.max(min, Math.floor(e[0]!.contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, [min]);
  return [ref, w];
}

/** Clean tick values for [lo, hi]. */
export function ticks(lo: number, hi: number, n = 4): number[] {
  if (!(hi > lo)) return [lo];
  const raw = (hi - lo) / n;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? raw;
  const out: number[] = [];
  for (let v = Math.ceil(lo / step) * step; v <= hi + step * 1e-9; v += step) out.push(Number(v.toFixed(10)));
  return out;
}

function timeLabel(ms: number, span: number): string {
  const d = new Date(ms).toISOString();
  return span > 2 * 86400_000 ? d.slice(5, 10) : d.slice(11, 16);
}

export interface Series {
  name: string;
  points: { x: number; y: number }[];
}

const seriesVar = ["var(--series-1)", "var(--series-2)", "var(--series-3)"];

/** Table view of chart values; collapsed by default. */
function TableView({ caption, head, rows }: { caption: string; head: string[]; rows: ReactNode[][] }) {
  return (
    <details className="chart-table">
      <summary>Show values as a table</summary>
      <div className="table-wrap" tabIndex={0} role="region" aria-label={caption + " values"}>
        <table>
          <caption className="sr-only">{caption}</caption>
          <thead>
            <tr>
              {head.map((h, i) => (
                <th key={h} scope="col" className={i > 0 ? "num" : undefined}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                {r.map((c, j) => (
                  <td key={j} className={j > 0 ? "num mono" : "mono"}>
                    {c}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

function Legend({ names, kind }: { names: string[]; kind: "line" | "rect" }) {
  if (names.length < 2) return null;
  return (
    <ul className="legend" aria-label="Legend">
      {names.map((n, i) => (
        <li key={n}>
          <svg width="16" height="10" aria-hidden="true">
            {kind === "line" ? <line x1="0" x2="16" y1="5" y2="5" stroke={seriesVar[i]} strokeWidth="2" /> : <rect width="10" height="10" fill={seriesVar[i]} rx="2" />}
          </svg>
          {n}
        </li>
      ))}
    </ul>
  );
}

/**
 * A time-series line chart (at most three series). x is epoch ms. The
 * crosshair snaps to the nearest x; arrow keys move it when the chart has
 * focus.
 */
export function LineChart({ title, series, unit, height = 180, format = (v: number) => compact(v) }: { title: string; series: Series[]; unit: string; height?: number; format?: (v: number) => string }) {
  const [ref, width] = useWidth();
  const [at, setAt] = useState<number | null>(null);
  const id = useId();
  const shown = series.slice(0, 3);
  const xs = useMemo(() => [...new Set(shown.flatMap((s) => s.points.map((p) => p.x)))].sort((a, b) => a - b), [shown]);
  const ys = shown.flatMap((s) => s.points.map((p) => p.y));
  if (xs.length === 0) return <p className="empty">No values in this range yet. Values appear after tool calls when observation is enabled.</p>;
  const m = { l: 48, r: 12, t: 10, b: 24 };
  const iw = width - m.l - m.r;
  const ih = height - m.t - m.b;
  const x0 = xs[0]!;
  const x1 = xs[xs.length - 1]!;
  const yMax = Math.max(...ys, 0);
  const yMin = Math.min(...ys, 0);
  const yt = ticks(yMin, yMax === yMin ? yMin + 1 : yMax);
  const top = yt[yt.length - 1]!;
  const bot = yt[0]!;
  const sx = (x: number) => m.l + (x1 === x0 ? iw / 2 : ((x - x0) / (x1 - x0)) * iw);
  const sy = (y: number) => m.t + ih - ((y - bot) / (top - bot || 1)) * ih;
  const xt = xs.length > 1 ? ticks(x0, x1, Math.max(2, Math.floor(iw / 110))) : [x0];
  const nearest = (px: number) => {
    let best = 0;
    for (let i = 1; i < xs.length; i++) if (Math.abs(sx(xs[i]!) - px) < Math.abs(sx(xs[best]!) - px)) best = i;
    return best;
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "ArrowRight") setAt((a) => Math.min(xs.length - 1, (a ?? -1) + 1));
    else if (e.key === "ArrowLeft") setAt((a) => Math.max(0, (a ?? xs.length) - 1));
    else if (e.key === "Escape") setAt(null);
    else return;
    e.preventDefault();
  };
  const ax = at !== null ? xs[at]! : null;
  return (
    <figure className="chart" ref={ref}>
      <figcaption id={id}>
        {title} <span className="muted">({unit})</span>
      </figcaption>
      <Legend names={shown.map((s) => s.name)} kind="line" />
      <div className="chart-plot">
        <svg
          width={width}
          height={height}
          role="img"
          aria-labelledby={id}
          tabIndex={0}
          onKeyDown={onKey}
          onBlur={() => setAt(null)}
          onPointerMove={(e) => {
            const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
            setAt(nearest(e.clientX - r.left));
          }}
          onPointerLeave={() => setAt(null)}
        >
          {yt.map((t) => (
            <g key={t}>
              <line x1={m.l} x2={width - m.r} y1={sy(t)} y2={sy(t)} className="grid" />
              <text x={m.l - 6} y={sy(t)} dy="0.32em" textAnchor="end" className="tick">
                {format(t)}
              </text>
            </g>
          ))}
          {xt.map((t) => (
            <text key={t} x={sx(t)} y={height - 6} textAnchor="middle" className="tick">
              {timeLabel(t, x1 - x0)}
            </text>
          ))}
          {shown.map((s, i) => {
            const pts = [...s.points].sort((a, b) => a.x - b.x);
            return (
              <g key={s.name}>
                <polyline fill="none" stroke={seriesVar[i]} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" points={pts.map((p) => `${sx(p.x)},${sy(p.y)}`).join(" ")} />
                {pts.length === 1 && <circle cx={sx(pts[0]!.x)} cy={sy(pts[0]!.y)} r="4" fill={seriesVar[i]} className="ringed" />}
              </g>
            );
          })}
          {ax !== null && (
            <g>
              <line x1={sx(ax)} x2={sx(ax)} y1={m.t} y2={m.t + ih} className="crosshair" />
              {shown.map((s, i) => {
                const p = s.points.find((q) => q.x === ax);
                return p ? <circle key={s.name} cx={sx(p.x)} cy={sy(p.y)} r="4" fill={seriesVar[i]} className="ringed" /> : null;
              })}
            </g>
          )}
        </svg>
        {ax !== null && (
          <div className="tooltip" role="status" style={{ left: Math.min(sx(ax) + 10, width - 180) }}>
            <div className="mono">{new Date(ax).toISOString().replace("T", " ").slice(0, 19)}</div>
            {shown.map((s, i) => {
              const p = s.points.find((q) => q.x === ax);
              return (
                <div key={s.name} className="tooltip-row">
                  <svg width="12" height="8" aria-hidden="true">
                    <line x1="0" x2="12" y1="4" y2="4" stroke={seriesVar[i]} strokeWidth="2" />
                  </svg>
                  <strong className="mono">{p ? format(p.y) : "none"}</strong> <span className="muted">{s.name}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
      <TableView
        caption={title}
        head={["Time (UTC)", ...shown.map((s) => `${s.name} (${unit})`)]}
        rows={xs.map((x) => [new Date(x).toISOString().replace("T", " ").slice(0, 19), ...shown.map((s) => format(s.points.find((p) => p.x === x)?.y ?? NaN))])}
      />
    </figure>
  );
}

export interface Bar {
  label: string;
  value: number;
  note?: string;
}

/** Horizontal bars from one baseline; each bar is focusable and shows its value. */
export function BarChart({ title, bars, unit, format = (v: number) => compact(v) }: { title: string; bars: Bar[]; unit: string; format?: (v: number) => string }) {
  const [ref, width] = useWidth();
  const [at, setAt] = useState<number | null>(null);
  const id = useId();
  if (bars.length === 0) return <p className="empty">No values in this range yet. Values appear after tool calls when observation is enabled.</p>;
  const labelW = Math.min(220, Math.max(80, Math.max(...bars.map((b) => b.label.length)) * 7.2 + 12));
  const valueW = 72;
  const band = 24;
  const thick = 16;
  const height = bars.length * band + 8;
  const max = Math.max(...bars.map((b) => b.value), 0) || 1;
  const iw = Math.max(40, width - labelW - valueW);
  return (
    <figure className="chart" ref={ref}>
      <figcaption id={id}>
        {title} <span className="muted">({unit})</span>
      </figcaption>
      <svg width={width} height={height} role="img" aria-labelledby={id}>
        <line x1={labelW} x2={labelW} y1={0} y2={height} className="axis" />
        {bars.map((b, i) => {
          const w = Math.max(b.value > 0 ? 2 : 0, (b.value / max) * iw);
          const y = i * band + (band - thick) / 2 + 4;
          const r = Math.min(4, w / 2);
          return (
            <g
              key={b.label + i}
              tabIndex={0}
              role="img"
              aria-label={`${b.label}: ${format(b.value)} ${unit}${b.note ? `, ${b.note}` : ""}`}
              onPointerEnter={() => setAt(i)}
              onPointerLeave={() => setAt(null)}
              onFocus={() => setAt(i)}
              onBlur={() => setAt(null)}
              className={at === i ? "bar bar-active" : "bar"}
            >
              <rect x={0} y={i * band + 4} width={width} height={band} fill="transparent" />
              <text x={labelW - 6} y={y + thick / 2} dy="0.32em" textAnchor="end" className="tick mono">
                {b.label.length > 30 ? b.label.slice(0, 29) + "…" : b.label}
              </text>
              <path d={`M${labelW},${y} h${w - r} a${r},${r} 0 0 1 ${r},${r} v${thick - 2 * r} a${r},${r} 0 0 1 -${r},${r} h-${w - r} z`} fill="var(--series-1)" />
              <text x={labelW + w + 6} y={y + thick / 2} dy="0.32em" className="tick mono">
                {format(b.value)}
              </text>
            </g>
          );
        })}
      </svg>
      {at !== null && bars[at]?.note && (
        <p className="small muted" role="status">
          {bars[at]!.label}: {bars[at]!.note}
        </p>
      )}
      <TableView caption={title} head={["Item", `Value (${unit})`, ...(bars.some((b) => b.note) ? ["Note"] : [])]} rows={bars.map((b) => [b.label, format(b.value), ...(bars.some((x) => x.note) ? [b.note ?? ""] : [])])} />
    </figure>
  );
}

export interface Dot {
  x: number;
  y: number;
  band: string;
  label: string;
  href?: string;
}

const bandTone: Record<string, string> = { elevated: "var(--pending)", abnormal: "var(--warn)", critical: "var(--bad)" };

/**
 * Score timeline: one dot per scored call at its time and combined z-score,
 * with the band thresholds as reference lines. Band is carried by shape and
 * by the tooltip text as well as by color.
 */
export function ScoreTimeline({ title, dots, thresholds, onOpen }: { title: string; dots: Dot[]; thresholds: Record<string, number>; onOpen?: (d: Dot) => void }) {
  const [ref, width] = useWidth();
  const [at, setAt] = useState<number | null>(null);
  const id = useId();
  if (dots.length === 0) return <p className="empty">No call scored elevated or worse in this range. Scores appear after tool calls while a promoted baseline snapshot is in force.</p>;
  const height = 200;
  const m = { l: 40, r: 12, t: 10, b: 24 };
  const iw = width - m.l - m.r;
  const ih = height - m.t - m.b;
  const xsorted = dots.map((d) => d.x).sort((a, b) => a - b);
  const x0 = xsorted[0]!;
  const x1 = xsorted[xsorted.length - 1]!;
  const yTop = Math.max(...dots.map((d) => d.y), ...Object.values(thresholds), 1);
  const yt = ticks(0, yTop);
  const top = yt[yt.length - 1]!;
  const sx = (x: number) => m.l + (x1 === x0 ? iw / 2 : ((x - x0) / (x1 - x0)) * iw);
  const sy = (y: number) => m.t + ih - (y / (top || 1)) * ih;
  const xt = x1 > x0 ? ticks(x0, x1, Math.max(2, Math.floor(iw / 110))) : [x0];
  const shape = (d: Dot, cx: number, cy: number, active: boolean) => {
    const fill = bandTone[d.band] ?? "var(--ink-3)";
    const r = active ? 6 : 4.5;
    if (d.band === "critical") return <path d={`M${cx},${cy - r - 1} L${cx + r + 1},${cy + r} L${cx - r - 1},${cy + r} Z`} fill={fill} className="ringed" />;
    if (d.band === "abnormal") return <rect x={cx - r} y={cy - r} width={2 * r} height={2 * r} transform={`rotate(45 ${cx} ${cy})`} fill={fill} className="ringed" />;
    return <circle cx={cx} cy={cy} r={r} fill={fill} className="ringed" />;
  };
  return (
    <figure className="chart" ref={ref}>
      <figcaption id={id}>
        {title} <span className="muted">(combined z-score; circle elevated, diamond abnormal, triangle critical)</span>
      </figcaption>
      <div className="chart-plot">
        {/* A group, not an image: its dots are buttons (an image may not contain controls). */}
        <svg width={width} height={height} role="group" aria-labelledby={id}>
          {yt.map((t) => (
            <g key={t}>
              <line x1={m.l} x2={width - m.r} y1={sy(t)} y2={sy(t)} className="grid" />
              <text x={m.l - 6} y={sy(t)} dy="0.32em" textAnchor="end" className="tick">
                {t}
              </text>
            </g>
          ))}
          {Object.entries(thresholds).map(([band, v]) => (
            <g key={band}>
              <line x1={m.l} x2={width - m.r} y1={sy(v)} y2={sy(v)} className="threshold" />
              <text x={width - m.r - 2} y={sy(v) - 3} textAnchor="end" className="tick">
                {band} {v}σ
              </text>
            </g>
          ))}
          {xt.map((t) => (
            <text key={t} x={sx(t)} y={height - 6} textAnchor="middle" className="tick">
              {timeLabel(t, x1 - x0)}
            </text>
          ))}
          {dots.map((d, i) => (
            <g
              key={i}
              tabIndex={0}
              role="button"
              aria-label={`${d.band} ${d.y.toFixed(2)} at ${new Date(d.x).toISOString()}: ${d.label}`}
              onPointerEnter={() => setAt(i)}
              onPointerLeave={() => setAt(null)}
              onFocus={() => setAt(i)}
              onBlur={() => setAt(null)}
              onClick={() => onOpen?.(d)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onOpen?.(d);
                }
              }}
              className="dot"
            >
              <circle cx={sx(d.x)} cy={sy(d.y)} r="12" fill="transparent" />
              {shape(d, sx(d.x), sy(d.y), at === i)}
            </g>
          ))}
        </svg>
        {at !== null && dots[at] && (
          <div className="tooltip" role="status" style={{ left: Math.min(sx(dots[at]!.x) + 10, width - 220) }}>
            <div className="tooltip-row">
              <strong className="mono">{dots[at]!.y.toFixed(2)}σ</strong> <span>{dots[at]!.band}</span>
            </div>
            <div className="mono small">{new Date(dots[at]!.x).toISOString().replace("T", " ").slice(0, 19)}</div>
            <div className="small">{dots[at]!.label}</div>
          </div>
        )}
      </div>
      <TableView
        caption={title}
        head={["Time (UTC)", "Combined z", "Band", "Context"]}
        rows={dots.map((d) => [new Date(d.x).toISOString().replace("T", " ").slice(0, 19), d.y.toFixed(2), d.band, d.label])}
      />
    </figure>
  );
}

/** A meter: used against a budget, with the numbers as text beside it. */
export function Meter({ label, used, budget, format = (v: number) => compact(v) }: { label: string; used: number; budget: number; format?: (v: number) => string }) {
  const pct = budget > 0 ? Math.min(1, used / budget) : 0;
  const tone = pct >= 0.9 ? "bad" : pct >= 0.75 ? "warn" : "ok";
  return (
    <div className="meter">
      <div className="meter-label">
        <span>{label}</span>
        <span className="mono">
          {format(used)} of {format(budget)} ({Math.round(pct * 100)}%)
        </span>
      </div>
      <div className={`meter-track meter-${tone}`} role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={budget} aria-valuenow={used}>
        <div className="meter-fill" style={{ width: `${pct * 100}%` }} />
      </div>
    </div>
  );
}
