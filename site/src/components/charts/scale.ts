/** Small scale helpers shared by the chart components. */

/** Round a maximum up to a clean axis end and return evenly spaced ticks from 0. */
export function niceTicks(max: number, target = 4): number[] {
  if (!(max > 0)) return [0, 1];
  const raw = max / target;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? 10 * mag;
  const end = Math.ceil(max / step) * step;
  const ticks: number[] = [];
  for (let v = 0; v <= end + step / 1000; v += step) ticks.push(Number(v.toFixed(6)));
  return ticks;
}

export function compact(n: number): string {
  if (Math.abs(n) >= 1000) return `${(n / 1000).toFixed(n % 1000 === 0 ? 0 : 1)}K`;
  return String(Number.isInteger(n) ? n : Number(n.toFixed(1)));
}

/** A rectangle whose right end is rounded and left end square (bars grow from the left baseline). */
export function barPath(x: number, y: number, w: number, h: number, r: number): string {
  const rr = Math.max(0, Math.min(r, w, h / 2));
  return `M${x},${y}H${x + w - rr}A${rr},${rr} 0 0 1 ${x + w},${y + rr}V${y + h - rr}A${rr},${rr} 0 0 1 ${x + w - rr},${y + h}H${x}Z`;
}

export function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max - 1).trimEnd()}…`;
}

/**
 * Spread end labels so they do not overlap: keep each label as close to its
 * line end as possible while holding a minimum gap.
 */
export function spreadLabels(ys: number[], gap: number, min: number, max: number): number[] {
  const order = ys.map((y, i) => ({ y, i })).sort((a, b) => a.y - b.y);
  const out = new Array<number>(ys.length);
  let prev = -Infinity;
  for (const o of order) {
    const y = Math.max(o.y, prev + gap, min);
    out[o.i] = y;
    prev = y;
  }
  // If the stack ran past the bottom, walk back up from the last label.
  let next = Infinity;
  for (let k = order.length - 1; k >= 0; k--) {
    const i = order[k].i;
    out[i] = Math.min(out[i], max, next - gap);
    next = out[i];
  }
  return out;
}
