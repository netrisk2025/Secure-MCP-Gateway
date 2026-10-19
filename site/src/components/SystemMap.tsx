"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { load, themeVariables } from "./Mermaid";

export type StageLink = { href: string; text: string };
export type Stage = { no: string; id: string; title: string; summary: string; links: StageLink[] };

type View = {
  /** Scale and translation of the drawing inside the viewport, in CSS pixels. */
  s: number;
  x: number;
  y: number;
  /** Natural size of the drawing (its viewBox) and the scale that fits it to the viewport width. */
  w: number;
  h: number;
  fit: number;
  zoomed: boolean;
};

const MAX_SCALE = 3;
const STAGE_MAX_SCALE = 1.5;
/** 14 px chart text at this scale is 11.9 px, above the 11 px floor of scripts/check-diagrams.mjs. */
const STAGE_MIN_SCALE = 0.85;
const PAD = 16;

function decode(b64: string): string {
  return new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
}

/**
 * The system map: one large Mermaid flowchart with built-in pan and zoom.
 *
 * Overview: the drawing is fitted to the full width of the viewport box and the
 * box is as tall as the fitted drawing, so the whole chart is on the page and
 * nothing scrolls sideways. Zoomed (buttons, Ctrl or Cmd + wheel, pinch, keys,
 * double click or a stage in the index): the box becomes as tall as the
 * browser window and the drawing pans and zooms inside it. Reset or Escape
 * returns to the overview.
 */
export default function SystemMap({ source, stages, label }: { source: string; stages: Stage[]; label: string }) {
  const box = useRef<HTMLDivElement>(null);
  const bar = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLDivElement>(null);
  const view = useRef<View>({ s: 1, x: 0, y: 0, w: 0, h: 0, fit: 1, zoomed: false });
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState("");
  const [zoomed, setZoomed] = useState(false);
  const [pct, setPct] = useState(100);
  const [current, setCurrent] = useState("");

  /** Height of the sticky toolbar, which covers the top of the page while the chart is in view. */
  const barHeight = useCallback(() => bar.current?.getBoundingClientRect().height ?? 0, []);

  /** Height of the viewport box while zoomed: the browser window below the toolbar. */
  const zoomHeight = useCallback(() => Math.max(320, window.innerHeight - barHeight() - PAD), [barHeight]);

  /** Keeps the drawing over the box while zoomed: centered when smaller, edges never pulled inside the box. */
  const clamp = useCallback(() => {
    const v = view.current;
    const el = box.current;
    if (!el) return;
    const bw = el.clientWidth;
    const bh = el.clientHeight;
    const cw = v.w * v.s;
    const ch = v.h * v.s;
    v.x = cw <= bw ? (bw - cw) / 2 : Math.min(PAD, Math.max(bw - cw - PAD, v.x));
    v.y = ch <= bh ? (bh - ch) / 2 : Math.min(PAD, Math.max(bh - ch - PAD, v.y));
  }, []);

  const apply = useCallback(() => {
    const v = view.current;
    const el = box.current;
    const c = canvas.current;
    if (!el || !c) return;
    el.style.height = `${Math.ceil(v.zoomed ? zoomHeight() : v.h * v.fit)}px`;
    if (v.zoomed) clamp();
    c.style.transform = `translate(${v.x}px, ${v.y}px) scale(${v.s})`;
    el.dataset.zoomed = v.zoomed ? "1" : "0";
    el.dataset.scale = String(v.s);
    setZoomed(v.zoomed);
    setPct(Math.round(v.s * 100));
  }, [clamp, zoomHeight]);

  const overview = useCallback(() => {
    const v = view.current;
    const el = box.current;
    if (!el || !v.w) return;
    v.fit = el.clientWidth / v.w;
    v.s = v.fit;
    v.x = 0;
    v.y = 0;
    v.zoomed = false;
    setCurrent("");
    apply();
  }, [apply]);

  /** Scrolls the page so the box starts just below the sticky toolbar. */
  const scrollToBox = useCallback(() => {
    const el = box.current;
    if (!el) return;
    const top = el.getBoundingClientRect().top - barHeight();
    if (Math.abs(top) > 2) window.scrollBy({ top, behavior: "instant" as ScrollBehavior });
  }, [barHeight]);

  /** Switches the box to the zoomed height (once) and brings it into view. */
  const enterZoom = useCallback(() => {
    const v = view.current;
    const el = box.current;
    if (!el) return;
    if (!v.zoomed) {
      v.zoomed = true;
      el.style.height = `${Math.ceil(zoomHeight())}px`;
    }
    scrollToBox();
  }, [scrollToBox, zoomHeight]);

  /** Smallest scale while zoomed: the whole chart inside the window-high box. */
  const minScale = useCallback(() => {
    const v = view.current;
    return Math.min(v.fit, zoomHeight() / v.h);
  }, [zoomHeight]);

  /** The whole chart in the window: small, for finding a stage; Reset returns to the width-fitted overview. */
  const fitWindow = useCallback(() => {
    const v = view.current;
    if (!v.w) return;
    enterZoom();
    v.s = minScale();
    setCurrent("");
    apply();
  }, [apply, enterZoom, minScale]);

  /** Zooms by a factor about a point given in box coordinates (the box center when omitted). */
  const zoomBy = useCallback(
    (factor: number, px?: number, py?: number) => {
      const v = view.current;
      const el = box.current;
      if (!el || !v.w) return;
      const floor = v.zoomed ? minScale() : v.fit;
      const next = Math.min(MAX_SCALE, Math.max(floor, v.s * factor));
      if (!v.zoomed && next <= v.fit + 1e-6) return;
      // Content point under the given box point, before any change of the box.
      const bx = px ?? el.clientWidth / 2;
      const byOverview = py ?? (v.zoomed ? el.clientHeight / 2 : Math.min(el.clientHeight, window.innerHeight) / 2);
      const cx = (bx - v.x) / v.s;
      const cy = (byOverview - v.y) / v.s;
      const wasZoomed = v.zoomed;
      if (!wasZoomed) enterZoom();
      const by = wasZoomed ? byOverview : el.clientHeight / 2;
      v.s = next;
      v.x = bx - cx * v.s;
      v.y = by - cy * v.s;
      apply();
    },
    [apply, enterZoom, minScale],
  );

  const panBy = useCallback(
    (dx: number, dy: number) => {
      const v = view.current;
      if (!v.zoomed) return;
      v.x += dx;
      v.y += dy;
      apply();
    },
    [apply],
  );

  /** Zooms to one stage (subgraph): its width fills the box, its top at the top of the box. */
  const zoomToStage = useCallback(
    (id: string) => {
      const v = view.current;
      const el = box.current;
      const c = canvas.current;
      const svg = c?.querySelector("svg");
      if (!el || !c || !svg) return;
      const cluster = svg.querySelector<SVGGElement>(`g.cluster[id="${id}"], g.cluster[id$="-${id}"]`);
      const rect = cluster?.querySelector("rect") ?? cluster;
      if (!rect) return;
      enterZoom();
      const cr = c.getBoundingClientRect();
      const r = rect.getBoundingClientRect();
      const bx = (r.left - cr.left) / v.s;
      const by = (r.top - cr.top) / v.s;
      const bw = r.width / v.s;
      const bh = r.height / v.s;
      // The stage's width fills the box, but never below a legible scale: on a
      // narrow screen the stage opens at its left edge and pans from there.
      const s = Math.max(v.fit, Math.min(STAGE_MAX_SCALE, Math.max(STAGE_MIN_SCALE, (el.clientWidth - 2 * PAD) / bw)));
      v.s = s;
      v.x = bw * s <= el.clientWidth - 2 * PAD ? (el.clientWidth - bw * s) / 2 - bx * s : PAD - bx * s;
      v.y = bh * s <= el.clientHeight - 2 * PAD ? (el.clientHeight - bh * s) / 2 - by * s : PAD - by * s;
      setCurrent(id);
      apply();
      el.focus({ preventScroll: true });
    },
    [apply, enterZoom],
  );

  // Draw the chart, then fit it.
  useEffect(() => {
    let cancelled = false;
    const draw = async () => {
      const c = canvas.current;
      if (!c) return;
      try {
        const mermaid = await load();
        const vars = { ...themeVariables(), fontSize: "14px" };
        mermaid.initialize({
          startOnLoad: false,
          securityLevel: "strict",
          theme: "base",
          look: "classic",
          themeVariables: vars,
          fontFamily: vars.fontFamily,
          maxTextSize: 200000,
          maxEdges: 1000,
          flowchart: { htmlLabels: true, curve: "basis", useMaxWidth: false, padding: 10, nodeSpacing: 28, rankSpacing: 36, wrappingWidth: 260 },
        });
        const { svg } = await mermaid.render(`sysmap-${Date.now()}`, decode(source));
        if (cancelled) return;
        c.innerHTML = svg;
        const el = c.querySelector("svg");
        if (!el) throw new Error("no SVG");
        const vb = el.viewBox.baseVal;
        view.current.w = vb.width;
        view.current.h = vb.height;
        el.setAttribute("width", String(vb.width));
        el.setAttribute("height", String(vb.height));
        el.style.maxWidth = "none";
        c.style.width = `${vb.width}px`;
        c.style.height = `${vb.height}px`;
        box.current!.dataset.rendered = "1";
        setState("ready");
        overview();
      } catch (e) {
        if (cancelled) return;
        box.current!.dataset.rendered = "error";
        setError(e instanceof Error ? e.message : String(e));
        setState("error");
      }
    };
    draw();
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const redraw = () => {
      if (box.current?.dataset.rendered) draw();
    };
    mq.addEventListener("change", redraw);
    return () => {
      cancelled = true;
      mq.removeEventListener("change", redraw);
    };
  }, [source, overview]);

  // Refit on resize: the overview follows the box width; a zoomed view keeps its scale.
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    let lastWidth = el.clientWidth;
    const ro = new ResizeObserver(() => {
      if (el.clientWidth === lastWidth) return;
      lastWidth = el.clientWidth;
      const v = view.current;
      if (!v.w) return;
      if (!v.zoomed) overview();
      else {
        v.fit = el.clientWidth / v.w;
        apply();
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [apply, overview]);

  // Wheel, pointer (drag and pinch) and double click on the box.
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const local = (e: { clientX: number; clientY: number }) => {
      const r = el.getBoundingClientRect();
      return [e.clientX - r.left, e.clientY - r.top] as const;
    };
    const onWheel = (e: WheelEvent) => {
      const v = view.current;
      if (!v.w) return;
      if (e.ctrlKey || e.metaKey) {
        // Ctrl or Cmd + wheel, and a trackpad pinch (which the browser reports as Ctrl + wheel).
        e.preventDefault();
        const [px, py] = local(e);
        zoomBy(Math.exp(-e.deltaY * (e.deltaMode === 1 ? 0.05 : 0.002)), px, py);
      } else if (v.zoomed) {
        e.preventDefault();
        const k = e.deltaMode === 1 ? 16 : 1;
        panBy(-(e.shiftKey ? e.deltaY : e.deltaX) * k, -(e.shiftKey ? 0 : e.deltaY) * k);
      }
      // In the overview a plain wheel scrolls the page.
    };
    const pointers = new Map<number, { x: number; y: number }>();
    let pinch: { d: number } | null = null;
    // A tap or click that did not move: on a chart drawn too small to read, it zooms to the stage under it.
    let tap: { x: number; y: number } | null = null;
    const onDown = (e: PointerEvent) => {
      if (e.button !== 0 || (e.target as Element).closest("a, button")) return;
      pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      tap = pointers.size === 1 ? { x: e.clientX, y: e.clientY } : null;
      if (pointers.size === 2) {
        const [a, b] = [...pointers.values()];
        pinch = { d: Math.hypot(a.x - b.x, a.y - b.y) };
      }
      if (view.current.zoomed || pointers.size === 2) el.setPointerCapture(e.pointerId);
    };
    const onMove = (e: PointerEvent) => {
      const prev = pointers.get(e.pointerId);
      if (!prev) return;
      const cur = { x: e.clientX, y: e.clientY };
      pointers.set(e.pointerId, cur);
      if (pointers.size === 2 && pinch) {
        const [a, b] = [...pointers.values()];
        const d = Math.hypot(a.x - b.x, a.y - b.y);
        if (pinch.d > 0) {
          const [px, py] = local({ clientX: (a.x + b.x) / 2, clientY: (a.y + b.y) / 2 });
          zoomBy(d / pinch.d, px, py);
        }
        pinch.d = d;
      } else if (pointers.size === 1 && view.current.zoomed) {
        panBy(cur.x - prev.x, cur.y - prev.y);
      }
    };
    const onUp = (e: PointerEvent) => {
      const wasTap = e.type === "pointerup" && tap && pointers.size === 1 && Math.hypot(e.clientX - tap.x, e.clientY - tap.y) < 5;
      pointers.delete(e.pointerId);
      if (pointers.size < 2) pinch = null;
      tap = null;
      if (!wasTap || view.current.s >= STAGE_MIN_SCALE) return;
      const svg = canvas.current?.querySelector("svg");
      for (const st of stages) {
        const r = svg?.querySelector(`g.cluster[id="${st.id}"] rect, g.cluster[id$="-${st.id}"] rect`)?.getBoundingClientRect();
        if (r && e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom) {
          zoomToStage(st.id);
          return;
        }
      }
    };
    const onDbl = (e: MouseEvent) => {
      if ((e.target as Element).closest("a, button")) return;
      const [px, py] = local(e);
      zoomBy(2, px, py);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    el.addEventListener("pointerdown", onDown);
    el.addEventListener("pointermove", onMove);
    el.addEventListener("pointerup", onUp);
    el.addEventListener("pointercancel", onUp);
    el.addEventListener("dblclick", onDbl);
    return () => {
      el.removeEventListener("wheel", onWheel);
      el.removeEventListener("pointerdown", onDown);
      el.removeEventListener("pointermove", onMove);
      el.removeEventListener("pointerup", onUp);
      el.removeEventListener("pointercancel", onUp);
      el.removeEventListener("dblclick", onDbl);
    };
  }, [panBy, stages, zoomBy, zoomToStage]);

  // Deep link: /flows/system-map/#stage-S6 opens zoomed to that stage once drawn.
  useEffect(() => {
    if (state !== "ready") return;
    const m = window.location.hash.match(/^#stage-(.+)$/);
    if (m && stages.some((s) => s.id === m[1])) zoomToStage(m[1]);
  }, [state, stages, zoomToStage]);

  const onKey = (e: React.KeyboardEvent) => {
    const step = 60;
    const keys: Record<string, () => void> = {
      "+": () => zoomBy(1.25),
      "=": () => zoomBy(1.25),
      "-": () => zoomBy(0.8),
      _: () => zoomBy(0.8),
      "0": overview,
      Escape: overview,
      ArrowLeft: () => panBy(step, 0),
      ArrowRight: () => panBy(-step, 0),
      ArrowUp: () => panBy(0, step),
      ArrowDown: () => panBy(0, -step),
    };
    const k = keys[e.key];
    if (!k || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key.startsWith("Arrow") && !view.current.zoomed) return;
    if (e.key === "Escape" && !view.current.zoomed) return;
    e.preventDefault();
    k();
  };

  const currentStage = stages.find((s) => s.id === current);


  return (
    <div className="sysmap">
      <nav className="sysmap-stages" aria-label="Stages of the system map">
        <ol>
          {stages.map((s) => (
            <li key={s.id} id={`stage-${s.id}`} aria-current={current === s.id ? "true" : undefined}>
              <button type="button" className="sysmap-stage-zoom" onClick={() => zoomToStage(s.id)} disabled={state !== "ready"}>
                <span className="sysmap-stage-no">{s.no}</span> {s.title}
              </button>
              <p>{s.summary}</p>
              {s.links.length > 0 && (
                <p className="sysmap-stage-links">
                  Detail:{" "}
                  {s.links.map((l, i) => (
                    <span key={l.href}>
                      {i > 0 && ", "}
                      <a href={l.href}>{l.text}</a>
                    </span>
                  ))}
                </p>
              )}
            </li>
          ))}
        </ol>
      </nav>
      <p className="sysmap-help" id="sysmap-help">
        Zoom with Ctrl or Cmd and the wheel, a pinch, the + and − buttons or keys, or a stage above; on a chart too small
        to read, a click or tap on a stage zooms to it. Drag, the wheel or the arrow keys pan when zoomed. 0 or Escape
        returns to the overview.
      </p>
      <div ref={bar} className="sysmap-bar" role="toolbar" aria-label="Zoom" aria-controls="sysmap-box">
        <button type="button" onClick={() => zoomBy(0.8)} disabled={!zoomed} aria-label="Zoom out">
          −
        </button>
        <span className="sysmap-pct" aria-live="polite">
          {state === "ready" ? `${pct}%` : state === "error" ? "not drawn" : "drawing"}
        </span>
        <button type="button" onClick={() => zoomBy(1.25)} disabled={state !== "ready"} aria-label="Zoom in">
          +
        </button>
        <button type="button" onClick={overview} disabled={!zoomed}>
          Overview
        </button>
        <button type="button" onClick={fitWindow} disabled={state !== "ready"}>
          Fit in window
        </button>
        <label className="sysmap-go">
          <span className="visually-hidden">Zoom to stage</span>
          <select
            value={current}
            disabled={state !== "ready"}
            onChange={(e) => (e.target.value ? zoomToStage(e.target.value) : overview())}
          >
            <option value="">{zoomed && !currentStage ? "Zoomed" : "Whole chart"}</option>
            {stages.map((s) => (
              <option key={s.id} value={s.id}>
                {s.no} {s.title}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div
        id="sysmap-box"
        ref={box}
        className="sysmap-box"
        tabIndex={0}
        role="group"
        aria-roledescription="zoomable diagram"
        aria-label={label}
        aria-describedby="sysmap-help"
        onKeyDown={onKey}
      >
        <div ref={canvas} className="sysmap-canvas" />
        {state !== "ready" && (
          <p className="sysmap-state">{state === "error" ? `The chart could not be drawn: ${error}. The edge table below lists every step.` : "Drawing the chart."}</p>
        )}
      </div>
    </div>
  );
}
