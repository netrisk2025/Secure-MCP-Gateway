"use client";

import { useEffect, useRef } from "react";

/**
 * One tooltip for every chart on the page. Chart marks and hit areas carry
 * their text in data-tip (lines separated by newlines). Charts render on the
 * server; this adds only the hover layer. The same values are in each chart's
 * data table, so nothing depends on hovering.
 */
export default function ChartTips() {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const tip = ref.current;
    if (!tip) return;
    let current: Element | null = null;
    const place = (x: number, y: number) => {
      const r = tip.getBoundingClientRect();
      const left = Math.min(window.innerWidth - r.width - 8, Math.max(8, x + 14));
      const top = y - r.height - 12 < 8 ? y + 18 : y - r.height - 12;
      tip.style.transform = `translate(${Math.round(left)}px, ${Math.round(top)}px)`;
    };
    const over = (e: PointerEvent) => {
      const t = (e.target as Element | null)?.closest?.("[data-tip]") ?? null;
      if (t === current) return;
      current = t;
      if (!t) {
        tip.hidden = true;
        return;
      }
      tip.textContent = t.getAttribute("data-tip");
      tip.hidden = false;
      place(e.clientX, e.clientY);
    };
    const move = (e: PointerEvent) => {
      if (current) place(e.clientX, e.clientY);
    };
    const hide = () => {
      current = null;
      tip.hidden = true;
    };
    document.addEventListener("pointerover", over);
    document.addEventListener("pointermove", move, { passive: true });
    document.addEventListener("scroll", hide, { passive: true });
    return () => {
      document.removeEventListener("pointerover", over);
      document.removeEventListener("pointermove", move);
      document.removeEventListener("scroll", hide);
    };
  }, []);
  return <div ref={ref} className="charttip" role="presentation" hidden />;
}
