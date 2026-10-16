"use client";

import { useEffect } from "react";

/** Finds server-rendered mermaid placeholders and draws them in the browser. */
export default function Mermaid() {
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const blocks = Array.from(document.querySelectorAll<HTMLElement>("[data-mermaid]:not([data-rendered])"));
      if (!blocks.length) return;
      const mermaid = (await import("mermaid")).default;
      const dark = document.documentElement.dataset.theme === "dark" ||
        (!document.documentElement.dataset.theme && window.matchMedia("(prefers-color-scheme: dark)").matches);
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: "strict",
        theme: "base",
        fontFamily: "var(--font-ui), sans-serif",
        themeVariables: dark
          ? {
              background: "#1b211d",
              primaryColor: "#243a31",
              primaryTextColor: "#e6eae4",
              primaryBorderColor: "#7fb39b",
              lineColor: "#9fb8aa",
              secondaryColor: "#2a3530",
              tertiaryColor: "#20292462",
              clusterBkg: "#1f2823",
              clusterBorder: "#3a4a41",
              edgeLabelBackground: "#1b211d",
              fontSize: "13px",
            }
          : {
              background: "#f6f7f3",
              primaryColor: "#e2e9e2",
              primaryTextColor: "#1c241f",
              primaryBorderColor: "#3f6b58",
              lineColor: "#56695f",
              secondaryColor: "#edf0ea",
              tertiaryColor: "#f6f7f3",
              clusterBkg: "#f1f3ee",
              clusterBorder: "#c6cfc7",
              edgeLabelBackground: "#f6f7f3",
              fontSize: "13px",
            },
      });
      let i = 0;
      for (const el of blocks) {
        if (cancelled) return;
        const src = new TextDecoder().decode(Uint8Array.from(atob(el.dataset.mermaid ?? ""), (c) => c.charCodeAt(0)));
        try {
          const { svg } = await mermaid.render(`mmd-${Date.now()}-${i++}`, src);
          el.innerHTML = svg;
          el.dataset.rendered = "1";
        } catch {
          el.dataset.rendered = "error";
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);
  return null;
}
