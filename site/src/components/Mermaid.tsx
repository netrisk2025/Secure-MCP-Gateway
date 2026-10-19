"use client";

import { useEffect } from "react";

type MermaidApi = typeof import("mermaid").default;

let api: Promise<MermaidApi> | null = null;
let seq = 0;

function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** Mermaid theme variables read from the page's CSS tokens, so diagrams follow light and dark. */
export function themeVariables() {
  const paper = token("--paper");
  const ink = token("--ink");
  return {
    background: paper,
    mainBkg: token("--surface"),
    primaryColor: token("--surface"),
    primaryTextColor: ink,
    primaryBorderColor: token("--ink-2"),
    secondaryColor: token("--surface-2"),
    tertiaryColor: paper,
    lineColor: token("--ink-2"),
    textColor: ink,
    clusterBkg: token("--surface-2"),
    clusterBorder: token("--rule-strong"),
    edgeLabelBackground: paper,
    titleColor: ink,
    nodeTextColor: ink,
    actorBkg: token("--surface"),
    actorBorder: token("--ink-2"),
    actorTextColor: ink,
    actorLineColor: token("--rule-strong"),
    signalColor: ink,
    signalTextColor: ink,
    labelBoxBkgColor: token("--surface-2"),
    labelBoxBorderColor: token("--rule-strong"),
    labelTextColor: ink,
    loopTextColor: ink,
    noteBkgColor: token("--ochre-wash"),
    noteBorderColor: token("--ochre"),
    noteTextColor: ink,
    activationBkgColor: token("--surface-2"),
    activationBorderColor: token("--ink-2"),
    sequenceNumberColor: paper,
    fontFamily: token("--font-mono-stack") || "monospace",
    fontSize: "13px",
  };
}

export async function load(): Promise<MermaidApi> {
  if (!api) api = import("mermaid").then((m) => m.default);
  return api;
}

function decode(b64: string): string {
  return new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
}

/** The drawn width of a diagram in CSS pixels at 100%, from its viewBox. */
function naturalWidth(svg: SVGSVGElement): number {
  return svg.viewBox.baseVal?.width || svg.getBoundingClientRect().width;
}

/** Shows the figure's "View full size" button only while the diagram is drawn smaller than 100%. */
function updateFullSize(el: HTMLElement) {
  const svg = el.querySelector<SVGSVGElement>(":scope > svg");
  const button = el.closest("figure")?.querySelector<HTMLButtonElement>(".diagram-full");
  if (!svg || !button) return;
  button.hidden = svg.getBoundingClientRect().width >= naturalWidth(svg) - 1;
}

let dialog: HTMLDialogElement | null = null;

/** One shared dialog that shows a copy of a diagram at 100%, scrollable in both directions. */
function openFullSize(figure: HTMLElement) {
  const svg = figure.querySelector<SVGSVGElement>(".mermaid-block > svg");
  if (!svg) return;
  if (!dialog) {
    dialog = document.createElement("dialog");
    dialog.className = "diagram-dialog";
    dialog.setAttribute("aria-labelledby", "diagram-dialog-title");
    dialog.innerHTML =
      '<div class="diagram-dialog-bar"><p id="diagram-dialog-title"></p>' +
      '<button type="button" class="diagram-dialog-close">Close</button></div>' +
      '<div class="diagram-dialog-body" tabindex="0"></div>';
    const d = dialog;
    d.querySelector(".diagram-dialog-close")?.addEventListener("click", () => d.close());
    // A click on the backdrop (outside the dialog box) closes it.
    d.addEventListener("click", (e) => {
      if (e.target === d) d.close();
    });
    d.addEventListener("close", () => {
      const body = d.querySelector(".diagram-dialog-body");
      if (body) body.innerHTML = "";
    });
    document.body.appendChild(d);
  }
  const copy = svg.cloneNode(true) as SVGSVGElement;
  const w = naturalWidth(svg);
  const vb = svg.viewBox.baseVal;
  copy.removeAttribute("style");
  copy.setAttribute("width", String(Math.ceil(w)));
  if (vb?.height) copy.setAttribute("height", String(Math.ceil(vb.height)));
  const title = dialog.querySelector("#diagram-dialog-title");
  if (title) title.textContent = `${figure.querySelector("figcaption")?.firstChild?.textContent?.trim() ?? "Diagram"} Full size.`;
  dialog.querySelector(".diagram-dialog-body")?.replaceChildren(copy);
  dialog.showModal();
}

async function draw(el: HTMLElement) {
  try {
    const mermaid = await load();
    const vars = themeVariables();
    const font = vars.fontFamily;
    // useMaxWidth: the SVG is as wide as its box and never wider than drawn,
    // so the whole diagram is always in view. The sources are laid out to
    // stay legible at the widths the site gives them (scripts/check-diagrams.mjs);
    // "View full size" shows a diagram at 100% when its box is narrower.
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "base",
      // Flat boxes with plain strokes; Mermaid's "neo" look adds drop shadows and gradient borders.
      look: "classic",
      themeVariables: vars,
      fontFamily: font,
      // Tighter than Mermaid's defaults (padding 15, spacing 50 and 50).
      flowchart: { htmlLabels: true, curve: "basis", useMaxWidth: true, padding: 10, nodeSpacing: 30, rankSpacing: 40 },
      sequence: {
        showSequenceNumbers: true,
        useMaxWidth: true,
        // Narrower actor columns than Mermaid's defaults (150, 50, 10): six
        // participants fit the 860 px of a document page and eight the
        // 1,136 px of a flow page at 100%.
        width: 112,
        actorMargin: 16,
        wrapPadding: 5,
        actorFontFamily: font,
        noteFontFamily: font,
        messageFontFamily: font,
        wrap: true,
      },
    });
    const { svg } = await mermaid.render(`mmd-${++seq}`, decode(el.dataset.mermaid ?? ""));
    el.innerHTML = svg;
    el.querySelector(":scope > svg")?.removeAttribute("height");
    el.dataset.rendered = "1";
    updateFullSize(el);
  } catch (e) {
    // Leave the source text visible; it is the fallback.
    el.dataset.rendered = "error";
    el.dataset.error = e instanceof Error ? e.message : String(e);
  }
}

/**
 * Draws server-rendered diagram placeholders when they scroll near the
 * viewport, so Mermaid loads only on pages that show a diagram and only when
 * one is about to be seen. Redraws when the color scheme changes.
 */
export default function Mermaid() {
  useEffect(() => {
    const blocks = Array.from(document.querySelectorAll<HTMLElement>("[data-mermaid]"));
    if (!blocks.length) return;
    let queue = Promise.resolve();
    const enqueue = (el: HTMLElement) => {
      queue = queue.then(() => draw(el));
    };
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (!e.isIntersecting) continue;
          io.unobserve(e.target);
          enqueue(e.target as HTMLElement);
        }
      },
      { rootMargin: "600px 0px" },
    );
    for (const b of blocks) io.observe(b);

    const ro = new ResizeObserver((entries) => {
      for (const e of entries) updateFullSize(e.target as HTMLElement);
    });
    const onClick = (e: Event) => {
      const button = (e.target as HTMLElement).closest(".diagram-full");
      const figure = button?.closest("figure");
      if (figure) openFullSize(figure as HTMLElement);
    };
    for (const b of blocks) {
      ro.observe(b);
      b.closest("figure")?.querySelector(".diagram-full")?.addEventListener("click", onClick);
    }

    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const redraw = () => {
      for (const b of blocks) if (b.dataset.rendered) enqueue(b);
    };
    mq.addEventListener("change", redraw);
    return () => {
      io.disconnect();
      ro.disconnect();
      for (const b of blocks) b.closest("figure")?.querySelector(".diagram-full")?.removeEventListener("click", onClick);
      mq.removeEventListener("change", redraw);
    };
  }, []);
  return null;
}
