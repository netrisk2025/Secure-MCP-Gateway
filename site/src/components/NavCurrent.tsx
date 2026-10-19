"use client";

import { usePathname } from "next/navigation";
import { useEffect } from "react";

/** Marks the current chapter link with aria-current. */
export default function NavCurrent() {
  const path = usePathname();
  useEffect(() => {
    const p = path.endsWith("/") ? path : `${path}/`;
    for (const a of document.querySelectorAll<HTMLAnchorElement>(".chapters a[data-href]")) {
      const href = a.dataset.href ?? "";
      if (p.startsWith(href)) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
  }, [path]);
  return null;
}
