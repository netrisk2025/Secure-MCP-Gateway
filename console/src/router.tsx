// A small History API router. Every view and every approval, session,
// server, event and decision has its own path (FR-8.28); smcpd serves the
// console page for any path that is not a control API route.
import { useEffect, useSyncExternalStore, type AnchorHTMLAttributes, type MouseEvent } from "react";

const listeners = new Set<() => void>();
function subscribe(f: () => void) {
  listeners.add(f);
  window.addEventListener("popstate", f);
  return () => {
    listeners.delete(f);
    window.removeEventListener("popstate", f);
  };
}
const snapshot = () => window.location.pathname + window.location.search;

export function navigate(to: string, replace = false): void {
  if (to === snapshot()) return;
  if (replace) window.history.replaceState(null, "", to);
  else window.history.pushState(null, "", to);
  listeners.forEach((f) => f());
}

export function useLocation(): { path: string; query: URLSearchParams } {
  const loc = useSyncExternalStore(subscribe, snapshot);
  const i = loc.indexOf("?");
  return { path: i < 0 ? loc : loc.slice(0, i), query: new URLSearchParams(i < 0 ? "" : loc.slice(i)) };
}

/** Matches "/sessions/:id" against a path; returns params or null. */
export function match(pattern: string, path: string): Record<string, string> | null {
  const a = pattern.split("/").filter(Boolean);
  const b = path.split("/").filter(Boolean);
  if (a.length !== b.length) return null;
  const out: Record<string, string> = {};
  for (let i = 0; i < a.length; i++) {
    const p = a[i]!;
    const v = b[i]!;
    if (p.startsWith(":")) out[p.slice(1)] = decodeURIComponent(v);
    else if (p !== v) return null;
  }
  return out;
}

export function Link({ to, onClick, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { to: string }) {
  const handle = (e: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(e);
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    navigate(to);
  };
  return <a href={to} onClick={handle} {...rest} />;
}

/** Sets document.title and moves focus to the view heading on navigation. */
export function useViewTitle(title: string): void {
  useEffect(() => {
    document.title = `${title} | Gateway console`;
  }, [title]);
}
