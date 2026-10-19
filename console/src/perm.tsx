// Route permissions of the signed-in account (FR-8.2, FR-8.28). The control
// API answers GET /api/v1/console/session with every registered route and
// the Appendix C roles that may use it; the navigation lists a view when
// the role may use one of its routes, and actions are offered only when
// the role may use the action's route. The server enforces the same table.
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { asApiError, get, type ApiError, type Role } from "./api";
import { ErrorBlock, Loading } from "./ui";

export interface RouteInfo {
  pattern: string;
  method: string;
  path: string;
  public?: boolean;
  roles?: string[];
  refined?: boolean;
}

interface ConsoleSession {
  actor: string;
  role: Role;
  routes: RouteInfo[];
}

export interface Perm {
  role: Role;
  actor: string;
  /** True when the role may use the route pattern ("POST /api/v1/backup"). */
  can: (pattern: string) => boolean;
  /** True when this build registers the route pattern. */
  has: (pattern: string) => boolean;
}

const PermContext = createContext<Perm | null>(null);

export function makePerm(role: Role, actor: string, routes: RouteInfo[]): Perm {
  const byPattern = new Map(routes.map((r) => [r.pattern, r]));
  return {
    role,
    actor,
    has: (p) => byPattern.has(p),
    can: (p) => {
      const r = byPattern.get(p);
      if (!r) return false;
      if (r.public) return true;
      return role === "administrator" || (r.roles ?? []).includes(role);
    },
  };
}

export function PermProvider({ role, children }: { role: Role; children: ReactNode }) {
  const [state, setState] = useState<{ perm?: Perm; error?: ApiError; n: number }>({ n: 0 });
  useEffect(() => {
    const ctl = new AbortController();
    get<ConsoleSession>("/api/v1/console/session", ctl.signal).then(
      (s) => setState((x) => ({ n: x.n, perm: makePerm(s.role ?? role, s.actor, s.routes ?? []) })),
      (e: unknown) => {
        if ((e as Error).name !== "AbortError") setState((x) => ({ n: x.n, error: asApiError(e) }));
      },
    );
    return () => ctl.abort();
  }, [role, state.n]);
  if (state.error)
    return (
      <main className="main" id="main">
        <ErrorBlock error={state.error} what="the permissions of this account" retry={() => setState((x) => ({ n: x.n + 1 }))} />
      </main>
    );
  if (!state.perm)
    return (
      <main className="main" id="main">
        <Loading what="the permissions of this account" />
      </main>
    );
  return <PermContext.Provider value={state.perm}>{children}</PermContext.Provider>;
}

export function usePerm(): Perm {
  const p = useContext(PermContext);
  if (!p) throw new Error("usePerm outside PermProvider");
  return p;
}

/** Renders children only when the role may use the route. */
export function Can({ route, children }: { route: string; children: ReactNode }) {
  return usePerm().can(route) ? <>{children}</> : null;
}
