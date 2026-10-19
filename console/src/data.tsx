// Data loading with live refresh. The live channel (the evidence stream for
// administrators, the approvals watch stream for approvers) bumps a
// version number on every change; every mounted resource refetches when it
// changes, keeping the old data on screen while it does (FR-8.23).
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError, get, stream } from "./api";

interface Live {
  version: number;
  connected: boolean;
  /** False when the role may read no live channel. */
  available: boolean;
  lastEvent: string;
}
const LiveContext = createContext<Live>({ version: 0, connected: false, available: false, lastEvent: "" });

/** Keeps the live channel at path open; null when the role has none. */
export function LiveProvider({ path, children }: { path: string | null; children: ReactNode }) {
  const [live, setLive] = useState<Live>({ version: 0, connected: false, available: path !== null, lastEvent: "" });
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => {
    if (!path) return;
    const stop = stream(
      path,
      (m) => {
        if (m.event !== "audit" && m.event !== "approval") return;
        window.clearTimeout(timer.current);
        // Coalesce bursts (a call writes several events) into one refresh.
        timer.current = window.setTimeout(() => setLive((l) => ({ ...l, version: l.version + 1, lastEvent: new Date().toISOString() })), 250);
      },
      (open) => setLive((l) => (l.connected === open ? l : { ...l, connected: open })),
    );
    return () => {
      stop();
      window.clearTimeout(timer.current);
    };
  }, [path]);
  return <LiveContext.Provider value={live}>{children}</LiveContext.Provider>;
}

export const useLive = () => useContext(LiveContext);

export type Resource<T> =
  | { status: "loading"; data?: undefined; error?: undefined; reload: () => void; refreshing: boolean }
  | { status: "ok"; data: T; error?: undefined; reload: () => void; refreshing: boolean }
  | { status: "error"; data?: undefined; error: ApiError; reload: () => void; refreshing: boolean };

/** Loads a control API GET route; null path loads nothing. */
export function useResource<T>(path: string | null, opts: { live?: boolean } = {}): Resource<T> {
  const { version } = useLive();
  const live = opts.live !== false;
  const [nonce, setNonce] = useState(0);
  const [state, setState] = useState<{ path: string | null; status: "loading" | "ok" | "error"; data?: T; error?: ApiError; refreshing: boolean }>({
    path,
    status: "loading",
    refreshing: false,
  });
  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const v = live ? version : 0;
  const last = useRef<{ path: string | null; nonce: number } | null>(null);
  useEffect(() => {
    if (!path) return;
    // A refetch caused only by the live channel is not user activity
    // (CP-29 idle limit); a new path or an explicit reload is.
    const background = last.current?.path === path && last.current.nonce === nonce;
    last.current = { path, nonce };
    const ctl = new AbortController();
    setState((s) => (s.path === path && s.status === "ok" ? { ...s, refreshing: true } : { path, status: "loading", refreshing: false }));
    get<T>(path, ctl.signal, background).then(
      (data) => setState({ path, status: "ok", data, refreshing: false }),
      (err: unknown) => {
        if ((err as Error).name === "AbortError") return;
        const e = err instanceof ApiError ? err : new ApiError(0, "client", String(err));
        setState({ path, status: "error", error: e, refreshing: false });
      },
    );
    return () => ctl.abort();
  }, [path, v, nonce]);
  if (state.path !== path || state.status === "loading") return { status: "loading", reload, refreshing: false };
  if (state.status === "error") return { status: "error", error: state.error!, reload, refreshing: state.refreshing };
  return { status: "ok", data: state.data as T, reload, refreshing: state.refreshing };
}

/** Re-renders every interval (for remaining-validity countdowns). */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(t);
  }, [intervalMs]);
  return now;
}
