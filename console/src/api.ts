// Control API client. The console signs in for a browser session
// (SR-2.6-1): the session ID is an HttpOnly, Secure, SameSite=Strict cookie
// that script cannot read, and no bearer token reaches the page. Every
// state-changing request sends the session's CSRF token and an If-Match
// precondition (SR-8.9-1). Revisions are per object on the server: a
// mutation is refused only when its own object changed after the tag it
// names. The console keeps the ETag of its latest answer for each resource
// collection (the first path segment below /api/v1/ or /admin/v1/) and
// sends the one of the collection it changes, so a change elsewhere never
// forces a re-read and a change to the same collection by someone else
// since the view read it is reported.

export type Role = "administrator" | "operator" | "policy_author" | "approver" | "session_approver" | "auditor" | "researcher";

/** Display names of the Appendix C roles. */
export const roleLabel: Record<Role, string> = {
  administrator: "Administrator",
  operator: "Operator",
  policy_author: "Policy Author",
  approver: "Approver",
  session_approver: "Session Approver",
  auditor: "Auditor",
  researcher: "Researcher",
};

/** The sign-in route of each account kind. */
export function loginPath(role: Role): string {
  if (role === "administrator") return "/admin/v1/login";
  if (role === "approver") return "/api/v1/approvals/login";
  return "/api/v1/console/login";
}

/** The sign-out route of a browser session (every account kind). */
export const logoutPath = "/admin/v1/session/logout";

const loginPaths = new Set(["/admin/v1/login", "/api/v1/approvals/login", "/api/v1/console/login"]);

/** The signed-in browser session as the page knows it (no secret but the CSRF token). */
export interface Credentials {
  role: Role;
  actor: string;
  csrf: string;
  expiresAt: number;
}

/** The answer of a login route in cookie mode, and of GET /api/v1/console/session. */
export interface SessionAnswer {
  role: Role;
  actor: string;
  csrf_token: string;
  expires_at: string;
}

export function credentialsOf(a: SessionAnswer): Credentials {
  return { role: a.role, actor: a.actor, csrf: a.csrf_token, expiresAt: Date.parse(a.expires_at) || Date.now() + 8 * 3600_000 };
}

/** An error answer of the control API, or a network failure (status 0). */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly body: unknown;
  constructor(status: number, code: string, message: string, body?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.body = body;
  }
  /** The route is not served by this build (another element not merged yet). */
  get unavailable(): boolean {
    return (this.status === 404 && (this.code === "route_not_found" || this.code === "")) || (this.status === 405 && this.code === "");
  }
}

let current: Credentials | null = null;
let onUnauthorized: (() => void) | null = null;
/** The ETag of the latest answer per resource collection, and overall (SR-8.9-1). */
const revisions = new Map<string, string>();
let revision = "";

/** The resource collection of a control API path ("principals" for /api/v1/principals/x/suspend). */
export function collectionOf(path: string): string {
  const m = /^\/(?:api|admin)\/v1\/([^/?#]+)/.exec(path);
  return m ? m[1]! : "";
}

export function setCredentials(c: Credentials | null): void {
  current = c;
}
export function credentials(): Credentials | null {
  return current;
}
export function setUnauthorizedHandler(f: () => void): void {
  onUnauthorized = f;
}

function isMutation(method: string): boolean {
  return method !== "GET" && method !== "HEAD";
}

export interface RequestOptions {
  signal?: AbortSignal;
  /** A refresh the console makes on its own: not user activity for the CP-29 idle limit. */
  background?: boolean;
  /** Extra headers (the login routes ask for a cookie session). */
  headers?: Record<string, string>;
}

function headers(method: string, json: boolean, o: RequestOptions = {}, path = ""): Headers {
  const h = new Headers({ Accept: "application/json" });
  if (json) h.set("Content-Type", "application/json");
  if (o.background) h.set("X-SMCP-Background", "1");
  if (current && isMutation(method)) {
    h.set("X-CSRF-Token", current.csrf);
    const tag = revisions.get(collectionOf(path)) || revision;
    if (tag) h.set("If-Match", tag);
  }
  for (const [k, v] of Object.entries(o.headers ?? {})) h.set(k, v);
  return h;
}

/** Whether tag names a later point than old: a higher sequence of the same smcpd start, or another start. */
function newer(tag: string, old: string | undefined): boolean {
  const a = /^"(.*)-(\d+)"$/.exec(tag);
  const b = old ? /^"(.*)-(\d+)"$/.exec(old) : null;
  if (!a || !b || a[1] !== b[1]) return true;
  return Number(a[2]) >= Number(b[2]);
}

function noteRevision(res: Response, path: string): void {
  const tag = res.headers.get("ETag");
  if (!tag) return;
  // A slow read that answers after a later change must not replace the
  // later tag (its view is older).
  if (newer(tag, revision)) revision = tag;
  const c = collectionOf(path);
  if (c && newer(tag, revisions.get(c))) revisions.set(c, tag);
}

/** Restores the browser session of this tab after a reload; null when there is none. */
export async function restoreSession(): Promise<Credentials | null> {
  try {
    const s = await request<SessionAnswer & { session?: string }>("GET", "/api/v1/console/session", undefined, { background: true });
    return s.session === "cookie" ? credentialsOf(s) : null;
  } catch {
    return null;
  }
}

async function parse(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function toError(res: Response, body: unknown): ApiError {
  const e = (body as { error?: { code?: string; message?: string } } | null)?.error;
  if (e?.code === "revision_stale")
    return new ApiError(res.status, e.code, "The Gateway state changed since this view was last read (another change reached it first). Check the view and submit again.", body);
  if (e?.code === "csrf_invalid") return new ApiError(res.status, e.code, "The request token of this session was missing or wrong. Reload the page and try again.", body);
  if (e) return new ApiError(res.status, e.code ?? "", e.message ?? res.statusText, body);
  if (res.status === 404 || res.status === 405) return new ApiError(res.status, "", "This route is not served by this Gateway build.", body);
  return new ApiError(res.status, "", typeof body === "string" && body ? body.slice(0, 300) : res.statusText || "request failed", body);
}

export async function request<T>(method: "GET" | "POST" | "DELETE", path: string, body?: unknown, o: RequestOptions = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers: headers(method, method === "POST", o, path),
      body: method === "POST" ? JSON.stringify(body ?? {}) : undefined,
      credentials: "same-origin",
      cache: "no-store",
      signal: o.signal,
    });
  } catch (err) {
    if ((err as Error).name === "AbortError") throw err;
    throw new ApiError(0, "network", "The Gateway did not answer. Check that smcpd is running and that this page is open at the admin listener address.");
  }
  noteRevision(res, path);
  const parsed = await parse(res);
  if (!res.ok) {
    const e = toError(res, parsed);
    if (res.status === 401 && current && !loginPaths.has(path)) onUnauthorized?.();
    throw e;
  }
  return parsed as T;
}

export const get = <T>(path: string, signal?: AbortSignal, background = false) => request<T>("GET", path, undefined, { signal, background });
export const post = <T>(path: string, body?: unknown) => request<T>("POST", path, body);
export const del = <T>(path: string) => request<T>("DELETE", path);

/** Signs in for a browser session at a login route. */
export async function signIn(path: string, body: Record<string, string>): Promise<Credentials> {
  const a = await request<SessionAnswer>("POST", path, body, { headers: { "X-SMCP-Session": "cookie" } });
  return credentialsOf(a);
}

/** Fetches a GET route as text (for files the console shows, not saves). */
export async function getText(path: string): Promise<string> {
  const res = await fetch(path, { headers: headers("GET", false), credentials: "same-origin", cache: "no-store" });
  noteRevision(res, path);
  const text = await res.text();
  if (!res.ok) {
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {
      // keep text
    }
    throw toError(res, body);
  }
  return text;
}

/** Normalizes anything thrown into an ApiError. */
export function asApiError(e: unknown): ApiError {
  return e instanceof ApiError ? e : new ApiError(0, "client", String(e));
}

/** Downloads a GET response as a file. */
export async function download(path: string, fallbackName: string): Promise<void> {
  const res = await fetch(path, { headers: headers("GET", false), credentials: "same-origin", cache: "no-store" });
  if (!res.ok) throw toError(res, await parse(res));
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") ?? "";
  const m = /filename="([^"]+)"/.exec(cd);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = m?.[1] ?? fallbackName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export interface SSEMessage {
  event: string;
  data: string;
}

/**
 * Reads a text/event-stream over fetch (so that the stream ends with the
 * session and its headers are under control). Reconnects with backoff until
 * aborted.
 */
export function stream(path: string, onMessage: (m: SSEMessage) => void, onState: (open: boolean) => void): () => void {
  const ctl = new AbortController();
  let delay = 1000;
  const run = async () => {
    while (!ctl.signal.aborted) {
      try {
        const res = await fetch(path, { headers: headers("GET", false, { background: true }), credentials: "same-origin", cache: "no-store", signal: ctl.signal });
        if (!res.ok || !res.body) {
          onState(false);
          if (res.status === 401 || res.status === 403 || res.status === 404) return;
          throw new Error(String(res.status));
        }
        onState(true);
        delay = 1000;
        const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += value;
          let i: number;
          while ((i = buf.indexOf("\n\n")) >= 0) {
            const chunk = buf.slice(0, i);
            buf = buf.slice(i + 2);
            let event = "message";
            const data: string[] = [];
            for (const line of chunk.split("\n")) {
              if (line.startsWith("event:")) event = line.slice(6).trim();
              else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
            }
            if (data.length) onMessage({ event, data: data.join("\n") });
          }
        }
        onState(false);
      } catch {
        if (ctl.signal.aborted) return;
        onState(false);
      }
      await new Promise((r) => setTimeout(r, delay));
      delay = Math.min(delay * 2, 15000);
    }
  };
  void run();
  return () => ctl.abort();
}
