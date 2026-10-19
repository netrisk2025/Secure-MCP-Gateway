// Console shell: sign-in for every Appendix C role, the status strip with
// enforcement state and emergency stop, the navigation of the views the
// role may open, and the current view.
import { Component, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { asApiError, loginPath, logoutPath, post, restoreSession, roleLabel, setCredentials, setUnauthorizedHandler, signIn, type ApiError, type Credentials, type Role } from "./api";
import { LiveProvider, useLive } from "./data";
import { EmergencyControl, HealthProvider, isStopped, useHealth } from "./health";
import { PermProvider, usePerm } from "./perm";
import { Link, navigate, useLocation } from "./router";
import { ThemeSelect } from "./theme";
import { ErrorBlock, Mono, StateLabel, toneOf } from "./ui";
import { allowed, startPath, viewFor, views, type ViewDef } from "./views/registry";

type Kind = "administrator" | "approver" | "session_approver" | "console";

const kinds: [Kind, string][] = [
  ["administrator", "Administrator"],
  ["approver", "Approver (tool-call approvals)"],
  ["session_approver", "Session Approver (client registrations)"],
  ["console", "Operator, Policy Author, Auditor or Researcher"],
];

function SignIn({ onSignedIn, expired }: { onSignedIn: (c: Credentials) => void; expired: boolean }) {
  const [kind, setKind] = useState<Kind>("administrator");
  const [user, setUser] = useState("admin");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [bootstrap, setBootstrap] = useState(false);
  const [token, setToken] = useState("");
  const [newPw, setNewPw] = useState("");
  const [bootDone, setBootDone] = useState(false);
  useEffect(() => {
    document.title = "Sign in | Gateway console";
  }, []);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const role: Role = kind === "console" ? "operator" : kind;
      const body: Record<string, string> = { username: user.trim(), password };
      if (kind === "session_approver") body.role = "session_approver";
      onSignedIn(await signIn(loginPath(role), body));
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
      setPassword("");
    }
  };
  const redeem = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await post("/admin/v1/bootstrap", { token: token.trim(), password: newPw });
      setBootDone(true);
      setBootstrap(false);
      setKind("administrator");
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
      setNewPw("");
      setToken("");
    }
  };
  return (
    <main className="signin" id="main">
      <h1>Gateway console</h1>
      <p className="lede">Sign in to control this Secure MCP Gateway. The console talks only to the control API on this loopback address.</p>
      {expired && (
        <p className="notice notice-warn" role="status">
          Your sign-in ended. Sign in again to continue where you were.
        </p>
      )}
      {bootDone && (
        <p className="notice notice-ok" role="status">
          The administrator password is set. Sign in with it.
        </p>
      )}
      {!bootstrap ? (
        <form onSubmit={submit} aria-label="Sign in">
          <fieldset className="choice choice-stack">
            <legend>Account</legend>
            {kinds.map(([k, label]) => (
              <label key={k}>
                <input
                  type="radio"
                  name="kind"
                  checked={kind === k}
                  onChange={() => {
                    setKind(k);
                    setUser(k === "administrator" ? "admin" : "");
                  }}
                />
                {label}
              </label>
            ))}
          </fieldset>
          <label className="field">
            <span>Username</span>
            <input value={user} onChange={(e) => setUser(e.target.value)} autoComplete="username" required name="username" />
          </label>
          <label className="field">
            <span>Password</span>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required name="password" />
          </label>
          {error && <ErrorBlock error={error} />}
          <button type="submit" className="btn-primary" disabled={busy}>
            {busy ? "Signing in" : "Sign in"}
          </button>
          <p className="small">
            Session Approvers also approve harness sign-ins on the Gateway's own sign-in page when a harness connects. First installation:{" "}
            <button
              type="button"
              className="link"
              onClick={() => {
                setBootstrap(true);
                setError(null);
              }}
            >
              set the administrator password with a bootstrap token
            </button>
            .
          </p>
        </form>
      ) : (
        <form onSubmit={redeem} aria-label="Set the administrator password">
          <p>
            <Mono>smcpctl bootstrap</Mono> without a password file prints a one-use bootstrap token that is valid for 24 hours. Enter it with the new
            administrator password (at least 12 characters).
          </p>
          <label className="field">
            <span>Bootstrap token</span>
            <input value={token} onChange={(e) => setToken(e.target.value)} required autoComplete="off" spellCheck={false} />
          </label>
          <label className="field">
            <span>New administrator password</span>
            <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} minLength={12} required autoComplete="new-password" />
          </label>
          {error && <ErrorBlock error={error} />}
          <div className="dialog-actions">
            <button type="button" onClick={() => setBootstrap(false)}>
              Back to sign-in
            </button>
            <button type="submit" className="btn-primary" disabled={busy}>
              Set password
            </button>
          </div>
        </form>
      )}
    </main>
  );
}

function StatusStrip({ cred, onSignOut }: { cred: Credentials; onSignOut: () => void }) {
  const health = useHealth();
  const live = useLive();
  const perm = usePerm();
  const h = health?.status === "ok" ? health.data : undefined;
  const stopped = isStopped(h);
  const cls = h ? (h.state === "fail-closed" ? "strip strip-bad" : h.state === "degraded" ? "strip strip-warn" : "strip") : "strip";
  return (
    <header className={cls} data-testid="status-strip">
      <a className="skip" href="#main">
        Skip to content
      </a>
      <span className="strip-name">Secure MCP Gateway</span>
      {h ? (
        <>
          <span className="strip-item" aria-live="polite">
            <span className="sr-only">Enforcement state: </span>
            <StateLabel tone={toneOf(h.state)}>{stopped ? "emergency stop" : h.state}</StateLabel>
          </span>
          <span className="strip-item">
            {h.profile}: <strong>{h.release_label}</strong>
          </span>
          <span className="strip-item">
            policy <Mono>{h.policy_revision ?? "none"}</Mono>
          </span>
          <span className="strip-item">
            <Mono>{h.sessions}</Mono> session{h.sessions === 1 ? "" : "s"}
          </span>
        </>
      ) : health?.status === "error" ? (
        <span className="strip-item">health unavailable: {health.error.message}</span>
      ) : (
        <span className="strip-item">reading health</span>
      )}
      <span className="strip-item strip-live" title={live.lastEvent ? `last change ${live.lastEvent}` : undefined}>
        {live.connected ? "live" : live.available ? "not live: refresh to update" : "updates on reload"}
      </span>
      <span className="strip-spacer" />
      {(perm.can("POST /admin/v1/stop") || perm.can("POST /admin/v1/resume")) && <EmergencyControl compact />}
      <span className="strip-item">
        {roleLabel[cred.role]} <Mono>{perm.actor || cred.actor}</Mono>
      </span>
      <button type="button" className="btn-quiet" onClick={onSignOut}>
        Sign out
      </button>
    </header>
  );
}

function Nav({ current }: { current?: ViewDef }) {
  const perm = usePerm();
  const shown = views.filter((v) => allowed(v, perm));
  const groups = [...new Set(shown.map((v) => v.group))];
  return (
    <nav className="rail" aria-label="Views">
      {groups.map((g) => (
        <div key={g} className="rail-group">
          <h2>{g}</h2>
          <ul>
            {shown
              .filter((v) => v.group === g)
              .map((v) => (
                <li key={v.path}>
                  <Link to={v.path} aria-current={current === v ? "page" : undefined}>
                    <span className="rail-code mono">{v.code ?? ""}</span>
                    {v.title}
                  </Link>
                </li>
              ))}
          </ul>
        </div>
      ))}
      <ThemeSelect />
    </nav>
  );
}

/** Keeps a failing view from blanking the console; shows the error as text. */
class ViewBoundary extends Component<{ path: string; children: ReactNode }, { error: string; path: string }> {
  state = { error: "", path: this.props.path };
  static getDerivedStateFromError(e: unknown) {
    return { error: String((e as Error)?.message ?? e) };
  }
  static getDerivedStateFromProps(p: { path: string }, s: { error: string; path: string }) {
    return p.path !== s.path ? { error: "", path: p.path } : null;
  }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="notice notice-bad" role="alert">
        <p>
          <strong>This view could not be shown.</strong> {this.state.error}
        </p>
        <p className="small">Reload the page; if it persists, the response of the control API did not have the expected shape.</p>
      </div>
    );
  }
}

function Shell({ cred, onSignOut }: { cred: Credentials; onSignOut: () => void }) {
  const { path } = useLocation();
  const perm = usePerm();
  const view = viewFor(path);
  const ok = view && allowed(view, perm);
  useEffect(() => {
    // A role without the start view lands on its own.
    if (path === "/" && startPath(perm) !== "/") navigate(startPath(perm), true);
  }, [perm, path]);
  const stream = perm.can("GET /api/v1/audit/stream") ? "/api/v1/audit/stream" : perm.can("GET /api/v1/approvals/watch") ? "/api/v1/approvals/watch" : null;
  return (
    <LiveProvider path={stream}>
      <HealthProvider>
        <StatusStrip cred={cred} onSignOut={onSignOut} />
        <div className="layout">
          <Nav current={view} />
          <main id="main" className="main">
            {!view ? (
              <>
                <h1 tabIndex={-1}>No such view</h1>
                <p className="empty">
                  <Mono>{path}</Mono> is not a console view. <Link to={startPath(perm)}>Open the start view</Link>.
                </p>
              </>
            ) : !ok ? (
              <>
                <h1 tabIndex={-1}>{view.title}</h1>
                <p className="notice notice-bad" role="alert">
                  The {roleLabel[perm.role]} role cannot open this view. Sign in with an account whose role may use it.
                </p>
              </>
            ) : (
              <ViewBoundary path={path}>{view.render(path)}</ViewBoundary>
            )}
          </main>
        </div>
      </HealthProvider>
    </LiveProvider>
  );
}

export function App() {
  // undefined while the page asks whether this tab still has a session.
  const [cred, setCred] = useState<Credentials | null | undefined>(undefined);
  const [expired, setExpired] = useState(false);
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setCredentials(null);
      setCred(null);
      setExpired(true);
    });
    let live = true;
    void restoreSession().then((c) => {
      if (!live) return;
      setCredentials(c);
      setCred(c);
    });
    return () => {
      live = false;
    };
  }, []);
  useEffect(() => {
    if (!cred) return;
    const t = window.setTimeout(
      () => {
        setCredentials(null);
        setCred(null);
        setExpired(true);
      },
      Math.max(0, cred.expiresAt - Date.now()),
    );
    return () => window.clearTimeout(t);
  }, [cred]);
  const signOut = async () => {
    try {
      await post(logoutPath, {});
    } catch {
      // The server ends the session on idle in any case.
    }
    setCredentials(null);
    setCred(null);
    setExpired(false);
  };
  if (cred === undefined) {
    return (
      <main className="signin" id="main">
        <h1>Gateway console</h1>
        <p className="lede" role="status">
          Checking the sign-in of this tab.
        </p>
      </main>
    );
  }
  if (!cred) {
    return (
      <SignIn
        expired={expired}
        onSignedIn={(c) => {
          setCredentials(c);
          setCred(c);
          setExpired(false);
        }}
      />
    );
  }
  return (
    <PermProvider key={cred.csrf} role={cred.role}>
      <Shell cred={cred} onSignOut={() => void signOut()} />
    </PermProvider>
  );
}
