// Hand-built components (no component kit). Lists are tables with sortable
// headers (FR-8.35); every view has loading, empty and error states that
// show the control API message and reason code (FR-8.29).
import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { ApiError, asApiError } from "./api";
import type { Resource } from "./data";
import { Link, useViewTitle } from "./router";

export function PageHeader({ code, title, children, actions }: { code?: string; title: string; children?: ReactNode; actions?: ReactNode }) {
  useViewTitle(title);
  const ref = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    // Move focus to the new view for screen-reader and keyboard users.
    ref.current?.focus({ preventScroll: true });
  }, [title]);
  return (
    <header className="page-head">
      <div className="page-title">
        <h1 ref={ref} tabIndex={-1}>
          {title}
        </h1>
        {code && <span className="view-code mono">{code}</span>}
      </div>
      {children && <div className="page-lede">{children}</div>}
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function Help({ children }: { children: ReactNode }) {
  return (
    <details className="help">
      <summary>Help for this view</summary>
      <div className="help-body">{children}</div>
    </details>
  );
}

export function Mono({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <span className="mono" title={title}>
      {children}
    </span>
  );
}

/** An ID shortened for tables; the full value is in the title and copyable. */
export function ShortId({ id }: { id: string }) {
  if (!id) return <span className="muted">none</span>;
  const s = id.length > 14 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id;
  return (
    <span className="mono" title={id}>
      {s}
    </span>
  );
}

const rtf = typeof Intl !== "undefined" ? new Intl.RelativeTimeFormat("en", { numeric: "auto", style: "narrow" }) : null;

export function relative(ms: number): string {
  const s = Math.round(ms / 1000);
  const a = Math.abs(s);
  if (!rtf) return `${s}s`;
  if (a < 60) return rtf.format(s, "second");
  if (a < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (a < 86400) return rtf.format(Math.round(s / 3600), "hour");
  return rtf.format(Math.round(s / 86400), "day");
}

export function Time({ value, now }: { value?: string; now?: number }) {
  if (!value) return <span className="muted">none</span>;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return <Mono>{value}</Mono>;
  const iso = d.toISOString().replace(".000Z", "Z");
  return (
    <time dateTime={value} title={iso} className="mono">
      {iso.slice(0, 19).replace("T", " ")} <span className="muted">({relative(d.getTime() - (now ?? Date.now()))})</span>
    </time>
  );
}

export type Tone = "ok" | "warn" | "bad" | "pending" | "neutral";

/** A state word with a tone marker; the word itself carries the meaning. */
export function StateLabel({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={`state state-${tone}`}>
      <span className="state-mark" aria-hidden="true" />
      {children}
    </span>
  );
}

export function toneOf(state: string): Tone {
  switch (state) {
    case "healthy":
    case "running":
    case "active":
    case "verified":
    case "approved":
    case "permit":
    case "delivered":
    case "completed":
    case "done":
      return "ok";
    case "degraded":
    case "not_running":
    case "expired":
    case "consumed":
    case "withheld":
    case "filtered":
    case "indeterminate":
    case "not_run":
    case "suspended":
      return "warn";
    case "fail-closed":
    case "failed":
    case "denied":
    case "deny":
    case "terminated":
    case "stopped":
      return "bad";
    case "pending":
      return "pending";
    default:
      return "neutral";
  }
}

export function ErrorBlock({ error, retry, what, doing }: { error: ApiError; retry?: () => void; what?: string; doing?: string }) {
  if (error.status === 403 && error.code !== "csrf_invalid") {
    return (
      <div className="notice notice-bad" role="alert">
        <p>
          <strong>Your account's role cannot open this.</strong> {error.message}
        </p>
        <p className="mono small">
          HTTP 403 {error.code && <>reason {error.code}</>}
        </p>
      </div>
    );
  }
  return (
    <div className="notice notice-bad" role="alert">
      <p>
        <strong>{what ? `Could not load ${what}.` : doing ? `Could not complete ${doing}.` : "The request failed."}</strong> {error.message}
      </p>
      <p className="mono small">
        {error.status ? `HTTP ${error.status}` : "no response"}
        {error.code && <> reason {error.code}</>}
      </p>
      {retry && (
        <button type="button" onClick={retry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function Unavailable({ route, what }: { route: string; what: string }) {
  return (
    <div className="notice notice-neutral" role="status">
      <p>
        <strong>Not available in this build.</strong> {what} needs <span className="mono">{route}</span>, which this Gateway does not serve yet. The view
        fills in once the element that owns the route is installed.
      </p>
    </div>
  );
}

export function Loading({ what }: { what: string }) {
  return (
    <p className="loading" role="status" aria-live="polite">
      Loading {what}
    </p>
  );
}

/** Renders a resource's loading, unavailable and error states, else children. */
export function Loaded<T>({ res, what, route, children }: { res: Resource<T>; what: string; route?: string; children: (data: T) => ReactNode }) {
  if (res.status === "loading") return <Loading what={what} />;
  if (res.status === "error") {
    if (route && res.error.unavailable) return <Unavailable route={route} what={what[0]!.toUpperCase() + what.slice(1)} />;
    if (res.error.code.endsWith("_disabled")) return <Disabled error={res.error} />;
    return <ErrorBlock error={res.error} retry={res.reload} what={what} />;
  }
  return <>{children(res.data)}</>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export interface Column<T> {
  key: string;
  label: string;
  /** Sort value; omit for an unsortable column. */
  sort?: (row: T) => string | number;
  render: (row: T) => ReactNode;
  className?: string;
}

/** A table with sortable column headers (aria-sort, keyboard buttons). */
export function DataTable<T>({
  caption,
  columns,
  rows,
  rowKey,
  initialSort,
  initialDir = "asc",
  empty,
  rowClass,
}: {
  caption: string;
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  initialSort?: string;
  initialDir?: "asc" | "desc";
  empty: ReactNode;
  rowClass?: (row: T) => string | undefined;
}) {
  const [sort, setSort] = useState<{ key?: string; dir: "asc" | "desc" }>({ key: initialSort, dir: initialDir });
  const sorted = useMemo(() => {
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.sort) return rows;
    const f = col.sort;
    const out = [...rows].sort((a, b) => {
      const x = f(a);
      const y = f(b);
      return x < y ? -1 : x > y ? 1 : 0;
    });
    return sort.dir === "desc" ? out.reverse() : out;
  }, [rows, columns, sort]);
  if (rows.length === 0) return <Empty>{empty}</Empty>;
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label={caption}>
      <table>
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => {
              const active = sort.key === c.key;
              return (
                <th key={c.key} scope="col" className={c.className} aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : c.sort ? "none" : undefined}>
                  {c.sort ? (
                    <button
                      type="button"
                      className="sort"
                      onClick={() => setSort({ key: c.key, dir: active && sort.dir === "asc" ? "desc" : "asc" })}
                    >
                      {c.label}
                      <span className="sort-mark" aria-hidden="true">
                        {active ? (sort.dir === "asc" ? "▲" : "▼") : "△"}
                      </span>
                    </button>
                  ) : (
                    c.label
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sorted.map((r) => (
            <tr key={rowKey(r)} className={rowClass?.(r)}>
              {columns.map((c) => (
                <td key={c.key} className={c.className}>
                  {c.render(r)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (
        <div key={k} className="kv-row">
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** The page budget for server-supplied evidence text (SR-3.3-1). */
export const EVIDENCE_PAGE_BYTES = 256 * 1024;

/** The text a JsonBlock shows for a value. */
export function blockText(value: unknown): string {
  return typeof value === "string" ? value : (JSON.stringify(value, null, 2) ?? "");
}

/** The UTF-8 length of a string. */
export function utf8Length(s: string): number {
  return new TextEncoder().encode(s).length;
}

/** Cuts a string to at most limit UTF-8 bytes without splitting a character. */
export function cutUtf8(s: string, limit: number): string {
  const b = new TextEncoder().encode(s);
  if (b.length <= limit) return s;
  return new TextDecoder().decode(b.slice(0, Math.max(0, limit))).replace(/�+$/, "");
}

/** Server-supplied content as escaped text, bounded in UTF-8 bytes (SR-3.3-1, SR-6.17-1). */
export function JsonBlock({ value, label, limit = EVIDENCE_PAGE_BYTES }: { value: unknown; label: string; limit?: number }) {
  const text = blockText(value);
  const size = utf8Length(text);
  const cut = size > limit;
  return (
    <figure className="json">
      <figcaption>{label}</figcaption>
      <pre tabIndex={0}>{cut ? cutUtf8(text, limit) : text}</pre>
      {cut && (
        <p className="small muted">
          Shown: the first {Math.floor(limit / 1024)} KiB of {Math.ceil(size / 1024)} KiB.
        </p>
      )}
    </figure>
  );
}

/** A modal confirmation built on the native dialog element (Escape closes). */
export function Dialog({
  open,
  title,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const id = useId();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog ref={ref} aria-labelledby={id} onClose={onClose} onCancel={onClose}>
      <h2 id={id}>{title}</h2>
      {open && children}
    </dialog>
  );
}

export function Crumbs({ items }: { items: [string, string | null][] }) {
  return (
    <nav aria-label="Breadcrumb" className="crumbs">
      <ol>
        {items.map(([label, to]) => (
          <li key={label}>{to ? <Link to={to}>{label}</Link> : <span aria-current="page">{label}</span>}</li>
        ))}
      </ol>
    </nav>
  );
}

export function Section({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  const id = useId();
  return (
    <section className="section" aria-labelledby={id}>
      <div className="section-head">
        <h2 id={id}>{title}</h2>
        {actions && <div className="section-actions">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

/** An element that this Gateway has but whose configuration turns it off. */
export function Disabled({ error }: { error: ApiError }) {
  return (
    <div className="notice notice-neutral" role="status">
      <p>
        <strong>Not enabled on this Gateway.</strong> {error.message}
      </p>
      <p className="mono small">reason {error.code}</p>
    </div>
  );
}

/** State of one control API action: busy flag, last error and last result. */
export function useAction<T = unknown>() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [result, setResult] = useState<T | null>(null);
  const run = async (f: () => Promise<T>, after?: (r: T) => void): Promise<boolean> => {
    setBusy(true);
    setError(null);
    try {
      const r = await f();
      setResult(r);
      after?.(r);
      return true;
    } catch (e) {
      setError(asApiError(e));
      return false;
    } finally {
      setBusy(false);
    }
  };
  const reset = () => {
    setError(null);
    setResult(null);
  };
  return { busy, error, result, run, reset };
}

/** A labelled text input. */
export function TextField({
  label,
  value,
  onChange,
  name,
  required,
  type = "text",
  placeholder,
  mono,
  autoComplete = "off",
  hint,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  name?: string;
  required?: boolean;
  type?: string;
  placeholder?: string;
  mono?: boolean;
  autoComplete?: string;
  hint?: ReactNode;
}) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        name={name}
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required={required}
        placeholder={placeholder}
        className={mono ? "mono" : undefined}
        autoComplete={autoComplete}
        spellCheck={false}
        aria-describedby={hint ? id + "-hint" : undefined}
      />
      {hint && (
        <span className="hint" id={id + "-hint"}>
          {hint}
        </span>
      )}
    </div>
  );
}

/** A labelled select of fixed options. */
export function SelectField({
  label,
  value,
  onChange,
  options,
  name,
  hint,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: (string | [string, string])[];
  name?: string;
  hint?: ReactNode;
}) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <select id={id} name={name} value={value} onChange={(e) => onChange(e.target.value)} aria-describedby={hint ? id + "-hint" : undefined}>
        {options.map((o) => {
          const [v, l] = typeof o === "string" ? [o, o] : o;
          return (
            <option key={v} value={v}>
              {l}
            </option>
          );
        })}
      </select>
      {hint && (
        <span className="hint" id={id + "-hint"}>
          {hint}
        </span>
      )}
    </div>
  );
}

/** A group of checkboxes choosing several of a fixed list (no free text). */
export function CheckList({ legend, options, value, onChange, hint }: { legend: string; options: string[]; value: string[]; onChange: (v: string[]) => void; hint?: ReactNode }) {
  const id = useId();
  return (
    <fieldset className="checklist" aria-describedby={hint ? id + "-hint" : undefined}>
      <legend>{legend}</legend>
      {hint && (
        <span className="hint" id={id + "-hint"}>
          {hint}
        </span>
      )}
      {options.length === 0 && <span className="muted small">none available</span>}
      {options.map((o) => (
        <label key={o}>
          <input type="checkbox" checked={value.includes(o)} onChange={(e) => onChange(e.target.checked ? [...value, o] : value.filter((x) => x !== o))} />
          <span className="mono">{o}</span>
        </label>
      ))}
    </fieldset>
  );
}

/** A short confirmation line after an action. */
export function Done({ children }: { children: ReactNode }) {
  return (
    <p className="notice notice-ok" role="status">
      {children}
    </p>
  );
}

/** Formats a byte count with binary units. */
export function bytes(n?: number | null): string {
  if (n === undefined || n === null || Number.isNaN(n)) return "unknown";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  let v = n;
  while (Math.abs(v) >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
}

/** Formats a number compactly (1,284 / 12.9K / 4.2M). */
export function compact(n?: number | null, digits = 1): string {
  if (n === undefined || n === null || Number.isNaN(n)) return "none";
  const a = Math.abs(n);
  if (a >= 1e6) return `${(n / 1e6).toFixed(digits)}M`;
  if (a >= 1e4) return `${(n / 1e3).toFixed(digits)}K`;
  if (Number.isInteger(n)) return n.toLocaleString("en");
  return n.toFixed(a < 10 ? 2 : 1);
}
