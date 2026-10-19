import type { ReactNode } from "react";
import type { Implementation, ReqStatus, StatusSnapshot } from "@/lib/status";
import { IMPL_TEXT, REQ_STATUS_TEXT, fmtDateTime } from "@/lib/labels";

/**
 * Page header in the manner of an RFC front block: two columns of document
 * control facts above the title, then the title and a one-paragraph summary.
 */
export function DocHead({
  chapter,
  title,
  left,
  right,
  children,
}: {
  chapter?: number;
  title: string;
  left: ReactNode[];
  right: ReactNode[];
  children?: ReactNode;
}) {
  return (
    <header className="dochead">
      <div className="frontblock">
        <ul>
          {left.map((l, i) => (
            <li key={i}>{l}</li>
          ))}
        </ul>
        <ul>
          {right.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      </div>
      <h1>
        {chapter !== undefined && <span className="h1no">{chapter}</span>}
        {title}
      </h1>
      {children && <div className="summary">{children}</div>}
    </header>
  );
}

/** A numbered section. The number hangs in the left margin on wide screens. */
export function Sec({ no, id, title, children }: { no: string; id: string; title: string; children: ReactNode }) {
  return (
    <section className="sec" aria-labelledby={`${id}-h`} id={id}>
      <h2 id={`${id}-h`}>
        <a className="secno" href={`#${id}`} aria-label={`Section ${no}`}>
          {no}
        </a>
        {title}
      </h2>
      {children}
    </section>
  );
}

/** A marginal note: in the right margin on wide screens, inline on narrow ones. */
export function Note({ children, label }: { children: ReactNode; label?: string }) {
  return (
    <aside className="note" aria-label={label ?? "Note"}>
      {children}
    </aside>
  );
}

const GLYPH: Record<ReqStatus, ReactNode> = {
  verified: <rect x="1" y="1" width="8" height="8" />,
  partial: (
    <>
      <rect x="1.5" y="1.5" width="7" height="7" fill="none" strokeWidth="1" />
      <rect x="1" y="1" width="4" height="8" />
    </>
  ),
  failing: <path d="M1.5 1.5 L8.5 8.5 M8.5 1.5 L1.5 8.5" fill="none" strokeWidth="2" />,
  unverified: <rect x="1.5" y="1.5" width="7" height="7" fill="none" strokeWidth="1" />,
};

/** Requirement status as glyph plus word. The word carries the meaning; color and glyph repeat it. */
export function ReqBadge({ status, text }: { status: ReqStatus; text?: string }) {
  return (
    <span className={`rbadge rb-${status}`}>
      <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true" focusable="false">
        {GLYPH[status]}
      </svg>
      {text ?? REQ_STATUS_TEXT[status]}
    </span>
  );
}

const IMPL_GLYPH: Record<Implementation, ReactNode> = {
  implemented: <rect x="1" y="1" width="8" height="8" />,
  partial: (
    <>
      <rect x="1.5" y="1.5" width="7" height="7" fill="none" strokeWidth="1" />
      <rect x="1" y="1" width="4" height="8" />
    </>
  ),
  "not-started": <rect x="1.5" y="1.5" width="7" height="7" fill="none" strokeWidth="1" />,
};

export function ImplBadge({ impl }: { impl: Implementation | undefined }) {
  if (!impl) return <span className="ibadge ib-none">no data</span>;
  return (
    <span className={`ibadge ib-${impl}`}>
      <svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true" focusable="false">
        {IMPL_GLYPH[impl]}
      </svg>
      {IMPL_TEXT[impl]}
    </span>
  );
}

/** Shown wherever status figures appear when they come from the checked-in sample. */
export function SampleNotice({ snap }: { snap: StatusSnapshot }) {
  if (snap.source !== "sample") return null;
  return (
    <p className="sample-notice" role="note">
      <strong>Sample data.</strong> The figures on this page come from <code>site/data/status.sample.json</code>, not
      from a CI run. {snap.reason} The next build after CI publishes <code>status.json</code> shows real figures.
    </p>
  );
}

export function GeneratedAt({ snap }: { snap: StatusSnapshot }) {
  return <time dateTime={snap.status.generatedAt}>{fmtDateTime(snap.status.generatedAt)}</time>;
}
