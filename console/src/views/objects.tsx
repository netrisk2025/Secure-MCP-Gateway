// Published observation objects (G-03, G-04, G-06, G-08): the Audit
// Profile, Observation Policy, Anomaly Response Policy and memory budget
// are revisions held by the Gateway (GET /api/v1/observations/objects).
// The observation components read them when smcpd starts, so a new
// revision is shown as pending until then.
import { useState } from "react";
import { post } from "../api";
import { useResource } from "../data";
import { usePerm } from "../perm";
import { Done, ErrorBlock, KV, Mono, Time, useAction } from "../ui";

export interface ObjectRevision {
  kind: string;
  number: number;
  digest: string;
  body: Record<string, unknown>;
  published_by: string;
  published_at: string;
  reason?: string;
}

export interface ObjectStatus {
  kind: string;
  active?: ObjectRevision;
  in_force: number;
  pending: boolean;
  restart_required?: string[];
  revisions: number;
}

export interface Objects {
  objects: ObjectStatus[];
  applies: string;
  effective?: Record<string, unknown>;
  effective_error?: string;
  apply_error?: string;
}

export const objectsRoute = "/api/v1/observations/objects";

export function useObjects() {
  return useResource<Objects>(objectsRoute);
}

/** The published and in-force revisions of one kind. */
export function ObjectState({ objects, kind, label }: { objects: Objects; kind: string; label: string }) {
  const o = objects.objects.find((x) => x.kind === kind);
  if (!o?.active) return <p className="small">No {label} has been published; the [observation] settings of smcp.toml are in force.</p>;
  const a = o.active;
  return (
    <>
      <KV
        rows={[
          [`Published ${label}`, <Mono>revision {a.number}</Mono>],
          ["Digest", <Mono>{a.digest.slice(0, 19)}</Mono>],
          ["Published by", <Mono>{a.published_by}</Mono>],
          ["Published", <Time value={a.published_at} />],
          ["In force", o.in_force ? <Mono>revision {o.in_force}</Mono> : "the smcp.toml settings"],
        ]}
      />
      {o.pending && (
        <p className="notice notice-warn" role="status">
          {o.restart_required?.length
            ? `Revision ${a.number} is in force except ${o.restart_required.join(" and ")}, which take effect at the next start of smcpd.`
            : `Revision ${a.number} is not in force; ${objects.apply_error ? `the running service refused it: ${objects.apply_error}` : "it takes effect at the next start of smcpd"}.`}
        </p>
      )}
    </>
  );
}

/** Publishes a revision of one kind with a reason; hidden when this build has no route. */
export function Publish({
  route,
  label,
  body,
  disabled,
  onPublished,
}: {
  route: string;
  label: string;
  body: Record<string, unknown>;
  disabled?: boolean;
  onPublished?: () => void;
}) {
  const perm = usePerm();
  const [reason, setReason] = useState("");
  const act = useAction<{ revision: ObjectRevision; applies?: string }>();
  if (!perm.has(`POST ${route}`)) return null;
  if (!perm.can(`POST ${route}`)) return <p className="small muted">Publishing the {label} needs another role.</p>;
  return (
    <form
      className="inline-form"
      aria-label={`Publish the ${label}`}
      onSubmit={(e) => {
        e.preventDefault();
        void act.run(
          () => post(route, { body, reason: reason.trim() }),
          () => {
            setReason("");
            onPublished?.();
          },
        );
      }}
    >
      <div className="field">
        <label htmlFor={`reason-${route}`}>Reason for this revision (recorded in the journal)</label>
        <input id={`reason-${route}`} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} autoComplete="off" />
      </div>
      <button type="submit" className="btn-primary" disabled={disabled || act.busy}>
        Publish the {label}
      </button>
      {act.error && <ErrorBlock error={act.error} doing={`publishing the ${label}`} />}
      {act.result && (
        <Done>
          Published {label} revision {act.result.revision.number}. It applies {act.result.applies ?? "at the next start of smcpd"}.
        </Done>
      )}
    </form>
  );
}
