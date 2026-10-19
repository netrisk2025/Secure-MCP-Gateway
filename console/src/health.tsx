// Gateway health shared by the status strip and Gateway control, and the
// emergency stop / resume actions (FR-4.14, FR-8.3).
import { createContext, useContext, useState, type ReactNode } from "react";
import { ApiError, post } from "./api";
import { useResource, type Resource } from "./data";
import { usePerm } from "./perm";
import type { Health } from "./types";
import { Dialog, ErrorBlock } from "./ui";

const HealthContext = createContext<Resource<Health> | null>(null);

export function HealthProvider({ children }: { children: ReactNode }) {
  const res = useResource<Health>("/admin/v1/health");
  return <HealthContext.Provider value={res}>{children}</HealthContext.Provider>;
}

export function useHealth(): Resource<Health> | null {
  return useContext(HealthContext);
}

export const causeText: Record<string, string> = {
  unconfined: "Standalone profile: server instances run as your user without a sandbox. The installation is not enforced.",
  unverified_manifests: "Tool lists come from the running servers, not from signed package manifests.",
  emergency_stop: "Emergency stop is in effect. No call is dispatched or released until an operator resumes.",
  no_decision_snapshot: "No policy snapshot is loaded, so every call is refused.",
  evidence_unavailable: "The evidence journal cannot record events, so every call is refused.",
  audit_capacity: "The disk holding the journal is below its free-space reserve.",
  graph_unavailable: "The graph mirror is unavailable. Enforcement is not affected.",
  vault_locked: "The secret vault is locked, so servers that need secrets do not start.",
};

export function isStopped(h?: Health): boolean {
  return !!h?.causes.includes("emergency_stop");
}

/** The emergency stop or resume button with its confirmation dialog. */
export function EmergencyControl({ compact = false }: { compact?: boolean }) {
  const health = useHealth();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [warning, setWarning] = useState("");
  const perm = usePerm();
  if (!health || health.status !== "ok") return null;
  const stopped = isStopped(health.data);
  if (stopped && !perm.can("POST /admin/v1/resume")) return <span className={compact ? "strip-item" : "small"}>Resume needs an Administrator</span>;
  if (!stopped && !perm.can("POST /admin/v1/stop")) return null;
  const close = () => {
    setOpen(false);
    setError(null);
  };
  const act = async () => {
    setBusy(true);
    setError(null);
    try {
      if (stopped) {
        await post("/admin/v1/resume", {});
      } else {
        const r = await post<{ state: string; warning?: string }>("/admin/v1/stop", { reason: reason.trim() });
        setWarning(r.warning ?? "");
      }
      setOpen(false);
      setReason("");
      health.reload();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <button type="button" className={stopped ? "btn-primary" : "btn-danger"} onClick={() => setOpen(true)} data-testid="emergency-button">
        {stopped ? "Resume" : "Emergency stop"}
      </button>
      {warning && stopped && (
        <span className={compact ? "strip-item" : "small"} role="status">
          Stopped, but the journal did not record it: {warning}
        </span>
      )}
      <Dialog open={open} onClose={close} title={stopped ? "Resume the Gateway" : "Emergency stop"}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void act();
          }}
        >
          {stopped ? (
            <p>Tool calls will be decided and dispatched again under the active policy revision. The resume is recorded in the evidence journal.</p>
          ) : (
            <>
              <p>
                The Gateway refuses every tool call at once: no call is dispatched to a server and no result of a call in flight is released to a harness.
                The stop lasts until someone resumes, also across sessions. It is recorded in the evidence journal with your account and the reason.
              </p>
              <label className="field">
                <span>Reason</span>
                <input value={reason} onChange={(e) => setReason(e.target.value)} required maxLength={500} autoFocus name="reason" />
              </label>
            </>
          )}
          {error && <ErrorBlock error={error} />}
          <div className="dialog-actions">
            <button type="button" onClick={close}>
              Cancel
            </button>
            <button type="submit" className={stopped ? "btn-primary" : "btn-danger"} disabled={busy || (!stopped && !reason.trim())}>
              {stopped ? "Resume the Gateway" : "Stop the Gateway"}
            </button>
          </div>
        </form>
      </Dialog>
    </>
  );
}
