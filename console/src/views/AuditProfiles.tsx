// G-03 Audit profile tuning (FR-8.5): the mandatory audit floor, shown
// read-only because it cannot be lowered, and the Audit Profile above it:
// observation retention and the parameters captured when a call scores
// elevated or worse. The editor publishes Audit Profile revisions
// (POST /api/v1/observations/audit-profile); the values in force are read
// from GET /api/v1/observations/status. Alert bands are under G-06.
import { useState } from "react";
import { useResource } from "../data";
import { DataTable, Help, JsonBlock, KV, Loaded, Mono, PageHeader, Section, TextField } from "../ui";
import { ObjectState, Publish, useObjects } from "./objects";
import type { ObsStatus } from "./Observations";

/** Evidence the journal always records, whatever the profile. */
const floor: [string, string, string][] = [
  ["call", "Every tool call phase: requested, authorized, dispatched, completed, delivered, and each refusal with its reason code", "E-02, E-12"],
  ["decision", "Each policy decision with its revision, considered and decisive rules", "E-06"],
  ["session", "Session establishment, refresh-token rotation, end and its reason", "E-04"],
  ["auth_failure", "Failed sign-ins and refused tokens on both listeners", "E-03, E-24"],
  ["admin", "Every administrative action with its actor: stop, resume, policy publication, configuration reload, key rotation, backup", "E-24"],
  ["approval", "Approval requests and decisions with the approver", "E-07"],
  ["filter", "Each filter chain run with every filter's action and findings", "E-09, E-11"],
  ["package", "Package import, enablement, suspension, drift and revocation", "E-13, E-14"],
  ["egress", "Every egress operation, allowed or denied", "E-18"],
  ["secret", "Secret creation, rotation, delivery, leak detection and revocation", "E-19, E-20"],
  ["journal", "Segment seals, key transitions and recovery", "E-21"],
];

function Editor({ s }: { s: ObsStatus }) {
  const objects = useObjects();
  const [retention, setRetention] = useState(s.retention?.replace(/m0s$/, "m").replace(/h0m$/, "h") ?? "2160h");
  const [escalation, setEscalation] = useState((s.escalation_parameters ?? []).join(" "));
  const params = escalation.split(/[\s,]+/).filter(Boolean);
  const ok = /^\d+(h|m)$|^\d+h\d+m$/.test(retention.trim());
  const toml = `[observation]\nretention = "${retention}"\nescalation_parameters = [${params.map((p) => JSON.stringify(p)).join(", ")}]\n`;
  return (
    <Section title="Audit Profile: optional capture and retention">
      {objects.status === "ok" && <ObjectState objects={objects.data} kind="audit_profile" label="Audit Profile" />}
      <div className="rule-grid">
        <TextField label="Observation retention (Go duration, at least 24h)" value={retention} onChange={setRetention} mono />
        <TextField label="Escalation parameters (captured from elevated)" value={escalation} onChange={setEscalation} mono />
      </div>
      {!ok && (
        <p className="notice notice-bad" role="alert">
          The retention must be a duration in hours or minutes, such as 2160h.
        </p>
      )}
      <Publish route="/api/v1/observations/audit-profile" label="Audit Profile" body={{ retention: retention.trim(), escalation_parameters: params }} disabled={!ok} onPublished={objects.reload} />
      {ok && <JsonBlock value={toml} label="The same settings as smcp.toml configuration" />}
      <p className="small">Nothing here can remove an event of the mandatory floor. The normal-band sampling rate is part of the Observation Policy (Observation workbench).</p>
    </Section>
  );
}

export function AuditProfiles() {
  const res = useResource<ObsStatus>("/api/v1/observations/status");
  return (
    <>
      <PageHeader code="G-03" title="Audit profile tuning">
        <p>The mandatory audit floor, which cannot be lowered, and the optional capture and retention settings above it. Alert bands are set under Anomaly response.</p>
      </PageHeader>
      <Help>
        <p>
          The evidence journal records the mandatory floor for every call and action, signed and hash-chained, regardless of any setting here. Audit profiles only
          add capture: how many normal calls are sampled into the Observation Store, which extra parameters are captured when a call scores elevated or worse,
          and how long observations are kept.
        </p>
      </Help>
      <Section title="Mandatory floor (read-only)">
        <DataTable
          caption="Mandatory audit floor"
          rows={floor}
          rowKey={(r) => r[0]}
          empty=""
          columns={[
            { key: "c", label: "Event class", render: (r) => <Mono>{r[0]}</Mono> },
            { key: "w", label: "Always recorded", render: (r) => r[1] },
            { key: "e", label: "Elements", render: (r) => <Mono>{r[2]}</Mono> },
          ]}
        />
      </Section>
      <Loaded res={res} what="the capture settings" route="/api/v1/observations/status">
        {(s) => (
          <>
            <Section title="In force">
              <KV
                rows={[
                  ["Observation", s.enabled ? "enabled" : "disabled"],
                  ["Sampling rate", <Mono>{s.sampling_rate ?? "none"}</Mono>],
                  ["Retention", <Mono>{s.retention ?? "none"}</Mono>],
                  ["Escalation parameters", <Mono>{(s.escalation_parameters ?? []).join(" ") || "none"}</Mono>],
                  ["Parameters captured", <Mono>{s.parameters?.length ?? 0}</Mono>],
                ]}
              />
            </Section>
            {s.enabled && <Editor s={s} />}
          </>
        )}
      </Loaded>
    </>
  );
}
