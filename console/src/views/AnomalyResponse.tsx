// G-06 Anomaly response policy (FR-8.14): what the Gateway does at each
// sigma band and in the uncharacterized state. Only actions from the
// restrict-only set can be chosen: they add obligations to a call and
// never widen what policy permits. The editor publishes Anomaly Response
// Policy revisions (POST /api/v1/observations/anomaly-response); the
// mapping in force is read from GET /api/v1/observations/status. The band
// thresholds belong to the Observation Policy (G-04) and are published
// there.
import { useEffect, useState } from "react";
import { useResource } from "../data";
import { DataTable, Help, JsonBlock, Loaded, Mono, PageHeader, Section, SelectField, StateLabel, TextField } from "../ui";
import { ObjectState, Publish, useObjects } from "./objects";
import type { ObsStatus } from "./Observations";

const bands = ["elevated", "abnormal", "critical"] as const;
type Band = (typeof bands)[number];

/** The restrict-only actions, each including the ones before it. */
const actions: [string, string][] = [
  ["alert", "Record and alert"],
  ["escalate", "Alert and escalate capture"],
  ["approve", "Escalate and require approval"],
  ["withhold", "Require approval and withhold the result"],
];

/** Restrict-only actions in the uncharacterized state (no snapshot for the context). */
const unchar: [string, string][] = [
  ["record", "Record only"],
  ["escalate", "Escalate capture"],
  ["approve", "Escalate and require approval"],
];

function current(s: ObsStatus, b: Band): string {
  const rank = (x?: string) => (x && x !== "off" ? bands.indexOf(x as Band) : 99);
  if (rank(s.withhold_band) <= bands.indexOf(b)) return "withhold";
  if (rank(s.require_approval_band) <= bands.indexOf(b)) return "approve";
  if (rank(s.escalate_capture_band ?? "elevated") <= bands.indexOf(b)) return "escalate";
  return "alert";
}

function Editor({ s }: { s: ObsStatus }) {
  const objects = useObjects();
  const [map, setMap] = useState<Record<Band, string>>(() => ({ elevated: current(s, "elevated"), abnormal: current(s, "abnormal"), critical: current(s, "critical") }));
  const [un, setUn] = useState(s.uncharacterized || "record");
  const t = s.thresholds ?? { elevated: 2, abnormal: 3, critical: 4 };
  const [th, setTh] = useState<Record<Band, string>>({ elevated: String(t.elevated ?? 2), abnormal: String(t.abnormal ?? 3), critical: String(t.critical ?? 4) });
  // A band's action is at least as strict as the band below it.
  useEffect(() => {
    const order = actions.map((a) => a[0]);
    let floor = 0;
    let changed = false;
    const next = { ...map };
    for (const b of bands) {
      const i = order.indexOf(next[b]);
      if (i < floor) {
        next[b] = order[floor]!;
        changed = true;
      }
      floor = Math.max(floor, order.indexOf(next[b]));
    }
    if (changed) setMap(next);
  }, [map]);
  const first = (a: string) => bands.find((b) => actions.findIndex((x) => x[0] === map[b]) >= actions.findIndex((x) => x[0] === a));
  const escalate = first("escalate") ?? "off";
  const approve = first("approve") ?? "off";
  const withhold = first("withhold") ?? "off";
  const sync = approve !== "off" || withhold !== "off" || un === "approve";
  const nums = bands.map((b) => Number(th[b]));
  const ordered = nums.every((n, i) => n > 0 && (i === 0 || n > nums[i - 1]!));
  const scoring = sync ? "sync" : ((s.scoring === "off" ? "async" : s.scoring) ?? "async");
  const toml = `[observation]\nscoring = "${scoring}"\nescalate_capture_band = "${escalate}"\nuncharacterized_action = "${un}"\nrequire_approval_band = "${approve}"\nwithhold_band = "${withhold}"\n\n[observation.baseline]\nbands = [${nums.join(", ")}]\n`;
  return (
    <Section title="Edit the response">
      <p className="small">Each band applies its action and every action of the bands below it. A higher band cannot be set less strict than a lower one.</p>
      <div className="table-wrap" tabIndex={0} role="region" aria-label="Band actions">
        <table>
          <caption className="sr-only">Band thresholds and actions</caption>
          <thead>
            <tr>
              <th scope="col">Band</th>
              <th scope="col">From (σ)</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>uncharacterized</td>
              <td className="muted">no snapshot for the context</td>
              <td>
                <SelectField label="uncharacterized action" value={un} onChange={setUn} options={unchar} />
              </td>
            </tr>
            {bands.map((b) => (
              <tr key={b}>
                <td>{b}</td>
                <td>
                  <TextField label={`${b} threshold`} value={th[b]} onChange={(v) => setTh({ ...th, [b]: v })} type="number" />
                </td>
                <td>
                  <SelectField label={`${b} action`} value={map[b]} onChange={(v) => setMap({ ...map, [b]: v })} options={actions} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!ordered && (
        <p className="notice notice-bad" role="alert">
          Thresholds must be positive and increase from elevated to critical.
        </p>
      )}
      {sync && <p className="small">Requiring approval or withholding results needs synchronous scoring, which adds the scoring time to each call.</p>}
      <p className="small">
        A band set to "Record and alert" records the score and alerts without escalating capture. In the uncharacterized state the context has no snapshot, so
        no score exists; the action applies to every such call.
      </p>
      {objects.status === "ok" && <ObjectState objects={objects.data} kind="anomaly_response" label="Anomaly Response Policy" />}
      <Publish
        route="/api/v1/observations/anomaly-response"
        label="Anomaly Response Policy"
        body={{ scoring, escalate_capture_band: escalate, uncharacterized: un, require_approval_band: approve, withhold_band: withhold }}
        onPublished={objects.reload}
      />
      {ordered && (
        <>
          <p className="small">
            The thresholds are published with the Observation Policy in the Observation workbench. The same settings as smcp.toml configuration:
          </p>
          <JsonBlock value={toml} label="Configuration for this response policy" />
        </>
      )}
    </Section>
  );
}

export function AnomalyResponse() {
  const res = useResource<ObsStatus>("/api/v1/observations/status");
  return (
    <>
      <PageHeader code="G-06" title="Anomaly response">
        <p>What the Gateway does when a call departs from its baseline: record, alert, escalate capture, require approval or withhold the result.</p>
      </PageHeader>
      <Help>
        <p>
          Every action restricts a call; none can permit what policy refuses. Asynchronous scoring (the default) only records, alerts and escalates capture after
          the result is released. Synchronous scoring can also add an approval obligation before dispatch or withhold the result. Suspending a session on an
          anomaly is part of the architecture but not of this build, so it is not offered.
        </p>
      </Help>
      <Loaded res={res} what="the response policy" route="/api/v1/observations/status">
        {(s) =>
          !s.enabled ? (
            <p className="empty">Observation is disabled, so calls are not scored. Set [observation] enabled = true.</p>
          ) : (
            <>
              <Section title="In force">
                <DataTable
                  caption="Current response per band"
                  rows={["uncharacterized", ...bands].map((b) => ({ b }))}
                  rowKey={(r) => r.b}
                  empty=""
                  columns={[
                    { key: "b", label: "Band", render: (r) => r.b },
                    { key: "t", label: "From (σ)", render: (r) => <Mono>{r.b === "uncharacterized" ? "none" : String(s.thresholds?.[r.b] ?? "")}</Mono> },
                    {
                      key: "a",
                      label: "Action",
                      render: (r) =>
                        s.scoring === "off" ? (
                          "record only"
                        ) : r.b === "uncharacterized" ? (
                          (unchar.find((a) => a[0] === (s.uncharacterized || "record"))?.[1] ?? "")
                        ) : (
                          <StateLabel tone={current(s, r.b as Band) === "withhold" ? "bad" : current(s, r.b as Band) === "approve" ? "pending" : "neutral"}>
                            {actions.find((a) => a[0] === current(s, r.b as Band))?.[1] ?? ""}
                          </StateLabel>
                        ),
                    },
                  ]}
                />
                <p className="small">
                  Scoring mode <Mono>{s.scoring}</Mono>, baseline snapshot <Mono>{s.baseline?.promoted ?? "none promoted"}</Mono>.
                </p>
              </Section>
              <Editor s={s} />
            </>
          )
        }
      </Loaded>
    </>
  );
}
