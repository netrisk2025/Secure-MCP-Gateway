// G-07 Performance & meta-metrics (FR-8.15): throughput over time, p50,
// p95 and p99 gateway-added overhead per policy revision, time per
// enforcement stage, and time per decisive rule and per filter, all
// filterable by policy revision.
// Routes: /api/v1/observations/metrics, /cost and /aggregate.
import { useState } from "react";
import { BarChart, LineChart } from "../charts";
import { useResource } from "../data";
import { DataTable, Help, Loaded, Mono, PageHeader, Section, SelectField, compact } from "../ui";

interface MetricRow {
  ts: string;
  throughput: number;
  concurrent_calls: number;
  cpu_per_element: string;
  observation_ingest_rate: number;
}

interface CostRow {
  group: Record<string, string>;
  count: number;
  mean: number;
  min: number;
  max: number;
  quantiles: number[];
  total_ms: number;
}

/** Span time of one rule or filter since start (FR-10.11, Collector.Cost). */
interface ObjectCost {
  stage: string;
  policy_revision: string;
  rule_id?: string;
  filter_id?: string;
  observation_policy?: string;
  spans: number;
  total_ms: number;
  mean_ms: number;
  max_ms: number;
}

function ObjectCostTable({ caption, rows, label, id }: { caption: string; rows: ObjectCost[]; label: string; id: (r: ObjectCost) => string }) {
  return (
    <DataTable
      caption={caption}
      rows={rows}
      rowKey={(r) => `${r.stage}|${r.policy_revision}|${r.rule_id ?? ""}|${r.filter_id ?? ""}|${r.observation_policy ?? ""}`}
      initialSort="total"
      initialDir="desc"
      empty="No timing recorded since smcpd started. Timings appear after tool calls when observation is enabled."
      columns={[
        { key: "id", label, sort: (r) => id(r), render: (r) => <Mono>{id(r)}</Mono> },
        { key: "stage", label: "Stage", sort: (r) => r.stage, render: (r) => <Mono>{r.stage}</Mono> },
        { key: "rev", label: "Policy revision", sort: (r) => r.policy_revision, render: (r) => <Mono>{r.policy_revision}</Mono> },
        { key: "n", label: "Spans", sort: (r) => r.spans, render: (r) => <Mono>{r.spans}</Mono>, className: "num" },
        { key: "mean", label: "Mean (ms)", sort: (r) => r.mean_ms, render: (r) => <Mono>{compact(r.mean_ms)}</Mono>, className: "num" },
        { key: "max", label: "Max (ms)", sort: (r) => r.max_ms, render: (r) => <Mono>{compact(r.max_ms)}</Mono>, className: "num" },
        { key: "total", label: "Total (ms)", sort: (r) => r.total_ms, render: (r) => <Mono>{compact(r.total_ms)}</Mono>, className: "num" },
      ]}
    />
  );
}

const ranges: [string, string][] = [
  ["1h", "last hour"],
  ["6h", "last 6 hours"],
  ["24h", "last 24 hours"],
  ["168h", "last 7 days"],
];

function cpu(s: string): number {
  try {
    const v = JSON.parse(s) as Record<string, number>;
    return v.smcpd ?? Object.values(v)[0] ?? 0;
  } catch {
    return 0;
  }
}

export function Performance() {
  const [range, setRange] = useState("6h");
  const [rev, setRev] = useState("");
  const metrics = useResource<{ rows: MetricRow[] }>(`/api/v1/observations/metrics?from=${range}&limit=2000`);
  const cost = useResource<{ rows: CostRow[]; policy_objects?: ObjectCost[] }>(`/api/v1/observations/cost?from=${range}`);
  const overhead = useResource<{ rows: CostRow[] }>(`/api/v1/observations/aggregate?feature=gateway_overhead&from=${range}&group_by=policy_revision&quantiles=0.5,0.95,0.99`);
  const revisions =
    cost.status === "ok"
      ? [...new Set([...cost.data.rows.map((r) => r.group.policy_revision ?? ""), ...(cost.data.policy_objects ?? []).map((r) => r.policy_revision)])].filter(Boolean).sort()
      : [];
  return (
    <>
      <PageHeader code="G-07" title="Performance">
        <p>Throughput, the time the Gateway adds to each call, and the time each enforcement stage and policy revision costs.</p>
      </PageHeader>
      <Help>
        <p>
          Gateway overhead is the end-to-end latency of a call minus the time the server spent. Stage time is measured with a monotonic clock for every stage
          and attributed to the policy revision and Observation Policy in force. Compare revisions by selecting them in turn, or read them side by side in the
          overhead table. The loopback /metrics endpoint exports the same counters for Prometheus.
        </p>
      </Help>
      <div className="filters">
        <SelectField label="Time range" value={range} onChange={setRange} options={ranges} />
        <SelectField label="Policy revision" value={rev} onChange={setRev} options={[["", "all revisions"], ...revisions.map((r) => [r, r] as [string, string])]} />
      </div>
      <Section title="Throughput">
        <Loaded res={metrics} what="meta-metrics" route="/api/v1/observations/metrics">
          {(d) => (
            <>
              <LineChart title="Calls assembled per second" unit="calls/s" series={[{ name: "throughput", points: d.rows.map((r) => ({ x: new Date(r.ts).getTime(), y: r.throughput })) }]} />
              <LineChart title="Gateway CPU" unit="percent" series={[{ name: "smcpd", points: d.rows.map((r) => ({ x: new Date(r.ts).getTime(), y: cpu(r.cpu_per_element) })) }]} />
            </>
          )}
        </Loaded>
      </Section>
      <Section title="Gateway overhead per policy revision">
        <Loaded res={overhead} what="overhead" route="/api/v1/observations/aggregate">
          {(d) => (
            <DataTable
              caption="Gateway overhead per policy revision"
              rows={d.rows.filter((r) => !rev || r.group.policy_revision === rev)}
              rowKey={(r) => r.group.policy_revision ?? ""}
              initialSort="rev"
              empty="No stored call in this range. Overhead is measured once calls are observed."
              columns={[
                { key: "rev", label: "Policy revision", sort: (r) => r.group.policy_revision ?? "", render: (r) => <Mono>{r.group.policy_revision}</Mono> },
                { key: "n", label: "Calls", sort: (r) => r.count, render: (r) => <Mono>{r.count}</Mono>, className: "num" },
                { key: "p50", label: "p50 (ms)", sort: (r) => r.quantiles?.[0] ?? 0, render: (r) => <Mono>{compact(r.quantiles?.[0])}</Mono>, className: "num" },
                { key: "p95", label: "p95 (ms)", sort: (r) => r.quantiles?.[1] ?? 0, render: (r) => <Mono>{compact(r.quantiles?.[1])}</Mono>, className: "num" },
                { key: "p99", label: "p99 (ms)", sort: (r) => r.quantiles?.[2] ?? 0, render: (r) => <Mono>{compact(r.quantiles?.[2])}</Mono>, className: "num" },
                { key: "max", label: "Max (ms)", sort: (r) => r.max, render: (r) => <Mono>{compact(r.max)}</Mono>, className: "num" },
              ]}
            />
          )}
        </Loaded>
      </Section>
      <Section title="Time per stage and policy object">
        <Loaded res={cost} what="stage cost" route="/api/v1/observations/cost">
          {(d) => {
            const rows = d.rows.filter((r) => !rev || r.group.policy_revision === rev);
            const byStage = new Map<string, number>();
            for (const r of rows) byStage.set(r.group.stage ?? "", (byStage.get(r.group.stage ?? "") ?? 0) + r.total_ms);
            return (
              <>
                <BarChart title={`Total time per stage${rev ? ` under ${rev}` : ""}`} unit="ms" bars={[...byStage.entries()].sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value }))} />
                <DataTable
                  caption="Time per stage, policy revision and observation policy"
                  rows={rows}
                  rowKey={(r) => JSON.stringify(r.group)}
                  initialSort="total"
                  initialDir="desc"
                  empty="No stage timing in this range. Stage timings appear after tool calls when observation is enabled."
                  columns={[
                    { key: "stage", label: "Stage or object", sort: (r) => r.group.stage ?? "", render: (r) => <Mono>{r.group.stage ?? r.group.rule ?? r.group.filter ?? ""}</Mono> },
                    { key: "rev", label: "Policy revision", sort: (r) => r.group.policy_revision ?? "", render: (r) => <Mono>{r.group.policy_revision}</Mono> },
                    { key: "op", label: "Observation policy", render: (r) => <Mono>{r.group.observation_policy}</Mono> },
                    { key: "n", label: "Count", sort: (r) => r.count, render: (r) => <Mono>{r.count}</Mono>, className: "num" },
                    { key: "mean", label: "Mean (ms)", sort: (r) => r.mean, render: (r) => <Mono>{compact(r.mean)}</Mono>, className: "num" },
                    { key: "p95", label: "p95 (ms)", render: (r) => <Mono>{compact(r.quantiles?.[1])}</Mono>, className: "num" },
                    { key: "total", label: "Total (ms)", sort: (r) => r.total_ms, render: (r) => <Mono>{compact(r.total_ms)}</Mono>, className: "num" },
                  ]}
                />
              </>
            );
          }}
        </Loaded>
      </Section>
      <Section title="Time per rule and filter">
        <Loaded res={cost} what="rule and filter cost" route="/api/v1/observations/cost">
          {(d) => {
            const objs = (d.policy_objects ?? []).filter((r) => !rev || r.policy_revision === rev);
            return (
              <>
                <p className="small">Span time since smcpd started, attributed to the decisive rule of each decision and to each filter that ran{rev ? ` under ${rev}` : ""}.</p>
                <ObjectCostTable caption="Time per decisive rule" label="Rule" rows={objs.filter((r) => r.rule_id)} id={(r) => r.rule_id ?? ""} />
                <ObjectCostTable caption="Time per filter" label="Filter" rows={objs.filter((r) => r.filter_id)} id={(r) => r.filter_id ?? ""} />
              </>
            );
          }}
        </Loaded>
      </Section>
    </>
  );
}
