import Link from "next/link";
import { DocHead, GeneratedAt, ImplBadge, Note, ReqBadge, SampleNotice, Sec } from "@/components/Sheet";
import VerificationBars, { type VerificationRow } from "@/components/charts/VerificationBars";
import TrendChart from "@/components/charts/TrendChart";
import { loadArch } from "@/lib/parse-arch";
import { loadStatus, type ReqStatus } from "@/lib/status";
import { consoleResults } from "@/lib/console-results";
import {
  REQ_STATUSES,
  REQ_STATUS_MEANING,
  buildCommit,
  chapter,
  elementStatusMap,
  fmtDate,
  fmtDateTime,
  fmtPct,
  plural,
  shortSha,
} from "@/lib/site";

export const metadata = { title: "Status" };

const CH = chapter("/status/");

export default function StatusPage() {
  const arch = loadArch();
  const snap = loadStatus();
  const s = snap.status;
  const els = elementStatusMap(s);
  const byEl = new Map(s.requirements.byElement.map((b) => [b.element, b]));
  const covBy = new Map(s.coverage.packages.map((c) => [c.name, c.pct]));
  const r = s.requirements;
  const cons = consoleResults(s);

  const implCount = (k: string) => arch.elements.filter((e) => els.get(e.id)?.implementation === k).length;
  const noData = arch.elements.filter((e) => !els.has(e.id));
  const extra = s.elements.filter((e) => !arch.elements.some((a) => a.id === e.id));

  const rows: VerificationRow[] = arch.subsystems.flatMap((ss) =>
    arch.elements
      .filter((e) => e.subsystemId === ss.id)
      .map((e) => {
        const b = byEl.get(e.id);
        const counts: Record<ReqStatus, number> = b
          ? {
              verified: b.verified,
              partial: b.partial,
              failing: b.failing,
              unverified: Math.max(0, b.total - b.verified - b.partial - b.failing),
            }
          : { verified: 0, partial: 0, failing: 0, unverified: 0 };
        return {
          id: e.id,
          name: e.name,
          group: `${ss.id} ${ss.name}`,
          counts,
          note: b ? undefined : "not in status data",
        };
      }),
  );

  const hist = snap.history;
  const points = hist.map((h) => ({ commit: shortSha(h.commit), date: fmtDate(h.generatedAt) }));
  const histEmpty =
    snap.source === "remote" && snap.historyReason
      ? `No history to plot: ${snap.historyReason}.`
      : "No history yet. Each CI run on main adds one point.";

  const pkgNames = Array.from(new Set([...s.tests.packages.map((p) => p.name), ...s.coverage.packages.map((c) => c.name)])).sort();
  const pkgTests = new Map(s.tests.packages.map((p) => [p.name, p]));

  return (
    <article className="sheet">
      <DocHead
        chapter={CH.n}
        title="Status"
        left={["Secure MCP Gateway", "Implementation and verification status", snap.source === "remote" ? "Source: status.json from CI" : "Source: sample data"]}
        right={[
          snap.source === "remote" ? `commit ${shortSha(s.commit)}` : "commit: none (sample)",
          <GeneratedAt key="g" snap={snap} />,
          `site build ${buildCommit()}`,
        ]}
      >
        <p>
          What exists in code, what its tests show, and which requirements those tests verify. CI writes these figures
          on every push to main; this page is rebuilt from them.
        </p>
      </DocHead>

      <SampleNotice snap={snap} />

      <Sec no={`${CH.n}.1`} id="run" title="Run under report">
        <Note label="Status rules">
          {REQ_STATUSES.map((k) => (
            <p key={k}>
              <ReqBadge status={k} /> {REQ_STATUS_MEANING[k]}
            </p>
          ))}
        </Note>
        <dl className="facts">
          <dt>Data source</dt>
          <dd>
            {snap.source === "remote" ? (
              <a href={snap.statusUrl}>{snap.statusUrl}</a>
            ) : (
              <>
                <code>site/data/status.sample.json</code>. {snap.reason}
              </>
            )}
          </dd>
          <dt>Commit</dt>
          <dd>
            {s.commitUrl ? <a href={s.commitUrl}>{snap.source === "remote" ? s.commit : "sample, no commit"}</a> : s.commit}
          </dd>
          <dt>CI run</dt>
          <dd>
            {s.runUrl ? <a href={s.runUrl}>{s.ci.workflow || "workflow run"}</a> : "not recorded"}
            {s.ci.conclusion ? `, concluded ${s.ci.conclusion}` : ""}
          </dd>
          <dt>Generated</dt>
          <dd>
            <GeneratedAt snap={snap} />
          </dd>
          <dt>Read by this build</dt>
          <dd>{fmtDateTime(snap.fetchedAt)}</dd>
          <dt>History</dt>
          <dd>{plural(hist.length, "run")} recorded{hist.length ? `, ${fmtDate(hist[0].generatedAt)} to ${fmtDate(hist[hist.length - 1].generatedAt)}` : ""}</dd>
        </dl>
      </Sec>

      <Sec no={`${CH.n}.2`} id="implementation" title="Implementation by subsystem">
        <Note label="Totals">
          <p>
            {implCount("implemented")} implemented, {implCount("partial")} partial, {implCount("not-started")} not
            started, of {arch.elements.length} elements.
          </p>
          {noData.length > 0 && <p>No status entry for {noData.map((e) => e.id).join(", ")}.</p>}
          {extra.length > 0 && <p>Status data names elements not in the architecture: {extra.map((e) => e.id).join(", ")}.</p>}
        </Note>
        <p>
          Each element of the architecture with the implementation state recorded in <code>docs/status/elements.json</code>.
          An element is recorded as implemented when its code is wired into <code>smcpd</code>, every requirement
          allocated to it is verified, none is deferred from release 1.0 and its note names no other gap in what the
          release ships; it is partial when it has code but one of those does not hold.
        </p>
        <div className="table-wrap wide">
          <table className="matrix">
            <caption>Elements by subsystem, in architecture order.</caption>
            <tbody>
              {arch.subsystems.map((ss) => {
                const mine = arch.elements.filter((e) => e.subsystemId === ss.id);
                return (
                  <tr key={ss.id}>
                    <th scope="row">
                      {ss.id}
                      <br />
                      {ss.name}
                    </th>
                    <td>
                      <ul>
                        {mine.map((e) => (
                          <li key={e.id}>
                            <span className="id">{e.id}</span>
                            <Link href={`/elements/${e.id}/`}>{e.name}</Link>
                            <ImplBadge impl={els.get(e.id)?.implementation} />
                          </li>
                        ))}
                      </ul>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Sec>

      <Sec no={`${CH.n}.3`} id="element-notes" title="Element status and notes">
        <Note label="Source">
          <p>
            Notes come from <code>docs/status/elements.json</code> through status.json. Requirement counts are those
            allocated to the element.
          </p>
        </Note>
        <p>
          What each element has in code and its main gaps, with the requirements allocated to it by verification status.
          The counts link to the element&apos;s requirements.
        </p>
        <div className="table-wrap wide">
          <table className="notes">
            <caption>
              {arch.elements.length} elements in architecture order. Requirement columns: verified, partial, failing, and
              the total allocated.
            </caption>
            <thead>
              <tr>
                <th scope="col">Element</th>
                <th scope="col">State</th>
                <th scope="col">Note</th>
                <th scope="col" className="num">
                  verified
                </th>
                <th scope="col" className="num">
                  partial
                </th>
                <th scope="col" className="num">
                  failing
                </th>
                <th scope="col" className="num">
                  total
                </th>
              </tr>
            </thead>
            <tbody>
              {arch.elements.map((e) => {
                const st = els.get(e.id);
                const b = byEl.get(e.id);
                const q = (status?: ReqStatus) =>
                  `/requirements/?element=${encodeURIComponent(e.id)}${status ? `&status=${status}` : ""}`;
                return (
                  <tr key={e.id} id={`note-${e.id}`}>
                    <th scope="row">
                      <span className="id">{e.id}</span> <Link href={`/elements/${e.id}/`}>{e.name}</Link>
                      {st && st.packages.length > 0 && (
                        <span className="pkgs">
                          {st.packages.map((p) => (
                            <code key={p}>{p}</code>
                          ))}
                        </span>
                      )}
                    </th>
                    <td>
                      <ImplBadge impl={st?.implementation} />
                    </td>
                    <td className="note-text">{st?.note ? st.note : <span className="nil">none</span>}</td>
                    <td className="num">{b ? <Link href={q("verified")}>{b.verified}</Link> : 0}</td>
                    <td className="num">{b ? <Link href={q("partial")}>{b.partial}</Link> : 0}</td>
                    <td className="num">{b?.failing ? <Link href={q("failing")}><strong>{b.failing}</strong></Link> : 0}</td>
                    <td className="num">{b ? <Link href={q()}>{b.total}</Link> : 0}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Sec>

      <Sec no={`${CH.n}.4`} id="verification" title="Requirement verification by element">
        <Note label="Totals">
          <p>
            {r.verified} verified, {r.partial} partial, {r.failing} failing, {r.unverified} unverified, of {r.total}{" "}
            requirements.
          </p>
        </Note>
        <p>
          Tests claim requirements with <code>reqtest.Verifies</code> (in full) or <code>reqtest.Partial</code>. Each
          requirement counts once, under the element it is allocated to.
        </p>
        <VerificationBars
          id="verif"
          title="Requirements per element by verification status"
          desc={`Horizontal stacked bars for ${rows.length} elements. In total ${r.verified} verified, ${r.partial} partial, ${r.failing} failing and ${r.unverified} unverified of ${r.total}. The data table below lists every value.`}
          rows={rows}
        />
      </Sec>

      <Sec no={`${CH.n}.5`} id="tests" title="Tests and coverage">
        <Note label="Run">
          <p>
            {s.tests.total} tests in {plural(s.tests.packages.length, "package")}, {s.tests.durationSec.toFixed(1)} s of
            package time.
          </p>
        </Note>
        <p>
          {s.tests.passed} passed, {s.tests.failed} failed, {s.tests.skipped} skipped. Total statement coverage as
          reported by CI is {fmtPct(s.coverage.totalPct)}.
        </p>
        <div className="table-wrap wide">
          <table>
            <caption>Go packages, from go test -json and -cover.</caption>
            <thead>
              <tr>
                <th scope="col">Package</th>
                <th scope="col" className="num">passed</th>
                <th scope="col" className="num">failed</th>
                <th scope="col" className="num">skipped</th>
                <th scope="col" className="num">coverage</th>
              </tr>
            </thead>
            <tbody>
              {pkgNames.map((name) => {
                const t = pkgTests.get(name);
                const c = covBy.get(name);
                return (
                  <tr key={name}>
                    <td className="id">{name}</td>
                    <td className="num">{t?.passed ?? 0}</td>
                    <td className="num">{t?.failed ? <strong>{t.failed}</strong> : 0}</td>
                    <td className="num">{t?.skipped ?? 0}</td>
                    <td className="num">{c === undefined ? <span className="nil">none</span> : fmtPct(c)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Sec>

      <Sec no={`${CH.n}.6`} id="trends" title="Trends">
        <p>
          One point per CI run on main, from history.json, which keeps the last 200 runs. Points are spaced by run, not
          by time, because runs are irregular.
        </p>
        <TrendChart
          id="trend-tests"
          title="Tests passed and failed per run"
          desc={`Two lines over ${plural(points.length, "run")}. Latest: ${hist.at(-1)?.testsPassed ?? 0} passed, ${hist.at(-1)?.testsFailed ?? 0} failed.`}
          points={points}
          series={[
            { key: "passed", label: "passed", tone: "passed", values: hist.map((h) => h.testsPassed) },
            { key: "failed", label: "failed", tone: "failed", values: hist.map((h) => h.testsFailed) },
          ]}
          empty={histEmpty}
        />
        <TrendChart
          id="trend-cov"
          title="Statement coverage per run, percent"
          desc={`One line over ${plural(points.length, "run")}. Latest: ${fmtPct(hist.at(-1)?.coveragePct ?? 0)}.`}
          points={points}
          series={[{ key: "cov", label: "coverage", tone: "ink", values: hist.map((h) => h.coveragePct) }]}
          unit="%"
          yMax={100}
          empty={histEmpty}
        />
        <TrendChart
          id="trend-reqs"
          title="Requirements by verification status per run"
          desc={`Three lines over ${plural(points.length, "run")}. Latest: ${hist.at(-1)?.verified ?? 0} verified, ${hist.at(-1)?.partial ?? 0} partial, ${hist.at(-1)?.unverified ?? 0} unverified.`}
          points={points}
          series={[
            { key: "verified", label: "verified", tone: "verified", values: hist.map((h) => h.verified) },
            { key: "partial", label: "partial", tone: "partial", values: hist.map((h) => h.partial) },
            { key: "unverified", label: "unverified", tone: "unverified", values: hist.map((h) => h.unverified) },
          ]}
          empty={histEmpty}
        />
      </Sec>

      <Sec no={`${CH.n}.7`} id="agents" title="Real-agent compatibility">
        <Note label="Totals">
          <p>
            {s.agents.filter((a) => a.result === "pass").length} pass, {s.agents.filter((a) => a.result === "fail").length}{" "}
            fail, {s.agents.filter((a) => a.result === "not-run").length} not run, of {plural(s.agents.length, "client")}.
          </p>
        </Note>
        <p>
          Shipping agent CLIs signed in to a running Gateway and driven through one prompt per scenario (sign-in, catalog,
          allowed call, denied call, approval, ungranted tool); each scenario is judged from the evidence journal. The
          method and the known client findings are in <Link href="/docs/agents-conformance/">the conformance suite</Link>;
          per-agent notes are in <Link href="/clients/">Agents</Link>.
        </p>
        {s.agents.length === 0 ? (
          <p className="empty-state">Not yet run. The compatibility job has not reported results for any client.</p>
        ) : (
          <div className="table-wrap wide">
            <table>
              <caption>Latest result per client from the Real agents workflow.</caption>
              <thead>
                <tr>
                  <th scope="col">Client</th>
                  <th scope="col">Version</th>
                  <th scope="col">Mode</th>
                  <th scope="col">Result</th>
                  <th scope="col">Detail</th>
                </tr>
              </thead>
              <tbody>
                {s.agents.map((a, i) => (
                  <tr key={`${a.client}-${a.mode}-${i}`}>
                    <td>{a.client}</td>
                    <td className="id">{a.version}</td>
                    <td>{a.mode}</td>
                    <td>
                      <ResultMark result={a.result} />
                    </td>
                    <td>{a.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Sec>

      <Sec no={`${CH.n}.8`} id="hostile" title="Hostile fixtures">
        <Note label="Totals">
          <p>
            {s.hostile.filter((h) => h.pass).length} pass, {s.hostile.filter((h) => !h.pass).length} fail, of{" "}
            {plural(s.hostile.length, "fixture")}.
          </p>
        </Note>
        <p>
          Deliberately malicious MCP servers and requests from SRS Appendix L, each run against the real Gateway with the
          behaviour it must show. Observed results cover the standalone and, where the host allows, the enforced profile.
          The fixtures are described in <Link href="/docs/hostile-fixtures/">the hostile fixture suite</Link>.
        </p>
        {s.hostile.length === 0 ? (
          <p className="empty-state">Not yet run. No hostile-fixture results have been reported.</p>
        ) : (
          <div className="table-wrap wide">
            <table>
              <caption>
                {s.hostile.filter((h) => h.pass).length} of {s.hostile.length} fixtures behaved as expected.
              </caption>
              <thead>
                <tr>
                  <th scope="col">Fixture</th>
                  <th scope="col">Attack</th>
                  <th scope="col">Expected</th>
                  <th scope="col">Observed</th>
                  <th scope="col">Result</th>
                </tr>
              </thead>
              <tbody>
                {s.hostile.map((h, i) => (
                  <tr key={`${h.fixture}-${i}`}>
                    <td className="id">{h.fixture}</td>
                    <td>{h.attack}</td>
                    <td>{h.expected}</td>
                    <td>{h.observed}</td>
                    <td>
                      <ResultMark result={h.pass ? "pass" : "fail"} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Sec>

      <Sec no={`${CH.n}.9`} id="console" title="Console in browsers">
        <Note label="Totals">
          <p>
            {cons.engines.length === 0
              ? "No console results in this run."
              : cons.engines.map((e) => `${e.engine}: ${e.passed} passed, ${e.failed} failed`).join("; ") + "."}
          </p>
        </Note>
        <p>
          Playwright drives the embedded console against a real <code>smcpd</code>: one test per view G-01 to G-14 and
          its actions, roles, sign-in and browser sessions, the content security policy, and axe-core WCAG 2.2 AA checks
          of every view in light and dark schemes. The CI job <code>console</code> runs every spec on each engine. The
          suite is described in <Link href="/docs/console/">the console guide</Link>.
        </p>
        {cons.engines.length === 0 ? (
          <p className="empty-state">Not in this run. The status data has no console/e2e packages.</p>
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <caption>Playwright results per browser engine (one version each).</caption>
                <thead>
                  <tr>
                    <th scope="col">Engine</th>
                    <th scope="col" className="num">passed</th>
                    <th scope="col" className="num">failed</th>
                    <th scope="col" className="num">skipped</th>
                  </tr>
                </thead>
                <tbody>
                  {cons.engines.map((e) => (
                    <tr key={e.engine}>
                      <th scope="row">{e.engine}</th>
                      <td className="num">{e.passed}</td>
                      <td className="num">{e.failed ? <strong>{e.failed}</strong> : 0}</td>
                      <td className="num">{e.skipped}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="table-wrap wide">
              <table>
                <caption>
                  {plural(cons.tests.length, "test")} that claim requirements, per engine. &quot;pass&quot; means no
                  requirement the test claims is failing; tests that claim no requirement are counted above only.
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Test</th>
                    {cons.engines.map((e) => (
                      <th key={e.engine} scope="col">
                        {e.engine}
                      </th>
                    ))}
                    <th scope="col">Requirements</th>
                  </tr>
                </thead>
                <tbody>
                  {cons.tests.map((t) => (
                    <tr key={`${t.spec}-${t.title}`}>
                      <td>
                        {t.title}
                        <span className="pkgs">
                          <code>{t.spec}</code>
                        </span>
                      </td>
                      {cons.engines.map((e) => (
                        <td key={e.engine}>
                          {t.engines[e.engine] === "pass" ? (
                            <ReqBadge status="verified" text="pass" />
                          ) : t.engines[e.engine] === "failing-claim" ? (
                            <ReqBadge status="failing" text="failing claim" />
                          ) : (
                            <ReqBadge status="unverified" text="no claim" />
                          )}
                        </td>
                      ))}
                      <td className="id">{t.requirements.join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Sec>

      <AcceptanceSection no={`${CH.n}.10`} s={s} />
      <PerformanceSection no={`${CH.n}.11`} s={s} />
    </article>
  );
}

function AcceptanceSection({ no, s }: { no: string; s: ReturnType<typeof loadStatus>["status"] }) {
  const a = s.acceptance;
  return (
    <Sec no={no} id="acceptance" title="Acceptance scenarios and release label">
      <Note label="Release label">
        <p>
          {a ? (
            <>
              <strong>{a.label}</strong>. {a.enforcedPassed} of {a.total} scenarios passed in the Enforced profile,{" "}
              {a.standalonePassed} in the Standalone profile.
            </>
          ) : (
            "Not computed in this run."
          )}
        </p>
      </Note>
      <p>
        The acceptance scenarios AT-01 to AT-21 of SRS Appendix M. A release is labelled &quot;enforced&quot; only when
        every scenario has a passing automated or recorded result for the release commit in the Enforced profile
        (FR-19.3); the release workflow applies the label from this data. A scenario passes in a profile when every test
        that claims it in that profile passed; a skipped test is not a result. The scenarios and their tests are described
        in <Link href="/docs/acceptance/">the acceptance guide</Link>.
      </p>
      {!a ? (
        <p className="empty-state">No acceptance results in this status data.</p>
      ) : (
        <div className="table-wrap wide">
          <table>
            <caption>
              {a.scenarios.filter((x) => x.enforced === "pass").length} enforced and{" "}
              {a.scenarios.filter((x) => x.standalone === "pass").length} standalone passes of {a.total} scenarios.
            </caption>
            <thead>
              <tr>
                <th scope="col">Scenario</th>
                <th scope="col">Evidence</th>
                <th scope="col">Enforced</th>
                <th scope="col">Standalone</th>
                <th scope="col">Claimed by</th>
              </tr>
            </thead>
            <tbody>
              {a.scenarios.map((x) => (
                <tr key={x.id}>
                  <td>
                    <span className="id">{x.id}</span> {x.title}
                  </td>
                  <td>{x.evidence}</td>
                  <td>
                    <ResultMark result={x.enforced} />
                  </td>
                  <td>
                    <ResultMark result={x.standalone} />
                  </td>
                  <td>
                    {x.tests.length + x.records.length === 0
                      ? "none"
                      : [...x.tests.map((t) => `${t.test} (${t.profile}, ${t.result})`), ...x.records.map((r) => `${r.record} (${r.result})`)].join(
                          "; ",
                        )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Sec>
  );
}

function PerformanceSection({ no, s }: { no: string; s: ReturnType<typeof loadStatus>["status"] }) {
  const p = s.performance;
  return (
    <Sec no={no} id="performance" title="Performance">
      <Note label="Host">
        <p>
          {p
            ? `${p.host.os}/${p.host.arch}, ${p.host.cpus} CPUs${p.host.cpu ? `, ${p.host.cpu}` : ""}; ${p.referenceHardware ? "the recorded reference hardware" : "not the recorded reference hardware"}.`
            : "No measurements in this status data."}
        </p>
      </Note>
      <p>
        The FR-11 measurements of the CI job <code>perf</code>, which runs <code>smcp-workload</code> against real{" "}
        <code>smcpd</code> instances with the reference dataset and eight concurrent callers. The budgets are the CP-32
        targets. Results from a CI runner are measurements of that runner, not of the reference hardware the SRS names, so
        they count as partial evidence only.
      </p>
      {!p ? (
        <p className="empty-state">Not yet run. The perf job runs on pushes to main and on demand.</p>
      ) : (
        <div className="table-wrap wide">
          <table>
            <caption>
              Measured {fmtDateTime(p.generatedAt)} for commit {shortSha(p.commit)}; dataset of {p.dataset.rules + p.dataset.registryNodes} rule
              and registry nodes, {p.dataset.candidateRules} candidate rules per decision, {p.dataset.events} events over{" "}
              {p.dataset.days} days, {p.dataset.callers} callers.
            </caption>
            <thead>
              <tr>
                <th scope="col">Requirement</th>
                <th scope="col">Measurement</th>
                <th scope="col" className="num">
                  Value
                </th>
                <th scope="col" className="num">
                  Budget
                </th>
                <th scope="col">Result</th>
                <th scope="col">Method</th>
              </tr>
            </thead>
            <tbody>
              {p.measurements.map((m) => (
                <tr key={m.requirement}>
                  <td className="id">{m.requirement}</td>
                  <td>
                    {m.name} ({m.metric})
                  </td>
                  <td className="num">
                    {m.value.toFixed(3)} {m.unit}
                  </td>
                  <td className="num">
                    {m.budget} {m.unit}
                  </td>
                  <td>
                    <ResultMark result={m.pass ? "pass" : "fail"} />
                  </td>
                  <td>
                    {m.method}
                    {m.note ? ` ${m.note}` : ""} ({m.samples} samples)
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Sec>
  );
}

function ResultMark({ result }: { result: "pass" | "fail" | "not-run" }) {
  if (result === "pass") return <ReqBadge status="verified" text="pass" />;
  if (result === "fail") return <ReqBadge status="failing" text="fail" />;
  return <ReqBadge status="unverified" text="not run" />;
}
