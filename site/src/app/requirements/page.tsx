import RequirementExplorer from "@/components/RequirementExplorer";
import { DocHead, SampleNotice } from "@/components/Sheet";
import { loadArch } from "@/lib/parse-arch";
import { loadRequirements, methodCounts } from "@/lib/parse-reqs";
import { loadSecurity } from "@/lib/parse-sec";
import { loadStatus, type ReqStatus } from "@/lib/status";
import { REQ_STATUSES, buildCommit, chapter, dataSourceLine, reqStatusMap, reqStatusOf } from "@/lib/site";

export const metadata = { title: "Requirements" };

const CH = chapter("/requirements/");

export default function RequirementsPage() {
  const { reqs, sections } = loadRequirements();
  const arch = loadArch();
  const { controls } = loadSecurity();
  const snap = loadStatus();
  const rs = reqStatusMap(snap.status);
  const elementNames: Record<string, string> = {};
  for (const e of arch.elements) elementNames[e.id] = e.name;
  for (const f of arch.functions) elementNames[f.id] = f.name;
  for (const x of arch.external) elementNames[x.id] = x.name;
  for (const d of arch.stores) elementNames[d.id] = d.name;
  for (const g of arch.gui) elementNames[g.id] = g.name;
  const secNames: Record<string, string> = {};
  for (const c of controls) secNames[c.id] = c.name;
  const methods = methodCounts(reqs);

  const statusById: Record<string, { s: ReqStatus; t: string[] }> = {};
  for (const r of reqs) statusById[r.id] = { s: reqStatusOf(rs, r.id), t: rs.get(r.id)?.tests ?? [] };
  const tally = Object.fromEntries(REQ_STATUSES.map((s) => [s, reqs.filter((r) => statusById[r.id].s === s).length]));
  const unknown = snap.status.requirements.items.filter((i) => !statusById[i.id]).map((i) => i.id);
  const fr = reqs.filter((r) => r.kind === "FR").length;

  return (
    <article className="sheet">
      <DocHead
        chapter={CH.n}
        title="Requirements"
        left={["Secure MCP Gateway", "Implementation SRS, from srs_build/req*.txt", `Status: ${dataSourceLine(snap)}`]}
        right={[`${reqs.length} requirements`, `${fr} functional, ${reqs.length - fr} security`, `site build ${buildCommit()}`]}
      >
        <p>
          Every SHALL statement in the implementation SRS, allocated to an element, a function and the interfaces it
          crosses. Security requirements trace to a control in the security-control SRS. The status of each one comes
          from the tests that claim it.
        </p>
      </DocHead>
      <SampleNotice snap={snap} />
      <p className="meta">
        By status: {REQ_STATUSES.map((s) => `${tally[s]} ${s}`).join(", ")}. By verification method: test{" "}
        {methods["Test"] ?? 0}, inspection {methods["Inspection"] ?? 0}, demonstration {methods["Demonstration"] ?? 0},
        analysis {methods["Analysis"] ?? 0}.
        {unknown.length > 0 && (
          <>
            {" "}
            Status data also names {unknown.length} ID{unknown.length === 1 ? "" : "s"} not in the SRS:{" "}
            {unknown.slice(0, 8).join(", ")}
            {unknown.length > 8 ? " and others" : ""}.
          </>
        )}
      </p>
      <RequirementExplorer
        reqs={reqs}
        sections={sections}
        elementNames={elementNames}
        secNames={secNames}
        statusById={statusById}
      />
    </article>
  );
}
