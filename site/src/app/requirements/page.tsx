import RequirementExplorer from "@/components/RequirementExplorer";
import { loadArch } from "@/lib/parse-arch";
import { loadRequirements, methodCounts } from "@/lib/parse-reqs";
import { loadSecurity } from "@/lib/parse-sec";

export const metadata = { title: "Requirements, Secure MCP Gateway" };

export default function RequirementsPage() {
  const { reqs, sections } = loadRequirements();
  const arch = loadArch();
  const { controls } = loadSecurity();
  const elementNames: Record<string, string> = {};
  for (const e of arch.elements) elementNames[e.id] = e.name;
  for (const f of arch.functions) elementNames[f.id] = f.name;
  for (const x of arch.external) elementNames[x.id] = x.name;
  for (const d of arch.stores) elementNames[d.id] = d.name;
  for (const g of arch.gui) elementNames[g.id] = g.name;
  const secNames: Record<string, string> = {};
  for (const c of controls) secNames[c.id] = c.name;
  const methods = methodCounts(reqs);

  return (
    <>
      <div className="page-head">
        <h1>Requirements</h1>
        <p className="lede">
          The implementation SRS: {reqs.length} SHALL statements, each allocated to an element, a function and the
          interfaces it crosses. Security requirements trace to a MUST in the security-control SRS. Everything here is
          read from the requirement source records that generate the SRS.
        </p>
        <p className="meta">
          Verified by test {methods["Test"] ?? 0}, inspection {methods["Inspection"] ?? 0}, demonstration{" "}
          {methods["Demonstration"] ?? 0}, analysis {methods["Analysis"] ?? 0}.
        </p>
      </div>
      <RequirementExplorer reqs={reqs} sections={sections} elementNames={elementNames} secNames={secNames} />
    </>
  );
}
