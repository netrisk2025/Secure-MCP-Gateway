// The view modules G-01 to G-14 of ArchitectureV2 §4 (E-24) plus the
// operator views of elements that have no G number. The navigation lists
// the views the signed-in role may open (FR-8.28): a view is listed when
// the role may use one of its routes (perm.tsx). An Administrator also
// sees views whose routes this build does not serve, which then say so.
import type { ReactNode } from "react";
import type { Perm } from "../perm";
import { Analytics } from "./Analytics";
import { AnomalyResponse } from "./AnomalyResponse";
import { Approvals } from "./Approvals";
import { Audit } from "./Audit";
import { AuditProfiles } from "./AuditProfiles";
import { Control } from "./Control";
import { DataServer } from "./DataServer";
import { Egress } from "./Egress";
import { Observations } from "./Observations";
import { Performance } from "./Performance";
import { Policy } from "./Policy";
import { Remote } from "./Remote";
import { Research } from "./Research";
import { Runtime } from "./Runtime";
import { Secrets } from "./Secrets";
import { Servers } from "./Servers";
import { Sessions } from "./Sessions";

export interface ViewDef {
  code?: string;
  title: string;
  path: string;
  group: "Operate" | "Policy" | "Approvals and evidence" | "Observation and research";
  /** Control API routes the view reads; the role must be allowed one of them. */
  routes: string[];
  /** Path prefixes this view also owns (detail pages). */
  prefixes?: string[];
  render: (path: string) => ReactNode;
}

export const views: ViewDef[] = [
  { code: "G-01", title: "Gateway control", path: "/", group: "Operate", routes: ["GET /admin/v1/health"], render: () => <Control /> },
  { code: "G-11", title: "Sessions and principals", path: "/sessions", prefixes: ["/sessions/"], group: "Operate", routes: ["GET /api/v1/sessions"], render: (p) => <Sessions path={p} /> },
  {
    code: "G-10",
    title: "Servers and library",
    path: "/servers",
    prefixes: ["/servers/", "/catalog", "/library"],
    group: "Operate",
    routes: ["GET /api/v1/servers", "GET /api/v1/packages"],
    render: (p) => <Servers path={p} />,
  },
  { code: "G-12", title: "Secrets", path: "/secrets", prefixes: ["/secrets/"], group: "Operate", routes: ["GET /api/v1/secrets"], render: (p) => <Secrets path={p} /> },
  { title: "Egress", path: "/egress", group: "Operate", routes: ["GET /api/v1/egress"], render: () => <Egress /> },
  { title: "Runtime", path: "/runtime", prefixes: ["/runtime/"], group: "Operate", routes: ["GET /api/v1/runtime"], render: (p) => <Runtime path={p} /> },
  { code: "G-11", title: "Remote access", path: "/remote", prefixes: ["/remote/"], group: "Operate", routes: ["GET /api/v1/remote", "GET /api/v1/clients"], render: (p) => <Remote path={p} /> },
  { code: "G-02", title: "Policy studio", path: "/policy", prefixes: ["/policy/"], group: "Policy", routes: ["GET /api/v1/policy", "POST /api/v1/filters/scan"], render: (p) => <Policy path={p} /> },
  { code: "G-03", title: "Audit profile tuning", path: "/audit-profiles", group: "Policy", routes: ["GET /api/v1/observations/status"], render: () => <AuditProfiles /> },
  { code: "G-06", title: "Anomaly response", path: "/anomaly-response", group: "Policy", routes: ["GET /api/v1/observations/status"], render: () => <AnomalyResponse /> },
  { code: "G-13", title: "Approvals", path: "/approvals", prefixes: ["/approvals/"], group: "Approvals and evidence", routes: ["GET /api/v1/approvals"], render: (p) => <Approvals path={p} /> },
  { code: "G-14", title: "Audit investigation", path: "/audit", prefixes: ["/audit/"], group: "Approvals and evidence", routes: ["GET /api/v1/audit/events"], render: (p) => <Audit path={p} /> },
  { code: "G-04", title: "Observation workbench", path: "/observations", group: "Observation and research", routes: ["GET /api/v1/observations/parameters"], render: () => <Observations /> },
  { code: "G-05", title: "Behavior analytics", path: "/analytics", prefixes: ["/analytics/"], group: "Observation and research", routes: ["GET /api/v1/baselines", "GET /api/v1/anomalies"], render: (p) => <Analytics path={p} /> },
  { code: "G-07", title: "Performance", path: "/performance", group: "Observation and research", routes: ["GET /api/v1/observations/metrics"], render: () => <Performance /> },
  { code: "G-08", title: "Data server and memory", path: "/data-server", group: "Observation and research", routes: ["GET /api/v1/graph/status", "GET /api/v1/backup", "GET /api/v1/observations/status"], render: () => <DataServer /> },
  { code: "G-09", title: "Research campaigns", path: "/research", prefixes: ["/research/"], group: "Observation and research", routes: ["GET /api/v1/research/campaigns", "GET /api/v1/research/exports"], render: (p) => <Research path={p} /> },
];

export function viewFor(path: string): ViewDef | undefined {
  return (
    views.find((v) => v.path === path) ??
    views.find((v) => v.prefixes?.some((p) => (p.endsWith("/") ? path.startsWith(p) : path === p || path.startsWith(p + "/"))))
  );
}

/** True when the signed-in role may open the view. */
export function allowed(v: ViewDef, perm: Perm): boolean {
  if (v.routes.some((r) => perm.can(r))) return true;
  return perm.role === "administrator" && !v.routes.some((r) => perm.has(r));
}

/** The view a role lands on after sign-in. */
export function startPath(perm: Perm): string {
  if (perm.role === "approver") return "/approvals";
  if (perm.role === "session_approver") return "/remote";
  return "/";
}
