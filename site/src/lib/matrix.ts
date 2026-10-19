/**
 * The client matrix of SRS Appendix K (docs/clients/matrix.json, FR-15.10),
 * joined with the latest real-agent results from the status data.
 */
import { docSlug, readDoc } from "./content.ts";
import type { AgentResult } from "./status";

export type MatrixClient = {
  client: string;
  vendor: string;
  runsOn: "local" | "vendor-cloud" | string;
  pinnedVersion: string | null;
  connectionMode: string | null;
  fallbackMode: string | null;
  session: string | null;
  lockdown: { mechanism: string | null; confirm: boolean };
  caTrust: { mechanism: string | null; confirm: boolean };
  label: string;
  lastResult: "pass" | "fail" | "not-run" | string;
  lastRun: string | null;
  quickStart: string;
  notes?: string;
  tunnelProvider?: string | null;
};

export type Matrix = { updated: string; note: string; clients: MatrixClient[] };

export const MATRIX_FILE = "docs/clients/matrix.json";

export function loadMatrix(): Matrix {
  const m = JSON.parse(readDoc(MATRIX_FILE)) as Matrix;
  if (!Array.isArray(m.clients) || m.clients.length === 0) throw new Error(`${MATRIX_FILE}: no clients`);
  return m;
}

/**
 * The status-data result for a matrix client. The suite records the matrix
 * name as `client`; results of diagnostic modes (+dns-only-ca,
 * +broken-gateway) are never the client's status.
 */
export function resultFor(c: MatrixClient, agents: AgentResult[]): AgentResult | undefined {
  return agents.find((a) => a.client === c.client && !a.mode.includes("+"));
}

/** Site path of a docs/ file. */
export function docPath(file: string): string {
  return `/docs/${docSlug(file)}/`;
}
