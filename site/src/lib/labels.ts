/**
 * Status vocabulary and formatting shared by server pages and client
 * components. Keep Node imports out of this file; type imports are erased.
 */
import type { Implementation, ReqStatus } from "./status";

export function fmtDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 16)} UTC`;
}

export function fmtDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 10);
}

export function fmtPct(n: number, digits = 1): string {
  return `${n.toFixed(digits)}%`;
}

export function shortSha(sha: string): string {
  return /^[0-9a-f]{7,}$/i.test(sha) ? sha.slice(0, 7) : sha;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

export const REQ_STATUSES: ReqStatus[] = ["verified", "partial", "failing", "unverified"];

export const REQ_STATUS_TEXT: Record<ReqStatus, string> = {
  verified: "verified",
  partial: "partial",
  failing: "failing",
  unverified: "unverified",
};

export const REQ_STATUS_MEANING: Record<ReqStatus, string> = {
  verified: "At least one passing test claims it in full and no claiming test fails.",
  partial: "Only partial claims, all passing.",
  failing: "A test that claims it failed.",
  unverified: "No test claims it.",
};

export const IMPL_TEXT: Record<Implementation, string> = {
  implemented: "implemented",
  partial: "partial",
  "not-started": "not started",
};
