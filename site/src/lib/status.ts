/**
 * Build status data: implementation, tests, coverage and requirement verification.
 *
 * Contract: CI publishes status.json and history.json to the orphan branch
 * "site-data" on every push to main. The site reads them once per build:
 *
 *   SITE_STATUS_URL   default DEFAULT_STATUS_URL
 *   SITE_HISTORY_URL  default: SITE_STATUS_URL with status.json replaced by history.json
 *
 * fetchStatusSnapshot() runs once, from next.config.ts, before any page renders.
 * It writes a snapshot file that every page reads through loadStatus(), so all
 * pages in one build show the same data. When the fetch fails, times out (5 s),
 * or returns something that is not schema 1, the snapshot holds the checked-in
 * sample (site/data/status.sample.json) and says why. The build never fails
 * because status data is missing.
 *
 * This module uses relative imports only, because next.config.ts loads it.
 */
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import https from "node:https";

export const DEFAULT_STATUS_URL =
  "https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/site-data/status.json";
export const FETCH_TIMEOUT_MS = 5000;

export type ReqStatus = "verified" | "partial" | "failing" | "unverified";
export type Implementation = "implemented" | "partial" | "not-started";

export type PackageTests = { name: string; passed: number; failed: number; skipped: number };
export type PackageCoverage = { name: string; pct: number };
export type ElementVerification = {
  element: string;
  name: string;
  total: number;
  verified: number;
  partial: number;
  failing: number;
};
export type RequirementItem = { id: string; element: string; status: ReqStatus; tests: string[] };
export type ElementStatus = {
  id: string;
  name: string;
  subsystem: string;
  implementation: Implementation;
  packages: string[];
  note?: string;
};
export type AgentResult = {
  client: string;
  version: string;
  mode: string;
  result: "pass" | "fail" | "not-run";
  detail: string;
};
export type HostileResult = { fixture: string; attack: string; expected: string; observed: string; pass: boolean };
export type ScenarioOutcome = "pass" | "fail" | "not-run";
/** One Appendix M acceptance scenario (FR-19.4), computed by tools/reqreport. */
export type ScenarioResult = {
  id: string;
  title: string;
  evidence: string;
  requirements: string[];
  enforced: ScenarioOutcome;
  standalone: ScenarioOutcome;
  tests: { test: string; result: string; profile: string }[];
  records: { record: string; commit: string; profile: string; date: string; result: string; counted: boolean; note?: string }[];
};
/** AT-01 to AT-21 and the release label of FR-19.3. */
export type Acceptance = {
  commit: string;
  label: string;
  reasons: string[];
  total: number;
  enforcedPassed: number;
  standalonePassed: number;
  scenarios: ScenarioResult[];
};
/** One FR-11 measurement of the perf job (cmd/smcp-workload). */
export type PerfMeasurement = {
  requirement: string;
  name: string;
  metric: string;
  unit: string;
  value: number;
  budget: number;
  ceiling?: number;
  samples: number;
  pass: boolean;
  method: string;
  note?: string;
};
export type Performance = {
  schema: number;
  commit: string;
  generatedAt: string;
  host: { os: string; arch: string; cpus: number; cpu?: string; goVersion: string; runner?: string };
  referenceHardware: boolean;
  dataset: { rules: number; registryNodes: number; candidateRules: number; events: number; days: number; callers: number };
  measurements: PerfMeasurement[];
};

export type Status = {
  schema: 1;
  sample?: boolean;
  generatedAt: string;
  commit: string;
  commitUrl: string;
  runUrl: string;
  tests: {
    total: number;
    passed: number;
    failed: number;
    skipped: number;
    durationSec: number;
    packages: PackageTests[];
  };
  coverage: { totalPct: number; packages: PackageCoverage[] };
  requirements: {
    total: number;
    verified: number;
    partial: number;
    failing: number;
    unverified: number;
    byElement: ElementVerification[];
    items: RequirementItem[];
  };
  elements: ElementStatus[];
  agents: AgentResult[];
  hostile: HostileResult[];
  /** Present when the run computed the Appendix M scenarios. */
  acceptance?: Acceptance;
  /** Present when the perf job's results were merged. */
  performance?: Performance;
  ci: { workflow: string; conclusion: string };
};

export type HistoryPoint = {
  commit: string;
  generatedAt: string;
  testsPassed: number;
  testsFailed: number;
  coveragePct: number;
  verified: number;
  partial: number;
  unverified: number;
};

export type StatusSnapshot = {
  /** "remote" when status.json came from the URL; "sample" when the checked-in sample was used. */
  source: "remote" | "sample";
  /** Why the sample was used, in one sentence. Empty for remote data. */
  reason: string;
  statusUrl: string;
  historyUrl: string;
  /** Empty when history.json could not be read; the reason is in historyReason. */
  historyReason: string;
  fetchedAt: string;
  status: Status;
  history: HistoryPoint[];
};

const SITE_DIR = process.cwd();
const SNAPSHOT_FILE = path.join(SITE_DIR, ".status", "snapshot.json");
const SAMPLE_STATUS = path.join(SITE_DIR, "data", "status.sample.json");
const SAMPLE_HISTORY = path.join(SITE_DIR, "data", "history.sample.json");
const ENV_MARK = "SMCP_STATUS_SNAPSHOT_READY";

export function statusUrls(): { statusUrl: string; historyUrl: string } {
  const statusUrl = process.env.SITE_STATUS_URL?.trim() || DEFAULT_STATUS_URL;
  const historyUrl =
    process.env.SITE_HISTORY_URL?.trim() ||
    (statusUrl.endsWith("status.json") ? statusUrl.slice(0, -"status.json".length) + "history.json" : "");
  return { statusUrl, historyUrl };
}

/** GET a URL with a hard timeout. Uses node:http(s) so Next's fetch cache never holds a stale copy. */
function get(url: string, timeoutMs: number, redirects = 3): Promise<string> {
  return new Promise((resolve, reject) => {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      reject(new Error(`not a URL: ${url}`));
      return;
    }
    if (u.protocol === "file:") {
      fs.readFile(u, "utf8", (err, data) => (err ? reject(err) : resolve(data)));
      return;
    }
    const lib = u.protocol === "http:" ? http : u.protocol === "https:" ? https : null;
    if (!lib) {
      reject(new Error(`unsupported protocol ${u.protocol}`));
      return;
    }
    const req = lib.get(u, { headers: { "user-agent": "smcp-site-build", accept: "application/json" } }, (res) => {
      const code = res.statusCode ?? 0;
      if (code >= 300 && code < 400 && res.headers.location && redirects > 0) {
        res.resume();
        get(new URL(res.headers.location, u).toString(), timeoutMs, redirects - 1).then(resolve, reject);
        return;
      }
      if (code !== 200) {
        res.resume();
        reject(new Error(`HTTP ${code}`));
        return;
      }
      res.setEncoding("utf8");
      let body = "";
      res.on("data", (c: string) => {
        body += c;
        if (body.length > 20_000_000) req.destroy(new Error("response larger than 20 MB"));
      });
      res.on("end", () => resolve(body));
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`timed out after ${timeoutMs / 1000} s`)));
    req.on("error", reject);
  });
}

const isNum = (x: unknown): x is number => typeof x === "number" && Number.isFinite(x);
const isStr = (x: unknown): x is string => typeof x === "string";
const isArr = Array.isArray;

/** Check the contract fields the pages depend on. Returns a reason string, or "" when valid. */
export function checkStatus(x: unknown): string {
  if (!x || typeof x !== "object") return "status.json is not a JSON object";
  const s = x as Record<string, unknown>;
  if (s.schema !== 1) return `status.json schema is ${JSON.stringify(s.schema)}, expected 1`;
  for (const k of ["generatedAt", "commit"]) if (!isStr(s[k])) return `status.json field ${k} is missing`;
  const t = s.tests as Record<string, unknown> | undefined;
  if (!t || !["total", "passed", "failed", "skipped"].every((k) => isNum(t[k])))
    return "status.json tests counts are missing";
  const r = s.requirements as Record<string, unknown> | undefined;
  if (!r || !["total", "verified", "partial", "failing", "unverified"].every((k) => isNum(r[k])))
    return "status.json requirements counts are missing";
  if (!isArr(r.items) || !isArr(r.byElement)) return "status.json requirements.items or byElement is missing";
  if (!isArr(s.elements)) return "status.json elements is missing";
  const c = s.coverage as Record<string, unknown> | undefined;
  if (!c || !isNum(c.totalPct)) return "status.json coverage.totalPct is missing";
  return "";
}

/** Fill optional parts so pages can rely on every array and string existing. */
function normalize(x: Status): Status {
  return {
    ...x,
    commitUrl: x.commitUrl ?? "",
    runUrl: x.runUrl ?? "",
    tests: { ...x.tests, durationSec: x.tests.durationSec ?? 0, packages: x.tests.packages ?? [] },
    coverage: { totalPct: x.coverage.totalPct, packages: x.coverage.packages ?? [] },
    agents: isArr(x.agents) ? x.agents : [],
    hostile: isArr(x.hostile) ? x.hostile : [],
    acceptance: x.acceptance && isArr(x.acceptance.scenarios) ? x.acceptance : undefined,
    performance: x.performance && isArr(x.performance.measurements) ? x.performance : undefined,
    ci: x.ci ?? { workflow: "", conclusion: "" },
  };
}

function checkHistory(x: unknown): HistoryPoint[] | string {
  if (!isArr(x)) return "history.json is not an array";
  const ok = x.filter(
    (p): p is HistoryPoint =>
      !!p && typeof p === "object" && isStr((p as HistoryPoint).generatedAt) && isNum((p as HistoryPoint).testsPassed),
  );
  return ok.slice(-200);
}

function readSample(reason: string, statusUrl: string, historyUrl: string): StatusSnapshot {
  const status = normalize(JSON.parse(fs.readFileSync(SAMPLE_STATUS, "utf8")) as Status);
  const bad = checkStatus(status);
  if (bad) throw new Error(`site/data/status.sample.json does not meet the status contract: ${bad}`);
  let history: HistoryPoint[] = [];
  try {
    const h = checkHistory(JSON.parse(fs.readFileSync(SAMPLE_HISTORY, "utf8")));
    if (isArr(h)) history = h;
  } catch {
    history = [];
  }
  return {
    source: "sample",
    reason,
    statusUrl,
    historyUrl,
    historyReason: "",
    fetchedAt: new Date().toISOString(),
    status: { ...status, sample: true },
    history,
  };
}

/**
 * Fetch status.json and history.json and write the build's snapshot.
 * Never throws for network or content problems; it falls back to the sample.
 */
export async function fetchStatusSnapshot(): Promise<StatusSnapshot> {
  const { statusUrl, historyUrl } = statusUrls();
  let snap: StatusSnapshot;
  try {
    const raw = await get(statusUrl, FETCH_TIMEOUT_MS);
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error("status.json is not valid JSON");
    }
    const bad = checkStatus(parsed);
    if (bad) throw new Error(bad);
    let history: HistoryPoint[] = [];
    let historyReason = "";
    if (!historyUrl) historyReason = "no history URL configured";
    else {
      try {
        const h = checkHistory(JSON.parse(await get(historyUrl, FETCH_TIMEOUT_MS)));
        if (isArr(h)) history = h;
        else historyReason = h;
      } catch (e) {
        historyReason = `history.json could not be read (${(e as Error).message})`;
      }
    }
    snap = {
      source: "remote",
      reason: "",
      statusUrl,
      historyUrl,
      historyReason,
      fetchedAt: new Date().toISOString(),
      status: normalize(parsed as Status),
      history,
    };
  } catch (e) {
    snap = readSample(`${statusUrl} could not be used: ${(e as Error).message}.`, statusUrl, historyUrl);
  }
  fs.mkdirSync(path.dirname(SNAPSHOT_FILE), { recursive: true });
  fs.writeFileSync(SNAPSHOT_FILE, JSON.stringify(snap));
  return snap;
}

/**
 * Called from next.config.ts. Build workers load the config again; the
 * environment mark set by the first call keeps them on the same snapshot.
 */
export async function prepareStatusSnapshot(log = true): Promise<void> {
  if (process.env[ENV_MARK] === "1" && fs.existsSync(SNAPSHOT_FILE)) return;
  const snap = await fetchStatusSnapshot();
  process.env[ENV_MARK] = "1";
  if (log) {
    const msg =
      snap.source === "remote"
        ? `status data: ${snap.statusUrl} (commit ${snap.status.commit.slice(0, 7)}, ${snap.history.length} history points)`
        : `status data: using site/data/status.sample.json. ${snap.reason}`;
    console.log(`[site] ${msg}`);
  }
}

let cached: StatusSnapshot | null = null;

/** The build's status snapshot. Falls back to the sample if the snapshot was never written. */
export function loadStatus(): StatusSnapshot {
  if (cached) return cached;
  const { statusUrl, historyUrl } = statusUrls();
  try {
    cached = JSON.parse(fs.readFileSync(SNAPSHOT_FILE, "utf8")) as StatusSnapshot;
  } catch {
    cached = readSample("No status snapshot was written for this build.", statusUrl, historyUrl);
  }
  return cached;
}
