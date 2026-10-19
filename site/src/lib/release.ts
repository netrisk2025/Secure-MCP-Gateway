/**
 * Published releases, read once per build for the Install page.
 *
 *   SITE_RELEASES_URL  default DEFAULT_RELEASES_URL (GitHub REST, latest 5 releases)
 *
 * prepareReleaseSnapshot() runs from next.config.ts with the status snapshot.
 * It writes .status/releases.json; pages read it with loadReleases(). A failed
 * or timed-out request (5 s) is recorded with its reason and the page says
 * the list could not be read. The build never fails because of it.
 *
 * Relative imports only, because next.config.ts loads this module.
 */
import fs from "node:fs";
import https from "node:https";
import path from "node:path";

export const DEFAULT_RELEASES_URL = "https://api.github.com/repos/ethan03805/Secure-MCP-Gateway/releases?per_page=5";
export const RELEASES_PAGE = "https://github.com/ethan03805/Secure-MCP-Gateway/releases";

export type ReleaseAsset = { name: string; size: number; url: string };
export type Release = {
  tag: string;
  name: string;
  publishedAt: string;
  prerelease: boolean;
  url: string;
  assets: ReleaseAsset[];
};
export type ReleaseSnapshot = {
  /** "remote" when the list was read; "unavailable" otherwise (reason says why). */
  source: "remote" | "unavailable";
  reason: string;
  url: string;
  fetchedAt: string;
  releases: Release[];
};

const SNAPSHOT_FILE = path.join(process.cwd(), ".status", "releases.json");

function getJSON(url: string, timeoutMs: number, redirects = 3): Promise<unknown> {
  return new Promise((resolve, reject) => {
    if (url.startsWith("file:")) {
      fs.readFile(new URL(url), "utf8", (err, data) => {
        if (err) return reject(err);
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
      return;
    }
    const headers: Record<string, string> = {
      "user-agent": "smcp-site-build",
      accept: "application/vnd.github+json",
    };
    const token = process.env.GITHUB_TOKEN?.trim();
    if (token && url.startsWith("https://api.github.com/")) headers.authorization = `Bearer ${token}`;
    const req = https.get(url, { headers }, (res) => {
      const code = res.statusCode ?? 0;
      if (code >= 300 && code < 400 && res.headers.location && redirects > 0) {
        res.resume();
        getJSON(new URL(res.headers.location, url).toString(), timeoutMs, redirects - 1).then(resolve, reject);
        return;
      }
      if (code !== 200) {
        res.resume();
        reject(new Error(`HTTP ${code}`));
        return;
      }
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        } catch (e) {
          reject(e);
        }
      });
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`timed out after ${timeoutMs} ms`)));
    req.on("error", reject);
  });
}

type RawRelease = {
  tag_name?: string;
  name?: string | null;
  published_at?: string | null;
  prerelease?: boolean;
  draft?: boolean;
  html_url?: string;
  assets?: { name?: string; size?: number; browser_download_url?: string }[];
};

/** Converts the GitHub REST answer; drafts are left out. Throws when it is not a list. */
export function parseReleases(data: unknown): Release[] {
  if (!Array.isArray(data)) throw new Error("the answer is not a list of releases");
  return (data as RawRelease[])
    .filter((r) => !r.draft && r.tag_name)
    .map((r) => ({
      tag: r.tag_name!,
      name: r.name || r.tag_name!,
      publishedAt: r.published_at ?? "",
      prerelease: Boolean(r.prerelease),
      url: r.html_url ?? `${RELEASES_PAGE}/tag/${r.tag_name}`,
      assets: (r.assets ?? [])
        .filter((a) => a.name)
        .map((a) => ({ name: a.name!, size: a.size ?? 0, url: a.browser_download_url ?? "" })),
    }));
}

export async function prepareReleaseSnapshot(): Promise<ReleaseSnapshot> {
  const url = process.env.SITE_RELEASES_URL?.trim() || DEFAULT_RELEASES_URL;
  let snap: ReleaseSnapshot;
  try {
    snap = { source: "remote", reason: "", url, fetchedAt: new Date().toISOString(), releases: parseReleases(await getJSON(url, 5000)) };
  } catch (e) {
    snap = {
      source: "unavailable",
      reason: e instanceof Error ? e.message : String(e),
      url,
      fetchedAt: new Date().toISOString(),
      releases: [],
    };
  }
  fs.mkdirSync(path.dirname(SNAPSHOT_FILE), { recursive: true });
  fs.writeFileSync(SNAPSHOT_FILE, JSON.stringify(snap, null, 1));
  return snap;
}

export function loadReleases(): ReleaseSnapshot {
  try {
    return JSON.parse(fs.readFileSync(SNAPSHOT_FILE, "utf8")) as ReleaseSnapshot;
  } catch {
    return {
      source: "unavailable",
      reason: "the build did not read the release list",
      url: DEFAULT_RELEASES_URL,
      fetchedAt: new Date().toISOString(),
      releases: [],
    };
  }
}

export type AssetKind = "archive" | "checksums" | "sigstore" | "minisign" | "sbom" | "other";

/** What a release asset is, by the names GoReleaser and the release workflow give them. */
export function assetKind(name: string): AssetKind {
  if (name.endsWith(".sigstore.json")) return "sigstore";
  if (name.endsWith(".minisig")) return "minisign";
  if (/checksums\.txt$/.test(name)) return "checksums";
  if (/\.(spdx|cdx|syft)(\.json)?$|sbom/i.test(name)) return "sbom";
  if (/\.(tar\.gz|tgz|zip)$/.test(name)) return "archive";
  return "other";
}

/** A minisign public key (base64 "RW..." line) published in SECURITY.md, or "" when none is. */
export function minisignKeyIn(text: string): string {
  const m = /(?:^|[\s`])(RW[A-Za-z0-9+/]{54})(?:$|[\s`])/m.exec(text);
  return m ? m[1] : "";
}

/**
 * Results of the separate verification workflows (tap, reference-packages),
 * which scripts/publish-workflow-result.sh publishes to site-data/workflows.json.
 *
 *   SITE_WORKFLOWS_URL  default DEFAULT_WORKFLOWS_URL
 *
 * prepareWorkflowSnapshot() runs from next.config.ts; pages read it with
 * loadWorkflowResults(). A failed request is recorded with its reason.
 */
export const DEFAULT_WORKFLOWS_URL =
  "https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/site-data/workflows.json";

export type WorkflowResult = {
  workflow: string;
  requirements: string[];
  ref: string;
  commit: string;
  conclusion: string;
  date: string;
  runUrl: string;
};
export type WorkflowSnapshot = {
  source: "remote" | "unavailable";
  reason: string;
  url: string;
  fetchedAt: string;
  results: WorkflowResult[];
};

const WORKFLOW_SNAPSHOT_FILE = path.join(process.cwd(), ".status", "workflows.json");

/** Converts site-data/workflows.json; entries without a workflow name or full commit are dropped. Throws when it is not a list. */
export function parseWorkflowResults(data: unknown): WorkflowResult[] {
  if (!Array.isArray(data)) throw new Error("workflows.json is not a list");
  const str = (x: unknown) => (typeof x === "string" ? x : "");
  return (data as Record<string, unknown>[])
    .filter((w) => !!w && typeof w === "object" && str(w.workflow) !== "" && /^[0-9a-f]{40}$/.test(str(w.commit)))
    .map((w) => ({
      workflow: str(w.workflow),
      requirements: Array.isArray(w.requirements) ? w.requirements.filter((r): r is string => typeof r === "string") : [],
      ref: str(w.ref),
      commit: str(w.commit),
      conclusion: str(w.conclusion),
      date: str(w.date),
      runUrl: /^https:\/\/github\.com\//.test(str(w.runUrl)) ? str(w.runUrl) : "",
    }))
    .sort((a, b) => a.workflow.localeCompare(b.workflow));
}

/** True when a workflow ran for a release tag (tools/reqreport counts it as a full claim), not a branch (partial). */
export function isReleaseRef(ref: string): boolean {
  return /^v\d/.test(ref);
}

export async function prepareWorkflowSnapshot(): Promise<WorkflowSnapshot> {
  const url = process.env.SITE_WORKFLOWS_URL?.trim() || DEFAULT_WORKFLOWS_URL;
  let snap: WorkflowSnapshot;
  try {
    snap = {
      source: "remote",
      reason: "",
      url,
      fetchedAt: new Date().toISOString(),
      results: parseWorkflowResults(await getJSON(url, 5000)),
    };
  } catch (e) {
    snap = {
      source: "unavailable",
      reason: e instanceof Error ? e.message : String(e),
      url,
      fetchedAt: new Date().toISOString(),
      results: [],
    };
  }
  fs.mkdirSync(path.dirname(WORKFLOW_SNAPSHOT_FILE), { recursive: true });
  fs.writeFileSync(WORKFLOW_SNAPSHOT_FILE, JSON.stringify(snap, null, 1));
  return snap;
}

export function loadWorkflowResults(): WorkflowSnapshot {
  try {
    return JSON.parse(fs.readFileSync(WORKFLOW_SNAPSHOT_FILE, "utf8")) as WorkflowSnapshot;
  } catch {
    return {
      source: "unavailable",
      reason: "the build did not read the workflow results",
      url: DEFAULT_WORKFLOWS_URL,
      fetchedAt: new Date().toISOString(),
      results: [],
    };
  }
}
