// Unit tests of the data behind the Control API, Install, Agents and console pages.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { OPENAPI_FILE, apiDocHref, parseOpenApi } from "../src/lib/openapi.ts";
import { assetKind, isReleaseRef, minisignKeyIn, parseReleases, parseWorkflowResults } from "../src/lib/release.ts";
import { consoleResults } from "../src/lib/console-results.ts";
import { loadMatrix, resultFor } from "../src/lib/matrix.ts";
import { REPO_ROOT } from "../src/lib/content.ts";
import type { Status } from "../src/lib/status.ts";

test("the committed OpenAPI document parses and every operation has roles or is public", () => {
  const api = parseOpenApi(fs.readFileSync(OPENAPI_FILE, "utf8"));
  assert.equal(api.openapi, "3.1.0");
  assert.ok(api.operations.length >= 60, `${api.operations.length} operations`);
  for (const o of api.operations) {
    assert.ok(o.public || o.roles[0] === "administrator", `${o.method} ${o.path} has no roles`);
    assert.ok(o.summary, `${o.method} ${o.path} has no summary`);
    assert.ok(o.doc, `${o.method} ${o.path} names no reference page`);
    assert.ok(fs.existsSync(path.join(REPO_ROOT, "docs", "api", o.doc)), `docs/api/${o.doc} is missing`);
  }
  const stop = api.operations.find((o) => o.method === "POST" && o.path === "/admin/v1/stop");
  assert.deepEqual(stop?.roles, ["administrator", "operator"]);
  assert.equal(apiDocHref("console.md"), "/docs/api/console/");
});

test("parseOpenApi rejects a document without paths", () => {
  assert.throws(() => parseOpenApi('{"openapi":"3.1.0","info":{"title":"x"}}', "x.json"), /x\.json/);
});

test("releases: drafts are dropped and asset kinds are recognized", () => {
  const rels = parseReleases([
    { tag_name: "v0.2.0", draft: true },
    {
      tag_name: "v0.1.0",
      published_at: "2026-10-18T00:00:00Z",
      assets: [{ name: "smcp_0.1.0_linux_amd64.tar.gz", size: 2048 }, { name: "smcp_0.1.0_checksums.txt" }],
    },
  ]);
  assert.equal(rels.length, 1);
  assert.equal(rels[0].tag, "v0.1.0");
  assert.equal(rels[0].assets.length, 2);
  assert.throws(() => parseReleases({ message: "rate limited" }), /not a list/);
  assert.equal(assetKind("smcp_0.1.0_linux_amd64.tar.gz"), "archive");
  assert.equal(assetKind("smcp_0.1.0_checksums.txt"), "checksums");
  assert.equal(assetKind("smcp_0.1.0_checksums.txt.sigstore.json"), "sigstore");
  assert.equal(assetKind("smcp_0.1.0_linux_amd64.tar.gz.minisig"), "minisign");
  assert.equal(assetKind("smcp_0.1.0_linux_amd64.tar.gz.sbom.json"), "sbom");
});

test("workflow results: invalid entries are dropped, run links must be GitHub, release refs are recognized", () => {
  const sha = "4ba218973fd4279d3e385cd4751285417a68103f";
  const res = parseWorkflowResults([
    { workflow: "tap", requirements: ["FR-13.3", 7], ref: "v1.0.0-rc.2", commit: sha, conclusion: "success", date: "2026-10-17T22:15:07Z", runUrl: "https://github.com/o/r/actions/runs/1" },
    { workflow: "reference-packages", requirements: ["FR-14.9"], ref: "main", commit: sha, conclusion: "success", runUrl: "javascript:alert(1)" },
    { workflow: "short-commit", commit: "4ba2189" },
    { commit: sha },
    null,
  ]);
  assert.deepEqual(
    res.map((w) => w.workflow),
    ["reference-packages", "tap"],
  );
  assert.equal(res[0].runUrl, "", "a run link that is not on github.com is dropped");
  assert.deepEqual(res[1].requirements, ["FR-13.3"]);
  assert.throws(() => parseWorkflowResults({ workflow: "tap" }), /not a list/);
  assert.equal(isReleaseRef("v1.0.0"), true);
  assert.equal(isReleaseRef("v1.0.0-rc.2"), true);
  assert.equal(isReleaseRef("main"), false);
});

test("minisign key detection", () => {
  const key = "RWQ" + "A".repeat(53);
  assert.equal(minisignKeyIn(`The key is \`${key}\`.`), key);
  assert.equal(minisignKeyIn("No signed release exists yet."), "");
  const published = minisignKeyIn(fs.readFileSync(path.join(REPO_ROOT, "SECURITY.md"), "utf8"));
  assert.match(published, /^RW[A-Za-z0-9+/]{54}$/, "SECURITY.md publishes the release key");
});

function status(over: Partial<Status>): Status {
  return {
    schema: 1,
    generatedAt: "",
    commit: "",
    commitUrl: "",
    runUrl: "",
    tests: { total: 0, passed: 0, failed: 0, skipped: 0, durationSec: 0, packages: [] },
    coverage: { totalPct: 0, packages: [] },
    requirements: { total: 0, verified: 0, partial: 0, failing: 0, unverified: 0, byElement: [], items: [] },
    elements: [],
    agents: [],
    hostile: [],
    ci: { workflow: "", conclusion: "" },
    ...over,
  };
}

test("console results group tests by spec and engine", () => {
  const s = status({
    tests: {
      total: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      durationSec: 0,
      packages: [
        { name: "console/e2e/chromium", passed: 2, failed: 0, skipped: 0 },
        { name: "console/e2e/webkit", passed: 1, failed: 1, skipped: 0 },
        { name: "console/e2e/browsers", passed: 2, failed: 0, skipped: 0 },
        { name: "internal/edge", passed: 9, failed: 0, skipped: 0 },
      ],
    },
    requirements: {
      total: 2,
      verified: 1,
      partial: 0,
      failing: 1,
      unverified: 0,
      byElement: [],
      items: [
        { id: "FR-8.3", element: "E-24", status: "verified", tests: ["console/e2e/chromium.views.spec.ts > G-01 control", "console/e2e/webkit.views.spec.ts > G-01 control"] },
        { id: "FR-8.10", element: "E-24", status: "failing", tests: ["console/e2e/webkit.views.spec.ts > G-01 control", "internal/edge.TestX"] },
      ],
    },
  });
  const r = consoleResults(s);
  assert.deepEqual(r.engines.map((e) => e.engine), ["chromium", "webkit"]);
  assert.equal(r.wrappers.length, 1);
  assert.equal(r.tests.length, 1);
  assert.equal(r.tests[0].spec, "views.spec.ts");
  assert.deepEqual(r.tests[0].engines, { chromium: "pass", webkit: "failing-claim" });
  assert.deepEqual(r.tests[0].requirements, ["FR-8.3", "FR-8.10"]);
});

test("the client matrix has a note for every client and diagnostic runs are not results", () => {
  const m = loadMatrix();
  for (const c of m.clients) assert.ok(c.notes && c.notes.length > 20, `${c.client} has no notes`);
  const cc = m.clients.find((c) => c.client === "Claude Code")!;
  const agents = [
    { client: "Claude Code", version: "1", mode: "ai-gateway+broken-gateway", result: "fail" as const, detail: "" },
    { client: "Claude Code", version: "1", mode: "ai-gateway", result: "pass" as const, detail: "" },
  ];
  assert.equal(resultFor(cc, agents)?.result, "pass");
  for (const name of ["Gemini CLI", "Grok Bot", "ChatGPT agent (dots)", "Meta Muse", "Grok Build"]) {
    assert.ok(m.clients.some((c) => c.client === name), `${name} missing from the matrix`);
  }
});
