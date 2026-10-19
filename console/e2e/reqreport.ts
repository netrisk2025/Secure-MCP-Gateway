// Playwright reporter that writes the suite's requirement claims in the
// `go test -json` event format, so that tools/reqreport counts them with
// the Go tests (FR-8.34, FR-12.10). Each test's annotations become claim
// lines: type "requirement" is a full claim (VERIFIES), type
// "requirement-partial" a partial one (PARTIAL), type "scenario" an
// acceptance scenario claim (SCENARIO). Only the last attempt of a retried
// test counts.
//
// Output: build/console-<project>-test.json at the repository root, one
// file per browser project, with Package "console/e2e/<project>". The CI
// console job runs one browser per Playwright invocation, each against a
// fresh Gateway; e2e/run-browsers.mjs then adds the cross-browser claims
// (FR-8.30, FR-8.34) with e2e/claims.mjs.
//
// A run in the Enforced profile (SMCP_E2E_PROFILE=enforced) writes
// build/console-<project>-enforced-test.json with Package
// "console/e2e/<project>/enforced", so tools/reqreport keeps its results
// apart from the Standalone run of the same tests.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { FullResult, Reporter, TestCase, TestResult } from "@playwright/test/reporter";
import { repoRoot, requestedProfile } from "./gateway";

const suffix = requestedProfile === "enforced" ? "enforced" : "";

interface Ev {
  Time: string;
  Action: string;
  Package: string;
  Test?: string;
  Output?: string;
  Elapsed?: number;
}

const outcome = (r: TestResult, t: TestCase): "pass" | "fail" | "skip" => {
  if (r.status === "skipped") return "skip";
  return t.outcome() === "expected" || t.outcome() === "flaky" ? "pass" : "fail";
};

export default class ReqReporter implements Reporter {
  private last = new Map<string, { t: TestCase; r: TestResult }>();

  onTestEnd(t: TestCase, r: TestResult) {
    this.last.set(t.id, { t, r });
  }

  onEnd(_: FullResult) {
    const byProject = new Map<string, Ev[]>();
    for (const { t, r } of this.last.values()) {
      const project = t.parent.project()?.name ?? "default";
      const pkg = `console/e2e/${project}${suffix ? "/" + suffix : ""}`;
      const evs = byProject.get(project) ?? [];
      const name = t
        .titlePath()
        .filter((s) => s && s !== project)
        .join(" > ");
      const at = new Date(r.startTime.getTime() + r.duration).toISOString();
      evs.push({ Time: r.startTime.toISOString(), Action: "run", Package: pkg, Test: name });
      for (const a of t.annotations) {
        // type "scenario" claims an acceptance scenario (FR-19.4), with a
        // description such as "AT-15 profile=standalone".
        const markers: Record<string, string> = {
          requirement: "VERIFIES:",
          "requirement-partial": "PARTIAL:",
          scenario: "SCENARIO:",
        };
        const marker = markers[a.type] ?? "";
        if (marker && a.description) evs.push({ Time: at, Action: "output", Package: pkg, Test: name, Output: `    ${marker} ${a.description}\n` });
      }
      if (r.error?.message) evs.push({ Time: at, Action: "output", Package: pkg, Test: name, Output: r.error.message.split("\n").slice(0, 5).join("\n") + "\n" });
      evs.push({ Time: at, Action: outcome(r, t), Package: pkg, Test: name, Elapsed: r.duration / 1000 });
      byProject.set(project, evs);
    }
    const dir = join(repoRoot, "build");
    mkdirSync(dir, { recursive: true });
    for (const [project, evs] of byProject) {
      const failed = evs.some((e) => e.Action === "fail");
      evs.push({ Time: new Date().toISOString(), Action: failed ? "fail" : "pass", Package: `console/e2e/${project}${suffix ? "/" + suffix : ""}` });
      writeFileSync(join(dir, `console-${project}${suffix ? "-" + suffix : ""}-test.json`), evs.map((e) => JSON.stringify(e)).join("\n") + "\n");
    }
  }

  printsToStdio() {
    return false;
  }
}
