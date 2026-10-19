// Cross-browser requirement claims of the console acceptance suite, from the
// per-browser files e2e/reqreport.ts writes. Writes
// build/console-browsers-test.json in the `go test -json` event format:
//
//   - FR-8.30 (partial): the suite ran on Chromium, Firefox and WebKit and
//     every test passed on each. Partial because Playwright runs one engine
//     version of each, not the two latest browser releases, and WebKit is
//     not Safari itself.
//   - FR-8.34: on every browser, each view G-01 to G-14 has a passing test
//     that claims the view's FR-8 requirement. A full claim when all views
//     are covered; partial (listing the missing views) otherwise.
//
// Usage: node e2e/claims.mjs [repo root]
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), "..", ".."));
const browsers = ["chromium", "firefox", "webkit"];
// SRS FR-8.3 to FR-8.22: the requirement of each view.
export const viewReqs = {
  "G-01": "FR-8.3",
  "G-02": "FR-8.4",
  "G-03": "FR-8.5",
  "G-04": "FR-8.6",
  "G-05": "FR-8.13",
  "G-06": "FR-8.14",
  "G-07": "FR-8.15",
  "G-08": "FR-8.16",
  "G-09": "FR-8.17",
  "G-10": "FR-8.18",
  "G-11": "FR-8.19",
  "G-12": "FR-8.20",
  "G-13": "FR-8.21",
  "G-14": "FR-8.22",
};

function read(browser) {
  const p = join(root, "build", `console-${browser}-test.json`);
  if (!existsSync(p)) return null;
  const tests = new Map();
  for (const line of readFileSync(p, "utf8").split("\n")) {
    if (!line.trim()) continue;
    const e = JSON.parse(line);
    if (!e.Test) continue;
    const t = tests.get(e.Test) ?? { claims: new Set(), result: "" };
    if (e.Action === "output") for (const m of e.Output.matchAll(/(?:VERIFIES|PARTIAL):((?:\s+[A-Z]+-[\d.-]+)+)/g)) for (const id of m[1].trim().split(/\s+/)) t.claims.add(id);
    if (["pass", "fail", "skip"].includes(e.Action)) t.result = e.Action;
    tests.set(e.Test, t);
  }
  return tests;
}

const pkg = "console/e2e/browsers";
const now = () => new Date().toISOString();
const evs = [];
function emit(name, claimLine, result, notes) {
  evs.push({ Time: now(), Action: "run", Package: pkg, Test: name });
  evs.push({ Time: now(), Action: "output", Package: pkg, Test: name, Output: `    ${claimLine}\n` });
  for (const n of notes) evs.push({ Time: now(), Action: "output", Package: pkg, Test: name, Output: `    ${n}\n` });
  evs.push({ Time: now(), Action: result, Package: pkg, Test: name, Elapsed: 0 });
}

const runs = Object.fromEntries(browsers.map((b) => [b, read(b)]));
const missing = browsers.filter((b) => !runs[b]);
const failing = browsers.filter((b) => runs[b] && [...runs[b].values()].some((t) => t.result === "fail" || t.result === ""));

emit(
  "TestConsoleSuiteOnEveryBrowser",
  "PARTIAL: FR-8.30",
  missing.length || failing.length ? "fail" : "pass",
  [...missing.map((b) => `no results for ${b}`), ...failing.map((b) => `failing tests on ${b}`)],
);

const uncovered = [];
for (const [view, id] of Object.entries(viewReqs)) {
  for (const b of browsers) {
    const ok = runs[b] && [...runs[b].values()].some((t) => t.result === "pass" && t.claims.has(id));
    if (!ok) uncovered.push(`${view} (${id}) on ${b}`);
  }
}
if (missing.length) emit("TestConsoleViewsClaimTheirRequirements", "PARTIAL: FR-8.34", "fail", missing.map((b) => `no results for ${b}`));
else emit("TestConsoleViewsClaimTheirRequirements", uncovered.length ? "PARTIAL: FR-8.34" : "VERIFIES: FR-8.34", "pass", uncovered.map((u) => `no passing claim: ${u}`));

evs.push({ Time: now(), Action: evs.some((e) => e.Action === "fail") ? "fail" : "pass", Package: pkg });
writeFileSync(join(root, "build", "console-browsers-test.json"), evs.map((e) => JSON.stringify(e)).join("\n") + "\n");
console.log(`claims: FR-8.30 ${missing.length || failing.length ? "fail" : "partial"}; FR-8.34 ${uncovered.length ? `partial, ${uncovered.length} gaps` : "verified"}`);
for (const u of uncovered) console.log("  " + u);
