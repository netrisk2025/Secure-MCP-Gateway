// Runs the acceptance suite once per browser project (FR-8.30), each run
// against a fresh Gateway from e2e/global-setup.ts, then writes the
// cross-browser claims (e2e/claims.mjs). Extra arguments go to every
// `playwright test` run. Exit status 1 when any run failed.
//
// Usage: node e2e/run-browsers.mjs [--browsers chromium,firefox,webkit] [playwright args]
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
let browsers = ["chromium", "firefox", "webkit"];
const i = args.indexOf("--browsers");
if (i >= 0) {
  browsers = args[i + 1].split(",");
  args.splice(i, 2);
}
let rc = 0;
for (const b of browsers) {
  console.log(`\n== ${b} ==`);
  const r = spawnSync("npx", ["--no-install", "playwright", "test", `--project=${b}`, ...args], { cwd: join(here, ".."), stdio: "inherit", env: { ...process.env, SMCP_E2E_PROJECT: b } });
  if (r.status !== 0) rc = 1;
}
const c = spawnSync(process.execPath, [join(here, "claims.mjs")], { stdio: "inherit" });
if (c.status !== 0) rc = 1;
process.exit(rc);
