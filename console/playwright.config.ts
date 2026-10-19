import { defineConfig, devices } from "@playwright/test";

// Acceptance tests against a real smcpd started by e2e/global-setup.ts.
// The admin listener uses the Gateway's local CA, which the browser does
// not trust, hence ignoreHTTPSErrors.
//
// One project per browser engine (FR-8.30). Run them one at a time with
// `npm run test:e2e` (e2e/run-browsers.mjs): each run gets a fresh Gateway,
// because the suite changes Gateway state (it suspends the reference server
// last). e2e/reqreport.ts writes each run's requirement claims for
// tools/reqreport (FR-8.34).
export default defineConfig({
  testDir: "e2e",
  testMatch: "*.spec.ts",
  globalSetup: "./e2e/global-setup.ts",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 180_000,
  reporter: process.env.CI
    ? [["list"], ["html", { open: "never", outputFolder: `playwright-report/${process.env.SMCP_E2E_PROJECT ?? "all"}` }], ["./e2e/reqreport.ts"]]
    : [["list"], ["./e2e/reqreport.ts"]],
  use: {
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
});
