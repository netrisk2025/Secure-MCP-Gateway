import type { NextConfig } from "next";
import { PHASE_DEVELOPMENT_SERVER, PHASE_PRODUCTION_BUILD } from "next/constants";
import { prepareStatusSnapshot } from "./src/lib/status";
import { prepareReleaseSnapshot, prepareWorkflowSnapshot } from "./src/lib/release";

const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  images: { unoptimized: true },
  // The site reads the specification documents from the repository root at build time.
  outputFileTracingRoot: process.cwd(),
};

// Fetch the CI status data, the release list and the verification workflow
// results once, before any page renders (see src/lib/status.ts and src/lib/release.ts).
export default async function config(phase: string): Promise<NextConfig> {
  if (phase === PHASE_PRODUCTION_BUILD || phase === PHASE_DEVELOPMENT_SERVER)
    await Promise.all([prepareStatusSnapshot(), prepareReleaseSnapshot(), prepareWorkflowSnapshot()]);
  return nextConfig;
}
