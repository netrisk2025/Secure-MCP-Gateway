import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  images: { unoptimized: true },
  // The site reads the specification documents from the repository root at build time.
  outputFileTracingRoot: process.cwd(),
};

export default nextConfig;
