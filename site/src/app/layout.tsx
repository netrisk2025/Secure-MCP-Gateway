import type { Metadata, Viewport } from "next";
import "@fontsource-variable/newsreader/opsz.css";
import "@fontsource-variable/newsreader/opsz-italic.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import Nav from "@/components/Nav";
import ChartTips from "@/components/charts/ChartTips";
import { loadStatus } from "@/lib/status";
import { REPO_URL, buildCommit, dataSourceLine, fmtDate } from "@/lib/site";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Secure MCP Gateway", template: "%s, Secure MCP Gateway" },
  description:
    "Reference for the Secure MCP Gateway: status, flows, architecture, elements, interfaces, requirements and security controls, built from the repository.",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f4f5f0" },
    { media: "(prefers-color-scheme: dark)", color: "#121614" },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const snap = loadStatus();
  const commit = buildCommit();
  return (
    <html lang="en">
      <body>
        <a className="skip" href="#main">
          Skip to content
        </a>
        <Nav commit={commit} sample={snap.source === "sample"} />
        <main id="main" tabIndex={-1}>
          {children}
        </main>
        <footer className="footer">
          <p>
            Site built from <a href={`${REPO_URL}/commit/${commit}`}>commit {commit}</a> on {fmtDate(new Date().toISOString())}.
            Status figures: {dataSourceLine(snap)}.
          </p>
          <p>
            <a href={REPO_URL}>Repository</a>
          </p>
        </footer>
        <ChartTips />
      </body>
    </html>
  );
}
