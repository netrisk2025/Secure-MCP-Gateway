import type { Metadata } from "next";
import { Newsreader, Instrument_Sans } from "next/font/google";
import { execSync } from "node:child_process";
import Nav from "@/components/Nav";
import "./globals.css";

const serif = Newsreader({
  subsets: ["latin"],
  variable: "--font-serif",
  style: ["normal", "italic"],
  weight: "variable",
});
const ui = Instrument_Sans({ subsets: ["latin"], variable: "--font-ui", weight: ["400", "500", "600"] });

export const metadata: Metadata = {
  title: "Secure MCP Gateway",
  description:
    "A local reference monitor and research instrument for agentic frameworks: specification, architecture and requirements, rendered from the repository.",
};

function buildStamp(): string {
  const sha = process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7);
  if (sha) return sha;
  try {
    return execSync("git rev-parse --short HEAD", { cwd: process.cwd(), stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
  } catch {
    return "local build";
  }
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const stamp = buildStamp();
  const date = new Date().toISOString().slice(0, 10);
  return (
    <html lang="en" className={`${serif.variable} ${ui.variable}`}>
      <body>
        <Nav />
        <main>{children}</main>
        <footer className="footer">
          <p>
            Built from the repository documents at commit {stamp} on {date}. The Gateway is specified, not
            implemented.
          </p>
          <p>
            <a href="https://github.com/ethan03805/Secure-MCP-Gateway">Repository on GitHub</a>
          </p>
        </footer>
      </body>
    </html>
  );
}
