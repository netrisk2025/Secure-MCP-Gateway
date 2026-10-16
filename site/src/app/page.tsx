import Link from "next/link";
import Hero from "@/components/Hero";
import { loadArch } from "@/lib/parse-arch";
import { loadRequirements } from "@/lib/parse-reqs";
import { loadSecurity } from "@/lib/parse-sec";

export default function Home() {
  const arch = loadArch();
  const { reqs } = loadRequirements();
  const { controls } = loadSecurity();
  const fr = reqs.filter((r) => r.kind === "FR").length;
  const sr = reqs.length - fr;
  const musts = controls.filter((c) => c.imperative === "MUST").length;

  return (
    <>
      <section className="hero">
        <h1>Three control points on every tool call.</h1>
        <p className="lede">
          The Secure MCP Gateway sits between an agentic framework and the MCP servers it uses. A tool call is checked
          before any server code runs, the server is contained while it runs, and the response is inspected before the
          agent reads it. Each call leaves a record. The Gateway is specified here and not yet implemented.
        </p>
        <Hero />
      </section>

      <section className="home-section">
        <h2>Principles</h2>
        <ul className="pillars">
          <li>
            <h3>Authority is an intersection</h3>
            <p>
              A signed server manifest sets the ceiling. A framework profile, a session policy and the harness&rsquo;s
              own claims can each narrow it. None of them can widen it, and model output never grants authority.
            </p>
          </li>
          <li>
            <h3>Signed and contained are separate</h3>
            <p>
              Only curated, signed packages run. They still run in a sandbox with brokered egress and a runtime
              monitor. Provenance says where code came from, not how it will behave.
            </p>
          </li>
          <li>
            <h3>Secrets stay on the Gateway side</h3>
            <p>
              Credentials are attached by the egress broker at the moment of use under a Secret Use Policy. Neither
              the harness nor the model receives a secret value.
            </p>
          </li>
          <li>
            <h3>Intent is recorded before launch</h3>
            <p>
              A dispatch barrier commits the decision and intent before a server is invoked. A release barrier commits
              the outcome before the response is returned.
            </p>
          </li>
          <li>
            <h3>Anomaly scores only restrict</h3>
            <p>
              Behaviour baselines score each call in standard deviations from the mean for its context. A high score
              can add an obligation. A low score is not a permit.
            </p>
          </li>
          <li>
            <h3>The Gateway measures its own cost</h3>
            <p>
              Each policy rule, filter and capture step emits its own time span, so the overhead of a policy revision
              is measured rather than estimated.
            </p>
          </li>
        </ul>
      </section>

      <section className="home-section">
        <h2>Status</h2>
        <p>The counts are read from the repository documents at build time.</p>
        <ul className="status">
          <li>
            <span className="n">{arch.elements.length}</span>
            <span className="l">elements in {arch.subsystems.length} subsystems</span>
          </li>
          <li>
            <span className="n">{arch.functions.length}</span>
            <span className="l">functions</span>
          </li>
          <li>
            <span className="n">{arch.external.length + arch.internal.length}</span>
            <span className="l">interfaces, {arch.external.length} external</span>
          </li>
          <li>
            <span className="n">{reqs.length}</span>
            <span className="l">
              requirements, {fr} functional and {sr} security
            </span>
          </li>
          <li>
            <span className="n">{controls.length}</span>
            <span className="l">security controls, {musts} as MUST</span>
          </li>
        </ul>

        <ol className="timeline">
          <li>
            <time dateTime="2026-09-21">21 Sep 2026</time>
            <span>Research brief: survey of gateways, policy engines, audit, secrets and filter tooling.</span>
          </li>
          <li>
            <time dateTime="2026-10-04">4 Oct 2026</time>
            <span>Security-control SRS V1 and architecture 2.0 baselined and tagged.</span>
          </li>
          <li>
            <time dateTime="2026-10-14">14 Oct 2026</time>
            <span>Architecture V2 decomposes the system into elements, functions and interfaces.</span>
          </li>
          <li>
            <time dateTime="2026-10-15">15 Oct 2026</time>
            <span>Implementation SRS V1.0 draft generated with traceability. Client compatibility brief written.</span>
          </li>
          <li>
            <time dateTime="2026-10-16">16 Oct 2026</time>
            <span>
              Harness authentication, protocol eras, adapters and tool naming revised to match shipping clients.
            </span>
          </li>
          <li>
            <time dateTime="2026-10-16">16 Oct 2026</time>
            <span>First Go implementation slice: OAuth sessions, policy decisions, stdio dispatch, signed journal.</span>
          </li>
        </ol>
      </section>

      <section className="home-section">
        <h2>Contents</h2>
        <ul className="read-list">
          <li>
            <Link href="/architecture/">Architecture</Link>
            <p>Decomposition, policy model, secrets design, anomaly method, diagrams.</p>
          </li>
          <li>
            <Link href="/elements/">Elements</Link>
            <p>Each element with its trust level, functions, interfaces and allocated requirements.</p>
          </li>
          <li>
            <Link href="/interfaces/">Interfaces and data</Link>
            <p>External and internal interfaces, data stores, console view modules, open decisions.</p>
          </li>
          <li>
            <Link href="/requirements/">Requirements</Link>
            <p>All requirements, filterable by root, element and verification method.</p>
          </li>
          <li>
            <Link href="/security/">Security controls</Link>
            <p>The control hierarchy and which requirements realize each control.</p>
          </li>
          <li>
            <Link href="/clients/">Clients</Link>
            <p>What Claude Code, Codex and Hermes expect, and how the specification meets them.</p>
          </li>
        </ul>
      </section>
    </>
  );
}
