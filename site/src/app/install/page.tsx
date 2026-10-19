import Link from "next/link";
import { DocHead, Note, Sec } from "@/components/Sheet";
import { readDoc } from "@/lib/content";
import {
  RELEASES_PAGE,
  assetKind,
  isReleaseRef,
  loadReleases,
  loadWorkflowResults,
  minisignKeyIn,
  type AssetKind,
  type Release,
} from "@/lib/release";
import { REPO_URL, buildCommit, chapter, fmtDate, fmtDateTime, plural } from "@/lib/site";

export const metadata = { title: "Install" };

const CH = chapter("/install/");

const KIND_TEXT: Record<AssetKind, string> = {
  archive: "archive",
  checksums: "SHA-256 checksum file",
  sigstore: "Sigstore bundle (cosign)",
  minisign: "minisign signature",
  sbom: "SBOM",
  other: "other",
};

function kb(n: number): string {
  return n >= 1048576 ? `${(n / 1048576).toFixed(1)} MiB` : `${Math.max(1, Math.round(n / 1024))} KiB`;
}

function has(r: Release, k: AssetKind) {
  return r.assets.some((a) => assetKind(a.name) === k);
}

const COSIGN = `cosign verify-blob --bundle smcp_<version>_checksums.txt.sigstore.json \\
  --certificate-identity-regexp '^https://github.com/ethan03805/Secure-MCP-Gateway/.github/workflows/release.yml@' \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
  smcp_<version>_checksums.txt`;

export default function InstallPage() {
  const snap = loadReleases();
  const rels = snap.releases;
  const latest = rels[0];
  const wf = loadWorkflowResults();
  const key = minisignKeyIn(readDoc("SECURITY.md"));
  const version = latest?.tag.replace(/^v/, "") ?? "<version>";
  const tag = latest?.tag ?? "<tag>";

  return (
    <article className="sheet">
      <DocHead
        chapter={CH.n}
        title="Install"
        left={["Secure MCP Gateway", "Releases, installation and verification"]}
        right={[
          latest ? `latest ${latest.tag}` : "no release published",
          `release list read ${fmtDateTime(snap.fetchedAt)}`,
          `site build ${buildCommit()}`,
        ]}
      >
        <p>
          Where to get the Gateway and how to check that what you downloaded is what the release workflow built. The
          full procedure for each platform and profile, upgrade, rollback and removal is in the{" "}
          <Link href="/docs/install/">install guide</Link>.
        </p>
      </DocHead>

      <Sec no={`${CH.n}.1`} id="releases" title="Releases">
        <Note label="Source">
          <p>
            Read from the GitHub releases API when the site was built.{" "}
            <a href={RELEASES_PAGE}>All releases on GitHub</a>.
          </p>
        </Note>
        {snap.source === "unavailable" ? (
          <p className="empty-state">
            The release list could not be read at build time ({snap.reason}). See <a href={RELEASES_PAGE}>the releases
            page</a>.
          </p>
        ) : rels.length === 0 ? (
          <p className="empty-state">
            No release has been published yet. Until the first tag, build from source (section {CH.n}.2). Pushing a tag{" "}
            <code>v*</code> runs <code>.github/workflows/release.yml</code>, which publishes the archives, the checksum
            file with its minisign signature and Sigstore bundle, and SBOMs.
          </p>
        ) : (
          <>
            <div className="table-wrap wide">
              <table>
                <caption>The {plural(rels.length, "most recent release")}, newest first, with the verification files each carries.</caption>
                <thead>
                  <tr>
                    <th scope="col">Release</th>
                    <th scope="col">Published</th>
                    <th scope="col" className="num">
                      archives
                    </th>
                    <th scope="col">Checksums</th>
                    <th scope="col">Sigstore bundle</th>
                    <th scope="col">minisign</th>
                    <th scope="col">SBOM</th>
                  </tr>
                </thead>
                <tbody>
                  {rels.map((r) => (
                    <tr key={r.tag}>
                      <th scope="row">
                        <a href={r.url}>{r.tag}</a>
                        {r.prerelease ? " (pre-release)" : ""}
                      </th>
                      <td>{r.publishedAt ? fmtDate(r.publishedAt) : "unknown"}</td>
                      <td className="num">{r.assets.filter((a) => assetKind(a.name) === "archive").length}</td>
                      <td>{has(r, "checksums") ? "yes" : "no"}</td>
                      <td>{has(r, "sigstore") ? "yes" : "no"}</td>
                      <td>{has(r, "minisign") ? "yes" : "no"}</td>
                      <td>{has(r, "sbom") ? "yes" : "no"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="table-wrap wide">
              <table>
                <caption>Files of {latest.tag}.</caption>
                <thead>
                  <tr>
                    <th scope="col">File</th>
                    <th scope="col">Kind</th>
                    <th scope="col" className="num">
                      size
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {latest.assets.map((a) => (
                    <tr key={a.name}>
                      <td>{a.url ? <a href={a.url}>{a.name}</a> : a.name}</td>
                      <td>{KIND_TEXT[assetKind(a.name)]}</td>
                      <td className="num">{kb(a.size)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Sec>

      <Sec no={`${CH.n}.2`} id="install" title="Install">
        <p>
          <strong>install.sh</strong> (Linux and macOS) downloads the archive for the host, the checksum file and its
          minisign signature. It verifies the signature with the release key embedded in the script, checks the
          Sigstore bundle when <code>cosign</code> is installed, then checks the archive&apos;s SHA-256, and installs
          nothing if any check fails. It installs into <code>~/.local/bin</code> and never runs <code>sudo</code>. On
          macOS install <code>minisign</code> first (<code>brew install minisign</code>).
        </p>
        <pre className="cmd">
          <code>{`curl -fsSL https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.sh | sh -s -- --version ${tag}`}</code>
        </pre>
        <p>
          <strong>Homebrew</strong>: <code>brew install ethan03805/tap/smcp</code> (checks the archive&apos;s SHA-256
          from the formula, not the minisign signature). <strong>From source</strong> needs Go (the version in{" "}
          <code>go.mod</code>) and git; Node.js is not needed, because the console is committed prebuilt and embedded.
        </p>
        <pre className="cmd">
          <code>{`git clone ${REPO_URL}.git
cd Secure-MCP-Gateway
go build -trimpath -o build/bin/ ./cmd/...
export PATH="$PWD/build/bin:$PATH"
smcpctl install          # or: smcpctl bootstrap --dir ~/smcp`}</code>
        </pre>
        <p>
          Then follow the <Link href="/docs/quickstart/">quick start</Link>. macOS runs the Standalone profile,
          labelled &quot;not enforced&quot;; server containment needs the{" "}
          <Link href="/docs/enforced-profile/">Enforced profile on Linux</Link>.
        </p>
      </Sec>

      <Sec no={`${CH.n}.3`} id="verify" title="Verify a release">
        <Note label="Why the checksum file">
          <p>
            The checksum file lists the SHA-256 of every archive. Its minisign signature binds it to the release key, and
            its Sigstore bundle binds it to the release workflow of this repository, so a replaced archive and a replaced
            checksum file are both detected.
          </p>
        </Note>
        <ol className="steps">
          <li>
            <p>
              Download the archive for your platform, <code>smcp_{version}_checksums.txt</code>,{" "}
              <code>smcp_{version}_checksums.txt.minisig</code> and, for the cosign check,{" "}
              <code>smcp_{version}_checksums.txt.sigstore.json</code> from the release.
            </p>
          </li>
          <li>
            <p>
              <strong>minisign.</strong>{" "}
              {key ? (
                <>
                  Check the checksum file&apos;s signature with the release key published in{" "}
                  <a href={`${REPO_URL}/blob/main/SECURITY.md`}>SECURITY.md</a> and embedded in <code>install.sh</code>:{" "}
                  <code>{key}</code>.
                </>
              ) : (
                <>
                  No release key is published in <a href={`${REPO_URL}/blob/main/SECURITY.md`}>SECURITY.md</a>, so this
                  step cannot be done; use the cosign check.
                </>
              )}
            </p>
            {key && (
              <pre className="cmd">
                <code>{`minisign -Vm smcp_${version}_checksums.txt -P ${key}`}</code>
              </pre>
            )}
          </li>
          <li>
            <p>
              <strong>cosign</strong> (optional, independent of the key). The release workflow also signs the checksum
              file keyless through GitHub OIDC; the command accepts only a certificate issued to{" "}
              <code>.github/workflows/release.yml</code> of this repository.
            </p>
            <pre className="cmd">
              <code>{COSIGN.replaceAll("<version>", version)}</code>
            </pre>
          </li>
          <li>
            <p>Check the archive against the checksum file.</p>
            <pre className="cmd">
              <code>{`sha256sum --check --ignore-missing smcp_${version}_checksums.txt   # macOS: shasum -a 256 --check --ignore-missing`}</code>
            </pre>
          </li>
        </ol>
        <p>
          <code>install.sh</code> performs these checks itself. The procedure for each platform is in the{" "}
          <Link href="/docs/install/">install guide</Link>; residual risks are in the{" "}
          <Link href="/docs/security-review-2026-10/">security review</Link>.
        </p>
        <p>
          The release pipeline was rehearsed with the pre-releases v1.0.0-rc.1, v1.0.0-rc.2 and v1.0.0-rc.3 before
          v1.0.0 was tagged on the same commit as rc.3. For rc.2 and again for v1.0.0 the <code>tap</code> workflow
          installed the formula from the Homebrew tap and the archive with <code>install.sh</code> on macOS and Ubuntu
          runners and found every binary equal to the release archive (
          <Link href="/docs/verification/fr-13-3/">supporting record</Link>, results below); the SBOM in every archive
          is checked in the <Link href="/docs/verification/inspections/">inspection records</Link>, and what the
          rehearsals showed is in the <Link href="/docs/release-checklist/">release checklist</Link>. Archives built
          after v1.0.0 also carry the build recipe, the lockfiles, <code>PROVENANCE.md</code> and{" "}
          <code>THIRD_PARTY_NOTICES.txt</code>, and the release workflow refuses an SBOM entry without an accepted
          license.
        </p>
        <p>
          Two workflows check a published release from outside the build: <code>tap</code> installs it from the
          Homebrew tap and with <code>install.sh</code> on macOS and Ubuntu and compares every binary with the release
          archive (FR-13.3); <code>reference-packages</code> builds, signs, imports and calls the four reference
          packages (FR-14.9). Each publishes its latest result, which the requirement report counts as a full claim for
          a release tag and a partial claim for a branch.
        </p>
        {wf.source === "unavailable" ? (
          <p className="empty-state">The workflow results could not be read at build time ({wf.reason}).</p>
        ) : wf.results.length === 0 ? (
          <p className="empty-state">No workflow result has been published yet.</p>
        ) : (
          <div className="table-wrap wide">
            <table>
              <caption>Latest published result of each release verification workflow.</caption>
              <thead>
                <tr>
                  <th scope="col">Workflow</th>
                  <th scope="col">Requirements</th>
                  <th scope="col">Ref</th>
                  <th scope="col">Commit</th>
                  <th scope="col">Result</th>
                  <th scope="col">Run</th>
                </tr>
              </thead>
              <tbody>
                {wf.results.map((w) => (
                  <tr key={w.workflow}>
                    <th scope="row">{w.workflow}</th>
                    <td>{w.requirements.join(", ")}</td>
                    <td>
                      {w.ref}
                      {isReleaseRef(w.ref) ? " (release tag)" : " (branch)"}
                    </td>
                    <td>
                      <a href={`${REPO_URL}/commit/${w.commit}`}>
                        <code>{w.commit.slice(0, 7)}</code>
                      </a>
                    </td>
                    <td>{w.conclusion || "unknown"}</td>
                    <td>{w.runUrl ? <a href={w.runUrl}>{w.date ? fmtDateTime(w.date) : "run"}</a> : w.date ? fmtDateTime(w.date) : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Sec>

      <Sec no={`${CH.n}.4`} id="packages" title="Verify a server package">
        <p>
          MCP servers run only from signed packages. Packages are signed with minisign: <code>index.json.minisig</code>{" "}
          covers <code>index.json</code>, which lists the SHA-256 of the artifact, manifest and provenance statement.
          Verification needs no network access.
        </p>
        <pre className="cmd">
          <code>{`smcpctl trust add ~/keys/smcp-packages.pub --name operator --expires 365d
smcpctl package verify <package-dir>                 # against the enrolled trust anchors
smcpctl package verify <package-dir> --pubkey <file> # against one public key
minisign -Vm <package-dir>/index.json -p <file>       # the signature alone, with the minisign tool`}</code>
        </pre>
        <p>
          <code>smcpctl package verify</code> checks every component, the signature, the anchor&apos;s expiry and risk
          classes, every digest, the manifest schema and the provenance binding, and names the first failed check. The
          Gateway repeats the artifact check before every launch. See the{" "}
          <Link href="/docs/packaging-guide/">packaging guide</Link>.
        </p>
      </Sec>
    </article>
  );
}
