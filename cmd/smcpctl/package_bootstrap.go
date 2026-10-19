package main

import (
	"context"
	"debug/buildinfo"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// RefPackageID is the server ID of the packaged reference server that
// bootstrap installs (FR-14.10).
const RefPackageID = "smcp-ref-filesystem"

// refRecipe is the packaging recipe of the bundled smcp-refserver with
// its file tools rooted at the "root" filesystem slot.
func refRecipe(refserver, sha, version string) *packaging.Recipe {
	r := &packaging.Recipe{
		RecipeVersion: packaging.RecipeVersion,
		Server: packaging.ServerInfo{ID: RefPackageID, Alias: "ref", Publisher: "Secure MCP Gateway project",
			Description: "Reference MCP server shipped with the Gateway: echo, time and read-only file tools under one directory."},
		Artifact:      packaging.ArtifactRef{Type: "binary", Name: refserver, Version: version, SHA256: sha},
		Launch:        packaging.Launch{Runtime: "native", Argv: []string{filepath.Base(refserver), "--root", "{root}"}},
		RiskClass:     "low",
		InstanceScope: []string{"shared"},
		Tools:         packaging.RecipeTools{Default: packaging.ToolClass{SideEffect: "read", SourceTrust: "trusted"}, Expect: []string{"echo", "time_now", "list_files", "read_file"}},
		Capabilities: packaging.Capabilities{Filesystem: []packaging.FilesystemSlot{{Slot: "root", Mode: "ro", ArgvPlaceholder: "{root}"}},
			Egress: []packaging.EgressRule{}},
		Licenses:     []string{"Apache-2.0"},
		OperatorNote: "Packaged by smcpctl bootstrap from the smcp-refserver binary of this Gateway release; the release checksums cover the binary, which is its own source evidence here.",
	}
	src := &packaging.RecipeSource{Kind: "archive", URI: "file://" + refserver, SHA256: sha}
	if bi, err := buildinfo.ReadFile(refserver); err == nil {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && regexp.MustCompile(`^[a-f0-9]{7,64}$`).MatchString(s.Value) {
				src.VCSCommit = s.Value
			}
		}
	}
	r.Source = src
	return r
}

// bootstrapRefPackage packages smcp-refserver, signs it with a key that is
// generated for this purpose and then discarded, enrolls that key as a
// trust anchor limited to the low risk class, imports the package and
// enables it. It returns the artifact digest for the configuration.
func bootstrapRefPackage(stateDir, refserver string, out io.Writer) (string, error) {
	sha, _, err := packaging.FileSHA256(refserver)
	if err != nil {
		return "", err
	}
	version := backend.Version
	if !regexp.MustCompile(`^[0-9]`).MatchString(version) {
		version = "0.0.0-dev"
	}
	lib, err := library.Open(library.Options{StateDir: stateDir})
	if err != nil {
		return "", err
	}
	defer lib.Close()
	// A state directory kept from an earlier bootstrap already holds this
	// artifact: enable that revision again instead of re-packaging.
	for _, rev := range lib.Revisions() {
		if rev.ServerID == RefPackageID && rev.ArtifactSHA256 == sha && (rev.State == library.StateEnabled || rev.State == library.StateVerifiedDisabled) {
			if _, err := lib.Enable(rev.ServerID, rev.Revision, library.EnableOptions{Actor: "smcpctl bootstrap", Standalone: true}); err != nil {
				return "", err
			}
			fmt.Fprintf(out, "reusing packaged %s (artifact sha256 %s)\n", rev.Key(), sha)
			return sha, nil
		}
	}
	work, cleanup, err := packaging.ThrowawayDir("smcp-bootstrap-")
	if err != nil {
		return "", err
	}
	defer cleanup()
	pkgDir := filepath.Join(work, "pkg")
	r := refRecipe(refserver, sha, version)
	// The revision carries the artifact digest, so a rebuilt binary of the
	// same version is a new immutable revision.
	r.Server.Revision = version + "+" + sha[:12]
	r.SetDir(work)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pkg, err := packaging.Build(ctx, r, pkgDir, packaging.BuildOptions{Version: backend.Version})
	if err != nil {
		return "", fmt.Errorf("package the reference server: %w", err)
	}
	secret, pub, keyID, err := packaging.GenerateKey("")
	if err != nil {
		return "", err
	}
	key, err := packaging.ParseSecretKey(secret, "")
	if err != nil {
		return "", err
	}
	if err := packaging.Sign(pkgDir, key, time.Now()); err != nil {
		return "", err
	}
	anchors, err := packaging.LoadAnchors(stateDir)
	if err != nil {
		return "", err
	}
	now := time.Now()
	if _, err := anchors.Add("bootstrap-"+keyID, pub, []string{"low"}, now.Add(packaging.DefaultAnchorLifetime), now, "smcpctl bootstrap"); err != nil {
		return "", err
	}
	if err := anchors.Save(); err != nil {
		return "", err
	}
	dst := filepath.Join(lib.Dir(), pkg.Index.ServerID, pkg.Index.Revision)
	if _, err := os.Stat(dst); err == nil {
		packaging.MakeWritable(dst)
		if err := os.RemoveAll(dst); err != nil {
			return "", err
		}
	}
	if err := packaging.CopyPackage(pkgDir, dst); err != nil {
		return "", err
	}
	// Bootstrap is the operator's own installation step: a rebuilt binary
	// may sort lower than an earlier one (SR-3-5 authorization).
	rc, err := lib.Import(dst, library.ImportOptions{Actor: "smcpctl bootstrap", AllowDowngrade: true})
	if err != nil {
		return "", fmt.Errorf("import the reference package: %w", err)
	}
	if _, err := lib.Enable(rc.ServerID, rc.Revision, library.EnableOptions{Actor: "smcpctl bootstrap", Standalone: true}); err != nil {
		return "", err
	}
	fmt.Fprintf(out, "packaged %s@%s (artifact sha256 %s), signed with a one-time key enrolled as trust anchor bootstrap-%s for risk class low\n",
		rc.ServerID, rc.Revision, pkg.Index.Artifact.SHA256, keyID)
	return pkg.Index.Artifact.SHA256, nil
}
