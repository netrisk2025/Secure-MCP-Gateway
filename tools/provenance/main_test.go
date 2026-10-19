package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const repoRoot = "../.."

// TestProvenanceFiles writes the provenance files for this checkout and
// checks them against FR-12.8: the source commit, the digest of each build
// recipe and lockfile, and license notices for every Go module linked into
// the release binaries and every npm package bundled into the console.
// It is partial: the inspection of a published release bundle is not
// done here.
func TestProvenanceFiles(t *testing.T) {
	reqtest.Partial(t, "FR-12.8")
	mods, err := linkedModules(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, m := range mods {
		have[m.Path] = true
		if m.Path == "github.com/ethan03805/secure-mcp-gateway" {
			t.Fatal("the main module is listed as a third-party module")
		}
	}
	for _, want := range []string{"github.com/modelcontextprotocol/go-sdk", "github.com/pelletier/go-toml/v2", "github.com/google/nftables", "golang.org/x/sys"} {
		if !have[want] {
			t.Errorf("%s missing from the linked modules %v", want, mods)
		}
	}
	if have["github.com/duckdb/duckdb-go/v2"] {
		t.Error("a module that no release binary links (duckdb) is listed")
	}

	pkgs, err := consolePackages(filepath.Join(repoRoot, "console", "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, p := range pkgs {
		names[p.Name] = true
		if p.License == "" {
			t.Errorf("npm package %s has no license in the lockfile", p.Name)
		}
	}
	if !names["react"] || !names["react-dom"] || names["vite"] || names["typescript"] {
		t.Fatalf("console production packages: %v", pkgs)
	}

	// A console/node_modules with license files: every package gets its
	// license text; without one, -require-npm refuses.
	nm := filepath.Join(t.TempDir(), "node_modules")
	if _, err := renderNotices(mods, pkgs, nm, true); err == nil || !strings.Contains(err.Error(), "no license file") {
		t.Fatalf("missing npm license files accepted: %v", err)
	}
	for _, p := range pkgs {
		d := filepath.Join(filepath.Dir(nm), p.Path)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "LICENSE"), []byte("license text of "+p.Name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	notices, err := renderNotices(mods, pkgs, nm, true)
	if err != nil {
		t.Fatal(err)
	}
	n := string(notices)
	if !strings.Contains(n, "Go standard library go") || !strings.Contains(n, "Redistribution and use") {
		t.Error("no Go standard library license")
	}
	for _, m := range mods {
		if !strings.Contains(n, "Go module "+m.Path+" "+m.Version+"\n") {
			t.Errorf("no notice for %s", m.Path)
		}
	}
	for _, p := range pkgs {
		if !strings.Contains(n, "license text of "+p.Name+"\n") {
			t.Errorf("no license text for npm package %s", p.Name)
		}
	}

	prov, err := renderProvenance(repoRoot, "9.9.9", mods)
	if err != nil {
		t.Fatal(err)
	}
	head, err := exec.Command("git", "-C", repoRoot, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	p := string(prov)
	if !strings.Contains(p, "| Source commit | `"+strings.TrimSpace(string(head))+"` |") {
		t.Errorf("PROVENANCE.md does not name the commit:\n%s", p)
	}
	for _, f := range RecipeFiles {
		d, err := fileSHA256(filepath.Join(repoRoot, f))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(p, "| `"+f+"` | `"+d+"` |") {
			t.Errorf("PROVENANCE.md lacks the digest of %s", f)
		}
	}
}

// TestArchivesCarryTheProvenanceFiles checks that .goreleaser.yaml copies
// the recipe, the lockfiles and the tool's output into every archive and
// runs the tool before the build, and that the release workflow checks
// them.
func TestArchivesCarryTheProvenanceFiles(t *testing.T) {
	reqtest.Partial(t, "FR-12.8")
	cfg, err := os.ReadFile(filepath.Join(repoRoot, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range RecipeFiles {
		if !strings.Contains(string(cfg), "      - src: "+f+"\n") {
			t.Errorf(".goreleaser.yaml does not put %s in the archives", f)
		}
	}
	for _, want := range []string{"- src: build/provenance/*\n", "go run ./tools/provenance -version {{ .Version }} -out build/provenance"} {
		if !strings.Contains(string(cfg), want) {
			t.Errorf(".goreleaser.yaml lacks %q", want)
		}
	}
	wf, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range append([]string{"PROVENANCE.md", "THIRD_PARTY_NOTICES.txt"}, RecipeFiles...) {
		if !strings.Contains(string(wf), f) {
			t.Errorf("the release workflow does not check %s", f)
		}
	}
}
