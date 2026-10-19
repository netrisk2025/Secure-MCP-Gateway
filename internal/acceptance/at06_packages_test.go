package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// copyTree copies a directory of regular files.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func readJSON(t *testing.T, p string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return m
}

func writeJSON(t *testing.T, p string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// refreshIndex rewrites the index entry of a changed package member with its
// new digest and size.
func refreshIndex(t *testing.T, pkg, member string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pkg, member+".json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	idx := readJSON(t, filepath.Join(pkg, "index.json"))
	e, _ := idx[member].(map[string]any)
	if e == nil {
		t.Fatalf("index has no %s entry", member)
	}
	e["sha256"], e["size"] = hex.EncodeToString(sum[:]), len(b)
	writeJSON(t, filepath.Join(pkg, "index.json"), idx)
}

// TestAT06SourceAndBuildEvidence is acceptance scenario AT-06 against the
// real smcpctl and smcpd, using the reference package that bootstrap built,
// signed and imported:
//
//   - its provenance statement binds the source reference and digest and
//     the SPDX license identifiers to the artifact digest (FR-14.5);
//   - re-signed by a key that is not enrolled, or by an anchor whose scope
//     lacks the package's risk class, it is refused (SR-3-1);
//   - with a provenance statement naming another artifact digest, or
//     without license identifiers, it is refused even when correctly
//     signed (SR-3.2-1, SR-3.1-1);
//   - when the imported artifact is altered, the next launch is refused
//     and the revision is suspended (SR-3-2).
//
// Partial: SR-3-1 does not cover an expired anchor (enrollment refuses
// past expiry dates); SR-3.1-1 removes the licenses, not each element of
// the source reference; SR-3.8-1 (drift) cannot be produced with the
// reference server and is claimed by the library tests; FR-14.5 inspects
// the bootstrap package, not every reference package.
func TestAT06SourceAndBuildEvidence(t *testing.T) {
	g := newGateway(t, options{})
	g.start()
	g.scenario("AT-06")
	reqtest.Partial(t, "FR-14.5", "SR-3-1", "SR-3-2", "SR-3.1-1", "SR-3.2-1")
	cs := g.session(g.token(""))
	g.mustCall(cs, "ref_echo", map[string]any{"text": "packaged"}, "packaged")
	g.stop()

	pkgs := filepath.Join(g.state, "packages")
	reg := readJSON(t, filepath.Join(pkgs, "registry.json"))
	revs, _ := reg["revisions"].([]any)
	if len(revs) != 1 {
		t.Fatalf("registry: %v", reg)
	}
	rev := revs[0].(map[string]any)
	artifactSHA := rev["artifact_sha256"].(string)
	revDir := filepath.Join(pkgs, "revisions", rev["server_id"].(string), rev["revision"].(string))

	// FR-14.5: the provenance statement.
	prov := readJSON(t, filepath.Join(revDir, "provenance.json"))
	art, _ := prov["artifact"].(map[string]any)
	src, _ := prov["source"].(map[string]any)
	lic, _ := prov["licenses"].([]any)
	if art["sha256"] != artifactSHA || src["sha256"] == "" || src["uri"] == "" || len(lic) == 0 || lic[0] != "Apache-2.0" {
		t.Fatalf("provenance: %v", prov)
	}

	// A package directory equal to the imported one.
	work := t.TempDir()
	pkg := filepath.Join(work, "pkg")
	copyTree(t, revDir, pkg)
	artifact, _ := os.ReadFile(filepath.Join(pkgs, "artifacts", "sha256", artifactSHA))
	writeFile(t, pkg, filepath.Join("artifact", "smcp-refserver"), string(artifact), 0o755)
	if out := g.mustCtl("package", "verify", pkg); !strings.Contains(strings.ToLower(out), "ok") && !strings.Contains(out, "verified") {
		t.Fatalf("the imported package does not verify as a copy: %s", out)
	}

	// SR-3-1: an unknown key, then an anchor without the low class.
	keyPfx := filepath.Join(work, "at06")
	g.mustCtl("package", "keygen", "--out", keyPfx, "--unencrypted")
	g.mustCtl("package", "sign", pkg, "--key", keyPfx+".key")
	refusedPkg := func(what, dir string) {
		t.Helper()
		if out, err := g.ctl("package", "verify", dir); err == nil {
			t.Fatalf("%s: package verify accepted it:\n%s", what, out)
		}
		if out, err := g.ctl("package", "install", dir); err == nil {
			t.Fatalf("%s: package install accepted it:\n%s", what, out)
		}
	}
	refusedPkg("unknown key", pkg)
	g.trustAdd(keyPfx+".pub", "at06-moderate", "--classes", "moderate")
	refusedPkg("anchor out of scope", pkg)
	g.mustCtl("trust", "remove", "at06-moderate")
	g.trustAdd(keyPfx+".pub", "at06", "--classes", "low")
	if out := g.mustCtl("package", "verify", pkg); out == "" {
		t.Fatal("no verify output")
	}

	// SR-3.2-1: provenance naming another artifact digest, correctly signed.
	bad := filepath.Join(work, "bad-provenance")
	copyTree(t, pkg, bad)
	p := readJSON(t, filepath.Join(bad, "provenance.json"))
	p["artifact"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
	writeJSON(t, filepath.Join(bad, "provenance.json"), p)
	refreshIndex(t, bad, "provenance")
	g.mustCtl("package", "sign", bad, "--key", keyPfx+".key")
	refusedPkg("provenance digest mismatch", bad)

	// SR-3.1-1: no license identifiers, correctly signed.
	nolic := filepath.Join(work, "no-license")
	copyTree(t, pkg, nolic)
	p = readJSON(t, filepath.Join(nolic, "provenance.json"))
	delete(p, "licenses")
	writeJSON(t, filepath.Join(nolic, "provenance.json"), p)
	refreshIndex(t, nolic, "provenance")
	g.mustCtl("package", "sign", nolic, "--key", keyPfx+".key")
	refusedPkg("missing licenses", nolic)

	// SR-3-2: alter the imported artifact; the next launch is refused and
	// the revision suspended.
	for _, f := range []string{filepath.Join(pkgs, "artifacts", "sha256", artifactSHA), filepath.Join(pkgs, "unpacked", artifactSHA, "smcp-refserver")} {
		if err := os.Chmod(f, 0o755); err != nil {
			t.Fatal(err)
		}
		fh, err := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fh.Write([]byte("altered"))
		fh.Close()
	}
	g.start()
	cs = g.session(g.token(""))
	if text, isErr, err := call(cs, "ref_echo", map[string]any{"text": "after tampering"}); err == nil && !isErr {
		t.Fatalf("the altered artifact was launched: %q", text)
	}
	list := g.mustCtl("package", "list")
	if !strings.Contains(list, "suspended") {
		t.Fatalf("the altered revision is not suspended:\n%s", list)
	}
	g.stop()
}
