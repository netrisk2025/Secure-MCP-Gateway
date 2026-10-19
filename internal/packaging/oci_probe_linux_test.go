//go:build linux

package packaging_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestIntegrationPackageBuildEachType is FR-14.1: package build accepts a
// pinned reference of each type (npm, pypi, oci, binary), fetches it,
// verifies the digest, probes it and stores the artifact in the package
// directory under its SHA-256; a wrong digest of each type is refused. The
// OCI image holds a statically linked smcp-refserver, so the probe really
// runs it with rootless Podman (`podman run oci-archive:...`) and reads
// its tool list. The registries are local test servers.
//
// Runs with SMCP_SANDBOX_IT=1 (the linux-integration job), like the other
// tests against real Podman; node and python3 are required there too.
func TestIntegrationPackageBuildEachType(t *testing.T) {
	if os.Getenv("SMCP_SANDBOX_IT") != "1" {
		t.Skip("set SMCP_SANDBOX_IT=1 to run against real rootless Podman")
	}
	for _, tool := range []string{"podman", "node", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required: %v", tool, err)
		}
	}
	reqtest.Verifies(t, "FR-14.1")

	// A statically linked reference server in an image layer.
	static := filepath.Join(t.TempDir(), "smcp-refserver")
	build := exec.Command("go", "build", "-trimpath", "-o", static, "github.com/ethan03805/secure-mcp-gateway/cmd/smcp-refserver")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	bin, err := os.ReadFile(static)
	if err != nil {
		t.Fatal(err)
	}
	var layerTar bytes.Buffer
	tw := tar.NewWriter(&layerTar)
	_ = tw.WriteHeader(&tar.Header{Name: "app/", Mode: 0o755, Typeflag: tar.TypeDir})
	_ = tw.WriteHeader(&tar.Header{Name: "app/smcp-refserver", Mode: 0o755, Size: int64(len(bin)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(bin)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var layer bytes.Buffer
	gz := gzip.NewWriter(&layer)
	_, _ = gz.Write(layerTar.Bytes())
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	r := newRegistriesImage(t, layer.Bytes(), []string{"sha256:" + packaging.SHA256Hex(layerTar.Bytes())})
	host := strings.TrimPrefix(r.srv.URL, "http://")
	binSHA, _, _ := packaging.FileSHA256(refserver)
	src := filepath.Join(t.TempDir(), "src.tar.gz")
	if err := os.WriteFile(src, []byte("source archive"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		art    packaging.ArtifactRef
		wrong  packaging.ArtifactRef
		launch packaging.Launch
		tools  []string
	}{
		{"npm", packaging.ArtifactRef{Type: "npm", Name: "@fx/hello", Version: "1.2.3", Integrity: sha512Integrity(r.npmTGZ)},
			packaging.ArtifactRef{Type: "npm", Name: "@fx/hello", Version: "1.2.3", Integrity: sha512Integrity([]byte("other"))},
			packaging.Launch{Runtime: "node", Argv: []string{"node", "node_modules/@fx/hello/index.js"}}, []string{"hello"}},
		{"pypi", packaging.ArtifactRef{Type: "pypi", Name: "fixture-mcp", Version: "1.0.0", SHA256: packaging.SHA256Hex(r.whl)},
			packaging.ArtifactRef{Type: "pypi", Name: "fixture-mcp", Version: "1.0.0", SHA256: strings.Repeat("c", 64)},
			packaging.Launch{Runtime: "python", Argv: []string{"python3", "-m", "fixture_mcp"}}, []string{"add"}},
		{"oci", packaging.ArtifactRef{Type: "oci", Name: host + "/fx/img", Version: "1.0.0", Integrity: r.ociDigest},
			packaging.ArtifactRef{Type: "oci", Name: host + "/fx/img", Version: "1.0.0", Integrity: "sha256:" + strings.Repeat("d", 64)},
			packaging.Launch{Runtime: "oci", Argv: []string{"/app/smcp-refserver"}}, []string{"echo", "time_now"}},
		{"binary", packaging.ArtifactRef{Type: "binary", Name: refserver, Version: "1.0.0", SHA256: binSHA},
			packaging.ArtifactRef{Type: "binary", Name: refserver, Version: "1.0.0", SHA256: strings.Repeat("e", 64)},
			packaging.Launch{Runtime: "native", Argv: []string{"smcp-refserver"}}, []string{"echo", "time_now"}},
	}
	recipe := func(name string, art packaging.ArtifactRef, launch packaging.Launch) *packaging.Recipe {
		rc := &packaging.Recipe{RecipeVersion: 1, Server: packaging.ServerInfo{ID: "fx-" + name, Alias: name, Publisher: "test"},
			Artifact: art, Launch: launch, RiskClass: "low", InstanceScope: []string{"shared"}, Licenses: []string{"MIT"},
			Tools:        packaging.RecipeTools{Default: packaging.ToolClass{SideEffect: "read", SourceTrust: "trusted"}},
			Capabilities: packaging.Capabilities{Filesystem: []packaging.FilesystemSlot{}, Egress: []packaging.EgressRule{}}}
		if art.Type == "binary" || art.Type == "oci" {
			rc.Source = &packaging.RecipeSource{Kind: "archive", URI: "https://example.invalid/src.tar.gz", Path: src}
		}
		return rc
	}
	for _, c := range cases {
		out := filepath.Join(t.TempDir(), "pkg")
		pkg, err := packaging.Build(context.Background(), recipe(c.name, c.art, c.launch), out, packaging.BuildOptions{Fetcher: r.fetcher(), Log: testWriter{t}})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		art := filepath.Join(out, filepath.FromSlash(pkg.Index.Artifact.Path))
		sum, _, err := packaging.FileSHA256(art)
		if err != nil || sum != pkg.Index.Artifact.SHA256 || pkg.Manifest.Artifact.SHA256 != sum || !strings.HasPrefix(pkg.Index.Artifact.Path, packaging.ArtifactDir+"/") {
			t.Fatalf("%s: artifact %s (sha256 %s, index %s): %v", c.name, art, sum, pkg.Index.Artifact.SHA256, err)
		}
		var names []string
		for _, tl := range pkg.Manifest.Tools {
			names = append(names, tl.Name)
		}
		for _, want := range c.tools {
			if !slices.Contains(names, want) {
				t.Fatalf("%s: probed tools %v lack %s", c.name, names, want)
			}
		}
		t.Logf("%s: artifact %s sha256 %s, tools %v, probe %+v", c.name, pkg.Index.Artifact.Path, sum, names, pkg.Provenance.Probe)

		if _, err := packaging.Build(context.Background(), recipe(c.name, c.wrong, c.launch), filepath.Join(t.TempDir(), "pkg"), packaging.BuildOptions{Fetcher: r.fetcher()}); err == nil {
			t.Fatalf("%s: a wrong digest was accepted", c.name)
		} else {
			t.Logf("%s: wrong digest refused: %v", c.name, err)
		}
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
