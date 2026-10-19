//go:build linux

package main

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/hostile"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestIntegrationPackageBuildProbeSandbox is SR-3.5-1 and the Enforced
// part of FR-14.3: smcpctl package build probes a candidate server (the
// PACKAGING fixture of smcp-hostile, statically linked) that, while its
// tool list is read, tries to read a host file, to read a secret variable
// of the operator's environment and to open a TCP connection to a host
// listener. With the probe in the rootless Podman sandbox (--sandbox
// podman, as in the Enforced profile) each attempt fails, the provenance
// records network "none", and the probe environment holds no variable
// besides what the container runtime sets. The same candidate probed as
// an unconfined subprocess (--sandbox none, the Standalone profile) reads
// the file and connects, which shows the fixture's attempts are real.
//
// Runs with SMCP_SANDBOX_IT=1 (the linux-integration job), like the other
// tests against real Podman.
func TestIntegrationPackageBuildProbeSandbox(t *testing.T) {
	if os.Getenv("SMCP_SANDBOX_IT") != "1" {
		t.Skip("set SMCP_SANDBOX_IT=1 to run against real rootless Podman")
	}
	reqtest.Verifies(t, "SR-3.5-1")
	reqtest.Partial(t, "FR-14.3")
	// The sandbox refuses mount targets at or below /tmp, and the probe's
	// slot directories are mounted at their own paths: keep the throwaway
	// directories elsewhere.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	tmp, err := os.MkdirTemp(home, "smcp-probe-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packaging.MakeWritable(tmp); os.RemoveAll(tmp) })
	t.Setenv("TMPDIR", tmp)
	t.Setenv("SMCP_PROBE_TEST_SECRET", "operator-secret-canary")

	work := t.TempDir()
	fixture := filepath.Join(work, "smcp-hostile")
	build := exec.Command("go", "build", "-trimpath", "-o", fixture, "../smcp-hostile")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build smcp-hostile: %v\n%s", err, out)
	}
	canaryFile := filepath.Join(work, "home-canary.txt")
	if err := os.WriteFile(canaryFile, []byte("private"), 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	sha, _, err := packaging.FileSHA256(fixture)
	if err != nil {
		t.Fatal(err)
	}
	r := packaging.Recipe{RecipeVersion: packaging.RecipeVersion,
		Server:   packaging.ServerInfo{ID: "probe-escape", Alias: "esc", Publisher: "test"},
		Artifact: packaging.ArtifactRef{Type: "binary", Name: fixture, Version: "1.0.0", SHA256: sha},
		Launch: packaging.Launch{Runtime: "native", Argv: []string{"smcp-hostile", "-fixture", "PACKAGING", "-canary-file", canaryFile,
			"-canary-env", "SMCP_PROBE_TEST_SECRET", "-canary-addr", ln.Addr().String()}},
		RiskClass: "low", InstanceScope: []string{"shared"},
		Tools:        packaging.RecipeTools{Default: packaging.ToolClass{SideEffect: "read", SourceTrust: "untrusted"}, Expect: []string{"report"}},
		Capabilities: packaging.Capabilities{Filesystem: []packaging.FilesystemSlot{}, Egress: []packaging.EgressRule{}},
		Source:       &packaging.RecipeSource{Kind: "archive", URI: "file://" + fixture, SHA256: sha},
		Licenses:     []string{"Apache-2.0"},
	}
	b, _ := json.Marshal(r)
	recipe := filepath.Join(work, "recipe.json")
	if err := os.WriteFile(recipe, b, 0o644); err != nil {
		t.Fatal(err)
	}
	probe := func(mode string) (hostile.PackagingReport, packaging.ProbeEnvironment) {
		t.Helper()
		out := filepath.Join(work, "pkg-"+mode)
		mustCtl(t, "package", "build", "--recipe", recipe, "--out", out, "--sandbox", mode)
		raw, err := os.ReadFile(filepath.Join(out, packaging.ManifestFile))
		if err != nil {
			t.Fatal(err)
		}
		m, err := packaging.ParseManifest(raw)
		if err != nil {
			t.Fatal(err)
		}
		var rep hostile.PackagingReport
		for _, tl := range m.Tools {
			if tl.Name == "report" {
				rep = hostile.ParsePackagingReport(tl.Description)
			}
		}
		var prov packaging.Provenance
		pb, err := os.ReadFile(filepath.Join(out, packaging.ProvenanceFile))
		if err != nil || json.Unmarshal(pb, &prov) != nil {
			t.Fatalf("provenance: %v", err)
		}
		t.Logf("%s probe: %+v; provenance probe %+v", mode, rep, prov.Probe)
		return rep, prov.Probe
	}

	rep, env := probe("podman")
	if rep.File != "blocked" || rep.Env != "absent" || rep.Net != "blocked" {
		t.Errorf("sandboxed probe: file %s, env %s, net %s; want blocked, absent, blocked", rep.File, rep.Env, rep.Net)
	}
	if env.Network != "none" || !env.Confined {
		t.Errorf("provenance probe environment %+v", env)
	}
	for _, n := range rep.EnvNames {
		if !slices.Contains([]string{"PATH", "HOME", "HOSTNAME", "container", "TERM"}, n) {
			t.Errorf("sandboxed probe environment holds %s (all: %v)", n, rep.EnvNames)
		}
	}

	rep, env = probe("none")
	if rep.File != "read" || rep.Net != "connected" || rep.Env != "absent" || env.Network != "host" {
		t.Errorf("unconfined probe: %+v %+v; want the file read and the connection made (the attempts are real), no secret variable", rep, env)
	}
	if !strings.Contains(strings.Join(rep.EnvNames, ","), "PATH") {
		t.Errorf("unconfined probe environment %v", rep.EnvNames)
	}
}
