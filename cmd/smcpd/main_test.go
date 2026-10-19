package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestVersionFlag(t *testing.T) {
	// smcpd --version prints the version the release build sets and
	// starts nothing (release checks, docs/release-checklist.md).
	reqtest.Partial(t, "FR-13.1")
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH")
	}
	bin := filepath.Join(t.TempDir(), "smcpd")
	build := exec.Command(goTool, "build", "-ldflags", "-X github.com/ethan03805/secure-mcp-gateway/internal/backend.Version=9.9.9-test", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "--version", "--config", filepath.Join(t.TempDir(), "missing.toml")).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "smcpd 9.9.9-test" {
		t.Fatalf("smcpd --version: %v %q", err, out)
	}
}
