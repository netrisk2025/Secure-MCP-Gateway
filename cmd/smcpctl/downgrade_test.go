package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestEnforcedWithoutPrerequisitesRefusesToStart is FR-13.9 at the daemon:
// a configuration that selects the Enforced profile on a host without
// rootless Podman and without nftables (here: neither on the PATH) makes
// smcpd exit with an error naming both, instead of falling back to the
// Standalone profile. On a non-Linux host the refusal names the platform
// prerequisite instead, which does not exercise the two named here, so the
// claim is partial there.
func TestEnforcedWithoutPrerequisitesRefusesToStart(t *testing.T) {
	if runtime.GOOS == "linux" {
		reqtest.Verifies(t, "FR-13.9")
	} else {
		reqtest.Partial(t, "FR-13.9")
	}
	_, cfg := instance(t)
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, append(raw, []byte("\n[profile]\nmode = \"enforced\"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(binDir, "smcpd"), "--config", cfg)
	cmd.Env = []string{"PATH=" + t.TempDir(), "HOME=" + os.Getenv("HOME")}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("smcpd exited 0 with the Enforced profile and no prerequisites:\n%s", out.String())
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("smcpd kept running with the Enforced profile and no prerequisites:\n%s", out.String())
	}
	log := out.String()
	if !strings.Contains(log, "prerequisites missing") {
		t.Fatalf("no prerequisite refusal:\n%s", log)
	}
	if runtime.GOOS == "linux" {
		for _, want := range []string{"Podman", "nftables"} {
			if !strings.Contains(log, want) {
				t.Errorf("refusal does not name %s:\n%s", want, log)
			}
		}
	} else if !strings.Contains(strings.ToLower(log), "linux") {
		t.Errorf("refusal does not name the platform:\n%s", log)
	}
}
