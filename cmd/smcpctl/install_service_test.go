package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestInstallStandaloneServiceManager runs `smcpctl install` in the
// Standalone profile with the host's real service manager (a launchd user
// agent on macOS, a systemd user unit on Linux) through
// scripts/ci-install-standalone.sh: install, the directories and their
// modes, the unit, profile = "standalone", the printed notice, the running
// service and its health, a second install that reports every step
// present and leaves configuration, keys, policy, journal and unit
// byte-for-byte unchanged, then uninstall, which removes the unit and the
// binaries and keeps a journal that verifies.
//
// It changes the current user's service manager and home directory, so it
// runs only with SMCP_INSTALL_SERVICE_TEST=1, in the CI job
// install-standalone (macos-latest, arm64; ubuntu-24.04 with Podman
// removed). FR-13.6 asks for both runners: the status job merges the
// results of this test only when both platforms reported one, so each run
// claims the requirement in full. FR-13.4 also needs the Enforced profile
// (scripts/ci-systemd.sh) and FR-13.11 the Enforced uninstall: partial.
func TestInstallStandaloneServiceManager(t *testing.T) {
	if os.Getenv("SMCP_INSTALL_SERVICE_TEST") != "1" {
		t.Skip("changes the user's service manager; set SMCP_INSTALL_SERVICE_TEST=1 on a disposable runner")
	}
	switch {
	case runtime.GOOS == "darwin" && runtime.GOARCH == "arm64":
	case runtime.GOOS == "linux":
		// FR-13.6: a Linux host without Podman.
		if p, err := exec.LookPath("podman"); err == nil {
			t.Fatalf("podman is installed (%s); FR-13.6 asks for a Linux runner without Podman", p)
		}
	default:
		t.Fatalf("FR-13.6 runs on macOS arm64 and Linux, not %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	reqtest.Verifies(t, "FR-13.6")
	reqtest.Partial(t, "FR-13.4", "FR-13.11")

	// uninstall removes the binaries it was given: use copies.
	bin := t.TempDir()
	for _, n := range []string{"smcpd", "smcpctl", "smcp-refserver"} {
		copyBin(t, filepath.Join(binDir, n), filepath.Join(bin, n))
	}
	cmd := exec.Command("bash", filepath.Join("..", "..", "scripts", "ci-install-standalone.sh"), bin, t.TempDir())
	cmd.Env = append(os.Environ(), "SMCP_REQUIRE_SERVICE=1", "SMCP_INSTALL_PORT="+freePort(t))
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("ci-install-standalone.sh: %v", err)
	}
	for _, want := range []string{"==> install-standalone: passed", "This installation is not enforced", "none created or updated"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("output lacks %q", want)
		}
	}
}
