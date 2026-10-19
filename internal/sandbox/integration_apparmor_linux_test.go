//go:build linux

package sandbox

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestIntegrationServerAppArmorProfile: with packaging/linux/apparmor/
// smcp-server loaded, a server started from /smcp/bin runs confined by it
// (rootless Podman cannot apply a profile itself; the profile attaches by
// path) and a file access that the container's own permissions allow is
// denied: the server's own environment in /proc, which holds S4 secret
// values. Reads that the profile allows still work. It runs when the
// profile is loaded; SMCP_SANDBOX_IT_APPARMOR=1 (set by the CI after the
// installer ran) makes a missing profile a failure.
func TestIntegrationServerAppArmorProfile(t *testing.T) {
	reqtest.Partial(t, "FR-13.5", "SR-4.7-1")
	required := os.Getenv("SMCP_SANDBOX_IT_APPARMOR") == "1"
	if !appArmorEnforced("", ServerAppArmorProfile) && !required {
		t.Skipf("AppArmor profile %s is not loaded", ServerAppArmorProfile)
	}
	h := realHarness(t, itRuntime(t))
	p, err := h.l.Launch(context.Background(), h.spec("probe"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s := connect(t, p)
	if label := strings.TrimSpace(callText(t, s, "read_file", map[string]any{"path": "/proc/self/attr/current"})); label != ServerAppArmorProfile+" (enforce)" {
		t.Fatalf("server AppArmor label %q, want %q (profile loaded according to apparmorfs: %v)", label, ServerAppArmorProfile+" (enforce)",
			appArmorEnforced("", ServerAppArmorProfile))
	}
	for _, path := range []string{"/proc/self/environ", "/proc/1/environ"} {
		if got := callText(t, s, "read_file", map[string]any{"path": path}); !strings.HasPrefix(got, "blocked:") || !strings.Contains(got, "permission denied") {
			t.Errorf("read %s under %s: %q", path, ServerAppArmorProfile, got)
		}
	}
	if got := callText(t, s, "read_file", map[string]any{"path": "/proc/self/status"}); !strings.Contains(got, "NoNewPrivs:\t1") {
		t.Errorf("read /proc/self/status: %q", got)
	}
	if got := callText(t, s, "write_file", map[string]any{"path": "/work/ok.txt", "text": "x"}); strings.HasPrefix(got, "blocked:") {
		t.Errorf("write /work: %q", got)
	}
}
