package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/profile"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// fakeSecrets is a SecretBroker with the optional seams app.Start wires.
type fakeSecrets struct {
	injector pipeline.SecretHeaderInjector
	share    func(ref string, version int, value []byte)
}

func (f *fakeSecrets) Resolve(context.Context, pipeline.SecretRequest) (map[string]string, error) {
	return map[string]string{}, nil
}
func (f *fakeSecrets) SetInjector(i pipeline.SecretHeaderInjector) { f.injector = i }
func (f *fakeSecrets) ShareFingerprints(fn func(string, int, []byte)) {
	f.share = fn
}

func startMinimal(t *testing.T, extra string, o Options) *App {
	t.Helper()
	dir := t.TempDir()
	if err := keys.Ensure(filepath.Join(dir, "state"), "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	pol := `{"revision": "r1", "framework_profiles": {"dev": {"templates": ["t"], "default_template": "t"}}, "templates": {"t": {"rules": []}}}`
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(pol), 0o600); err != nil {
		t.Fatal(err)
	}
	toml := fmt.Sprintf(`
[listener]
address = "127.0.0.1:1"
public_url = "https://127.0.0.1:1"
[admin_listener]
address = "127.0.0.1:2"
[state]
dir = %q
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[policy]
file = %q
%s
`, filepath.Join(dir, "state"), filepath.Join(dir, "policy.json"), extra)
	p := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(p, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	o.Log = diag.Discard()
	o.Host = &profile.Host{OS: "darwin", Arch: "arm64"}
	a, err := Start(context.Background(), cfg, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

// TestSecretBrokerWiring: app.Start gives the Secret Broker the Egress
// Broker as its S1 header injector when [egress] is enabled, and makes
// delivered secret values part of the E-09/E-11 inspector's registered
// fingerprints, so the secret-fingerprint filter detects them.
func TestSecretBrokerWiring(t *testing.T) {
	reqtest.Partial(t, "FR-6.6", "FR-6.10")
	sec := &fakeSecrets{}
	a := startMinimal(t, "[egress]\nenabled = true\n", Options{Secrets: sec})
	if a.Egress == nil || sec.injector == nil || sec.injector != pipeline.SecretHeaderInjector(a.Egress) {
		t.Fatalf("S1 injector not wired: %v", sec.injector)
	}
	if sec.share == nil {
		t.Fatal("fingerprints not shared")
	}
	value := "delivered-secret-value-1234567890"
	if _, ok := a.Inspector.Fingerprints().Match("x " + value + " y"); ok {
		t.Fatal("matched before delivery")
	}
	sec.share("gh-token", 3, []byte(value))
	ref, ok := a.Inspector.Fingerprints().Match("leaked: " + value)
	if !ok || !strings.HasPrefix(ref, "gh-token@3") {
		t.Fatalf("inspector does not detect the delivered value: %q %v", ref, ok)
	}

	// Without [egress] there is no injector, and S1 stays unavailable.
	sec2 := &fakeSecrets{}
	startMinimal(t, "", Options{Secrets: sec2})
	if sec2.injector != nil {
		t.Fatal("injector set without an Egress Broker")
	}
}
