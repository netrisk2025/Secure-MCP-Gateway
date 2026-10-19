package secrets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const baseConfig = `
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[server]]
alias = "t"
command = "/inproc/t"
`

func loadConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(p, []byte(baseConfig+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestSettingsDefaultsAndSchema(t *testing.T) {
	reqtest.Partial(t, "FR-6")
	if _, ok := SettingsFrom(loadConfig(t, "")); ok {
		t.Fatal("secrets enabled without a [secrets] table")
	}
	cfg := loadConfig(t, "[secrets]\npassphrase_file = \"pp\"\n")
	s, ok := SettingsFrom(cfg)
	if !ok || s.VaultDir != filepath.Join(cfg.State.Dir, "vault") || s.KeySource != KeySourceAuto || s.RotationOverlap != DefaultOverlap ||
		s.PassphraseFile != filepath.Join(cfg.Dir, "pp") || s.RuntimeDir == "" {
		t.Fatalf("defaults: %+v", s)
	}
	for _, bad := range []string{"[secrets]\nkey_source = \"tpm\"\n", "[secrets]\nrotation_overlap = \"soon\"\n", "[secrets]\nunknown = 1\n"} {
		if _, err := config.Parse([]byte(baseConfig + bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestConfigureWiresSeams(t *testing.T) {
	reqtest.Partial(t, "FR-6")
	cfg := loadConfig(t, "[secrets]\nkey_source = \"passphrase\"\npassphrase_file = \"pp\"\nuse_policy_file = \"use.json\"\nruntime_dir = \"run\"\nrotation_overlap = \"2h\"\n")
	o := app.Options{Log: diag.Discard()}
	// Without an initialized vault, Configure names the command to run.
	if _, err := Configure(cfg, &o, nil, diag.Discard()); err == nil || !strings.Contains(err.Error(), "use.json") {
		t.Fatalf("missing use policy: %v", err)
	}
	os.WriteFile(filepath.Join(cfg.Dir, "use.json"), []byte(`{"revision": "u"}`), 0o600)
	if _, err := Configure(cfg, &o, nil, diag.Discard()); err == nil || !strings.Contains(err.Error(), "smcpctl secrets init") {
		t.Fatalf("uninitialized vault: %v", err)
	}
	s, _ := SettingsFrom(cfg)
	ks := Passphrase{Path: filepath.Join(s.VaultDir, MasterKeyFile), Passphrase: func() (string, error) { return testPassphrase, nil }, WorkFactor: 10}
	if _, err := Init(s.VaultDir, ks); err != nil {
		t.Fatal(err)
	}
	if _, err := Configure(cfg, &o, nil, diag.Discard()); err == nil {
		t.Fatal("unlocked without the passphrase file")
	}
	os.WriteFile(filepath.Join(cfg.Dir, "pp"), []byte(testPassphrase+"\n"), 0o600)
	svc, err := Configure(cfg, &o, nil, diag.Discard())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	if o.Secrets != svc.Broker || o.Launcher == nil || o.Launcher.Name() != "subprocess" || o.Observers["secret-broker"] == nil || o.Filters != nil {
		t.Fatalf("seams: %+v", o)
	}
	if svc.Vault.DefaultOverlap() != 2*time.Hour || svc.Settings.RuntimeDir != filepath.Join(cfg.Dir, "run") {
		t.Fatalf("settings: %+v", svc.Settings)
	}
	// app.Start registers the broker's filters; Configure leaves the chain
	// unset so the built-in E-09/E-11 filters are still installed.
	chain := pipeline.NewFilters()
	if err := svc.Broker.RegisterFilters(chain); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{FilterArgsLeak, FilterResultLeak, FilterS2Delivery, FilterS2Release} {
		if len(chain.Unavailable([]string{id})) != 0 {
			t.Fatalf("filter %s not registered", id)
		}
	}
	// The wrapped launcher keeps the inner launcher's identity.
	o2 := app.Options{Launcher: pipeline.InProcessLauncher{Confine: true}}
	svc2, err := Configure(cfg, &o2, nil, diag.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if o2.Launcher.Name() != "in-process" || !o2.Launcher.Confined() {
		t.Fatal("launcher identity changed")
	}
	svc2.Close()
	// Run sweeps and stops with its context.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx, time.Millisecond); close(done) }()
	cancel()
	<-done
	var nilSvc *Service
	nilSvc.Attach(nil, nil)
	nilSvc.Close()
	nilSvc.Run(context.Background(), 0)
	_ = fmt.Sprint(svc.status())
}
