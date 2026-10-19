package secrets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// refusingLauncher stands in for the package artifact check (SR-3-2),
// which wraps the broker's launcher and refuses a launch before the
// broker's wrapper runs.
type refusingLauncher struct{ inner pipeline.Launcher }

func (r refusingLauncher) Name() string   { return r.inner.Name() }
func (r refusingLauncher) Confined() bool { return r.inner.Confined() }
func (refusingLauncher) Launch(context.Context, pipeline.ServerSpec) (pipeline.Process, error) {
	return nil, fmt.Errorf("artifact changed: %w", pipeline.ErrServerSuspended)
}

// A launch refused outside the broker's wrapper must not leave the
// launch-time deliveries behind: the S3 file and instance directory are
// removed, the S1 header grant is withdrawn and each delivery has a
// withdrawn event.
func TestRefusedLaunchWithdrawsDeliveries(t *testing.T) {
	reqtest.Partial(t, "FR-6.8", "SR-3-2")
	tv := newTestVault(t)
	for name, v := range map[string]string{"env-secret": envValue, "file-secret": fileValue, "call-secret": callValue, "hdr-secret": hdrValue} {
		tv.create(t, name, v)
	}
	cfg, err := config.Parse([]byte(`
[listener]
address = "127.0.0.1:0"
public_url = "https://127.0.0.1:1"
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[server]]
alias = "t"
command = "/inproc/t"
[server.secret_env]
API_TOKEN = "env-secret"
`))
	if err != nil {
		t.Fatal(err)
	}
	use, err := CompileUsePolicy([]byte(brokerUsePolicy), cfg.Servers)
	if err != nil {
		t.Fatal(err)
	}
	inj := &fakeInjector{}
	runtime := filepath.Join(t.TempDir(), "run")
	log := slog.New(slog.DiscardHandler)
	b, err := NewBroker(BrokerOptions{Vault: tv.v, Use: use, Servers: cfg.Servers, RuntimeDir: runtime, Injector: inj, Log: log, Now: tv.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	fan := audit.NewFanout(tv.mem, log)
	t.Cleanup(func() { fan.Close() })
	b.AttachEvidence(fan)
	el := &envLauncher{}
	reg, err := backend.Start(context.Background(), cfg.Servers, backend.Options{
		Limits:   backend.Limits{PerPrincipal: 1, Total: 1, Queue: 1, UpstreamTimeout: time.Second, ResultBytes: 65536},
		Launcher: refusingLauncher{inner: b.WrapLauncher(el)}, Secrets: b, Capabilities: pipeline.NewCapabilities(time.Minute), Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.Close)
	if reg.Servers()["t"] != nil || len(el.envs) != 0 {
		t.Fatal("refused launch started an instance")
	}
	if n := len(useEvents(tv.mem, "delivered")); n != 3 {
		t.Fatalf("delivered events: %d (the test needs launch-time deliveries)", n)
	}
	if len(inj.active()) != 0 {
		t.Fatal("S1 header grant survives a refused launch")
	}
	entries, err := os.ReadDir(runtime)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("runtime dir keeps %d entries after a refused launch", len(entries))
	}
	if n := len(useEvents(tv.mem, "withdrawn")); n != 3 {
		t.Fatalf("withdrawn events: %d", n)
	}
}
