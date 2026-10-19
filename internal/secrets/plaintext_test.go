package secrets

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestDeliveryBuffersOverwritten supports the SR-2.13-2 inspection record
// (docs/verification/inspections.md): the decrypted value the vault hands
// the broker for each launch-time delivery (S1, S3, S4) is the buffer the
// fingerprint sinks see, and it is all zeros once Resolve returns; the S1
// value lives only in the Egress Broker's grant, which is cleared when the
// instance is torn down, and the S3 file is removed with it. The S4 value
// is the one string the broker returns (Go strings cannot be overwritten;
// the narrowed requirement allows exactly this copy).
func TestDeliveryBuffersOverwritten(t *testing.T) {
	reqtest.Partial(t, "FR-6.8")
	tv := newTestVault(t)
	for name, v := range map[string]string{"env-secret": envValue, "file-secret": fileValue, "call-secret": callValue, "hdr-secret": hdrValue} {
		tv.create(t, name, v)
	}
	cfg, err := config.Parse([]byte(`
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
	b, err := NewBroker(BrokerOptions{Vault: tv.v, Use: use, Servers: cfg.Servers, RuntimeDir: filepath.Join(t.TempDir(), "run"), Injector: inj, Now: tv.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	b.AttachEvidence(&audit.Memory{})
	var mu sync.Mutex
	var seen [][]byte
	b.ShareFingerprints(func(_ string, _ int, value []byte) {
		mu.Lock()
		seen = append(seen, value) // keeps the slice, not a copy, to look at it afterwards
		mu.Unlock()
	})
	env, err := b.Resolve(context.Background(), pipeline.SecretRequest{Server: "t", Refs: cfg.Servers[0].SecretEnv})
	if err != nil {
		t.Fatal(err)
	}
	if env["API_TOKEN"] != envValue {
		t.Fatal("S4 value not returned")
	}
	if got, _ := os.ReadFile(env["DB_PASS_FILE"]); string(got) != fileValue {
		t.Fatal("S3 file not written")
	}
	mu.Lock()
	if len(seen) != 3 {
		t.Fatalf("%d delivered buffers, want 3 (S1, S3, S4)", len(seen))
	}
	for i, v := range seen {
		if !bytes.Equal(v, make([]byte, len(v))) || len(v) == 0 {
			t.Fatalf("delivery buffer %d not overwritten after the delivery", i)
		}
	}
	mu.Unlock()
	grants := inj.active()
	if len(grants) != 1 || string(grants[0].Value) != hdrValue {
		t.Fatalf("S1 grant %+v", grants)
	}
	held := grants[0].Value
	b.Teardown("t", "test")
	if !bytes.Equal(held, make([]byte, len(held))) {
		t.Fatal("S1 grant value not cleared at teardown")
	}
	if _, err := os.Stat(env["DB_PASS_FILE"]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("S3 file survives teardown")
	}
}
