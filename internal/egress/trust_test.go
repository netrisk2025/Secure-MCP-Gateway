package egress

import (
	"context"
	"encoding/pem"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

// TestDestinationTrust: [egress] resolvers send the broker's DNS queries
// to the listed servers only, and ca_file adds trust anchors; a missing
// or empty CA file is an error. FromConfig requires capabilities unless
// require_capability = false.
func TestDestinationTrust(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	got := make(chan int, 4)
	go func() {
		buf := make([]byte, 512)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			got <- n
		}
	}()
	res, roots, err := destinationTrust(config.Egress{Resolvers: []string{pc.LocalAddr().String()}})
	if err != nil || roots != nil || res == nil {
		t.Fatalf("%v %v %v", res, roots, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	_, _ = res.LookupNetIP(ctx, "ip4", "probe.test")
	cancel()
	select {
	case n := <-got:
		if n < 12 {
			t.Fatalf("short DNS query %d", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no query reached the configured resolver")
	}

	dir := t.TempDir()
	if _, _, err := destinationTrust(config.Egress{CAFile: filepath.Join(dir, "missing.pem")}); err == nil {
		t.Fatal("missing CA file accepted")
	}
	empty := filepath.Join(dir, "empty.pem")
	os.WriteFile(empty, []byte("not pem"), 0o600)
	if _, _, err := destinationTrust(config.Egress{CAFile: empty}); err == nil || !strings.Contains(err.Error(), "no PEM") {
		t.Fatalf("empty CA file: %v", err)
	}
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	ca := filepath.Join(dir, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	if _, roots, err := destinationTrust(config.Egress{CAFile: ca}); err != nil || roots == nil {
		t.Fatalf("%v %v", roots, err)
	}

	f := false
	for _, tc := range []struct {
		req  *bool
		want bool
	}{{nil, true}, {&f, false}} {
		b, err := FromConfig(&config.Config{Egress: config.Egress{Enabled: true, RequireCapability: tc.req, CAFile: ca}}, &audit.Memory{}, slog.Default())
		if err != nil || b.o.RequireCapability != tc.want || b.o.RootCAs == nil {
			t.Fatalf("require %v: %v %v", tc.req, err, b.o.RequireCapability)
		}
	}
}
