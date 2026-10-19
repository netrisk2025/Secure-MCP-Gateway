package edge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestServeFailClosed: while the journal cannot be opened, the harness
// listener answers every MCP request with HTTP 503 and -31004
// JOURNAL_UNAVAILABLE carrying the request's ID, /healthz reports
// fail-closed, and once ready reports true the server stops and the
// listener stays open for the Gateway (FR-9.17). The end-to-end case with
// smcpd and a read-only journal directory is AT-03.
func TestServeFailClosed(t *testing.T) {
	reqtest.Partial(t, "FR-9.17")
	state := t.TempDir()
	if err := keys.Ensure(state, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg, err := config.Parse([]byte(`
[listener]
address = "` + ln.Addr().String() + `"
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listener.TLSCert = filepath.Join(state, "tls", "server.crt")
	cfg.Listener.TLSKey = filepath.Join(state, "tls", "server.key")
	if _, err := os.Stat(cfg.Listener.TLSCert); err != nil {
		t.Fatal(err)
	}
	var ready atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- ServeFailClosed(context.Background(), cfg, ln, ReasonJournalUnavailable, ready.Load, 50*time.Millisecond)
	}()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test server certificate
	base := "https://" + ln.Addr().String()
	var resp *http.Response
	for i := 0; ; i++ {
		resp, err = client.Post(base+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":42,"method":"tools/list","params":{}}`))
		if err == nil {
			break
		}
		if i > 50 {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var body struct {
		ID    int `json:"id"`
		Error struct {
			Code int `json:"code"`
			Data struct {
				ReasonCode string `json:"reasonCode"`
			} `json:"data"`
		} `json:"error"`
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(raw, &body); err != nil || resp.StatusCode != http.StatusServiceUnavailable || body.ID != 42 ||
		body.Error.Code != CodeGatewayFailClosed || body.Error.Data.ReasonCode != ReasonJournalUnavailable {
		t.Fatalf("MCP request: %d %s", resp.StatusCode, raw)
	}
	resp, err = client.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(raw), `"fail-closed"`) {
		t.Fatalf("healthz: %d %s", resp.StatusCode, raw)
	}
	ready.Store(true)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("did not stop when ready")
	}
	// The listener is still open and accepts for the next server.
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "gateway") }), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	r, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("listener closed by the fail-closed server: %v", err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if string(b) != "gateway" {
		t.Fatalf("next server: %q", b)
	}
	// Ending the context also stops it.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	if err := ServeFailClosed(ctx, cfg, ln2, ReasonJournalUnavailable, func() bool { return false }, 20*time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("context end: %v", err)
	}
}
