package edge

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

func sessionParams() session.CreateParams {
	return session.CreateParams{PrincipalID: "cc", ClientID: "c", Listener: "tls", Claims: session.Claims{Template: "ro"}}
}

// TestSessionEndEffects is FR-2.11 as narrowed for release 1.0: whether a
// session is terminated, expires or is revoked (here by refresh-token
// reuse, which revokes the token family), its open listen streams are
// closed and its in-flight call is cancelled and answered -31006, and the
// Gateway no longer tracks either. Server instances are shared per server
// revision and secret deliveries belong to instances (FR-6.8), so a session
// owns neither.
func TestSessionEndEffects(t *testing.T) {
	reqtest.Verifies(t, "FR-2.11")
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h := newHarness(t, harnessOpts{backend: gatedBackend(started, release)})
	now := time.Now()
	h.store.SetNow(func() time.Time { return now })

	for _, end := range []struct {
		name string
		do   func(id, refresh string)
	}{
		{"terminated", func(id, _ string) {
			if !h.store.Terminate(id) {
				t.Fatal("terminate")
			}
		}},
		{"expired", func(string, string) {
			now = now.Add(h.cfg.Limits.SessionMaxLifetime.Duration + time.Minute)
			h.store.Sweep()
		}},
		{"revoked", func(_, refresh string) {
			if _, _, err := h.store.Refresh(refresh, "c"); err != nil {
				t.Fatalf("first refresh: %v", err)
			}
			if _, _, err := h.store.Refresh(refresh, "c"); err == nil {
				t.Fatal("refresh-token reuse accepted")
			}
		}},
	} {
		s, tok, err := h.store.Create(sessionParams())
		if err != nil {
			t.Fatal(err)
		}
		msgs := openListen(t, h, tok.Access, "L-"+end.name, `{"toolsListChanged":true}`)
		if ack := next(t, msgs, 5*time.Second); ack.Method != "notifications/subscriptions/acknowledged" {
			t.Fatalf("%s: %+v", end.name, ack)
		}
		cs := h.client(tok.Access)
		errc := make(chan error, 1)
		go func() {
			_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_slow", Arguments: map[string]any{}})
			errc <- err
		}()
		select {
		case <-started:
		case err := <-errc:
			t.Fatalf("%s: call ended early: %v", end.name, err)
		case <-time.After(30 * time.Second):
			t.Fatalf("%s: call never reached the backend", end.name)
		}
		if h.gw.InFlight() != 1 || h.gw.ListenStreams() != 1 {
			t.Fatalf("%s: %d calls, %d streams before the end", end.name, h.gw.InFlight(), h.gw.ListenStreams())
		}

		end.do(s.ID, tok.Refresh)

		var we *jsonrpc.Error
		select {
		case err := <-errc:
			if !errors.As(err, &we) || we.Code != CodeSessionInvalid {
				t.Fatalf("%s: in-flight call ended with %v", end.name, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: in-flight call not cancelled", end.name)
		}
		deadline := time.After(10 * time.Second)
	drain:
		for {
			select {
			case _, ok := <-msgs:
				if !ok {
					break drain
				}
			case <-deadline:
				t.Fatalf("%s: listen stream not closed", end.name)
			}
		}
		if h.gw.InFlight() != 0 || h.gw.ListenStreams() != 0 {
			t.Fatalf("%s: %d calls, %d streams after the end", end.name, h.gw.InFlight(), h.gw.ListenStreams())
		}
		if h.store.IsActive(s.ID) {
			t.Fatalf("%s: session still active", end.name)
		}
	}
}
