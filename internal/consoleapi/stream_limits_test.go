package consoleapi

import (
	"bufio"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

type mapAuth struct {
	mu sync.Mutex
	m  map[string][2]string
}

func (a *mapAuth) Authenticate(tok string) (string, string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.m[tok]
	return v[0], v[1], ok
}

// An evidence stream ends once the token that opened it is signed out; it
// does not keep delivering events to a session that no longer exists.
func TestEvidenceStreamEndsAfterSignOut(t *testing.T) {
	f := newFixture(t, nil)
	auth := &mapAuth{m: map[string][2]string{"aud-tok": {"auditor:bob", adminapi.RoleAuditor}}}
	f.console.d.Admin.AddAuthenticator(auth)
	r := f.raw("GET", "/api/v1/audit/stream", "aud-tok", nil)
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("stream: %d", r.StatusCode)
	}
	rd := bufio.NewReader(r.Body)
	if l, _ := rd.ReadString('\n'); !strings.HasPrefix(l, ": stream open") {
		t.Fatalf("first line %q", l)
	}
	auth.mu.Lock()
	delete(auth.m, "aud-tok")
	auth.mu.Unlock()
	f.record(audit.Event{Class: "admin", Outcome: "stopped", ReasonCode: "EMERGENCY_STOP"})
	done := make(chan string, 1)
	go func() {
		var data string
		for {
			l, err := rd.ReadString('\n')
			if strings.HasPrefix(l, "data: ") {
				data = l
			}
			if err != nil {
				done <- data
				return
			}
		}
	}()
	select {
	case data := <-done:
		if data != "" {
			t.Fatalf("event delivered after sign-out: %q", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream still open 5 s after sign-out and a new event")
	}
}

// Concurrent evidence streams are bounded.
func TestEvidenceStreamLimit(t *testing.T) {
	f := newFixture(t, nil)
	var open []*http.Response
	t.Cleanup(func() {
		for _, r := range open {
			r.Body.Close()
		}
	})
	for i := range maxStreams {
		r := f.raw("GET", "/api/v1/audit/stream", f.operator, nil)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("stream %d: %d", i, r.StatusCode)
		}
		open = append(open, r)
		if l, _ := bufio.NewReader(r.Body).ReadString('\n'); !strings.HasPrefix(l, ": stream open") {
			t.Fatalf("stream %d first line %q", i, l)
		}
	}
	r := f.raw("GET", "/api/v1/audit/stream", f.operator, nil)
	r.Body.Close()
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("stream beyond the limit: %d, want 503", r.StatusCode)
	}
	open[0].Body.Close()
	open = open[1:]
	deadline := time.Now().Add(5 * time.Second)
	for {
		r := f.raw("GET", "/api/v1/audit/stream", f.operator, nil)
		if r.StatusCode == http.StatusOK {
			open = append(open, r)
			break
		}
		r.Body.Close()
		if time.Now().After(deadline) {
			t.Fatalf("closing a stream did not free a slot: %d", r.StatusCode)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
