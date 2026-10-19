package approval

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestApproverNoticesWithinTwoSeconds is FR-3.23 end to end at the
// Approval Service: creating a pending approval produces, within 2
// seconds, a notice on the approvals watch stream, which both the
// console's Approvals view (G-13; console/src/App.tsx subscribes approver
// sessions to /api/v1/approvals/watch) and `smcpctl approvals watch` read,
// and an OS desktop notification whose text holds only the public tool
// name, the server alias, the approval ID and the console URL, and no
// argument. With the notifier binary missing, the approval flow is
// unaffected and a diagnostic warning is written.
func TestApproverNoticesWithinTwoSeconds(t *testing.T) {
	reqtest.Verifies(t, "FR-3.23")
	f := newFixture(t, nil)
	stream, cancel := f.svc.Watch()
	defer cancel()
	start := time.Now()
	r := <-f.request(call("s1", "c1"), args(`{"path":"/etc/passwd","token":"hunter2-value"}`), 0, nil)
	select {
	case n := <-stream:
		if n.Type != "requested" || n.Approval.ID != r.res.ApprovalID || time.Since(start) > 2*time.Second {
			t.Fatalf("watch notice %+v after %v", n, time.Since(start))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no watch notice within 2 s")
	}
	f.svc.Close() // waits for the notifier goroutine
	texts := f.notes.all()
	if len(texts) != 1 || f.notes.at[0].Sub(start) > 2*time.Second {
		t.Fatalf("desktop notifications %v", texts)
	}
	for _, want := range []string{"fs_write_file", "fs", r.res.ApprovalID, f.svc.URL(r.res.ApprovalID)} {
		if !strings.Contains(texts[0], want) {
			t.Fatalf("notification %q lacks %q", texts[0], want)
		}
	}
	for _, leak := range []string{"/etc/passwd", "hunter2", "path", "token"} {
		if strings.Contains(texts[0], leak) {
			t.Fatalf("notification %q contains argument content %q", texts[0], leak)
		}
	}

	// The notifier program is missing: the approval flow is unaffected and
	// a warning is logged.
	var logs bytes.Buffer
	var logMu sync.Mutex
	log := slog.New(slog.NewTextHandler(lockedWriter{&logs, &logMu}, nil))
	f2 := newFixture(t, func(cfg *config.Config, o *Options) {
		cfg.Approvals.Notify, cfg.Approvals.NotifyCommand = "command", filepath.Join(t.TempDir(), "no-such-notifier")
		o.Notifier, o.Log = nil, log
	})
	stream2, cancel2 := f2.svc.Watch()
	defer cancel2()
	r = <-f2.request(call("s1", "c2"), args(`{"v":2}`), 0, nil)
	if r.err != nil || r.res.Outcome != pipeline.Pending {
		t.Fatalf("%+v", r)
	}
	select {
	case <-stream2:
	case <-time.After(2 * time.Second):
		t.Fatal("no watch notice with the notifier missing")
	}
	if err := f2.svc.Decide(context.Background(), r.res.ApprovalID, true, "admin:admin", ""); err != nil {
		t.Fatal(err)
	}
	f2.svc.Close()
	logMu.Lock()
	defer logMu.Unlock()
	if !strings.Contains(logs.String(), "desktop notification failed") {
		t.Fatalf("no warning: %s", logs.String())
	}
}
