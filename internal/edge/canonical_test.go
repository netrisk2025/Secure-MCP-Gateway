package edge

import (
	"fmt"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestCanonicalRequest: each tools/call becomes a canonical request: the
// requested event carries the correlation, session and principal IDs, the
// public tool name, the server and tool revisions, the digest of the
// canonicalized arguments and the receipt time. Calls that differ only in
// key order and whitespace get the same digest; different arguments do not
// (FR-4.1).
func TestCanonicalRequest(t *testing.T) {
	reqtest.Verifies(t, "FR-4.1")
	h := newHarness(t, harnessOpts{})
	s, tok := h.session("ro")
	before := time.Now().Add(-time.Second)
	digest := func(id int, args string) audit.Event {
		t.Helper()
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"t_echo","arguments":%s,"_meta":{%s}}}`, id, args, wireMeta)
		hdr := wireHeaders(tok, "tools/call")
		hdr["Mcp-Name"] = "t_echo"
		// The echo tool's schema refuses the extra member, after the
		// canonical request was recorded.
		if status, _, b := h.post(body, hdr); status != 400 && status != 200 {
			t.Fatalf("call %d: %d %s", id, status, b)
		}
		var found *audit.Event
		h.rec.mu.Lock()
		for i := len(h.rec.events) - 1; i >= 0; i-- {
			if e := h.rec.events[i]; e.Phase == audit.PhaseRequested {
				found = &e
				break
			}
		}
		h.rec.mu.Unlock()
		if found == nil {
			t.Fatal("no requested event")
		}
		return *found
	}
	a := digest(1, `{"text":"hello","n":1}`)
	b := digest(2, " {\n  \"n\" : 1 ,\n  \"text\":\"hello\"\n } ")
	c := digest(3, `{"text":"hello","n":2}`)
	da, _ := a.Detail.(map[string]any)
	db, _ := b.Detail.(map[string]any)
	dc, _ := c.Detail.(map[string]any)
	if da["arguments_sha256"] == nil || da["arguments_sha256"] != db["arguments_sha256"] {
		t.Fatalf("equivalent arguments: %v vs %v", da["arguments_sha256"], db["arguments_sha256"])
	}
	if da["arguments_sha256"] == dc["arguments_sha256"] {
		t.Fatal("different arguments share a digest")
	}
	at, err := time.Parse(time.RFC3339Nano, fmt.Sprint(da["received_at"]))
	if err != nil || at.Before(before) || at.After(time.Now()) {
		t.Fatalf("receipt time %v", da["received_at"])
	}
	if a.CorrelationID == "" || a.CorrelationID == b.CorrelationID || a.SessionID != s.ID || a.PrincipalID != "cc" ||
		da["public_name"] != "t_echo" || a.ServerRevision == "" || a.ToolRevision != a.ServerRevision+"/echo" {
		t.Fatalf("canonical request %+v", a)
	}
}
