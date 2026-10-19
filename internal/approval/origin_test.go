package approval

import (
	"context"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/channel"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestRemoteOriginOnApprovalEvents: a call that arrived on the Remote
// Access listener carries its origin (FR-16.8) on every approval event,
// including the decision and consumption that happen outside the call.
func TestRemoteOriginOnApprovalEvents(t *testing.T) {
	reqtest.Partial(t, "FR-16.8")
	f := newFixture(t, nil)
	ctx := channel.With(context.Background(), channel.Origin{Channel: channel.Remote, ClientID: "client-1", ClientAddress: "203.0.113.7"})
	res, err := f.svc.Request(ctx, pipeline.ApprovalRequest{Call: call("s1", "c1"), Arguments: args(`{"v":1}`)})
	if err != nil || res.Outcome != pipeline.Pending {
		t.Fatalf("%+v %v", res, err)
	}
	if rec, _ := f.svc.Get(res.ApprovalID); rec.Channel != channel.Remote || rec.Summary().Channel != channel.Remote {
		t.Fatalf("record origin %+v", rec)
	}
	if err := f.svc.Decide(context.Background(), res.ApprovalID, true, "admin:admin", ""); err != nil {
		t.Fatal(err)
	}
	if res, err = f.svc.Request(ctx, pipeline.ApprovalRequest{Call: call("s1", "c2"), Arguments: args(`{"v":1}`)}); err != nil || res.Outcome != pipeline.Approved {
		t.Fatalf("retry %+v %v", res, err)
	}
	seen := map[string]bool{}
	for _, e := range f.mem.Events() {
		if e.Class != "approval" {
			continue
		}
		if e.Channel != channel.Remote || e.ClientID != "client-1" || e.ClientAddress != "203.0.113.7" || e.ClientAddressSource != channel.AddressSource {
			t.Fatalf("%s event without remote origin: %+v", e.Outcome, e)
		}
		seen[e.Outcome] = true
	}
	for _, want := range []string{"requested", "approved", "consumed"} {
		if !seen[want] {
			t.Fatalf("no %s event: %v", want, seen)
		}
	}
	// A local call has no origin fields.
	res, _ = f.svc.Request(context.Background(), pipeline.ApprovalRequest{Call: call("s2", "c3"), Arguments: args(`{"v":3}`)})
	for _, e := range f.mem.Events() {
		if d, _ := e.Detail.(map[string]any); d["approval_id"] == res.ApprovalID && e.Channel != "" {
			t.Fatalf("local approval event has channel %q", e.Channel)
		}
	}
}
