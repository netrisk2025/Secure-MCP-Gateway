package secrets

import (
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestSecretUseEventsCarryEveryField is FR-6.11: each delivery and each
// denial of a secret is recorded with the secret reference, version,
// slot, mode, server revision, tool, correlation ID and decision ID, and
// no event (nor the diagnostic log) carries the secret value in any
// encoding. Deliveries are a per-call S2 delivery; denials are an S2 call
// over the binding's rate and a call to a binding that needs an approval
// the decision does not carry.
func TestSecretUseEventsCarryEveryField(t *testing.T) {
	reqtest.Verifies(t, "FR-6.11")
	h := newBrokerHarness(t)
	cs := h.client()
	for range 3 { // calls_per_minute = 3
		if _, rpcErr, _ := call(t, cs, "readcall", nil); rpcErr != nil {
			t.Fatal(rpcErr)
		}
	}
	if _, rpcErr, data := call(t, cs, "readcall", nil); rpcErr == nil || data["reasonCode"] != ReasonRateLimited {
		t.Fatalf("rate: %v %v", rpcErr, data)
	}
	if _, rpcErr, data := call(t, cs, "needsapproval", nil); rpcErr == nil || data["reasonCode"] != ReasonApproval {
		t.Fatalf("approval: %v %v", rpcErr, data)
	}
	check := func(e audit.Event, tool string) {
		t.Helper()
		d := detail(e)
		ref, _ := d["secret_ref"].(string)
		if ref == "" || d["version"] == nil || d["version"] == 0 || d["slot"] == "" || d["mode"] != ModeS2 || d["tool"] != tool ||
			e.ServerRevision == "" || e.CorrelationID == "" || e.DecisionID == "" {
			t.Errorf("%s event lacks a field: %+v %v", e.Outcome, e, d)
		}
	}
	var delivered, denied int
	for _, e := range useEvents(h.mem, "delivered") {
		if detail(e)["mode"] == ModeS2 {
			delivered++
			check(e, "readcall")
		}
	}
	for _, e := range useEvents(h.mem, "denied") {
		denied++
		if e.ReasonCode == ReasonRateLimited {
			check(e, "readcall")
		} else {
			check(e, "needsapproval")
		}
	}
	if delivered != 3 || denied != 2 {
		t.Fatalf("%d S2 deliveries, %d denials", delivered, denied)
	}
	h.assertNoValues()
}
