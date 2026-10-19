package e2e

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestCorrelationAcrossRecords: one call gets one UUIDv7 correlation ID,
// and its evidence events, its observation record and its timing spans all
// carry it (FR-4.2).
func TestCorrelationAcrossRecords(t *testing.T) {
	reqtest.Verifies(t, "FR-4.2")
	of := startObservation(t, "sampling_rate = 1.0\nflush_interval = \"20ms\"")
	access, _, _ := of.oauthLogin("smcp:template:ro")
	res, err := of.mcpClient(access).CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": "trace"}})
	if err != nil {
		t.Fatal(err)
	}
	prov, _ := res.Meta["local.smcpgw/provenance"].(map[string]any)
	decision, _ := prov["decisionId"].(string)
	evs, err := audit.ReadEvents(filepath.Join(of.stateDir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	corr := ""
	phases := map[audit.Phase]bool{}
	for _, e := range evs {
		if e.DecisionID == decision && decision != "" {
			if corr == "" {
				corr = e.CorrelationID
			}
			if e.CorrelationID != corr {
				t.Fatalf("events of one call carry %s and %s", corr, e.CorrelationID)
			}
		}
	}
	for _, e := range evs {
		if e.CorrelationID == corr {
			phases[e.Phase] = true
		}
	}
	// UUIDv7: version nibble 7, RFC 4122 variant.
	if len(corr) != 36 || corr[14] != '7' || (corr[19] != '8' && corr[19] != '9' && corr[19] != 'a' && corr[19] != 'b') {
		t.Fatalf("correlation ID %q is not a UUIDv7", corr)
	}
	for _, p := range []audit.Phase{audit.PhaseRequested, audit.PhaseAuthorized, audit.PhaseDispatched, audit.PhaseCompleted, audit.PhaseDelivered} {
		if !phases[p] {
			t.Fatalf("no %s event with the correlation ID; saw %v", p, phases)
		}
	}
	of.obs.Sync()
	count := func(table string) int {
		n := 0
		if err := of.obs.Store.Scan(table, obsstore.Filter{}, func(r obsstore.Row) error {
			if r["correlation_id"] == corr {
				n++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count("records"); n != 1 {
		t.Fatalf("%d observation records with the correlation ID", n)
	}
	if n := count("spans"); n < 3 {
		t.Fatalf("%d timing spans with the correlation ID", n)
	}
}
