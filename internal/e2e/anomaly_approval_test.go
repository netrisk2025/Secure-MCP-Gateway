package e2e

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// recordingApprover keeps every approval request and leaves it pending.
type recordingApprover struct {
	mu   sync.Mutex
	reqs []pipeline.ApprovalRequest
}

func (a *recordingApprover) Request(_ context.Context, r pipeline.ApprovalRequest) (pipeline.ApprovalResult, error) {
	a.mu.Lock()
	a.reqs = append(a.reqs, r)
	a.mu.Unlock()
	return pipeline.ApprovalResult{Outcome: pipeline.Pending, ReasonCode: pipeline.ReasonApprovalRequired, RetryText: "pending"}, nil
}

// TestAnomalyApprovalCarriesEvidence: an approval obligation added by
// synchronous scoring reaches the Approval Service with the evidence the
// approval view shows (FR-3.18): public tool name, server revision,
// canonical arguments, decisive rules and the anomaly band with the
// contributing feature and its z-score, plus the baseline snapshot.
func TestAnomalyApprovalCarriesEvidence(t *testing.T) {
	reqtest.Partial(t, "FR-3.18") // the G-13 display is the Inspection record
	ap := &recordingApprover{}
	of := startObservationOpts(t, `sampling_rate = 1.0
scoring = "sync"
require_approval_band = "abnormal"
withhold_band = "off"
`+scoringFeatures, nil, nil, false, ap)
	access, _, _ := of.oauthLogin("smcp:template:ro")
	cs := of.mcpClient(access)
	learnAndPromote(t, of, cs)
	ap.mu.Lock()
	ap.reqs = nil
	ap.mu.Unlock()

	jerr, data := callErr(t, cs, "t_echo", map[string]any{"text": strings.Repeat("B", 50000)})
	if jerr == nil || jerr.Code != edge.CodeApprovalRequired {
		t.Fatalf("abnormal request: %v %v", jerr, data)
	}
	ap.mu.Lock()
	defer ap.mu.Unlock()
	if len(ap.reqs) != 1 {
		t.Fatalf("%d approval requests", len(ap.reqs))
	}
	c := ap.reqs[0].Call
	if c.PublicName != "t_echo" || c.ServerRevision == "" || len(c.DecisiveRules) != 1 || c.DecisiveRules[0] != "ro-t" ||
		!strings.Contains(string(ap.reqs[0].Arguments), `"text"`) {
		t.Fatalf("approval request %+v args %s", c, ap.reqs[0].Arguments)
	}
	a := c.Anomaly
	if a == nil {
		t.Fatal("no anomaly evidence on the approval request")
	}
	if a.Band != "abnormal" && a.Band != "critical" {
		t.Fatalf("band %q", a.Band)
	}
	if a.Feature != "request_bytes" || a.ZScore < 3 || a.SnapshotID == "" || a.SnapshotID != c.AnomalySnapshot {
		t.Fatalf("anomaly evidence %+v (snapshot %q)", a, c.AnomalySnapshot)
	}
}
