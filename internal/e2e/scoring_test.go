package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const scoringFeatures = `[observation.baseline]
n_min = 20
snapshot_records = 0
snapshot_interval = "1000h"
[[observation.baseline.feature]]
parameter = "request_bytes"
transform = "log1p"
sigma_floor = 0.05
[[observation.baseline.feature]]
parameter = "response_bytes"
transform = "log1p"
sigma_floor = 0.05
`

// learnAndPromote runs normal echo and big calls, then builds and promotes
// a snapshot through the control API.
func learnAndPromote(t *testing.T, of *obsFixture, cs *mcp.ClientSession) {
	t.Helper()
	for i := range 40 {
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": fmt.Sprintf("v%03d", i)}}); err != nil {
			t.Fatal(err)
		}
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_big", Arguments: map[string]any{"kib": 10 + i%10}}); err != nil {
			t.Fatal(err)
		}
	}
	of.waitAssembled(80)
	code, built := of.admin("POST", "/api/v1/baselines/snapshots", of.operator, map[string]any{})
	if code != 200 {
		t.Fatalf("build: %d %v", code, built)
	}
	id := built["snapshot"].(map[string]any)["id"].(string)
	if code, p := of.admin("POST", "/api/v1/baselines/"+id+"/promote", of.operator, map[string]any{}); code != 200 {
		t.Fatalf("promote: %d %v", code, p)
	}
}

func phasesOf(evs []audit.Event, corr string) []string {
	var out []string
	for _, e := range evs {
		if e.CorrelationID == corr && e.Phase != "" {
			out = append(out, string(e.Phase))
		}
	}
	return out
}

// TestSynchronousScoringBeforeDispatchAndRelease is FR-4.15: with
// synchronous scoring, the request band is obtained before launch
// authorization (an abnormal request gets the approval obligation and is
// never dispatched) and the response band before release authorization
// (an abnormal response is withheld after dispatch and never delivered).
func TestSynchronousScoringBeforeDispatchAndRelease(t *testing.T) {
	reqtest.Verifies(t, "FR-4.15")
	of := startObservation(t, `sampling_rate = 1.0
scoring = "sync"
require_approval_band = "abnormal"
withhold_band = "abnormal"
`+scoringFeatures)
	access, _, _ := of.oauthLogin("smcp:template:ro")
	cs := of.mcpClient(access)
	learnAndPromote(t, of, cs)

	// Request side: refused before dispatch.
	jerr, data := callErr(t, cs, "t_echo", map[string]any{"text": strings.Repeat("B", 50000)})
	if jerr == nil || jerr.Code != edge.CodeApprovalRequired {
		t.Fatalf("abnormal request: %v %v", jerr, data)
	}
	reqCorr, _ := data["correlationId"].(string)
	// Response side: a normal request whose result is abnormal is withheld.
	jerr, data = callErr(t, cs, "t_big", map[string]any{"kib": 99})
	if jerr == nil || data["reasonCode"] != "ANOMALY_WITHHELD" {
		t.Fatalf("abnormal response: %v %v", jerr, data)
	}
	respCorr, _ := data["correlationId"].(string)
	// FR-1.51: the Table B.2 message (TestEveryReasonCodeEndToEnd lists
	// ANOMALY_WITHHELD as triggered here).
	_, messages, _ := appendixB(t)
	if want := strings.ReplaceAll(messages["ANOMALY_WITHHELD"], "{correlationId}", respCorr); jerr.Code != edge.CodeResponseWithheld || data["message"] != want {
		t.Fatalf("ANOMALY_WITHHELD: code %d message %q, want %q", jerr.Code, data["message"], want)
	}
	evs := of.journal()
	if p := strings.Join(phasesOf(evs, reqCorr), ","); strings.Contains(p, "dispatched") || p == "" {
		t.Fatalf("abnormal request phases %s", p)
	}
	p := phasesOf(evs, respCorr)
	joined := strings.Join(p, ",")
	if !strings.Contains(joined, "dispatched") || strings.Contains(joined, "delivered") || p[len(p)-1] != "withheld" {
		t.Fatalf("abnormal response phases %s", joined)
	}
}

// TestAsynchronousScoringAfterRelease is FR-10.28: with asynchronous
// scoring an abnormal call is released as usual (no obligation, no
// withholding), and the assembled record is scored after release: the
// anomaly alert is recorded after the call's delivered event, and its
// actions hold no blocking action.
func TestAsynchronousScoringAfterRelease(t *testing.T) {
	reqtest.Verifies(t, "FR-10.28")
	of := startObservation(t, `sampling_rate = 1.0
scoring = "async"
`+scoringFeatures)
	access, _, _ := of.oauthLogin("smcp:template:ro")
	cs := of.mcpClient(access)
	learnAndPromote(t, of, cs)
	start := time.Now()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": strings.Repeat("B", 50000)}})
	if err != nil || res.IsError {
		t.Fatalf("abnormal call not released: %v %+v", err, res)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("release took %v", d)
	}
	prov, _ := res.Meta["local.smcpgw/provenance"].(map[string]any)
	decision, _ := prov["decisionId"].(string)
	var corr string
	var delivered, alert *audit.Event
	for deadline := time.Now().Add(10 * time.Second); alert == nil; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no anomaly alert for the abnormal call")
		}
		evs := of.journal()
		for i := range evs {
			e := evs[i]
			if e.DecisionID == decision && e.CorrelationID != "" {
				corr = e.CorrelationID
			}
		}
		for i := range evs {
			e := evs[i]
			switch {
			case e.CorrelationID == corr && e.Phase == audit.PhaseDelivered:
				delivered = &e
			case e.CorrelationID == corr && e.Class == "anomaly":
				alert = &e
			}
		}
	}
	if delivered == nil {
		t.Fatal("no delivered event")
	}
	dt, _ := time.Parse(time.RFC3339Nano, delivered.Time)
	at, _ := time.Parse(time.RFC3339Nano, alert.Time)
	if at.Before(dt) {
		t.Fatalf("scored before release: alert %s, delivered %s", alert.Time, delivered.Time)
	}
	d, _ := alert.Detail.(map[string]any)
	acts := fmt.Sprint(d["actions"])
	if strings.Contains(acts, "require_approval") || strings.Contains(acts, "withhold") || strings.Contains(acts, "sync") {
		t.Fatalf("blocking action on an asynchronous score: %v", d)
	}
}
