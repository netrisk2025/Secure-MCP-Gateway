package obspolicy

import (
	"slices"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/analytics"
	"github.com/ethan03805/secure-mcp-gateway/internal/anomaly"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// Objects published while the Gateway runs apply to the running analytics
// service at once; the baseline contexts and the memory budget, which the
// running components were built with, are reported as waiting for the next
// start.
func TestPublishedObjectsApplyWithoutRestart(t *testing.T) {
	reqtest.Partial(t, "FR-8.5", "FR-8.10", "FR-8.14", "FR-8.16")
	cfg := testConfig(t, "127.0.0.1:0")
	cfg.Observation.Store = "jsonl"
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	obsCfg := *cfg
	if err := s.Apply(&obsCfg); err != nil {
		t.Fatal(err)
	}
	svc, err := analytics.New(analytics.Options{Config: &obsCfg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	s.SetApplier(svc.Update)
	params := someParams(t)

	if _, err := s.Publish(KindAnomalyResponse, body(t, AnomalyResponse{Scoring: "sync", RequireApprovalBand: "abnormal", WithholdBand: "critical"}), "policy_author:pat", ""); err != nil {
		t.Fatal(err)
	}
	if c := svc.Current(); c.Scoring != "sync" || c.RequireApproval != "abnormal" || c.Withhold != "critical" {
		t.Fatalf("anomaly response not in force: %+v", c)
	}
	if _, err := s.Publish(KindAuditProfile, body(t, AuditProfile{Retention: "48h", EscalationParameters: params[1:2]}), "policy_author:pat", ""); err != nil {
		t.Fatal(err)
	}
	if c := svc.Current(); c.Retention != 48*time.Hour || !slices.Equal(c.Escalation, params[1:2]) {
		t.Fatalf("audit profile not in force: %v %v", c.Retention, c.Escalation)
	}
	ctx := svc.S.Baseline.Dimensions
	if _, err := s.Publish(KindObservationPolicy, body(t, ObservationPolicy{PolicyID: "lab", Parameters: params[:1], SamplingRate: 0.5,
		Contexts: ctx, Bands: []float64{1.5, 2.5, 4}}), "policy_author:pat", ""); err != nil {
		t.Fatal(err)
	}
	c := svc.Current()
	if c.PolicyID != "lab" || c.SamplingRate != 0.5 || svc.Scorer.Thresholds() != (anomaly.Thresholds{Elevated: 1.5, Abnormal: 2.5, Critical: 4}) {
		t.Fatalf("observation policy not in force: %+v %+v", c, svc.Scorer.Thresholds())
	}
	if sel := svc.Collector.SelectedParameters(); !slices.Contains(sel, params[0]) || slices.Contains(sel, params[1]) {
		t.Fatalf("collector selection: %v", sel)
	}
	objs, _, _ := s.Status()
	for _, o := range objs {
		if o.Active != nil && (o.Pending || o.InForce != o.Active.Number || len(o.RestartRequired) != 0) {
			t.Fatalf("%s not in force: %+v", o.Kind, o)
		}
	}

	// Changed contexts and a memory budget wait for the next start; the
	// other fields of the same revision apply.
	if _, err := s.Publish(KindObservationPolicy, body(t, ObservationPolicy{PolicyID: "lab2", Parameters: params[:1], SamplingRate: 0.25,
		Contexts: []string{"tool"}}), "policy_author:pat", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(KindMemoryBudget, body(t, MemoryBudget{ObservationMemoryLimitBytes: 128 << 20}), "operator:olga", ""); err != nil {
		t.Fatal(err)
	}
	if c := svc.Current(); c.PolicyID != "lab2" || c.SamplingRate != 0.25 || svc.Scorer.Thresholds() != anomaly.DefaultThresholds {
		t.Fatalf("live fields of the second policy: %+v %+v", c, svc.Scorer.Thresholds())
	}
	objs, _, _ = s.Status()
	want := map[string]string{KindObservationPolicy: "baseline.contexts", KindMemoryBudget: "memory_limit_bytes"}
	for _, o := range objs {
		if f, ok := want[o.Kind]; ok {
			if !o.Pending || !slices.Equal(o.RestartRequired, []string{f}) {
				t.Fatalf("%s: %+v", o.Kind, o)
			}
		} else if o.Active != nil && o.Pending {
			t.Fatalf("%s pending: %+v", o.Kind, o)
		}
	}
	if live, err := s.Live(); !live || err != nil {
		t.Fatalf("live %v %v", live, err)
	}
}
