package obspolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func testConfig(t *testing.T, addr string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	if err := keys.Ensure(dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf(`[admin_listener]
address = %q
[state]
dir = %q
[policy]
file = %q
[admin]
username = "admin"
password_hash = "$argon2id$x"
[observation]
sampling_rate = 0.1
`, addr, dir, filepath.Join(dir, "policy.json"))))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func body(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// someParams returns two per-call S0/S1 parameter names of the shipped
// catalog.
func someParams(t *testing.T) []string {
	t.Helper()
	ps := observe.DefaultCatalog().DefaultParameters()
	if len(ps) < 2 {
		t.Fatal("catalog has fewer than two default parameters")
	}
	return ps[:2]
}

// TestPublishAndApply publishes each object kind, checks validation and
// revision numbering, and checks that Apply overlays the active revisions
// onto the analytics configuration copy and reports them in force.
func TestPublishAndApply(t *testing.T) {
	reqtest.Partial(t, "FR-8.5", "FR-8.10", "FR-8.14", "FR-8.16")
	cfg := testConfig(t, "127.0.0.1:0")
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	params := someParams(t)
	bad := []struct {
		kind string
		body any
	}{
		{KindAuditProfile, AuditProfile{Retention: "1h"}},
		{KindAuditProfile, map[string]any{"retention": "720h", "floor": "off"}}, // unknown field: the floor is not editable
		{KindObservationPolicy, ObservationPolicy{PolicyID: "p", Parameters: params, SamplingRate: 0}},
		{KindObservationPolicy, ObservationPolicy{PolicyID: "p", Parameters: []string{"no_such_parameter"}, SamplingRate: 0.5}},
		{KindObservationPolicy, ObservationPolicy{PolicyID: "p", Parameters: params, SamplingRate: 0.5, Bands: []float64{3, 2, 4}}},
		{KindAnomalyResponse, AnomalyResponse{Scoring: "async", RequireApprovalBand: "abnormal", WithholdBand: "off"}}, // approval needs sync scoring
		{KindAnomalyResponse, AnomalyResponse{Scoring: "sync", RequireApprovalBand: "allow", WithholdBand: "off"}},     // not a restrict-only action
		{KindMemoryBudget, MemoryBudget{ObservationMemoryLimitBytes: 1 << 20}},
	}
	for _, b := range bad {
		if _, err := s.Publish(b.kind, body(t, b.body), "admin:admin", ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s %+v: %v", b.kind, b.body, err)
		}
	}
	if _, err := s.Publish("nope", []byte(`{}`), "a", ""); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("unknown kind: %v", err)
	}
	r1, err := s.Publish(KindAuditProfile, body(t, AuditProfile{Retention: "720h", EscalationParameters: params[:1]}), "policy_author:pat", "shorter retention")
	if err != nil || r1.Number != 1 || r1.Digest == "" {
		t.Fatalf("audit profile: %v %+v", err, r1)
	}
	if _, err := s.Publish(KindObservationPolicy, body(t, ObservationPolicy{PolicyID: "lab", Parameters: params, SamplingRate: 0.5, Contexts: []string{"principal"}, Bands: []float64{2.5, 3.5, 5}}), "policy_author:pat", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(KindAnomalyResponse, body(t, AnomalyResponse{Scoring: "sync", RequireApprovalBand: "abnormal", WithholdBand: "critical"}), "policy_author:pat", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(KindMemoryBudget, body(t, MemoryBudget{ObservationMemoryLimitBytes: 256 << 20}), "operator:olga", ""); err != nil {
		t.Fatal(err)
	}
	r2, err := s.Publish(KindAuditProfile, body(t, AuditProfile{Retention: "1440h"}), "policy_author:pat", "")
	if err != nil || r2.Number != 2 {
		t.Fatalf("second revision: %v %+v", err, r2)
	}
	objs, eff, err := s.Status()
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range objs {
		if o.Active == nil || !o.Pending || o.InForce != 0 {
			t.Errorf("before apply %s: %+v", o.Kind, o)
		}
	}
	if eff.Retention.Duration != 1440*time.Hour || *eff.SamplingRate != 0.5 || eff.WithholdBand != "critical" || eff.MemoryLimitBytes != 256<<20 {
		t.Fatalf("effective: %+v", eff)
	}

	// Reopen (as smcpd does at start) and apply to a copy.
	s2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := *cfg
	if err := s2.Apply(&c); err != nil {
		t.Fatal(err)
	}
	o := c.Observation
	if o.Retention.Duration != 1440*time.Hour || len(o.EscalationParameters) != 0 || o.PolicyID != "lab" || *o.SamplingRate != 0.5 ||
		o.Scoring != "sync" || o.RequireApprovalBand != "abnormal" || o.MemoryLimitBytes != 256<<20 || len(o.Baseline.Bands) != 3 {
		t.Fatalf("applied: %+v", o)
	}
	if *cfg.Observation.SamplingRate != 0.1 {
		t.Fatal("Apply changed the shared configuration")
	}
	objs, _, _ = s2.Status()
	for _, o := range objs {
		if o.Pending || o.InForce == 0 {
			t.Errorf("after apply %s: %+v", o.Kind, o)
		}
	}
	revs, _ := s2.Revisions(KindAuditProfile)
	if len(revs) != 2 || revs[0].Number != 2 || revs[1].Reason != "shorter retention" {
		t.Fatalf("revisions: %+v", revs)
	}
	if st, _ := os.Stat(filepath.Join(cfg.State.Dir, File)); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
}

// TestBandActionsAndEscalationObjects publishes the FR-8.14 fields of the
// Anomaly Response Policy (alert-only bands, the uncharacterized action)
// and the FR-8.10 fields of the Observation Policy (per-band escalation
// parameters, per-feature statistics options), and checks validation and
// the applied configuration.
func TestBandActionsAndEscalationObjects(t *testing.T) {
	reqtest.Partial(t, "FR-8.9", "FR-8.10", "FR-8.14")
	cfg := testConfig(t, "127.0.0.1:0")
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	params := someParams(t)
	floor := 0.25
	bad := []struct {
		kind string
		body any
	}{
		{KindAnomalyResponse, AnomalyResponse{Scoring: "async", EscalateCaptureBand: "normal", RequireApprovalBand: "off", WithholdBand: "off"}},
		{KindAnomalyResponse, AnomalyResponse{Scoring: "async", Uncharacterized: "suspend", RequireApprovalBand: "off", WithholdBand: "off"}},
		{KindAnomalyResponse, AnomalyResponse{Scoring: "async", Uncharacterized: "approve", RequireApprovalBand: "off", WithholdBand: "off"}}, // approval needs sync
		{KindObservationPolicy, ObservationPolicy{PolicyID: "p", Parameters: params, SamplingRate: 0.5, Escalation: map[string][]string{"normal": params}}},
		{KindObservationPolicy, ObservationPolicy{PolicyID: "p", Parameters: params, SamplingRate: 0.5, Escalation: map[string][]string{"critical": {"no_such_parameter"}}}},
		{KindObservationPolicy, ObservationPolicy{PolicyID: "p", Parameters: params, SamplingRate: 0.5, Features: []config.ObservationFeature{{Parameter: "request_bytes", Transform: "cube"}}}},
		{KindObservationPolicy, ObservationPolicy{PolicyID: "p", Parameters: params, SamplingRate: 0.5, Scope: &config.ObservationScope{Frameworks: []string{"not-a-framework"}}}},
		{KindObservationPolicy, ObservationPolicy{PolicyID: "p", Parameters: params, SamplingRate: 0.5, Scope: &config.ObservationScope{Tools: []string{"echo"}}}},
	}
	for _, b := range bad {
		if _, err := s.Publish(b.kind, body(t, b.body), "admin:admin", ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s %+v: %v", b.kind, b.body, err)
		}
	}
	if _, err := s.Publish(KindAnomalyResponse, body(t, AnomalyResponse{Scoring: "sync", EscalateCaptureBand: "abnormal", Uncharacterized: "approve",
		RequireApprovalBand: "critical", WithholdBand: "off"}), "policy_author:pat", ""); err != nil {
		t.Fatal(err)
	}
	feats := []config.ObservationFeature{{Parameter: "request_bytes", Transform: "log1p", Robust: true, SigmaFloor: &floor}, {Parameter: "argument_count"}}
	if _, err := s.Publish(KindObservationPolicy, body(t, ObservationPolicy{PolicyID: "lab", Parameters: params, SamplingRate: 0.2,
		Escalation: map[string][]string{"abnormal": params[:1], "critical": params[1:]}, Features: feats,
		Scope: &config.ObservationScope{Principals: []string{"agents-codex"}, Frameworks: []string{"codex"}, Tools: []string{"ref/echo", "ref/read_file"}}}), "policy_author:pat", ""); err != nil {
		t.Fatal(err)
	}
	c := *cfg
	if err := s.Apply(&c); err != nil {
		t.Fatal(err)
	}
	o := c.Observation
	if o.EscalateCaptureBand != "abnormal" || o.UncharacterizedAction != "approve" || o.RequireApprovalBand != "critical" {
		t.Fatalf("anomaly response applied: %+v", o)
	}
	if len(o.EscalationBands["abnormal"]) != 1 || len(o.EscalationBands["critical"]) != len(params)-1 || len(o.Baseline.Features) != 2 ||
		!o.Baseline.Features[0].Robust || *o.Baseline.Features[0].SigmaFloor != 0.25 || o.Baseline.Features[0].Transform != "log1p" ||
		len(o.Scope.Principals) != 1 || len(o.Scope.Tools) != 2 || o.Scope.Frameworks[0] != "codex" {
		t.Fatalf("observation policy applied: %+v", o)
	}
	// An earlier revision without the new fields keeps the defaults.
	if _, err := s.Publish(KindAnomalyResponse, []byte(`{"scoring":"async","require_approval_band":"off","withhold_band":"off"}`), "policy_author:pat", ""); err != nil {
		t.Fatal(err)
	}
	c = *cfg
	if err := s.Apply(&c); err != nil || c.Observation.EscalateCaptureBand != "" || c.Observation.UncharacterizedAction != "" {
		t.Fatalf("revision without the fields: %v %+v", err, c.Observation)
	}
}

type fakeCtl struct{}

func (fakeCtl) Health() edge.Health                                   { return edge.Health{State: "healthy", Causes: []string{}} }
func (fakeCtl) Stop(string, string) error                             { return nil }
func (fakeCtl) Resume(string) error                                   { return nil }
func (fakeCtl) ActivatePolicy(string, *policy.Snapshot) (bool, error) { return false, nil }

func TestRoutes(t *testing.T) {
	reqtest.Partial(t, "FR-8.5", "FR-8.14", "FR-8.16")
	srv := httptest.NewUnstartedServer(nil)
	cfg := testConfig(t, srv.Listener.Addr().String())
	mem := &audit.Memory{}
	admin, err := adminapi.New(adminapi.Options{Config: cfg, Controller: fakeCtl{}, Evidence: mem})
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	(&Service{Store: st, Evidence: mem}).Register(admin)
	srv.Config.Handler = admin.Handler()
	srv.StartTLS()
	defer srv.Close()
	op, _ := keys.LoadAdminToken(cfg.State.Dir)
	do := func(method, path string, v any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if v != nil {
			rd = bytes.NewReader(body(t, v))
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+op)
		r, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(r.Body).Decode(&out)
		return r.StatusCode, out
	}
	if code, out := do("POST", "/api/v1/observations/anomaly-response", map[string]any{"body": AnomalyResponse{Scoring: "async", RequireApprovalBand: "elevated", WithholdBand: "off"}}); code != 422 {
		t.Fatalf("invalid: %d %v", code, out)
	}
	code, out := do("POST", "/api/v1/observations/anomaly-response", map[string]any{"body": AnomalyResponse{Scoring: "sync", RequireApprovalBand: "elevated", WithholdBand: "critical"}, "reason": "test"})
	if code != 201 {
		t.Fatalf("publish: %d %v", code, out)
	}
	code, out = do("POST", "/api/v1/observations/memory-budget", map[string]any{"body": MemoryBudget{ObservationMemoryLimitBytes: 128 << 20}})
	if code != 201 {
		t.Fatalf("budget: %d %v", code, out)
	}
	code, out = do("GET", "/api/v1/observations/objects", nil)
	eff, _ := out["effective"].(map[string]any)
	if code != 200 || eff["withhold_band"] != "critical" || eff["memory_limit_bytes"] != float64(128<<20) {
		t.Fatalf("status: %d %v", code, out)
	}
	if code, out := do("GET", "/api/v1/observations/objects/anomaly_response", nil); code != 200 || len(out["revisions"].([]any)) != 1 {
		t.Fatalf("revisions: %d %v", code, out)
	}
	found := false
	for _, e := range mem.Events() {
		found = found || e.ReasonCode == "OBSERVATION_OBJECT_PUBLISHED"
	}
	if !found {
		t.Fatal("publication not recorded")
	}
	mem.Fail(errors.New("disk full"))
	if code, _ := do("POST", "/api/v1/observations/memory-budget", map[string]any{"body": MemoryBudget{ObservationMemoryLimitBytes: 256 << 20}}); code != 503 {
		t.Fatalf("publish without evidence: %d", code)
	}
	if revs, _ := st.Revisions(KindMemoryBudget); len(revs) != 1 {
		t.Fatal("a publication without evidence was stored")
	}
}
