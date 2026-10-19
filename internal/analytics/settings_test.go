package analytics

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/anomaly"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func parse(t *testing.T, obs string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte("[state]\ndir = \"/tmp/smcp-test-state\"\n[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g\"\n[policy]\nfile = \"p.json\"\n[observation]\n" + obs))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestResolveDefaults(t *testing.T) {
	s, err := Resolve(parse(t, ""), observe.DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if !s.Enabled || s.SamplingRate != 0.1 || s.Retention != 90*24*time.Hour || s.Scoring != "async" || s.RequireApproval != "off" ||
		s.Thresholds.Elevated != 2 || s.Thresholds.Critical != 4 || s.Baseline.NMin != 30 || s.FlushRecords != 1000 ||
		s.FlushInterval != 200*time.Millisecond || s.MetricsInterval != 10*time.Second || s.MemoryLimit != 512<<20 ||
		s.Dir != filepath.Join("/tmp/smcp-test-state", "observation") || len(s.Baseline.Features) != len(DefaultFeatures) {
		t.Fatalf("defaults %+v", s)
	}
	for _, p := range s.Parameters {
		par, _ := observe.DefaultCatalog().Lookup(p)
		if par.Sensitivity != "S0" && par.Sensitivity != "S1" {
			t.Fatalf("default parameter %s is %s", p, par.Sensitivity)
		}
	}
}

func TestResolveErrors(t *testing.T) {
	for obs, want := range map[string]string{
		`parameters = ["P-999"]`:                                                              "unknown parameter",
		`parameters = ["P-145"]`:                                                              "S3",
		`parameters = ["P-240"]`:                                                              "periodic",
		`require_approval_band = "abnormal"`:                                                  "scoring",
		`uncharacterized_action = "approve"`:                                                  "scoring",
		"[observation.escalation_bands]\nabnormal = [\"P-999\"]":                              "unknown parameter",
		"[observation.escalation_bands]\ncritical = [\"P-240\"]":                              "cannot be captured",
		"[observation.escalation_bands]\nabnormal = [\"P-024\"]":                              "",
		"[observation.baseline]\nbands = [3, 2, 4]":                                           "elevated < abnormal",
		"[[observation.baseline.feature]]\nparameter = \"tool_name\"":                         "not numeric",
		"[[observation.baseline.feature]]\nparameter = \"tool_name\"\nkind = \"categorical\"": "",
	} {
		_, err := Resolve(parse(t, obs), observe.DefaultCatalog())
		if want == "" {
			if err != nil {
				t.Fatalf("%q: %v", obs, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%q: %v, want %q", obs, err, want)
		}
	}
}

func TestDisabledService(t *testing.T) {
	cfg := parse(t, "enabled = false")
	s, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Disabled() || s.Observer() != nil {
		t.Fatal("disabled service observes")
	}
	f := pipeline.NewFilters()
	if err := s.RegisterFilters(f); err != nil || len(f.Unavailable([]string{"observe-request"})) != 1 {
		t.Fatal("disabled service registered filters")
	}
	s.Close()
}

func TestStoreUnavailableDoesNotFail(t *testing.T) {
	dir := t.TempDir()
	cfg := parse(t, `store = "duckdb"`)
	cfg.State.Dir = dir
	s, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if s.Disabled() || s.Observer() == nil {
		t.Fatal("service not running")
	}
	// With cgo the store opens; without it the service runs without storage.
	if s.Store == nil && s.storeErr == nil {
		t.Fatal("no store and no error")
	}
	s.Close()
}

// TestObservationScope: the Observation Policy scope (FR-8.9) matches a
// call only when every non-empty list contains the call's value; tools are
// "<server alias>/<tool>".
func TestObservationScope(t *testing.T) {
	reqtest.Partial(t, "FR-8.9")
	if scopeFilter(config.ObservationScope{}) != nil {
		t.Fatal("an empty scope must not filter")
	}
	in := scopeFilter(config.ObservationScope{Principals: []string{"p1"}, Frameworks: []string{"codex"}, Templates: []string{"dev"}, Tools: []string{"ref/echo", "ref/read_file"}})
	rec := func(p, f, tpl, srv, tool string) *observe.Record {
		return &observe.Record{ServerID: srv, Values: map[string]any{"principal_id": p, "framework_type": f, "session_template": tpl, "tool_name": tool}}
	}
	if !in(rec("p1", "codex", "dev", "ref", "echo")) {
		t.Error("matching call out of scope")
	}
	for _, r := range []*observe.Record{rec("p2", "codex", "dev", "ref", "echo"), rec("p1", "goose", "dev", "ref", "echo"),
		rec("p1", "codex", "other", "ref", "echo"), rec("p1", "codex", "dev", "ref", "time_now"), rec("p1", "codex", "dev", "git", "echo")} {
		if in(r) {
			t.Errorf("call in scope: %v %s", r.Values, r.ServerID)
		}
	}
	if _, err := Resolve(parse(t, "[observation.scope]\nprincipals = [\"p1\"]\ntools = [\"ref/echo\"]"), observe.DefaultCatalog()); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Parse([]byte("[state]\ndir = \"/tmp/x\"\n[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g\"\n[policy]\nfile = \"p.json\"\n[observation.scope]\ntools = [\"echo\"]\n")); err == nil {
		t.Error("a tool without its server alias was accepted")
	}
}

// TestAnomalyResponseActions:the band actions of the Anomaly Response
// Policy (FR-8.14). Bands below escalate_capture_band alert only, the
// uncharacterized action applies to calls without a baseline, and with
// synchronous scoring "approve" puts an approval obligation on such a call.
func TestAnomalyResponseActions(t *testing.T) {
	reqtest.Partial(t, "FR-8.14")
	s, err := Resolve(parse(t, `escalate_capture_band = "abnormal"`), observe.DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if s.EscalateCapture != "abnormal" || s.Uncharacterized != "record" {
		t.Fatalf("settings %+v", s)
	}
	for band, want := range map[string]string{
		anomaly.Normal: "", anomaly.Uncharacterized: "", anomaly.Elevated: "alert",
		anomaly.Abnormal: "alert capture_escalation", anomaly.Critical: "alert capture_escalation",
	} {
		if got := strings.Join(s.bandActions(band), " "); got != want {
			t.Errorf("%s: %q, want %q", band, got, want)
		}
	}
	if d, _ := Resolve(parse(t, ""), observe.DefaultCatalog()); strings.Join(d.bandActions(anomaly.Elevated), " ") != "alert capture_escalation" {
		t.Error("default no longer escalates capture from elevated")
	}
	off, _ := Resolve(parse(t, `escalate_capture_band = "off"`+"\nuncharacterized_action = \"escalate\""), observe.DefaultCatalog())
	if strings.Join(off.bandActions(anomaly.Critical), " ") != "alert" || strings.Join(off.bandActions(anomaly.Uncharacterized), " ") != "capture_escalation" {
		t.Errorf("off: %v %v", off.bandActions(anomaly.Critical), off.bandActions(anomaly.Uncharacterized))
	}

	// Synchronous scoring with no baseline: every context is
	// uncharacterized, so "approve" obliges approval for every call.
	cfg := parse(t, "scoring = \"sync\"\nuncharacterized_action = \"approve\"\nstore = \"jsonl\"")
	cfg.State.Dir = t.TempDir()
	svc, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	call := &pipeline.Call{CorrelationID: "c1", SessionID: "s1", PrincipalID: "p1", Server: "ref", Tool: "echo"}
	if _, err := (&requestProbe{s: svc}).FilterRequest(context.Background(), call, []byte(`{"text":"x"}`)); err != nil {
		t.Fatal(err)
	}
	if !call.RequireApproval || call.ApprovalReason != "anomaly context uncharacterized" {
		t.Fatalf("uncharacterized call: approval %v %q", call.RequireApproval, call.ApprovalReason)
	}
}
