package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/anomaly"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// jsonlService starts an enabled service on the JSON Lines store with its
// state in a temporary directory, recording evidence in mem.
func jsonlService(t *testing.T, mod func(*config.Config)) (*Service, *audit.Memory) {
	t.Helper()
	cfg := parse(t, `store = "jsonl"`)
	cfg.State.Dir = t.TempDir()
	if mod != nil {
		mod(cfg)
	}
	s, err := New(Options{Config: cfg, Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	if s.Store == nil {
		t.Fatalf("store: %v", s.storeErr)
	}
	mem := &audit.Memory{}
	s.Start(context.Background(), mem, nil, nil)
	t.Cleanup(s.Close)
	return s, mem
}

func scanAll(t *testing.T, s *Service, table string) []obsstore.Row {
	t.Helper()
	s.Sync()
	var out []obsstore.Row
	if err := s.Store.Scan(table, obsstore.Filter{}, func(r obsstore.Row) error { out = append(out, r); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestMetaMetricsSampling: the meta-metrics P-240 to P-250 are sampled
// every MetricsInterval, 10 s by default, and each sample carries every one
// of them, including the journal signing lag and the graph memory once
// their sources are set; 30 intervals give 30 samples (FR-10.9; the
// interval is shortened here so the 30 intervals take a fraction of a
// second instead of five minutes).
func TestMetaMetricsSampling(t *testing.T) {
	reqtest.Verifies(t, "FR-10.9")
	st, err := Resolve(parse(t, ""), observe.DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if st.MetricsInterval != 10*time.Second {
		t.Fatalf("default interval %s", st.MetricsInterval)
	}
	s, _ := jsonlService(t, nil)
	s.SetMetricSources(MetricSources{
		SigningLag:  func() (int, time.Time) { return 3, time.Now().Add(-2 * time.Second) },
		GraphMemory: func() any { return map[string]any{"heap_used": 1 << 20} },
	})
	for i := 0; i < 30; i++ {
		s.sampleMetrics()
	}
	rows := scanAll(t, s, "metrics")
	if len(rows) != 30 {
		t.Fatalf("%d samples", len(rows))
	}
	names := []string{"throughput", "concurrent_calls", "queue_depths", "rss_per_element", "graph_memory", "observation_ingest_rate",
		"capture_drops", "journal_signing_lag", "baseline_cache_size", "cpu_per_element", "store_sizes"}
	for _, r := range rows {
		for _, n := range names {
			if r[n] == nil {
				t.Fatalf("sample lacks %s: %v", n, r)
			}
		}
	}
	// The loop samples at the configured interval.
	s2, _ := jsonlService(t, func(c *config.Config) {
		c.Observation.MetricsInterval = config.Duration{Duration: 20 * time.Millisecond}
	})
	time.Sleep(700 * time.Millisecond)
	if n := len(scanAll(t, s2, "metrics")); n < 10 || n > 40 {
		t.Fatalf("%d samples in 700 ms at a 20 ms interval", n)
	}
}

// TestScoringRecord: the scoring record of an abnormal call holds the
// snapshot ID, the context key, each feature's value and z-score, the
// combined score, the band and the resulting actions, in the scores table
// and in the anomaly evidence event (FR-10.29).
func TestScoringRecord(t *testing.T) {
	reqtest.Verifies(t, "FR-10.29")
	s, mem := jsonlService(t, nil)
	r := &observe.Record{CorrelationID: "corr-abn", Time: time.Now(), Values: map[string]any{"principal_id": "cc", "session_id": "s1", "tool_name": "fs_write"}}
	res := &anomaly.Result{SnapshotID: "snap-7", Context: "cc|dev|fs", Combined: 6.2, Contributor: "request_bytes", Band: anomaly.Abnormal,
		Features: []anomaly.FeatureScore{{Feature: "request_bytes", Value: 50000, Transformed: 10.8, Z: 6.2}, {Feature: "argument_entropy", Value: 3.1, Z: 0.4}},
		Actions:  []string{"alert", "escalate_capture"}}
	s.writeScore(r, res, "async")
	rows := scanAll(t, s, "scores")
	if len(rows) != 1 {
		t.Fatalf("%d score rows", len(rows))
	}
	row := rows[0]
	if row["correlation_id"] != "corr-abn" || row["snapshot_id"] != "snap-7" || row["context"] != "cc|dev|fs" || row["band"] != "abnormal" ||
		row["combined"].(float64) != 6.2 || row["contributing_feature"] != "request_bytes" {
		t.Fatalf("score row %v", row)
	}
	var feats []anomaly.FeatureScore
	if err := json.Unmarshal([]byte(row["features"].(string)), &feats); err != nil || len(feats) != 2 || feats[0].Value != 50000 || feats[0].Z != 6.2 {
		t.Fatalf("features %v %v", row["features"], err)
	}
	if !strings.Contains(row["actions"].(string), "escalate_capture") {
		t.Fatalf("actions %v", row["actions"])
	}
	var ev *audit.Event
	for _, e := range mem.Events() {
		if e.Class == "anomaly" && e.CorrelationID == "corr-abn" {
			e := e
			ev = &e
		}
	}
	if ev == nil || ev.ReasonCode != "ANOMALY_ABNORMAL" {
		t.Fatalf("anomaly evidence %+v", ev)
	}
	d := ev.Detail.(map[string]any)
	if d["snapshot_id"] != "snap-7" || d["context"] != "cc|dev|fs" || d["combined"] != 6.2 || d["features"] == nil || d["actions"] == nil {
		t.Fatalf("anomaly detail %v", d)
	}
}

// TestPurgeReceipt: an Administrator's purge of observation data before a
// date deletes those day partitions and leaves a deletion receipt in the
// journal that names them; when the receipt cannot be recorded, nothing is
// deleted (SR-6.15-1).
func TestPurgeReceipt(t *testing.T) {
	reqtest.Verifies(t, "SR-6.15-1")
	s, mem := jsonlService(t, nil)
	day := func(d string) time.Time { tm, _ := time.Parse("2006-01-02", d); return tm.Add(12 * time.Hour) }
	for _, d := range []string{"2026-10-01", "2026-10-02", "2026-10-03"} {
		if err := s.Store.Append("records", []obsstore.Row{{"ts": day(d), "correlation_id": "c-" + d, "raw_arguments": "payload"}}); err != nil {
			t.Fatal(err)
		}
	}
	purge := func(body string) (int, map[string]any) {
		req := httptest.NewRequest("POST", "/api/v1/observations/purge", bytes.NewReader([]byte(body)))
		w := httptest.NewRecorder()
		s.purge(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, _ := purge(`{"before": "2026-10-03"}`); code != http.StatusBadRequest {
		t.Fatalf("purge without a reason: %d", code)
	}
	mem.Fail(errors.New("disk full"))
	if code, _ := purge(`{"before": "2026-10-03", "reason": "test"}`); code != http.StatusServiceUnavailable {
		t.Fatalf("unrecorded purge: %d", code)
	}
	if n := len(scanAll(t, s, "records")); n != 3 {
		t.Fatalf("a purge without a receipt deleted data: %d rows left", n)
	}
	mem.Fail(nil)
	code, out := purge(`{"before": "2026-10-03", "reason": "data subject request"}`)
	if code != http.StatusOK || out["receipt_id"] == nil {
		t.Fatalf("purge: %d %v", code, out)
	}
	rows := scanAll(t, s, "records")
	if len(rows) != 1 || rows[0]["correlation_id"] != "c-2026-10-03" {
		t.Fatalf("rows left %v", rows)
	}
	var receipt *audit.Event
	for _, e := range mem.Events() {
		if e.ReasonCode == ReasonDataPurged {
			e := e
			receipt = &e
		}
	}
	if receipt == nil {
		t.Fatal("no deletion receipt in the journal")
	}
	d := receipt.Detail.(map[string]any)
	parts, _ := d["partitions"].([]string)
	if d["receipt_id"] != out["receipt_id"] || d["reason"] != "data subject request" || len(parts) != 2 ||
		parts[0] != "records/day=2026-10-01" || parts[1] != "records/day=2026-10-02" {
		t.Fatalf("receipt %v", d)
	}
}
