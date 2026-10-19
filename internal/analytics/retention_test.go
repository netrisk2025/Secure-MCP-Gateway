package analytics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestRetentionExecution is FR-9.14: with a one-day Observation Policy
// retention, the retention run deletes observation partitions and exported
// research datasets (with their pseudonymization keys) older than a day,
// keeps newer ones, and records what it removed. Retention runs at start
// and then every retainInterval, at least once a day.
func TestRetentionExecution(t *testing.T) {
	reqtest.Verifies(t, "FR-9.14")
	if retainInterval > 24*time.Hour {
		t.Fatalf("retention runs every %v", retainInterval)
	}
	s, mem := jsonlService(t, func(c *config.Config) { c.Observation.Retention = config.Duration{Duration: 24 * time.Hour} })
	if s.cur().Retention != 24*time.Hour {
		t.Fatalf("retention %v", s.cur().Retention)
	}
	if s.Exporter == nil {
		t.Fatal("no research exporter")
	}
	now := time.Now()
	old, recent := now.Add(-72*time.Hour), now.Add(-time.Hour)
	if err := s.Store.Append("records", []obsstore.Row{{"ts": old, "correlation_id": "old"}, {"ts": recent, "correlation_id": "recent"}}); err != nil {
		t.Fatal(err)
	}
	// The key and the data are written before the manifest, as an export
	// does: the start-up retention run of s.Start runs concurrently and
	// may already remove the expired dataset once its manifest exists.
	// Written in the other order, that run could delete the directory
	// before the key existed and leave the key behind.
	dataset := func(id string, created time.Time) {
		t.Helper()
		if err := os.MkdirAll(s.Exporter.KeyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(s.Exporter.KeyDir, id+".key"), []byte("00\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(s.Exporter.Dir, id)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "dataset.jsonl"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		mb, _ := json.Marshal(map[string]any{"dataset_id": id, "created_at": created})
		tmp := filepath.Join(dir, "manifest.json.tmp")
		if err := os.WriteFile(tmp, mb, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, "manifest.json")); err != nil {
			t.Fatal(err)
		}
	}
	dataset("ds-old", old)
	dataset("ds-recent", recent)
	s.Sync()

	s.retain()

	rows := scanAll(t, s, "records")
	if len(rows) != 1 || rows[0]["correlation_id"] != "recent" {
		t.Fatalf("observation rows left: %v", rows)
	}
	if _, err := os.Stat(filepath.Join(s.Exporter.Dir, "ds-old")); !os.IsNotExist(err) {
		t.Fatalf("expired dataset kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.Exporter.KeyDir, "ds-old.key")); !os.IsNotExist(err) {
		t.Fatalf("expired dataset key kept: %v", err)
	}
	for _, p := range []string{filepath.Join(s.Exporter.Dir, "ds-recent", "dataset.jsonl"), filepath.Join(s.Exporter.KeyDir, "ds-recent.key")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("unexpired data removed: %v", err)
		}
	}
	var obs, research bool
	for _, e := range mem.Events() {
		if e.Outcome != "retention" {
			continue
		}
		d, _ := e.Detail.(map[string]any)
		switch e.Class {
		case "observation":
			obs = d["removed"] != nil
		case "research":
			ids, _ := d["removed_datasets"].([]string)
			research = len(ids) == 1 && ids[0] == "ds-old"
		}
	}
	if !obs || !research {
		t.Fatalf("retention events: observation %v, research %v", obs, research)
	}
}
