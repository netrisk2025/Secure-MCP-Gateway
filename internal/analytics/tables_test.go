package analytics

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestObservationTablesLayout is FR-9.7: the Observation Store holds
// observation records, timing spans and system metrics in separate
// tables; the records table has one column for every per-call Parameter
// Catalog parameter and the metrics table one for every periodic
// parameter; and after fixture traffic spanning two UTC days each table is
// partitioned by UTC day, for both store backends.
func TestObservationTablesLayout(t *testing.T) {
	reqtest.Verifies(t, "FR-9.7")
	cat := observe.DefaultCatalog()
	tables := map[string]obsstore.Table{}
	for _, tb := range Tables(cat) {
		tables[tb.Name] = tb
	}
	cols := func(name string) map[string]bool {
		out := map[string]bool{}
		for _, c := range tables[name].Columns {
			if out[c.Name] {
				t.Fatalf("%s: column %s twice", name, c.Name)
			}
			out[c.Name] = true
		}
		return out
	}
	rec, met := cols("records"), cols("metrics")
	if len(tables["spans"].Columns) == 0 {
		t.Fatal("no spans table")
	}
	n := 0
	for _, p := range cat.Params {
		n++
		switch {
		case p.CapturePoint == "periodic" && !met[p.Name]:
			t.Errorf("metrics lacks %s (%s)", p.Name, p.ID)
		case p.CapturePoint != "periodic" && !rec[p.Name]:
			t.Errorf("records lacks %s (%s)", p.Name, p.ID)
		}
	}
	if n < 90 {
		t.Fatalf("catalog has %d parameters", n)
	}
	day1 := time.Date(2026, 10, 16, 23, 59, 0, 0, time.UTC)
	day2 := day1.Add(2 * time.Minute)
	backends := []string{"jsonl"}
	if obsstore.DuckDBAvailable() {
		backends = append(backends, "duckdb")
	}
	for _, b := range backends {
		t.Run(b, func(t *testing.T) {
			st, err := obsstore.Open(obsstore.Options{Dir: filepath.Join(t.TempDir(), "store"), Backend: b, Tables: Tables(cat)})
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			for _, ts := range []time.Time{day1, day2} {
				if err := st.Append("records", []obsstore.Row{{"ts": ts, "correlation_id": "c-" + ts.Format("150405"), "request_bytes": int64(10)}}); err != nil {
					t.Fatal(err)
				}
				if err := st.Append("spans", []obsstore.Row{{"ts": ts, "correlation_id": "c", "stage": "dispatch", "duration_ms": 1.5}}); err != nil {
					t.Fatal(err)
				}
				if err := st.Append("metrics", []obsstore.Row{{"ts": ts, "interval_seconds": 5.0}}); err != nil {
					t.Fatal(err)
				}
			}
			stats, err := st.Stats()
			if err != nil {
				t.Fatal(err)
			}
			for _, tb := range []string{"records", "spans", "metrics"} {
				if d := stats.Days[tb]; len(d) != 2 || d[0] != "2026-10-16" || d[1] != "2026-10-17" {
					t.Errorf("%s partitions %v", tb, d)
				}
			}
		})
	}
}
