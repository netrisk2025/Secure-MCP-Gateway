package obsstore

import (
	"crypto/sha256"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

var recordsV1 = Table{Name: "records", Columns: []Column{
	{"ts", Timestamp}, {"principal_id", Varchar}, {"tool_name", Varchar}, {"request_bytes", BigInt}, {"argument_entropy", Double}, {"approval_state", Varchar},
}}

// recordsV2 adds a parameter, as a new catalog version would.
var recordsV2 = Table{Name: "records", Columns: append(append([]Column{}, recordsV1.Columns...), Column{"response_bytes", BigInt})}

func backends(t *testing.T) []string {
	b := []string{"jsonl"}
	if DuckDBAvailable() {
		b = append(b, "duckdb")
	} else {
		t.Log("DuckDB backend not in this build (CGO_ENABLED=0); testing jsonl only")
	}
	return b
}

func open(t *testing.T, backend, dir string, tables ...Table) Store {
	t.Helper()
	s, err := Open(Options{Dir: dir, Backend: backend, Tables: tables, MemoryLimit: 256 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

var day0 = time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)

func fixture(n int, seed uint64) []Row {
	r := rand.New(rand.NewPCG(seed, 7))
	rows := make([]Row, n)
	for i := range rows {
		ts := day0.Add(time.Duration(i) * (48 * time.Hour / time.Duration(n)))
		rows[i] = Row{"ts": ts, "principal_id": []string{"p1", "p2"}[i%2], "tool_name": []string{"read", "write", "list"}[i%3],
			"request_bytes": int64(100 + r.IntN(900)), "argument_entropy": r.NormFloat64()*0.5 + 4,
			"approval_state": map[string]any{"required": i%5 == 0}}
	}
	return rows
}

func TestStoreLayoutAndModes(t *testing.T) {
	reqtest.Partial(t, "FR-9.7", "SR-4.2-2")
	for _, b := range backends(t) {
		t.Run(b, func(t *testing.T) {
			dir := t.TempDir()
			metrics := Table{Name: "metrics", Columns: []Column{{"ts", Timestamp}, {"throughput", Double}}}
			spans := Table{Name: "spans", Columns: []Column{{"ts", Timestamp}, {"stage", Varchar}}}
			s := open(t, b, dir, recordsV1, metrics, spans)
			if err := s.Append("records", fixture(200, 1)); err != nil {
				t.Fatal(err)
			}
			if err := s.Append("metrics", []Row{{"ts": day0, "throughput": 1.5}}); err != nil {
				t.Fatal(err)
			}
			if err := s.Append("spans", []Row{{"ts": day0, "stage": "capture"}}); err != nil {
				t.Fatal(err)
			}
			st, err := s.Stats()
			if err != nil {
				t.Fatal(err)
			}
			if got := st.Days["records"]; len(got) != 2 || got[0] != "2026-10-15" || got[1] != "2026-10-16" {
				t.Fatalf("records partitions %v", got)
			}
			if len(st.Days["metrics"]) != 1 || len(st.Days["spans"]) != 1 {
				t.Fatalf("separate tables: %v", st.Days)
			}
			err = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				info, _ := d.Info()
				want := os.FileMode(0o600)
				if d.IsDir() {
					want = 0o700
				}
				if info.Mode().Perm()&^want != 0 {
					t.Errorf("%s mode %v, want %v or stricter", p, info.Mode().Perm(), want)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Append("records", []Row{{"ts": day0, "unknown_col": 1}}); err == nil {
				t.Fatal("undeclared column accepted")
			}
		})
	}
}

func TestStoreScanFilter(t *testing.T) {
	for _, b := range backends(t) {
		t.Run(b, func(t *testing.T) {
			s := open(t, b, t.TempDir(), recordsV1)
			rows := fixture(300, 2)
			if err := s.Append("records", rows[:150]); err != nil {
				t.Fatal(err)
			}
			if err := s.Append("records", rows[150:]); err != nil {
				t.Fatal(err)
			}
			from, to := day0.Add(12*time.Hour), day0.Add(36*time.Hour)
			want := 0
			for _, r := range rows {
				ts := r["ts"].(time.Time)
				if !ts.Before(from) && ts.Before(to) && r["principal_id"] == "p2" {
					want++
				}
			}
			got := 0
			var last time.Time
			err := s.Scan("records", Filter{From: from, To: to, Equals: map[string][]string{"principal_id": {"p2"}}}, func(r Row) error {
				got++
				ts := r["ts"].(time.Time)
				if ts.Before(last) {
					t.Fatal("rows not in time order")
				}
				last = ts
				if _, ok := r["request_bytes"].(int64); !ok {
					t.Fatalf("request_bytes type %T", r["request_bytes"])
				}
				if _, ok := r["approval_state"].(string); !ok {
					t.Fatalf("object stored as %T, want JSON text", r["approval_state"])
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if got != want || got == 0 {
				t.Fatalf("scan returned %d rows, want %d", got, want)
			}
		})
	}
}

// reference computes the aggregate independently of aggregateRows.
func reference(rows []Row, feature string, bucket time.Duration) map[string][]float64 {
	out := map[string][]float64{}
	for _, r := range rows {
		x, ok := toFloat(r[feature])
		if !ok {
			continue
		}
		k := r["principal_id"].(string) + "|" + r["tool_name"].(string)
		if bucket > 0 {
			k += "|" + r["ts"].(time.Time).Truncate(bucket).Format(time.RFC3339)
		}
		out[k] = append(out[k], x)
	}
	return out
}

func TestStoreAggregateMatchesIndependentComputation(t *testing.T) {
	reqtest.Verifies(t, "FR-9.9")
	for _, b := range backends(t) {
		t.Run(b, func(t *testing.T) {
			s := open(t, b, t.TempDir(), recordsV1)
			rows := fixture(3000, 3)
			if err := s.Append("records", rows); err != nil {
				t.Fatal(err)
			}
			for _, feature := range []string{"request_bytes", "argument_entropy"} {
				q := AggQuery{Feature: feature, GroupBy: []string{"principal_id", "tool_name"}, Bucket: 6 * time.Hour,
					Quantiles: []float64{0, 0.5, 0.95, 1}, Histogram: []float64{3.5, 4, 4.5, 500}}
				res, err := s.Aggregate(q)
				if err != nil {
					t.Fatal(err)
				}
				ref := reference(rows, feature, 6*time.Hour)
				if len(res) != len(ref) {
					t.Fatalf("%s: %d groups, want %d", feature, len(res), len(ref))
				}
				for _, r := range res {
					k := r.Group["principal_id"] + "|" + r.Group["tool_name"] + "|" + r.Bucket.Format(time.RFC3339)
					vals := ref[k]
					if int64(len(vals)) != r.Count {
						t.Fatalf("%s %s: count %d, want %d", feature, k, r.Count, len(vals))
					}
					sum := 0.0
					for _, v := range vals {
						sum += v
					}
					mean := sum / float64(len(vals))
					ss := 0.0
					for _, v := range vals {
						ss += (v - mean) * (v - mean)
					}
					variance := ss / float64(len(vals)-1)
					if !close(r.Mean, mean) || !close(r.Variance, variance) {
						t.Fatalf("%s %s: mean %v var %v, want %v %v", feature, k, r.Mean, r.Variance, mean, variance)
					}
					sorted := append([]float64(nil), vals...)
					sort.Float64s(sorted)
					if r.Quantiles[0] != sorted[0] || r.Quantiles[3] != sorted[len(sorted)-1] {
						t.Fatalf("min/max quantiles %v", r.Quantiles)
					}
					// Median by hand: (n-1)/2 interpolation.
					h := float64(len(sorted)-1) * 0.5
					med := sorted[int(h)] + (h-math.Floor(h))*(sorted[min(int(h)+1, len(sorted)-1)]-sorted[int(h)])
					if !close(r.Quantiles[1], med) {
						t.Fatalf("median %v, want %v", r.Quantiles[1], med)
					}
					var hist [5]int64
					for _, v := range vals {
						switch {
						case v <= 3.5:
							hist[0]++
						case v <= 4:
							hist[1]++
						case v <= 4.5:
							hist[2]++
						case v <= 500:
							hist[3]++
						default:
							hist[4]++
						}
					}
					for i := range hist {
						if r.Histogram[i] != hist[i] {
							t.Fatalf("%s histogram %v, want %v", feature, r.Histogram, hist)
						}
					}
				}
			}
			// No bucket, no group: one row over the filter range.
			res, err := s.Aggregate(AggQuery{Feature: "request_bytes", Filter: Filter{Equals: map[string][]string{"tool_name": {"read"}}}})
			if err != nil {
				t.Fatal(err)
			}
			if len(res) != 1 || res[0].Count != 1000 || res[0].Bucket != nil {
				t.Fatalf("ungrouped: %+v", res)
			}
			if _, err := s.Aggregate(AggQuery{Feature: "tool_name"}); err == nil {
				t.Fatal("non-numeric feature accepted")
			}
			if _, err := s.Aggregate(AggQuery{Feature: "request_bytes", GroupBy: []string{`x"; DROP`}}); err == nil {
				t.Fatal("bad group column accepted")
			}
		})
	}
}

func close(a, b float64) bool {
	if a == b {
		return true
	}
	return math.Abs(a-b) <= 1e-9*math.Max(math.Abs(a), math.Abs(b))
}

func hashFiles(t *testing.T, dir string) map[string][32]byte {
	out := map[string][32]byte{}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			out[p] = sha256.Sum256(b)
		}
		return nil
	})
	return out
}

func TestStoreSchemaEvolutionAddsNullableColumn(t *testing.T) {
	reqtest.Verifies(t, "FR-9.8")
	for _, b := range backends(t) {
		t.Run(b, func(t *testing.T) {
			dir := t.TempDir()
			s1 := open(t, b, dir, recordsV1)
			if err := s1.Append("records", fixture(50, 4)); err != nil {
				t.Fatal(err)
			}
			s1.Close()
			before := hashFiles(t, dir)

			s2 := open(t, b, dir, recordsV2)
			late := day0.Add(47 * time.Hour)
			if err := s2.Append("records", []Row{{"ts": late, "principal_id": "p1", "tool_name": "read", "response_bytes": int64(77)}}); err != nil {
				t.Fatal(err)
			}
			after := hashFiles(t, dir)
			for p, h := range before {
				if after[p] != h {
					t.Fatalf("existing partition file %s was rewritten", p)
				}
			}
			n, withNew := 0, 0
			if err := s2.Scan("records", Filter{}, func(r Row) error {
				n++
				if v, ok := r["response_bytes"]; ok {
					withNew++
					if v != int64(77) {
						t.Fatalf("new column value %v", v)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if n != 51 || withNew != 1 {
				t.Fatalf("rows %d, with new column %d", n, withNew)
			}
			res, err := s2.Aggregate(AggQuery{Feature: "response_bytes"})
			if err != nil || len(res) != 1 || res[0].Count != 1 {
				t.Fatalf("aggregate over new column: %+v %v", res, err)
			}
		})
	}
}

func TestStoreRetention(t *testing.T) {
	reqtest.Partial(t, "FR-9.14")
	for _, b := range backends(t) {
		t.Run(b, func(t *testing.T) {
			s := open(t, b, t.TempDir(), recordsV1)
			if err := s.Append("records", fixture(100, 5)); err != nil {
				t.Fatal(err)
			}
			removed, err := s.Retain(day0.Add(60*time.Hour), 24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if len(removed) != 1 || removed[0] != "records/day=2026-10-15" {
				t.Fatalf("removed %v", removed)
			}
			n := 0
			s.Scan("records", Filter{}, func(Row) error { n++; return nil })
			if n != 50 {
				t.Fatalf("%d rows left, want 50", n)
			}
		})
	}
}

func TestBackendsAgree(t *testing.T) {
	if !DuckDBAvailable() {
		t.Skip("DuckDB backend not in this build")
	}
	rows := fixture(500, 6)
	var res [2][]AggRow
	for i, b := range []string{"jsonl", "duckdb"} {
		s := open(t, b, t.TempDir(), recordsV1)
		if err := s.Append("records", rows); err != nil {
			t.Fatal(err)
		}
		var err error
		if res[i], err = s.Aggregate(AggQuery{Feature: "argument_entropy", GroupBy: []string{"tool_name"}, Bucket: time.Hour, Quantiles: []float64{0.25, 0.75}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(res[0]) != len(res[1]) {
		t.Fatalf("group counts differ: %d vs %d", len(res[0]), len(res[1]))
	}
	for i := range res[0] {
		a, b := res[0][i], res[1][i]
		if a.Count != b.Count || !close(a.Mean, b.Mean) || !close(a.Variance, b.Variance) || !close(a.Quantiles[0], b.Quantiles[0]) || !a.Bucket.Equal(*b.Bucket) {
			t.Fatalf("row %d differs:\n%+v\n%+v", i, a, b)
		}
	}
}

func TestIngestRate(t *testing.T) {
	reqtest.Partial(t, "FR-11.6")
	if testing.Short() {
		t.Skip("ingest rate measurement")
	}
	for _, b := range backends(t) {
		t.Run(b, func(t *testing.T) {
			s := open(t, b, t.TempDir(), recordsV1)
			rows := fixture(20000, 8)
			start := time.Now()
			for i := 0; i < len(rows); i += 1000 {
				if err := s.Append("records", rows[i:i+1000]); err != nil {
					t.Fatal(err)
				}
			}
			rate := float64(len(rows)) / time.Since(start).Seconds()
			t.Logf("%s ingest: %.0f records/s in batches of 1000", b, rate)
			if rate < 2000 {
				t.Fatalf("ingest %.0f records/s below 2,000", rate)
			}
		})
	}
}
