package research

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/baseline"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

var t0 = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func clock(t *time.Time) func() time.Time { return func() time.Time { return *t } }

func f64(v float64) *float64 { return &v }

func spec() Spec {
	return Spec{Name: "latency study", Scope: Scope{Principals: []string{"agent-a"}, Tools: []string{"read"}}, Parameters: []string{"P-024", "end_to_end_latency"},
		Sampling: f64(1), Start: t0.Add(time.Hour), End: t0.Add(3 * time.Hour), QuotaBytes: 1000}
}

func TestCampaignLifecycle(t *testing.T) {
	reqtest.Verifies(t, "FR-10.30")
	now := t0
	cs, err := OpenCampaigns(filepath.Join(t.TempDir(), "c.json"), observe.DefaultCatalog(), clock(&now))
	if err != nil {
		t.Fatal(err)
	}
	cp, err := cs.Create(spec(), "admin:alice")
	if err != nil {
		t.Fatal(err)
	}
	if cp.State != Draft || cp.Parameters[0] != "request_bytes" || cp.Sampling != 1 || cp.QuotaBytes != 1000 || cp.CreatedBy != "admin:alice" {
		t.Fatalf("created %+v", cp)
	}
	if _, err := cs.Act(cp.ID, "approve", "admin", ""); !errors.Is(err, ErrTransition) {
		t.Fatal("approve from draft allowed")
	}
	steps := []struct{ action, want string }{{"submit", Submitted}, {"reject", Draft}, {"submit", Submitted}, {"approve", Approved}}
	for _, s := range steps {
		if cp, err = cs.Act(cp.ID, s.action, "admin:bob", "r"); err != nil || cp.State != s.want {
			t.Fatalf("%s: %v %s", s.action, err, cp.State)
		}
	}
	if tr, _ := cs.Tick(); len(tr) != 0 {
		t.Fatal("activated before start")
	}
	now = t0.Add(time.Hour)
	if tr, _ := cs.Tick(); len(tr) != 1 || tr[0].To != Active {
		t.Fatalf("activation %+v", tr)
	}
	if len(cs.Active()) != 1 {
		t.Fatal("active campaign not offered to the collector")
	}
	now = t0.Add(3 * time.Hour)
	cs.Tick()
	if cp, _ = cs.Get(cp.ID); cp.State != Completed {
		t.Fatalf("not completed at end: %s", cp.State)
	}
	cs.MarkExported(cp.ID, "ds1", "admin")
	if cp, _ = cs.Get(cp.ID); cp.State != Exported || cp.LastDataset != "ds1" {
		t.Fatalf("export: %+v", cp)
	}
	if cp, err = cs.Act(cp.ID, "expire", "admin", ""); err != nil || cp.State != Expired {
		t.Fatalf("expire: %v", err)
	}
	var seen []string
	for _, h := range cp.History {
		seen = append(seen, h.To)
	}
	if strings.Join(seen, ",") != "draft,submitted,draft,submitted,approved,active,completed,exported,expired" {
		t.Fatalf("history %v", seen)
	}
	// Persisted.
	cs2, _ := OpenCampaigns(cs.path, observe.DefaultCatalog(), nil)
	if c2, _ := cs2.Get(cp.ID); c2.State != Expired || len(c2.History) != 9 {
		t.Fatal("not persisted")
	}
	// Validation.
	bad := spec()
	bad.Parameters = []string{"P-045"}
	if _, err := cs.Create(bad, "a"); !errors.Is(err, ErrInvalid) {
		t.Fatal("S3 parameter without grant accepted")
	}
	bad.RawExport = true
	if _, err := cs.Create(bad, "a"); err != nil {
		t.Fatalf("S3 with grant: %v", err)
	}
}

func TestCampaignQuota(t *testing.T) {
	reqtest.Verifies(t, "FR-10.31")
	now := t0.Add(time.Hour)
	cs, _ := OpenCampaigns(filepath.Join(t.TempDir(), "c.json"), observe.DefaultCatalog(), clock(&now))
	cp, _ := cs.Create(spec(), "a")
	cs.Act(cp.ID, "submit", "a", "")
	cs.Act(cp.ID, "approve", "a", "")
	cs.Tick()
	for i := 0; i < 9; i++ {
		if done := cs.Account([]string{cp.ID}, 100); len(done) != 0 {
			t.Fatalf("completed early at %d", i)
		}
	}
	if done := cs.Account([]string{cp.ID}, 100); len(done) != 1 {
		t.Fatal("not completed at quota")
	}
	c, _ := cs.Get(cp.ID)
	if c.State != Completed || c.UsedBytes != 1000 || c.Records != 10 || len(cs.Active()) != 0 {
		t.Fatalf("%+v", c)
	}
	if done := cs.Account([]string{cp.ID}, 100); len(done) != 0 {
		t.Fatal("completed campaign still accounting")
	}
}

var records = obsstore.Table{Name: "records", Columns: []obsstore.Column{
	{Name: "ts", Type: obsstore.Timestamp}, {Name: "correlation_id", Type: obsstore.Varchar}, {Name: "server_id", Type: obsstore.Varchar},
	{Name: "policy_revision", Type: obsstore.Varchar}, {Name: "capture", Type: obsstore.Varchar},
	{Name: "principal_id", Type: obsstore.Varchar}, {Name: "session_id", Type: obsstore.Varchar}, {Name: "tool_name", Type: obsstore.Varchar},
	{Name: "server_revision", Type: obsstore.Varchar}, {Name: "decision_outcome", Type: obsstore.Varchar}, {Name: "baseline_snapshot_id", Type: obsstore.Varchar},
	{Name: "request_bytes", Type: obsstore.BigInt}, {Name: "end_to_end_latency", Type: obsstore.Double}, {Name: "end_user_claim", Type: obsstore.Varchar},
	{Name: "argument_value_hashes", Type: obsstore.Varchar}, {Name: "argument_entropy", Type: obsstore.Double},
}}

func exporter(t *testing.T, backend string) (*Exporter, *Campaigns, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	st, err := obsstore.Open(obsstore.Options{Dir: filepath.Join(dir, "store"), Backend: backend, Tables: []obsstore.Table{records}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := t0.Add(time.Hour)
	cs, _ := OpenCampaigns(filepath.Join(dir, "c.json"), observe.DefaultCatalog(), clock(&now))
	var rows []obsstore.Row
	for i := 0; i < 40; i++ {
		p := []string{"agent-a", "agent-b"}[i%2]
		tool := []string{"read", "read", "write", "read"}[i%4]
		rows = append(rows, obsstore.Row{"ts": t0.Add(time.Duration(i) * 6 * time.Minute), "correlation_id": "corr-" + string(rune('A'+i)),
			"server_id": "fs", "policy_revision": "rev-7", "capture": "sampled", "principal_id": p, "session_id": "sess-" + p, "tool_name": tool,
			"server_revision": "live-1", "decision_outcome": "permit", "baseline_snapshot_id": "snap-9", "request_bytes": int64(100 + i),
			"end_to_end_latency": float64(i) / 3, "end_user_claim": "alice@example.com", "argument_value_hashes": `{"path":"abc"}`,
			"argument_entropy": 3.5})
	}
	rows[0]["tool_name"] = "=HYPERLINK(\"x\")"
	if err := st.Append("records", rows); err != nil {
		t.Fatal(err)
	}
	snaps, _ := baseline.OpenSnapshotStore(filepath.Join(dir, "snaps"))
	return &Exporter{Store: st, Catalog: observe.DefaultCatalog(), Campaigns: cs, Snapshots: snaps, Dir: filepath.Join(dir, "exports"),
		KeyDir: filepath.Join(dir, "keys"), Now: clock(&now)}, cs, &now
}

func completedCampaign(t *testing.T, cs *Campaigns, now *time.Time) Campaign {
	cp, err := cs.Create(spec(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	cs.Act(cp.ID, "submit", "a", "")
	cs.Act(cp.ID, "approve", "a", "")
	cs.Tick()
	*now = t0.Add(4 * time.Hour)
	cs.Tick()
	cp, _ = cs.Get(cp.ID)
	return cp
}

func readJSONL(t *testing.T, path string) []map[string]any {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		json.Unmarshal(sc.Bytes(), &m)
		out = append(out, m)
	}
	return out
}

func TestExtractionScopeAndPseudonyms(t *testing.T) {
	reqtest.Verifies(t, "FR-10.32", "FR-10.33", "SR-6-1")
	x, cs, now := exporter(t, "jsonl")
	cp := completedCampaign(t, cs, now)
	m1, err := x.Export(Request{CampaignID: cp.ID, Format: JSONL, Parameters: []string{"request_bytes", "end_user_claim", "argument_value_hashes"}}, "admin:alice")
	if err != nil {
		t.Fatal(err)
	}
	rows := readJSONL(t, filepath.Join(x.Dir, m1.DatasetID, "dataset.jsonl"))
	// In scope: agent-a, tool read, within [t0+1h, t0+3h): i even, i%4 != 2, 10 <= i < 30.
	want := 0
	for i := 10; i < 30; i++ {
		if i%2 == 0 && i%4 != 2 {
			want++
		}
	}
	if len(rows) != want || m1.Rows != int64(want) {
		t.Fatalf("%d rows, want %d", len(rows), want)
	}
	raw, _ := os.ReadFile(filepath.Join(x.Dir, m1.DatasetID, "dataset.jsonl"))
	for _, ident := range []string{"agent-a", "sess-agent-a", "alice@example.com", "corr-", `"path"`} {
		if strings.Contains(string(raw), ident) {
			t.Fatalf("export contains identifier %q in clear", ident)
		}
	}
	p1 := rows[0]["principal_id"].(string)
	for _, r := range rows {
		if r["principal_id"] != p1 || r["tool_name"] != "read" {
			t.Fatalf("inconsistent pseudonym or out of scope: %v", r)
		}
		if _, ok := r["request_bytes"].(float64); !ok {
			t.Fatal("numeric parameter not kept")
		}
	}
	m2, err := x.Export(Request{CampaignID: cp.ID, Format: JSONL}, "admin:alice")
	if err != nil {
		t.Fatal(err)
	}
	rows2 := readJSONL(t, filepath.Join(x.Dir, m2.DatasetID, "dataset.jsonl"))
	if rows2[0]["principal_id"] == p1 || rows2[0]["session_id"] == rows[0]["session_id"] {
		t.Fatal("pseudonyms repeat across datasets")
	}
	key, _ := os.ReadFile(filepath.Join(x.KeyDir, m1.DatasetID+".key"))
	k, _ := hex.DecodeString(strings.TrimSpace(string(key)))
	if Pseudonym(k, "agent-a") != p1 {
		t.Fatal("pseudonym is not HMAC-SHA-256 under the dataset key")
	}
	info, _ := os.Stat(filepath.Join(x.KeyDir, m1.DatasetID+".key"))
	if info.Mode().Perm() != 0o600 {
		t.Fatal("key file mode")
	}
}

func TestExportFormatsAndManifest(t *testing.T) {
	reqtest.Partial(t, "FR-10.34", "SR-6.17-1")
	reqtest.Verifies(t, "FR-10.35")
	backends := []string{"jsonl"}
	if obsstore.DuckDBAvailable() {
		backends = append(backends, "duckdb")
	}
	for _, b := range backends {
		t.Run(b, func(t *testing.T) {
			x, _, _ := exporter(t, b)
			counts := map[string]int{}
			formats := []string{JSONL, CSV}
			if b == "duckdb" {
				formats = append(formats, Parquet)
			}
			for _, f := range formats {
				m, err := x.Export(Request{Format: f, Parameters: []string{"request_bytes", "end_to_end_latency"}}, "admin")
				if err != nil {
					t.Fatalf("%s: %v", f, err)
				}
				dir := filepath.Join(x.Dir, m.DatasetID)
				checkSums(t, dir)
				var dict []DictEntry
				raw, _ := os.ReadFile(filepath.Join(dir, "dictionary.json"))
				json.Unmarshal(raw, &dict)
				var gotDict bool
				for _, d := range dict {
					if d.Column == "request_bytes" && d.ID == "P-024" && d.Unit == "bytes" && d.Description != "" {
						gotDict = true
					}
					if d.Column == "principal_id" && !d.Pseudonymized {
						t.Fatal("dictionary does not mark pseudonymized column")
					}
				}
				if !gotDict {
					t.Fatalf("dictionary %s", raw)
				}
				var man Manifest
				raw, _ = os.ReadFile(filepath.Join(dir, "manifest.json"))
				json.Unmarshal(raw, &man)
				if man.CatalogVersion == "" || len(man.PolicyRevisions) != 1 || man.PolicyRevisions[0] != "rev-7" ||
					len(man.BaselineSnapshots) != 1 || man.TimeRange["first"] == nil || man.Filters["parameters"] == nil {
					t.Fatalf("manifest %s", raw)
				}
				switch f {
				case JSONL:
					counts[f] = len(readJSONL(t, filepath.Join(dir, "dataset.jsonl")))
				case CSV:
					fh, _ := os.Open(filepath.Join(dir, "dataset.csv"))
					recs, err := csv.NewReader(fh).ReadAll()
					fh.Close()
					if err != nil {
						t.Fatal(err)
					}
					counts[f] = len(recs) - 1
					found := false
					for _, r := range recs {
						for _, c := range r {
							if strings.Contains(c, "HYPERLINK") {
								found = true
								if !strings.HasPrefix(c, "'=") {
									t.Fatalf("formula cell not neutralized: %q", c)
								}
							}
						}
					}
					if !found {
						t.Fatal("formula fixture missing")
					}
				case Parquet:
					db, err := sql.Open("duckdb", "")
					if err != nil {
						t.Fatal(err)
					}
					var n int
					if err := db.QueryRow("SELECT count(*) FROM read_parquet('" + filepath.Join(dir, "dataset.parquet") + "')").Scan(&n); err != nil {
						t.Fatal(err)
					}
					db.Close()
					counts[f] = n
				}
			}
			for f, n := range counts {
				if n != 40 {
					t.Fatalf("%s has %d rows, want 40 (%v)", f, n, counts)
				}
			}
			if b == "jsonl" {
				if _, err := x.Export(Request{Format: Parquet}, "a"); !errors.Is(err, ErrNoParquet) {
					t.Fatalf("parquet without duckdb: %v", err)
				}
			}
			if _, err := x.Export(Request{Format: "xlsx"}, "a"); !errors.Is(err, ErrFormat) {
				t.Fatal("unknown format accepted")
			}
		})
	}
}

func checkSums(t *testing.T, dir string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("SHA256SUMS: %q", raw)
	}
	for _, l := range lines {
		sum, name, _ := strings.Cut(l, "  ")
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != sum {
			t.Fatalf("checksum mismatch for %s", name)
		}
	}
}

func TestRawGrantAndGraphML(t *testing.T) {
	reqtest.Partial(t, "SR-6-2", "FR-10.34")
	x, cs, now := exporter(t, "jsonl")
	if _, err := x.Export(Request{Format: JSONL, Parameters: []string{"P-045"}}, "a"); !errors.Is(err, ErrRawGrant) {
		t.Fatalf("S3 export without a campaign grant: %v", err)
	}
	cp := completedCampaign(t, cs, now)
	if _, err := x.Export(Request{CampaignID: cp.ID, Format: JSONL, Parameters: []string{"P-145"}}, "a"); !errors.Is(err, ErrRawGrant) {
		t.Fatal("S3 export with a campaign lacking the grant")
	}
	// GraphML of a promoted snapshot.
	if _, err := x.Export(Request{Format: GraphML}, "a"); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("graphml without snapshot: %v", err)
	}
	e, _ := baseline.NewEngine(baseline.Config{Dimensions: []string{"principal", "tool"}, Features: []baseline.FeatureSpec{{Name: "x"}}}, nil)
	prev := ""
	for _, tool := range []string{"list", "read", "read", "write"} {
		e.Learn(baseline.Sample{Time: time.Now(), Session: "s", Tool: tool, PrevTool: prev, Dims: map[string]string{"principal": "agent-a", "tool": tool}, Numeric: map[string]float64{"x": 1}}, baseline.LearnInfo{})
		prev = tool
	}
	snap, _ := e.Build("operator")
	x.Snapshots.Save(snap)
	x.Snapshots.SetPromoted(baseline.Promotion{ID: snap.ID})
	m, err := x.Export(Request{Format: GraphML}, "a")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(x.Dir, m.DatasetID)
	checkSums(t, dir)
	raw, _ := os.ReadFile(filepath.Join(dir, "behavior-model.graphml"))
	if strings.Contains(string(raw), "agent-a") {
		t.Fatal("principal in clear in GraphML")
	}
	var doc gmlDoc
	if err := xml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	next, ctx := 0, 0
	for _, e := range doc.Graph.Edges {
		for _, d := range e.Data {
			if d.Key == "rel" && d.Value == "NEXT_TOOL" {
				next++
			}
		}
	}
	for _, n := range doc.Graph.Nodes {
		for _, d := range n.Data {
			if d.Key == "kind" && d.Value == "BaselineContext" {
				ctx++
			}
		}
	}
	if next != 3 || ctx != 3 {
		t.Fatalf("graph: %d NEXT_TOOL edges, %d contexts", next, ctx)
	}
}
