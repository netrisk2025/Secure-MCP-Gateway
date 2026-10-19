package research

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/baseline"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestAuditGraphML: the audit subgraph has one Call node per record in
// scope, pseudonymized sessions and principals, and the OPENED, MADE,
// INVOKED and DECIDED_UNDER edges; an unknown subgraph is refused.
func TestAuditGraphML(t *testing.T) {
	reqtest.Partial(t, "FR-10.34")
	x, _, _ := exporter(t, "jsonl")
	if _, err := x.Export(Request{Format: GraphML, Subgraph: "everything"}, "a"); !errors.Is(err, ErrFormat) {
		t.Fatalf("unknown subgraph: %v", err)
	}
	m, err := x.Export(Request{Format: GraphML, Subgraph: SubgraphAudit}, "a")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(x.Dir, m.DatasetID)
	checkSums(t, dir)
	raw, _ := os.ReadFile(filepath.Join(dir, "audit.graphml"))
	for _, ident := range []string{"agent-a", "sess-agent-a", "corr-"} {
		if strings.Contains(string(raw), ident) {
			t.Fatalf("audit GraphML holds %q in clear", ident)
		}
	}
	var doc gmlDoc
	if err := xml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	kinds, rels := map[string]int{}, map[string]int{}
	for _, n := range doc.Graph.Nodes {
		for _, d := range n.Data {
			if d.Key == "kind" {
				kinds[d.Value]++
			}
		}
	}
	for _, e := range doc.Graph.Edges {
		for _, d := range e.Data {
			if d.Key == "rel" {
				rels[d.Value]++
			}
		}
	}
	if kinds["Call"] != 40 || m.Rows != 40 || kinds["Session"] != 2 || kinds["Principal"] != 2 || kinds["Tool"] != 3 || kinds["PolicyRevision"] != 1 {
		t.Fatalf("nodes %v, rows %d", kinds, m.Rows)
	}
	if rels["MADE"] != 40 || rels["INVOKED"] != 40 || rels["DECIDED_UNDER"] != 40 || rels["OPENED"] != 2 {
		t.Fatalf("edges %v", rels)
	}
}

// TestExportsLoadInPythonTools is FR-10.34's verification: a dataset is
// exported in Parquet, CSV and JSON Lines and the audit and behavior-model
// subgraphs in GraphML, and the pinned pyarrow, pandas and NetworkX
// (testdata/pyload/requirements.txt) load every file with identical row
// counts: 40 records in each tabular file and 40 Call nodes in the audit
// subgraph. It runs where SMCP_RESEARCH_PYTHON names the Python of a
// virtual environment with those packages and the DuckDB store backend is
// built in (Parquet), as in the CI go job.
func TestExportsLoadInPythonTools(t *testing.T) {
	py := os.Getenv("SMCP_RESEARCH_PYTHON")
	if py == "" || !obsstore.DuckDBAvailable() {
		t.Skip("needs SMCP_RESEARCH_PYTHON (a venv with testdata/pyload/requirements.txt) and the DuckDB backend")
	}
	reqtest.Verifies(t, "FR-10.34")
	x, _, _ := exporter(t, "duckdb")
	args := []string{"-I", filepath.Join("testdata", "pyload", "load.py")}
	for kind, f := range map[string]string{Parquet: "dataset.parquet", CSV: "dataset.csv", JSONL: "dataset.jsonl"} {
		m, err := x.Export(Request{Format: kind, Parameters: []string{"request_bytes", "end_to_end_latency"}}, "a")
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		args = append(args, kind+"="+filepath.Join(x.Dir, m.DatasetID, f))
	}
	m, err := x.Export(Request{Format: GraphML, Subgraph: SubgraphAudit}, "a")
	if err != nil {
		t.Fatal(err)
	}
	args = append(args, "audit="+filepath.Join(x.Dir, m.DatasetID, "audit.graphml"))
	e, _ := baseline.NewEngine(baseline.Config{Dimensions: []string{"principal", "tool"}, Features: []baseline.FeatureSpec{{Name: "x"}}}, nil)
	prev := ""
	for _, tool := range []string{"list", "read", "read", "write"} {
		e.Learn(baseline.Sample{Time: time.Now(), Session: "s", Tool: tool, PrevTool: prev, Dims: map[string]string{"principal": "agent-a", "tool": tool},
			Numeric: map[string]float64{"x": 1}}, baseline.LearnInfo{})
		prev = tool
	}
	snap, _ := e.Build("operator")
	x.Snapshots.Save(snap)
	x.Snapshots.SetPromoted(baseline.Promotion{ID: snap.ID})
	bm, err := x.Export(Request{Format: GraphML}, "a")
	if err != nil {
		t.Fatal(err)
	}
	args = append(args, "behavior="+filepath.Join(x.Dir, bm.DatasetID, "behavior-model.graphml"))

	out, err := exec.Command(py, args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("load.py: %v\n%s", err, ee.Stderr)
		}
		t.Fatal(err)
	}
	var got struct {
		Versions map[string]string `json:"versions"`
		Pyarrow  map[string]int    `json:"pyarrow"`
		Pandas   map[string]int    `json:"pandas"`
		NetworkX map[string]int    `json:"networkx"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	t.Logf("versions %v: pyarrow %v, pandas %v, networkx %v", got.Versions, got.Pyarrow, got.Pandas, got.NetworkX)
	for lib, counts := range map[string]map[string]int{"pyarrow": got.Pyarrow, "pandas": got.Pandas} {
		for _, kind := range []string{Parquet, CSV, JSONL} {
			if counts[kind] != 40 {
				t.Errorf("%s read %d rows of the %s export, want 40", lib, counts[kind], kind)
			}
		}
	}
	if got.NetworkX["audit"] != 40 {
		t.Errorf("NetworkX read %d Call nodes of the audit subgraph, want 40", got.NetworkX["audit"])
	}
	if int64(got.NetworkX["behavior"]) != bm.Rows || bm.Rows == 0 {
		t.Errorf("NetworkX read %d behavior-model nodes, the manifest has %d", got.NetworkX["behavior"], bm.Rows)
	}
}
