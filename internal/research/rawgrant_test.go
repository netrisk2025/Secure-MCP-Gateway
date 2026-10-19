package research

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/baseline"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestS3FieldsOnlyWithGrant is SR-6-2: an export includes the S3
// raw-payload field (P-045 raw_arguments) only when the campaign carries
// an approved raw-export grant. Without a campaign, with a campaign that
// has no grant, and for a campaign spec asking for S3 fields without the
// grant, the export (or the campaign) is refused; with the granted and
// approved campaign the field is exported.
func TestS3FieldsOnlyWithGrant(t *testing.T) {
	reqtest.Verifies(t, "SR-6-2")
	dir := t.TempDir()
	table := obsstore.Table{Name: "records", Columns: append(append([]obsstore.Column{}, records.Columns...), obsstore.Column{Name: "raw_arguments", Type: obsstore.Varchar})}
	st, err := obsstore.Open(obsstore.Options{Dir: filepath.Join(dir, "store"), Backend: "jsonl", Tables: []obsstore.Table{table}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var rows []obsstore.Row
	for i := range 10 {
		rows = append(rows, obsstore.Row{"ts": t0.Add(time.Duration(i+11) * 6 * time.Minute), "correlation_id": "c" + string(rune('A'+i)), "server_id": "fs",
			"principal_id": "agent-a", "session_id": "s", "tool_name": "read", "decision_outcome": "permit", "capture": "sampled",
			"request_bytes": int64(10 + i), "raw_arguments": `{"path":"/secret/plan.txt"}`})
	}
	if err := st.Append("records", rows); err != nil {
		t.Fatal(err)
	}
	now := t0
	cs, _ := OpenCampaigns(filepath.Join(dir, "c.json"), observe.DefaultCatalog(), clock(&now))
	snaps, _ := baseline.OpenSnapshotStore(filepath.Join(dir, "snaps"))
	x := &Exporter{Store: st, Catalog: observe.DefaultCatalog(), Campaigns: cs, Snapshots: snaps, Dir: filepath.Join(dir, "exports"),
		KeyDir: filepath.Join(dir, "keys"), Now: clock(&now)}
	complete := func(s Spec) Campaign {
		t.Helper()
		cp, err := cs.Create(s, "admin")
		if err != nil {
			t.Fatal(err)
		}
		cs.Act(cp.ID, "submit", "author", "")
		cs.Act(cp.ID, "approve", "admin", "")
		now = t0.Add(time.Hour)
		cs.Tick()
		now = t0.Add(4 * time.Hour)
		cs.Tick()
		cp, _ = cs.Get(cp.ID)
		return cp
	}
	// No campaign: refused.
	if _, err := x.Export(Request{Format: JSONL, Parameters: []string{"P-045"}}, "a"); !errors.Is(err, ErrRawGrant) {
		t.Fatalf("S3 export without a campaign: %v", err)
	}
	// A campaign spec asking for S3 fields without the grant is invalid.
	noGrant := spec()
	noGrant.Parameters = []string{"P-024", "P-045"}
	if _, err := cs.Create(noGrant, "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("campaign with S3 fields and no grant: %v", err)
	}
	// A campaign without the grant cannot export S3 fields.
	plain := complete(spec())
	if _, err := x.Export(Request{CampaignID: plain.ID, Format: JSONL, Parameters: []string{"P-045"}}, "a"); !errors.Is(err, ErrRawGrant) {
		t.Fatalf("S3 export with an ungranted campaign: %v", err)
	}
	// The approved campaign with the grant exports the field.
	granted := spec()
	granted.Parameters = []string{"P-024", "P-045"}
	granted.RawExport = true
	cp := complete(granted)
	if !cp.RawExport || (cp.State != Completed && cp.State != Exported) {
		t.Fatalf("granted campaign %+v", cp)
	}
	m, err := x.Export(Request{CampaignID: cp.ID, Format: JSONL}, "a")
	if err != nil {
		t.Fatal(err)
	}
	got := readJSONL(t, filepath.Join(x.Dir, m.DatasetID, "dataset.jsonl"))
	if len(got) == 0 {
		t.Fatal("no rows exported")
	}
	for _, r := range got {
		if r["raw_arguments"] != `{"path":"/secret/plan.txt"}` {
			t.Fatalf("row without the granted S3 field: %v", r)
		}
	}
}
