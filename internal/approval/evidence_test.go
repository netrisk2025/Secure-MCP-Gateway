package approval

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestApprovalRecordEvidence: the approval record that GET
// /api/v1/approvals/{id} returns to the approval view holds the FR-3.18
// evidence: public tool name, server revision, canonical arguments,
// decisive rules and, for an approval an anomaly band required, the band,
// contributing feature and z-score.
func TestApprovalRecordEvidence(t *testing.T) {
	reqtest.Partial(t, "FR-3.18") // the G-13 display is the Inspection record
	f := newFixture(t, nil)
	c := call("s1", "c1")
	c.Anomaly = &pipeline.AnomalyEvidence{Band: "abnormal", Feature: "request_bytes", ZScore: 4.25, SnapshotID: "snap-1", Context: "cc|fs"}
	r := <-f.request(c, args(`{"b":2, "a":1}`), 0, nil)
	if r.res.Outcome != pipeline.Pending {
		t.Fatalf("%+v %v", r.res, r.err)
	}
	rec, ok := f.svc.Get(r.res.ApprovalID)
	if !ok {
		t.Fatal("no record")
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"public_name":"fs_write_file"`, `"server_revision":"sr1"`, `"arguments":{"a":1,"b":2}`, `"decisive_rules":["ap-write"]`,
		`"anomaly":{"band":"abnormal","contributing_feature":"request_bytes","z_score":4.25,"snapshot_id":"snap-1","context":"cc|fs"}`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("record lacks %s: %s", want, raw)
		}
	}
	// An approval with another cause has no anomaly evidence.
	r = <-f.request(call("s1", "c2"), args(`{"k":3}`), 0, nil)
	rec, _ = f.svc.Get(r.res.ApprovalID)
	if rec.Anomaly != nil {
		t.Fatalf("anomaly evidence on a rule approval: %+v", rec.Anomaly)
	}
}
