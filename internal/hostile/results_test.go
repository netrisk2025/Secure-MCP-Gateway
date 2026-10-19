package hostile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func find(rs []Result, id string) Result {
	for _, r := range rs {
		if r.Fixture == id {
			return r
		}
	}
	return Result{}
}

func TestMergeProfiles(t *testing.T) {
	by := map[string][]Result{
		"standalone": {
			{Fixture: "HF-01", Observed: "blocked", Pass: true},
			{Fixture: "HF-17", Observed: "-31008", Pass: false},
			{Fixture: "HF-20", Observed: "spawned 64", Pass: false},
			{Fixture: "HF-23", Observed: "connected", Pass: true}, // ignored: Enforced row
			{Fixture: "HF-04", Observed: HarnessError},
		},
		"enforced": {
			{Fixture: "HF-01", Observed: "blocked", Pass: true},
			{Fixture: "HF-20", Observed: "pids limit", Pass: true},
			{Fixture: "HF-04", Observed: "tagged", Pass: true},
		},
	}
	rs := Merge(by)
	if len(rs) != len(Rows) {
		t.Fatalf("%d rows", len(rs))
	}
	for id, want := range map[string]bool{"HF-01": true, "HF-17": false, "HF-20": true, "HF-23": false, "HF-04": true, "HF-27": false} {
		if got := find(rs, id); got.Pass != want {
			t.Errorf("%s pass %v, want %v (%+v)", id, got.Pass, want, got)
		}
	}
	if r := find(rs, "HF-01"); r.Profile != "standalone+enforced" || r.Observed != "standalone: blocked | enforced: blocked" || r.Attack == "" || r.Expected == "" {
		t.Fatalf("%+v", r)
	}
	if r := find(rs, "HF-27"); r.Observed != "not run" {
		t.Fatalf("%+v", r)
	}
	// A harness error alone is not a pass.
	if r := Merge(map[string][]Result{"standalone": {{Fixture: "HF-04", Observed: HarnessError, Pass: true}}}); find(r, "HF-04").Pass {
		t.Fatal("harness error counted")
	}
	md := Markdown(rs)
	if !strings.Contains(md, "3 of 27 rows") || !strings.Contains(md, "| HF-01 |") {
		t.Fatal(md)
	}
	if mdCell("a|b\nc") != `a\|b c` {
		t.Fatal(mdCell("a|b\nc"))
	}
}

func TestWriteResults(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteResults(dir, "enforced", []Result{{Fixture: "HF-21", Observed: "oom kill", Pass: true}}); err != nil {
		t.Fatal(err)
	}
	merged, err := WriteResults(dir, "standalone", []Result{{Fixture: "HF-21", Observed: "allocated", Pass: false}, {Fixture: "HF-01", Pass: true, Observed: "ok"}})
	if err != nil {
		t.Fatal(err)
	}
	if r := find(merged, "HF-21"); !r.Pass || !strings.Contains(r.Observed, "oom kill") {
		t.Fatalf("%+v", r)
	}
	b, err := os.ReadFile(filepath.Join(dir, "hostile.json"))
	if err != nil {
		t.Fatal(err)
	}
	var published []map[string]any
	if err := json.Unmarshal(b, &published); err != nil || len(published) != len(Rows) {
		t.Fatalf("%v %d", err, len(published))
	}
	for _, k := range []string{"fixture", "attack", "expected", "observed", "pass"} {
		if _, ok := published[0][k]; !ok {
			t.Errorf("hostile.json lacks %s", k)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "hostile.md")); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "hostile-enforced.json"), []byte("{"), 0o644)
	if _, err := WriteResults(dir, "standalone", nil); err == nil {
		t.Fatal("corrupt profile file accepted")
	}
}
