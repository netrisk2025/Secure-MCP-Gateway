package obsstore

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

var spansTable = Table{Name: "spans", Columns: []Column{
	{Name: "ts", Type: Timestamp}, {Name: "correlation_id", Type: Varchar}, {Name: "stage", Type: Varchar},
	{Name: "duration_ms", Type: Double}, {Name: "monotonic", Type: BigInt}, {Name: "policy_revision", Type: Varchar},
	{Name: "observation_policy", Type: Varchar}, {Name: "principal_id", Type: Varchar}, {Name: "tool_name", Type: Varchar},
	{Name: "cpu_ms", Type: Double}, {Name: "rule_id", Type: Varchar}, {Name: "filter_id", Type: Varchar},
}}

// TestRowJSONMatchesEncodingJSON: a row written by appendRowJSON decodes
// to the values its encoding/json encoding decodes to, for strings with
// escapes, control characters, invalid UTF-8, U+2028 and HTML, for
// integers, floats of every magnitude and timestamps.
func TestRowJSONMatchesEncodingJSON(t *testing.T) {
	strs := []string{"", "plain", `quote " and \ backslash`, "ctl \x00\x01\x1f\x7f\b\f\n\r\t", "bad \xff\xc3 utf-8", "sep \u2028 \u2029",
		"<html> & </html>", "é ✓ 𝄞 日本", strings.Repeat("x", 300)}
	floats := []float64{0, 1, -1, 0.1, 1.5e-7, 123456789.125, 1e21, 1e-300, math.MaxFloat64, -math.SmallestNonzeroFloat64, 2.5}
	b := &base{cols: map[string]map[string]Column{}}
	b.cols["spans"] = map[string]Column{}
	for _, c := range spansTable.Columns {
		b.cols["spans"][c.Name] = c
	}
	for i := range 200 {
		r := Row{"ts": time.Date(2026, 10, 17, 12, 0, 0, i*1000, time.UTC), "correlation_id": strs[i%len(strs)], "stage": strs[(i/3)%len(strs)],
			"duration_ms": floats[i%len(floats)], "monotonic": int64(i - 100), "cpu_ms": floats[(i/2)%len(floats)]}
		if i%4 == 0 {
			r["rule_id"] = map[string]any{"nested": strs[i%len(strs)]} // stored as its JSON text
		}
		n, err := b.normalize(spansTable, r)
		if err != nil {
			t.Fatal(err)
		}
		got, err := appendRowJSON(nil, spansTable, n)
		if err != nil {
			t.Fatal(err)
		}
		obj := map[string]any{}
		for k, v := range n {
			obj[k] = jsonValue(v)
		}
		want, _ := json.Marshal(obj)
		var a, w map[string]any
		if err := json.Unmarshal(got, &a); err != nil {
			t.Fatalf("row %d: %v: %s", i, err, got)
		}
		if err := json.Unmarshal(want, &w); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a, w) {
			t.Fatalf("row %d:\n got %s\nwant %s", i, got, want)
		}
	}
	if _, err := appendRowJSON(nil, spansTable, Row{"ts": time.Now(), "cpu_ms": math.NaN()}); err == nil {
		t.Fatal("NaN encoded")
	}
}

// BenchmarkAppendRowJSON encodes one call's worth of span rows (22).
func BenchmarkAppendRowJSON(b *testing.B) {
	rows := make([]Row, 22)
	for i := range rows {
		rows[i] = Row{"ts": time.Now().UTC(), "correlation_id": fmt.Sprintf("corr-%d", i), "stage": "dispatch", "duration_ms": 1.5, "monotonic": int64(1),
			"policy_revision": "r1", "observation_policy": "op", "cpu_ms": 0.1, "rule_id": "r1/x/y"}
	}
	var buf []byte
	b.ReportAllocs()
	for b.Loop() {
		for _, r := range rows {
			buf, _ = appendRowJSON(buf[:0], spansTable, r)
		}
	}
}
